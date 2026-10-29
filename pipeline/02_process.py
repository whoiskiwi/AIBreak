"""
02_process.py — Pipeline Step 2: Data Processing and Classification
Zero LLM, pure rule-based extraction

Reads:  pipeline/output/raw_report.md        (auto-collected real CVEs)
        pipeline/data/overrides.json         (human-maintained additions + corrections)
Output: pipeline/output/vulns.json  (used by 03_environment_agent)
        pipeline/output/summary.md  (human-readable summary)

The manifest is rebuilt deterministically: given the same raw_report.md and the
same overrides.json, vulns.json is byte-for-byte identical across runs (sorted by
CVE id, sorted keys). A sha256 of the output is printed so this can be verified.

Overrides file format (pipeline/data/overrides.json):
    {
      "add": [ { ...full vuln object..., "synthetic": true } ],
      "override": { "CVE-2024-xxxx": { "reproducible": true, ... } }
    }
  - "add":      entries not present in raw_report.md (manual or synthetic scenarios).
                Synthetic scenarios should carry "synthetic": true.
  - "override": field-level patches merged onto the auto-parsed entry with that id,
                so manual corrections to real CVEs survive a rebuild.

Usage: python 02_process.py
"""

import re
import json
import os
import hashlib
from collections import Counter

INPUT  = "/Users/chenqi/Desktop/HF_ML/pipeline/output/raw_report.md"
OVERRIDES      = "/Users/chenqi/Desktop/HF_ML/pipeline/data/overrides.json"
OUTPUT_JSON    = "/Users/chenqi/Desktop/HF_ML/pipeline/output/vulns.json"
OUTPUT_SUMMARY = "/Users/chenqi/Desktop/HF_ML/pipeline/output/summary.md"


# ── Vulnerability type classification rules ───────────────────────────────

TYPE_RULES = [
    # Code execution
    ("pickle_rce",       ["pickle", "deserialization", "torch.load", "pickle.load", "pickle.loads", "unsafe deserialization"]),
    ("code_injection",   ["code injection", "github.head_ref", "command injection", "arbitrary code execution",
                          "remote code execution", "rce", "eval(", "exec(", "fickling"]),
    ("sandbox_escape",   ["sandbox", "escape", "local_python_executor", "code execution environment"]),
    # Injection
    ("config_injection", ["config.json", "_attn_implementation", "hub_kernels", "trust_remote_code"]),
    ("sql_injection",    ["sql injection", "sqli", "sql query", "database injection"]),
    ("xpath_injection",  ["xpath injection", "xpath query"]),
    # File operations
    ("path_traversal",   ["path traversal", "directory traversal", "arbitrary file write", "arbitrary file read",
                          "arbitrary file", "shard filename", "hdf5", "zip slip"]),
    ("file_upload",      ["unrestricted upload", "dangerous type", "arbitrary file upload", "malicious file"]),
    # Network requests
    ("ssrf",             ["ssrf", "server-side request forgery", "request forgery"]),
    ("open_redirect",    ["open redirect"]),
    # Authentication and authorization
    ("auth_missing",     ["missing authentication", "no authentication", "unauthenticated", "zeromq", "without auth",
                          "missing authorization", "improper authorization", "unauthorized access",
                          "missing capability check", "privilege escalation", "broken access"]),
    # Information disclosure
    ("data_exfiltration",["data exfiltration", "pre-approved", "webfetch", "out-of-band",
                          "information disclosure", "sensitive data", "credential leak"]),
    # Denial of service
    ("dos",              ["denial of service", "dos attack", "memory exhaustion", "infinite loop",
                          "out of memory", "resource exhaustion", "crash"]),
    # Cross-site scripting
    ("xss",              ["cross-site scripting", "xss", "stored xss", "reflected xss", "svg file upload"]),
    # Memory safety
    ("memory_corruption",["buffer overflow", "stack buffer", "heap overflow", "memory corruption",
                          "use after free", "out-of-bounds"]),
    # ReDoS
    ("redos",            ["redos", "regular expression denial", "catastrophic backtracking"]),
]

# Known packages/products unrelated to HuggingFace, marked directly as irrelevant
IRRELEVANT_PACKAGES = {
    "filament", "suricata", "lunary", "apache-superset", "swiper",
    "org.apache.opennlp", "io.vertx", "github.com/argoproj",
    "xibo", "opensift", "dataease", "chartbrew", "apache superset",
    "wordpress", "joomla", "splunk", "arista", "zfs",
}

def classify_type(desc: str, pkg: str = "") -> str:
    # Filter out obviously unrelated packages
    if any(irr in pkg.lower() for irr in IRRELEVANT_PACKAGES):
        return "irrelevant"
    # Also filter if description contains unrelated product names
    desc_lower = desc.lower()
    irrelevant_keywords = ["wordpress", "filament", "suricata", "linux kernel",
                           "apache superset", "argo cd", "xibo", "splunk", "arista eos",
                           "hypervisor", "symcrypto", "cvat", "eclipse dataspace",
                           "lunary", "data.all", "palantir", "opensift", "qrscp",
                           "dicom", "com_privacy", "zfs_ioc", "llama-cpp-python",
                           "llama.cpp"]
    if any(kw in desc_lower for kw in irrelevant_keywords):
        return "irrelevant"
    for vuln_type, keywords in TYPE_RULES:
        if any(kw in desc_lower for kw in keywords):
            return vuln_type
    return "other"


# ── CVSS vector parsing ───────────────────────────────────────

def parse_cvss_vector(vector: str) -> dict:
    """
    Extract key fields from a CVSS vector string.
    Format: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    """
    result = {
        "attack_vector": "unknown",   # N=network, A=adjacent, L=local, P=physical
        "attack_complexity": "unknown",
        "user_interaction": "none",   # N=none, R=required
        "privileges_required": "none",
    }
    if not vector:
        return result

    av_map  = {"N": "network", "A": "adjacent", "L": "local", "P": "physical"}
    ac_map  = {"L": "low", "H": "high"}
    ui_map  = {"N": "none", "R": "required"}
    pr_map  = {"N": "none", "L": "low", "H": "high"}

    m = re.search(r"AV:([NALP])", vector)
    if m: result["attack_vector"] = av_map.get(m.group(1), "unknown")

    m = re.search(r"AC:([LH])", vector)
    if m: result["attack_complexity"] = ac_map.get(m.group(1), "unknown")

    m = re.search(r"UI:([NR])", vector)
    if m: result["user_interaction"] = ui_map.get(m.group(1), "none")

    m = re.search(r"PR:([NLH])", vector)
    if m: result["privileges_required"] = pr_map.get(m.group(1), "none")

    return result


# ── Reproducibility determination ────────────────────────────

# These types have clear attack paths and can be set up in a Docker environment
REPRODUCIBLE_TYPES = {
    "pickle_rce", "config_injection", "sandbox_escape",
    "code_injection", "path_traversal", "ssrf",
    "auth_missing", "data_exfiltration", "file_upload",
    # irrelevant/redos/dos/xss/memory_corruption/open_redirect excluded
}

def is_reproducible(vuln_type: str, attack_vector: str, cvss: float) -> bool:
    """
    Determine whether a Docker reproduction environment can be set up.
    ReDoS is real but has low reproduction value (service just slows down), excluded for now.
    """
    if vuln_type not in REPRODUCIBLE_TYPES:
        return False
    if cvss == "N/A" or float(cvss) < 4.0:
        return False
    return True


# ── Markdown parsing ──────────────────────────────────────────

def parse_report(path: str) -> list:
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    entries = []
    blocks = re.split(r"\n---\n", content)

    for block in blocks:
        cve_match = re.search(r"### (CVE-\d{4}-\d+)", block)
        if not cve_match:
            continue
        cve_id = cve_match.group(1)

        def field(label):
            m = re.search(rf"\*\*{label}\*\*：(.*)", block)
            return m.group(1).strip() if m else ""

        # Base fields
        pub      = field("Published")
        severity = field("Severity")
        cvss_raw = field("CVSS Score")
        pkg      = field("Affected Package")
        ver      = field("Affected Versions")
        fix      = field("Fixed Version")
        desc     = field("Description")
        source   = field("Data Source")

        # CVSS numeric value
        cvss_num = re.search(r"[\d.]+", cvss_raw)
        cvss = float(cvss_num.group()) if cvss_num else "N/A"

        # CVSS vector (not yet available from description or source data, left empty for future extension)
        cvss_vector = ""
        cvss_fields = parse_cvss_vector(cvss_vector)

        # Classification
        vuln_type = classify_type(desc, pkg)

        # Discard irrelevant entries, do not include in vulns.json
        if vuln_type == "irrelevant":
            continue

        # Reproducibility
        reproducible = is_reproducible(vuln_type, cvss_fields["attack_vector"], cvss)

        entries.append({
            "cve_id":               cve_id,
            "published":            pub,
            "severity":             severity,
            "cvss":                 cvss,
            "cvss_conflict":        "Discrepancy" in source,
            "type":                 vuln_type,
            "affected_package":     pkg,
            "affected_version":     ver,
            "fixed_version":        fix,
            "attack_vector":        cvss_fields["attack_vector"],
            "attack_complexity":    cvss_fields["attack_complexity"],
            "user_interaction":     cvss_fields["user_interaction"],
            "privileges_required":  cvss_fields["privileges_required"],
            "description":          desc,
            "reproducible":         reproducible,
            "synthetic":            False,
        })

    return entries


# ── Overrides: non-destructive manual additions and corrections ───────────

def load_overrides(path: str) -> dict:
    """Load the overrides file. Missing file is fine (returns empty structure)."""
    if not os.path.exists(path):
        print(f"No overrides file at {path} (skipping)")
        return {"add": [], "override": {}}
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    data.setdefault("add", [])
    data.setdefault("override", {})
    return data


def apply_overrides(entries: list, overrides: dict) -> list:
    """Merge overrides onto auto-parsed entries without losing manual work.

    - "override": field-level patches merged onto the matching auto-parsed entry.
    - "add":      full entries appended (manual/synthetic). If an id collides with
                  an auto-parsed entry, the add-entry replaces it (manual wins).
    Every entry ends up with an explicit "synthetic" flag.
    """
    by_id = {e["cve_id"]: e for e in entries}

    # Field-level patches onto existing auto-parsed entries
    for cve_id, patch in overrides.get("override", {}).items():
        if cve_id in by_id:
            by_id[cve_id].update(patch)
        else:
            print(f"[WARN] override for {cve_id} but no such auto-parsed entry; ignored")

    # Full manual/synthetic additions (manual wins on id collision)
    for add in overrides.get("add", []):
        cid = add.get("cve_id")
        if not cid:
            print(f"[WARN] overrides 'add' entry without cve_id; skipped: {add}")
            continue
        entry = dict(add)
        entry.setdefault("synthetic", False)
        if cid in by_id:
            print(f"[INFO] overrides 'add' replaces auto-parsed {cid}")
        by_id[cid] = entry

    # Ensure every entry carries the synthetic flag
    for e in by_id.values():
        e.setdefault("synthetic", False)

    return list(by_id.values())


def write_deterministic_json(path: str, entries: list) -> str:
    """Write vulns.json deterministically (sorted entries + sorted keys) and return its sha256."""
    ordered = sorted(entries, key=lambda e: e["cve_id"])
    text = json.dumps(ordered, ensure_ascii=False, indent=2, sort_keys=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ── Generate summary ──────────────────────────────────────────

def generate_summary(vulns: list) -> str:
    total        = len(vulns)
    auto         = [v for v in vulns if not v.get("synthetic")]
    synthetic    = [v for v in vulns if v.get("synthetic")]
    reproducible = [v for v in vulns if v["reproducible"]]
    types        = Counter(v["type"] for v in vulns)
    severities   = Counter(v["severity"] for v in vulns)

    pct = (len(reproducible) * 100 // total) if total else 0
    lines = [
        f"# Vulnerability Data Summary\n",
        f"**Total:** {total} CVEs "
        f"(auto-collected: {len(auto)}, synthetic: {len(synthetic)})",
        f"**Reproducible:** {len(reproducible)} ({pct}%)\n",
        "## Vulnerability Type Distribution\n",
        "| Type | Count |",
        "|------|-------|",
    ]
    for t, count in types.most_common():
        lines.append(f"| {t} | {count} |")

    lines += [
        "\n## Severity Distribution\n",
        "| Severity | Count |",
        "|----------|-------|",
    ]
    for s, count in severities.most_common():
        lines.append(f"| {s} | {count} |")

    if synthetic:
        lines += [
            "\n## Synthetic Scenarios (not real CVEs; counted separately)\n",
            "| CVE | Type | CVSS | Package |",
            "|-----|------|------|---------|",
        ]
        for v in sorted(synthetic, key=lambda x: x["cve_id"]):
            lines.append(f"| {v['cve_id']} | {v['type']} | {v['cvss']} | {v['affected_package']} |")

    lines += [
        "\n## Reproducible Vulnerability List (for use by Environment Agent)\n",
        "| CVE | Type | CVSS | Package | Synthetic |",
        "|-----|------|------|---------|-----------|",
    ]
    for v in sorted(reproducible, key=lambda x: -(x["cvss"] if x["cvss"] != "N/A" else 0)):
        syn = "yes" if v.get("synthetic") else ""
        lines.append(f"| {v['cve_id']} | {v['type']} | {v['cvss']} | {v['affected_package']} | {syn} |")

    return "\n".join(lines)


# ── Main flow ────────────────────────────────────────────────

def main():
    print(f"Reading: {INPUT}")
    auto = parse_report(INPUT)
    print(f"Parsed {len(auto)} CVEs from raw report")

    overrides = load_overrides(OVERRIDES)
    print(f"Overrides: {len(overrides['add'])} add, {len(overrides['override'])} patch")

    vulns = apply_overrides(auto, overrides)
    synthetic = [v for v in vulns if v.get("synthetic")]
    reproducible = [v for v in vulns if v["reproducible"]]
    print(f"Total after overrides: {len(vulns)} "
          f"(auto {len(vulns) - len(synthetic)}, synthetic {len(synthetic)})")
    print(f"Reproducible: {len(reproducible)}")

    # Output JSON (deterministic)
    os.makedirs(os.path.dirname(OUTPUT_JSON), exist_ok=True)
    digest = write_deterministic_json(OUTPUT_JSON, vulns)
    print(f"JSON written to: {OUTPUT_JSON}")
    print(f"sha256: {digest}")

    # Output summary
    summary = generate_summary(vulns)
    with open(OUTPUT_SUMMARY, "w", encoding="utf-8") as f:
        f.write(summary)
    print(f"Summary written to: {OUTPUT_SUMMARY}")

    # Print type distribution
    types = Counter(v["type"] for v in vulns)
    print("\nVulnerability type distribution:")
    for t, count in types.most_common():
        mark = " <- reproducible" if t in REPRODUCIBLE_TYPES else ""
        print(f"  {t}: {count}{mark}")


if __name__ == "__main__":
    main()
