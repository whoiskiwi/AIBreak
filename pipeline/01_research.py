"""
01_research.py — Pipeline Step 1: Vulnerability Data Collection
Fully standalone, zero LLM, zero external dependencies (only requires requests)

Usage: python 01_research.py
Output: pipeline/output/raw_report.md
        pipeline/data/raw/<run-timestamp>/   (raw API snapshots, gitignored)

Snapshots: every NVD/GHSA response is written verbatim to the run directory with
a timestamp, the exact source URL and the HTTP status, so a run can be audited or
replayed without re-hitting the APIs.
"""

import os
import re
import json
import time
import urllib.parse
from datetime import datetime, timezone

import requests

# ============================================================
# Edit here
# ============================================================
COMPANY    = "Hugging Face"
START_DATE = "2024-01-01"
END_DATE   = "2026-12-31"
OUTPUT     = "/Users/chenqi/Desktop/HF_ML/pipeline/output/raw_report.md"
RAW_DIR    = "/Users/chenqi/Desktop/HF_ML/pipeline/data/raw"

# HuggingFace sub-projects — NVD registers by product name rather than company name, so each must be searched separately
SUBPROJECTS = ["LeRobot", "smolagents", "diffusers", "tokenizers", "peft"]
# "datasets" and "accelerate" are too generic and would match many unrelated CVEs, so they are not used as search terms
# "transformers" also carries false-positive risk and is covered by company-name variants
# ============================================================

NVD  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
HEAD = {"User-Agent": "StandaloneResearch/1.0"}

# NVD allows up to 2000 results per page; paginate via startIndex until totalResults is reached.
PAGE_SIZE = 2000

# Product/description keywords unrelated to HuggingFace — any match causes the CVE to be skipped and excluded from the report
IRRELEVANT_VENDORS = {
    "filament", "suricata", "lunary", "apache superset", "swiper",
    "opennlp", "vert.x", "argo cd", "xibo", "opensift", "dataease",
    "chartbrew", "wordpress", "joomla", "splunk", "arista", "zfs",
    "palantir", "cvat", "qrscp", "dicom", "symcrypto", "hypervisor",
    "eclipse dataspace", "llama.cpp", "llama-cpp-python",
}


# ── Snapshot / logging infrastructure ─────────────────────────────

# Set by main(); holds the per-run snapshot directory and an accumulating error log.
_RUN_DIR = None
_ERRORS = []


def _log_error(context: str, url: str, detail: str):
    """Record an explicit error instead of silently swallowing it."""
    msg = f"[ERROR] {context} | url={url} | {detail}"
    print(msg)
    _ERRORS.append({
        "context": context,
        "url": url,
        "detail": detail,
        "at": datetime.now(timezone.utc).isoformat(),
    })


def _safe_name(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s)[:120]


def _snapshot(name: str, url: str, status, data):
    """Write a raw API response (or error payload) to the run snapshot directory."""
    if not _RUN_DIR:
        return
    path = os.path.join(_RUN_DIR, _safe_name(name) + ".json")
    payload = {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "source_url": url,
        "status_code": status,
        "data": data,
    }
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"[WARN] failed to write snapshot {path}: {e}")


def is_relevant(nvd: dict) -> bool:
    """Determine whether a CVE is relevant to the HuggingFace ecosystem; irrelevant entries are excluded from the report."""
    desc = ""
    for d in nvd.get("descriptions", []):
        if d.get("lang") == "en":
            desc = d.get("value", "").lower()
            break
    return not any(kw in desc for kw in IRRELEVANT_VENDORS)


# ── Data Fetching ────────────────────────────────────────────────

def search_nvd(keyword: str) -> list:
    """Search NVD for a keyword, paginating through every result page.

    Previously this capped at a single 100-result page, silently dropping any
    matches beyond the first page. It now follows startIndex/totalResults to the
    end and logs any page that fails instead of discarding it quietly.
    """
    results = []
    start = 0
    page = 0
    while True:
        url = (
            f"{NVD}?keywordSearch={urllib.parse.quote(keyword)}"
            f"&resultsPerPage={PAGE_SIZE}&startIndex={start}"
        )
        try:
            time.sleep(6)  # NVD rate limit: 5 requests / 30s without an API key
            r = requests.get(url, headers=HEAD, timeout=30)
        except Exception as e:
            _log_error(f"search_nvd({keyword!r}) page {page}", url, f"request failed: {e}")
            _snapshot(f"search_{keyword}_p{page}_error", url, None, {"error": str(e)})
            break

        if r.status_code != 200:
            _log_error(f"search_nvd({keyword!r}) page {page}", url, f"HTTP {r.status_code}: {r.text[:200]}")
            _snapshot(f"search_{keyword}_p{page}_http{r.status_code}", url, r.status_code, {"body": r.text[:1000]})
            break

        try:
            body = r.json()
        except Exception as e:
            _log_error(f"search_nvd({keyword!r}) page {page}", url, f"bad JSON: {e}")
            _snapshot(f"search_{keyword}_p{page}_badjson", url, r.status_code, {"body": r.text[:1000]})
            break

        _snapshot(f"search_{keyword}_p{page}", url, r.status_code, body)

        batch = body.get("vulnerabilities", [])
        results.extend(batch)

        total = body.get("totalResults", len(results))
        start += PAGE_SIZE
        page += 1
        if start >= total or not batch:
            break

    return results


def detail_nvd(cve_id: str) -> dict:
    url = f"{NVD}?cveId={cve_id}"
    try:
        time.sleep(7)
        r = requests.get(url, headers=HEAD, timeout=30)
    except Exception as e:
        _log_error(f"detail_nvd({cve_id})", url, f"request failed: {e}")
        _snapshot(f"detail_nvd_{cve_id}_error", url, None, {"error": str(e)})
        return {}

    if r.status_code != 200:
        _log_error(f"detail_nvd({cve_id})", url, f"HTTP {r.status_code}: {r.text[:200]}")
        _snapshot(f"detail_nvd_{cve_id}_http{r.status_code}", url, r.status_code, {"body": r.text[:1000]})
        return {}

    try:
        body = r.json()
    except Exception as e:
        _log_error(f"detail_nvd({cve_id})", url, f"bad JSON: {e}")
        _snapshot(f"detail_nvd_{cve_id}_badjson", url, r.status_code, {"body": r.text[:1000]})
        return {}

    _snapshot(f"detail_nvd_{cve_id}", url, r.status_code, body)
    items = body.get("vulnerabilities", [])
    return items[0].get("cve", {}) if items else {}


def detail_ghsa(cve_id: str) -> dict:
    url = f"https://api.github.com/advisories?cve_id={cve_id}&per_page=5"
    h = {**HEAD, "Accept": "application/vnd.github+json"}
    try:
        time.sleep(3)
        r = requests.get(url, headers=h, timeout=15)
    except Exception as e:
        _log_error(f"detail_ghsa({cve_id})", url, f"request failed: {e}")
        _snapshot(f"detail_ghsa_{cve_id}_error", url, None, {"error": str(e)})
        return {}

    if r.status_code != 200:
        # GHSA is a best-effort enrichment source; log but continue.
        _log_error(f"detail_ghsa({cve_id})", url, f"HTTP {r.status_code}: {r.text[:200]}")
        _snapshot(f"detail_ghsa_{cve_id}_http{r.status_code}", url, r.status_code, {"body": r.text[:1000]})
        return {}

    try:
        data = r.json()
    except Exception as e:
        _log_error(f"detail_ghsa({cve_id})", url, f"bad JSON: {e}")
        _snapshot(f"detail_ghsa_{cve_id}_badjson", url, r.status_code, {"body": r.text[:1000]})
        return {}

    _snapshot(f"detail_ghsa_{cve_id}", url, r.status_code, data)
    return data[0] if data else {}


# ── Data Processing ────────────────────────────────────────────────

def get_cvss(cve: dict) -> tuple:
    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        m = cve.get("metrics", {}).get(key)
        if m:
            d = m[0].get("cvssData", {})
            return d.get("baseScore", "N/A"), d.get("baseSeverity", "N/A")
    return "N/A", "N/A"


def get_desc(cve: dict) -> str:
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value", "")
    return ""


def nvd_get_versions(nvd: dict) -> tuple:
    """Extract affected versions from NVD CPE configurations (used as a fallback when GHSA has no version data)."""
    for config in nvd.get("configurations", []):
        for node in config.get("nodes", []):
            for cpe in node.get("cpeMatch", []):
                if cpe.get("vulnerable"):
                    end_inc = cpe.get("versionEndIncluding", "")
                    end_exc = cpe.get("versionEndExcluding", "")
                    if end_exc:
                        return f"< {end_exc}", ""
                    if end_inc:
                        return f"<= {end_inc}", ""
    return "", ""


def merge(nvd: dict, ghsa: dict) -> dict:
    # Priority rules:
    # CVSS score   → NVD takes precedence (official scoring is more authoritative)
    # Version info → GHSA takes precedence (written by maintainers, more accurate), NVD CPE as fallback
    # Description  → NVD takes precedence (more detailed)

    score, sev = get_cvss(nvd)
    desc = get_desc(nvd)

    pkg = ver = fix = ghsa_id = ""
    conflict = ""

    if ghsa:
        ghsa_id = ghsa.get("ghsa_id", "")
        gs = ghsa.get("cvss", {}).get("score")
        if gs and str(gs) != str(score):
            conflict = f" (GHSA score is {gs}; using NVD)"
        vulns = ghsa.get("vulnerabilities", [])
        if vulns:
            p = vulns[0].get("package", {})
            pkg = p.get("name", "")
            ver = vulns[0].get("vulnerable_version_range", "") or ""
            fix = vulns[0].get("first_patched_version", "") or ""

    # Fall back to NVD CPE when GHSA has no version information
    if not ver:
        nvd_ver, _ = nvd_get_versions(nvd)
        ver = nvd_ver

    return {
        "cve_id":   nvd.get("id", ""),
        "ghsa_id":  ghsa_id,
        "pub":      nvd.get("published", "")[:10],
        "score":    score,
        "severity": sev,
        "conflict": conflict,
        "desc":     desc[:500],
        "pkg":      pkg or "see description",
        "ver":      ver or "N/A",
        "fix":      fix or "N/A",
    }


def to_markdown(v: dict) -> str:
    ghsa = f" / {v['ghsa_id']}" if v["ghsa_id"] else ""
    src  = "NVD and GHSA consistent" if not v["conflict"] else f"Discrepancy{v['conflict']}"
    return (
        f"### {v['cve_id']}{ghsa}\n\n"
        f"- **Published**：{v['pub']}\n"
        f"- **Severity**：{v['severity']}\n"
        f"- **CVSS Score**：{v['score']}{v['conflict']}\n"
        f"- **Affected Package**：{v['pkg']}\n"
        f"- **Affected Versions**：{v['ver']}\n"
        f"- **Fixed Version**：{v['fix']}\n"
        f"- **Description**：{v['desc']}\n"
        f"- **Data Source**：{src}\n\n"
        f"---\n\n"
    )


# ── Main Flow ──────────────────────────────────────────────────

def main():
    global _RUN_DIR

    os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)

    # Per-run snapshot directory
    run_id = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    _RUN_DIR = os.path.join(RAW_DIR, run_id)
    os.makedirs(_RUN_DIR, exist_ok=True)
    print(f"Raw snapshots → {_RUN_DIR}\n")

    # Read already-recorded CVE IDs for deduplication
    existing = set()
    if os.path.exists(OUTPUT):
        with open(OUTPUT, "r", encoding="utf-8") as f:
            existing = set(re.findall(r"### (CVE-\d{4}-\d+)", f.read()))

    # Search: company name variants + sub-project names
    print(f"Company: {COMPANY}  Date range: {START_DATE} ~ {END_DATE}\n")
    keywords = (
        {COMPANY, COMPANY.replace(" ", ""),
         COMPANY.lower(), COMPANY.replace(" ", "").lower()}
        | set(SUBPROJECTS)
    )
    seen, cves_to_process = set(), []
    for kw in sorted(keywords):
        print(f"Searching: {kw!r}")
        hits = search_nvd(kw)
        print(f"  → {len(hits)} raw hits")
        for item in hits:
            cve = item.get("cve", {})
            cid = cve.get("id", "")
            pub = cve.get("published", "")[:10]
            if cid not in seen and START_DATE <= pub <= END_DATE:
                seen.add(cid)
                cves_to_process.append(cid)
    print(f"\nFound {len(cves_to_process)} CVEs in date range\n")

    # Filter out already-recorded CVEs (snapshot taken before the search)
    new_cves = [c for c in cves_to_process if c not in existing]
    skipped  = len(cves_to_process) - len(new_cves)
    if skipped:
        print(f"Already recorded {skipped}, skipping.")
    if not new_cves:
        print("No new CVEs to process.")
        _write_manifest(run_id, keywords, cves_to_process, [], [])
        return

    # Fetch details and append to report
    # written tracks CVEs written in this run to prevent duplicates when multiple keywords match the same CVE
    written, ok, fail = set(), 0, []
    for i, cid in enumerate(new_cves, 1):
        if cid in written:
            continue
        print(f"[{i}/{len(new_cves)}] {cid}", end="  ")
        nvd  = detail_nvd(cid)
        ghsa = detail_ghsa(cid)
        if not nvd:
            print("✗ NVD failed")
            fail.append(cid)
            continue
        if not is_relevant(nvd):
            print("✗ Irrelevant, skipping")
            continue
        with open(OUTPUT, "a", encoding="utf-8") as f:
            f.write(to_markdown(merge(nvd, ghsa)))
        written.add(cid)
        score, _ = get_cvss(nvd)
        print(f"✓  CVSS {score}")
        ok += 1

    print(f"\nDone {ok}/{len(new_cves)}  Failed: {fail if fail else 'none'}")
    if _ERRORS:
        print(f"Errors this run: {len(_ERRORS)} (see manifest.json)")
    print(f"Report: {OUTPUT}")

    _write_manifest(run_id, keywords, cves_to_process, sorted(written), fail)


def _write_manifest(run_id, keywords, found, written, failed):
    """Write a per-run manifest summarising what was fetched and any errors."""
    manifest = {
        "run_id": run_id,
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "company": COMPANY,
        "date_range": [START_DATE, END_DATE],
        "keywords": sorted(keywords),
        "cves_found_in_range": sorted(found),
        "cves_written": written,
        "cves_failed": failed,
        "errors": _ERRORS,
    }
    path = os.path.join(_RUN_DIR, "manifest.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)
    print(f"Manifest: {path}")


if __name__ == "__main__":
    main()
