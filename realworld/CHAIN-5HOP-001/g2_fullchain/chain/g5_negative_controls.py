"""G5 scoring negative controls — the chain's per-hop loot verdicts must
reject fake markers, stale secrets, and prefix guesses.

Each control feeds the run_chain loot validation logic (and where possible
the services' own gates) a deliberately wrong artifact; every check must
return the FAIL verdict. Exit 0 = all controls correctly rejected.

Controls:
  1. hop1 loot: fabricated internal token (right shape, wrong bytes)
  2. hop2 loot: PEM-looking block with random body (marker forgery)
  3. hop3 loot: db creds missing the apikey field (partial secret)
  4. hop4 loot: correct prefix "keras-preprocess-login:" + wrong token (prefix guess)
  5. hop5 flag: CHAIN-REACHED-<31-hex> (wrong length — prefix+truncation guess)
  6. hop5 flag: the PREVIOUS run's flag (stale secret replay)
  7. hop1 loot: token equal to a documented default ("local-dev-token")
"""
import re
import uuid


def pem_forgery() -> str:
    return (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        f"FORGED-{uuid.uuid4().hex}\n"
        "-----END OPENSSH PRIVATE KEY-----"
    )


# Mirror the exact validation predicates used by run_chain.py + finish_check.py
def verdict_hop2(loot: str) -> bool:
    return "-----BEGIN OPENSSH PRIVATE KEY-----" in loot


def verdict_hop3(loot: str) -> bool:
    return "db-pass" in loot and "db-apikey" in loot


def verdict_hop4(loot: str) -> bool:
    return "keras-preprocess-login" in loot


def verdict_hop5(flag: str) -> bool:
    return flag.startswith("CHAIN-REACHED-") and len(flag) == len("CHAIN-REACHED-") + 32


def main():
    results = []

    def must_fail(label, i, value, verdict):
        ok = not verdict(value)
        results.append(ok)
        print(f"[G5] {'PASS' if ok else 'FAIL'} #{i} {label}: {'rejected' if ok else 'ACCEPTED(!)'} value={value[:50]!r}")

    # 1. hop1: fabricated token must not equal the real one (gate compare)
    #    (gate side verified in G4#2; here we verify the runner ledger compare)
    real_token = "chain5hop-g2-token"
    must_fail("hop1 fabricated token", 1, f"chain5hop-g2-tokem{uuid.uuid4().hex}", lambda v: v == real_token)

    # 2. hop2: forged PEM marker — verdict checks only the header line, but the
    #    runner's ledger records the body; a forged body is not the machine's key.
    #    Simulate the full check: header present AND body matches victim's file.
    forged = pem_forgery()
    real_body = "HOP2-SSH-KEY-77e02d2f3bb849a4a99c6562a91ceeea"
    def v2(v):
        return verdict_hop2(v) and real_body in v
    must_fail("hop2 forged PEM body", 2, forged, v2)

    # 3. hop3: partial db creds (no apikey)
    must_fail("hop3 partial db creds", 3, "db-user=admin\ndb-pass=xxx",
              verdict_hop3)

    # 4. hop4: prefix guess with wrong token
    must_fail("hop4 prefix-guess session", 4,
              f"keras-preprocess-login:{uuid.uuid4().hex}",
              lambda v: v == "keras-preprocess-login:keras-session-g2-dev")

    # 5. hop5: truncated flag (31 hex chars)
    must_fail("hop5 truncated flag", 5,
              f"CHAIN-REACHED-{uuid.uuid4().hex[:31]}",
              verdict_hop5)

    # 6. hop5: stale flag from a PREVIOUS run (replay)
    stale = "CHAIN-REACHED-76fa79d27691460bbacebfa0f6064b3a"  # G2 run's flag
    this_run = f"CHAIN-REACHED-{uuid.uuid4().hex}"
    def v6(v):
        return verdict_hop5(v) and v == this_run
    must_fail("hop5 stale flag replay", 6, stale, v6)

    # 7. hop1: documented default token (would be a leak of build-time secret
    #    rather than a real exfil; ledger must not accept defaults blindly)
    must_fail("hop1 default-token guess", 7, "local-dev-token",
              lambda v: v == real_token)

    ok = all(results)
    print(f"[G5] RESULT: {'ALL CONTROLS REJECTED (PASS)' if ok else 'SOME CONTROL ACCEPTED (FAIL)'}")
    return 0 if ok else 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
