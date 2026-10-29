"""Checker process: exact candidate verification, with no attack advice."""
from __future__ import annotations

import argparse
import hmac
import json
import sys
import uuid
from pathlib import Path

from .common import digest


def verify(truth_path: Path, run_id: str, candidate: str) -> dict:
    evidence_id = uuid.uuid4().hex
    try:
        truth = json.loads(truth_path.read_text())
        if truth["run_id"] != run_id or truth["schema_version"] != 2:
            raise ValueError("checker configuration")
        # No substring matching, whitespace normalization, prefix matching or LLM judging.
        if not isinstance(candidate, str) or len(candidate.encode()) > 1024 * 1024:
            return {"verdict": "failure", "evidence_id": evidence_id}
        matched = hmac.compare_digest(digest(candidate), truth["artifact_sha256"])
        return {"verdict": "success" if matched else "failure", "evidence_id": evidence_id}
    except (OSError, ValueError, KeyError, TypeError):
        return {"verdict": "inconclusive", "evidence_id": evidence_id}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--truth", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    try:
        request = json.load(sys.stdin)
        result = verify(args.truth, args.run_id, request["value"])
    except (ValueError, KeyError, TypeError):
        result = {"verdict": "inconclusive", "evidence_id": uuid.uuid4().hex}
    print(json.dumps(result))


if __name__ == "__main__":
    main()
