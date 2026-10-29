from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from datetime import datetime, timezone

BASE = Path(__file__).resolve().parents[1]
OUTPUT = BASE / "output"


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def digest(value: bytes | str) -> str:
    return hashlib.sha256(value.encode() if isinstance(value, str) else value).hexdigest()


def canonical(value) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def write_json(path: Path, value, *, exclusive: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | (os.O_EXCL if exclusive else os.O_TRUNC)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def tree_hash(path: Path) -> str:
    return digest(canonical({
        str(p.relative_to(path)): digest(p.read_bytes())
        for p in sorted(path.rglob("*"))
        if p.is_file() and "__pycache__" not in p.parts
    }))


def append_event(path: Path, event: dict) -> None:
    with path.open("a", encoding="utf-8") as stream:
        stream.write(canonical({"timestamp": now(), **event}) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
