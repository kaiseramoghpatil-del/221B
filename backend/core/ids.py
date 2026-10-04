"""Deterministic IDs. Stable across re-runs so truth files, tests and UI links survive."""
from __future__ import annotations

import hashlib

PIPELINE_VERSION = "0.1.0"


def sha1_hex(*parts: str | bytes) -> str:
    h = hashlib.sha1()
    for p in parts:
        h.update(p if isinstance(p, bytes) else p.encode("utf-8"))
        h.update(b"\x00")
    return h.hexdigest()


def file_id(name: str, content: bytes) -> str:
    return sha1_hex(name, content)[:10]


def event_id(fid: str, line_no: int) -> str:
    """12 hex chars (48 bits): negligible collision odds at 200k events (8 hex would collide)."""
    return "E-" + sha1_hex(fid, str(line_no))[:12]


def short(prefix: str, *parts: str) -> str:
    return f"{prefix}-" + sha1_hex(*parts)[:10]
