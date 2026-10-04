"""nginx / Apache combined access-log parser."""
from __future__ import annotations

import re

from backend.core.models import Action, Category, Outcome, SourceType

from .base import EVENT, QUARANTINE, FileCtx
from .timeutil import parse_nginx_ts

_COMBINED = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] "(?P<req>[^"]*)" (?P<status>\d{3}) (?P<bytes>\S+)'
    r'(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?'
)


class WebAccessParser:
    name = "web_access_combined"

    def detect(self, sample: list[str], filename: str) -> float:
        rows = [s for s in sample if s.strip()]
        if not rows:
            return 0.0
        ok = sum(1 for s in rows if _COMBINED.match(s))
        return ok / len(rows) * 0.95

    def parse_line(self, line: str, line_no: int, fctx: FileCtx):
        m = _COMBINED.match(line)
        if not m:
            return QUARANTINE, "no_access_log_match"
        try:
            ts = parse_nginx_ts(m["ts"])
        except (ValueError, KeyError) as e:
            return QUARANTINE, f"bad_timestamp: {e}"
        status = int(m["status"])
        req = m["req"]
        parts = req.split(" ")
        obj = f"{parts[0]} {parts[1]}" if len(parts) >= 2 else req or None
        user = None if m["user"] == "-" else m["user"]
        b = int(m["bytes"]) if m["bytes"].isdigit() else None
        ua = m["ua"] if m["ua"] not in (None, "-") else None
        return EVENT, dict(
            ts_utc=ts, ts_original=m["ts"], tz_assumed=False, source_type=SourceType.web, category=Category.web,
            action=Action.http, outcome=Outcome.success if status < 400 else Outcome.failure, host=fctx.host_hint, user=user,
            src_ip=m["ip"], dst_ip=None, dst_port=None, session_id=None, object=obj, bytes_in=None, bytes_out=b, user_agent=ua,
            attrs={"status": status}, parse_flags=[],
        )
