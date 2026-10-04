"""Timestamp parsing -> aware UTC datetimes, plus flags describing what was assumed."""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from .base import FileCtx

UTC = timezone.utc
MONTHS = {m: i for i, m in enumerate(["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}

_NGINX_RE = re.compile(r"^(\d{1,2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})$")
_NAIVE_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})(?:[.,](\d{1,6}))?$")
_EPOCH_RE = re.compile(r"\d{9,13}(\.\d+)?")


def parse_nginx_ts(text: str) -> datetime:
    m = _NGINX_RE.match(text)
    if not m:
        raise ValueError(f"bad nginx timestamp: {text!r}")
    d, mon, y, hh, mm, ss, sign, oh, om = m.groups()
    off = timedelta(hours=int(oh), minutes=int(om)) * (1 if sign == "+" else -1)
    local = datetime(int(y), MONTHS[mon.capitalize()], int(d), int(hh), int(mm), int(ss))
    return (local - off).replace(tzinfo=UTC)


def parse_generic_ts(value: object, fctx: FileCtx) -> tuple[datetime, list[str], str]:
    """ISO-8601 (with/without tz), 'YYYY-MM-DD HH:MM:SS', epoch s/ms. Returns (utc, flags, original)."""
    flags: list[str] = []
    if isinstance(value, bool):
        raise ValueError("bool is not a timestamp")
    if isinstance(value, (int, float)) or (isinstance(value, str) and _EPOCH_RE.fullmatch(value.strip())):
        x = float(value)
        if x > 1e11:  # epoch millis
            x /= 1000.0
        return datetime.fromtimestamp(x, tz=UTC), flags, str(value)
    text = str(value).strip()
    m = _NAIVE_RE.match(text)
    if m:
        y, mo, d, hh, mi, ss, frac = m.groups()
        us = int((frac or "0").ljust(6, "0")[:6])
        local = datetime(int(y), int(mo), int(d), int(hh), int(mi), int(ss), us)
        flags.append("tz_assumed")
        return (local - timedelta(minutes=fctx.tz_offset_min)).replace(tzinfo=UTC), flags, text
    iso = text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text
    dt = datetime.fromisoformat(iso)
    if dt.tzinfo is None:
        flags.append("tz_assumed")
        return (dt - timedelta(minutes=fctx.tz_offset_min)).replace(tzinfo=UTC), flags, text
    return dt.astimezone(UTC), flags, text


def syslog_year(fctx: FileCtx, month: int) -> int:
    """Year inference for year-less syslog stamps, with Dec->Jan roll-over and tolerance for stragglers."""
    base = fctx.state.setdefault("year", fctx.year)
    last = fctx.state.get("last_month")
    if last is None:
        fctx.state["last_month"] = month
        return base
    if month < last - 6:  # wrapped into a new year
        base += 1
        fctx.state["year"] = base
        fctx.state["last_month"] = month
        return base
    if month > last + 6:  # straggler from the previous year
        return base - 1
    fctx.state["last_month"] = month
    return base


def syslog_to_utc(mon: str, day: int, hms: str, fctx: FileCtx) -> datetime:
    month = MONTHS[mon.capitalize()]
    year = syslog_year(fctx, month)
    hh, mm, ss = (int(x) for x in hms.split(":"))
    local = datetime(year, month, day, hh, mm, ss)
    return (local - timedelta(minutes=fctx.tz_offset_min)).replace(tzinfo=UTC)
