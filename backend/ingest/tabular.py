"""Generic CSV and JSON-lines parsers with an alias map (ECS-style dotted names supported).

This is the 'unknown format' path: if someone hands us a log in some other shape, header/key
aliases map it onto the Event schema; anything we cannot map is kept in attrs, never silently dropped.
"""
from __future__ import annotations

import csv
import io
import json
from typing import Any

from backend.core.models import Action, Category, Outcome, SourceType

from .base import EVENT, QUARANTINE, SKIP, FileCtx
from .timeutil import parse_generic_ts

ALIASES: dict[str, tuple[str, ...]] = {
    "ts": ("timestamp", "time", "ts", "@timestamp", "datetime", "date", "event_time", "eventtime", "event.created", "log_time"),
    "src_ip": ("src_ip", "source_ip", "src", "source.ip", "client_ip", "remote_ip", "srcaddr", "sourceip", "src_addr", "ip", "clientip"),
    "dst_ip": ("dst_ip", "destination_ip", "dst", "dest_ip", "destination.ip", "dstaddr", "destinationip", "dst_addr"),
    "dst_port": ("dst_port", "dest_port", "destination_port", "destination.port", "dport", "port"),
    "user": ("user", "username", "user.name", "account", "user_name", "usr", "actor", "uid_name"),
    "host": ("host", "hostname", "host.name", "computer", "src_host", "device", "server"),
    "action": ("action", "event", "event_type", "eventtype", "activity", "event.action", "type", "event.type"),
    "outcome": ("outcome", "status", "result", "event.outcome"),
    "bytes_out": ("bytes_out", "bytes_sent", "sentbytes", "out_bytes", "bytes", "source.bytes", "network.bytes_out"),
    "bytes_in": ("bytes_in", "bytes_received", "rcvdbytes", "in_bytes", "destination.bytes", "network.bytes_in"),
    "object": ("object", "path", "url", "cmd", "command", "process", "file", "file.path", "process.command_line", "cmdline"),
    "user_agent": ("user_agent", "useragent", "user_agent.original", "ua"),
    "protocol": ("protocol", "proto", "network.protocol"),
}
_REV = {a: canon for canon, als in ALIASES.items() for a in als}

_ACTION = {
    "login": Action.login, "logon": Action.login, "signin": Action.login, "sign-in": Action.login, "auth": Action.login,
    "authentication": Action.login, "logout": Action.logout, "logoff": Action.logout, "signout": Action.logout,
    "sudo": Action.sudo, "su": Action.su, "useradd": Action.useradd, "user_add": Action.useradd, "create_user": Action.useradd,
    "group_add": Action.group_add, "add_to_group": Action.group_add,
    "http": Action.http, "request": Action.http, "get": Action.http, "post": Action.http,
    "conn": Action.conn, "connection": Action.conn, "flow": Action.conn, "traffic": Action.conn, "netflow": Action.conn,
    "exec": Action.proc_exec, "execve": Action.proc_exec, "process": Action.proc_exec, "process_start": Action.proc_exec,
    "proc_exec": Action.proc_exec, "command": Action.proc_exec,
    "file_read": Action.file_read, "read": Action.file_read, "file_write": Action.file_write, "write": Action.file_write,
    "cron_add": Action.cron_add, "key_add": Action.key_add, "log_clear": Action.log_clear,
}
_FW_ALLOW = {"allow", "allowed", "permit", "accept", "accepted", "pass"}
_FW_DENY = {"deny", "denied", "drop", "dropped", "block", "blocked", "reject", "rejected", "refused"}
_OK = {"success", "succeeded", "ok", "allowed", "accepted", "pass", "permit", "true", "0"}
_BAD = {"failure", "failed", "fail", "denied", "deny", "blocked", "drop", "reject", "refused", "error", "false"}


def _norm_key(k: str) -> str:
    return k.strip().lower().replace(" ", "_")


def _flatten(d: dict, prefix: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in d.items():
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            out.update(_flatten(v, key + "."))
        else:
            out[key] = v
    return out


def _to_int(v: Any) -> int | None:
    if v is None or v == "" or v == "-":
        return None
    try:
        return int(float(str(v).replace(",", "")))
    except ValueError:
        return None


def _s(v: Any) -> str | None:
    if v is None:
        return None
    t = str(v).strip()
    return t if t and t != "-" else None


def map_record(rec: dict[str, Any], fctx: FileCtx):
    """Map an already-flattened record (lower-cased keys) onto an Event draft."""
    canon: dict[str, Any] = {}
    extra: dict[str, Any] = {}
    for k, v in rec.items():
        c = _REV.get(_norm_key(k))
        if c and c not in canon and v not in (None, ""):
            canon[c] = v
        elif not c:
            extra[k] = v
    if "ts" not in canon:
        return QUARANTINE, "no_timestamp_field"
    try:
        ts, flags, orig = parse_generic_ts(canon["ts"], fctx)
    except (ValueError, OverflowError, OSError) as e:
        return QUARANTINE, f"bad_timestamp: {e}"

    raw_action = (_s(canon.get("action")) or "").lower()
    raw_outcome = (_s(canon.get("outcome")) or "").lower()
    action = _ACTION.get(raw_action)
    outcome = Outcome.unknown
    if action is None and raw_action in _FW_ALLOW | _FW_DENY:
        action = Action.conn
        outcome = Outcome.success if raw_action in _FW_ALLOW else Outcome.failure
    if raw_outcome:
        if raw_outcome in _OK or (raw_outcome.isdigit() and int(raw_outcome) < 400 and raw_outcome != "0" and action is Action.http):
            outcome = Outcome.success
        elif raw_outcome in _BAD or (raw_outcome.isdigit() and int(raw_outcome) >= 400):
            outcome = Outcome.failure
        elif raw_outcome in _FW_ALLOW:
            outcome = Outcome.success
        elif raw_outcome in _FW_DENY:
            outcome = Outcome.failure
    dst_ip = _s(canon.get("dst_ip"))
    if action is None:
        action = Action.conn if (dst_ip and not raw_action) else Action.other
    if raw_action and _ACTION.get(raw_action) is None and raw_action not in _FW_ALLOW | _FW_DENY:
        extra["raw_action"] = raw_action

    cat_for = {
        Action.login: Category.authentication, Action.logout: Category.authentication, Action.sudo: Category.iam,
        Action.su: Category.iam, Action.useradd: Category.iam, Action.group_add: Category.iam, Action.http: Category.web,
        Action.conn: Category.network, Action.file_read: Category.file, Action.file_write: Category.file,
    }
    category = cat_for.get(action, Category.network if dst_ip else Category.process)
    src_for = {
        Category.authentication: SourceType.auth, Category.web: SourceType.web, Category.network: SourceType.net,
        Category.iam: SourceType.auth,
    }
    source_type = src_for.get(category, SourceType.audit)

    attrs = {k: v for k, v in extra.items() if v not in (None, "")}
    if _s(canon.get("protocol")):
        attrs["protocol"] = canon["protocol"]
    return EVENT, dict(
        ts_utc=ts, ts_original=orig, tz_assumed="tz_assumed" in flags, source_type=source_type, category=category, action=action,
        outcome=outcome, host=_s(canon.get("host")) or fctx.host_hint, user=_s(canon.get("user")), src_ip=_s(canon.get("src_ip")),
        dst_ip=dst_ip, dst_port=_to_int(canon.get("dst_port")), session_id=None, object=_s(canon.get("object")),
        bytes_in=_to_int(canon.get("bytes_in")), bytes_out=_to_int(canon.get("bytes_out")), user_agent=_s(canon.get("user_agent")),
        attrs=attrs, parse_flags=flags,
    )


def _recognized(keys: list[str]) -> tuple[bool, int]:
    canon = {_REV.get(_norm_key(k)) for k in keys} - {None}
    return "ts" in canon, len(canon - {"ts"})


class GenericCsvParser:
    name = "generic_csv"

    def detect(self, sample: list[str], filename: str) -> float:
        rows = [s for s in sample if s.strip()]
        if not rows:
            return 0.0
        try:
            header = next(csv.reader([rows[0]]))
        except csv.Error:
            return 0.0
        has_ts, n = _recognized(header)
        if not has_ts or n < 2:
            return 0.0
        return min(0.9, 0.4 + 0.1 * n)

    def parse_line(self, line: str, line_no: int, fctx: FileCtx):
        if "header" not in fctx.state:
            try:
                fctx.state["header"] = next(csv.reader([line]))
            except (csv.Error, StopIteration):
                return QUARANTINE, "bad_csv_header"
            return SKIP, "header"
        try:
            row = next(csv.reader(io.StringIO(line)))
        except (csv.Error, StopIteration):
            return QUARANTINE, "bad_csv_row"
        hdr = fctx.state["header"]
        if len(row) != len(hdr):
            return QUARANTINE, f"column_count_mismatch({len(row)}!={len(hdr)})"
        return map_record(dict(zip(hdr, row)), fctx)


class GenericJsonlParser:
    name = "generic_jsonl"

    def detect(self, sample: list[str], filename: str) -> float:
        rows = [s for s in sample if s.strip()]
        if not rows:
            return 0.0
        good = 0
        for s in rows:
            try:
                o = json.loads(s)
            except ValueError:
                continue
            if isinstance(o, dict):
                has_ts, n = _recognized(list(_flatten(o).keys()))
                if has_ts and n >= 1:
                    good += 1
        return min(0.9, good / len(rows) * 0.9)

    def parse_line(self, line: str, line_no: int, fctx: FileCtx):
        try:
            o = json.loads(line)
        except ValueError:
            return QUARANTINE, "invalid_json"
        if not isinstance(o, dict):
            return QUARANTINE, "json_not_object"
        return map_record(_flatten(o), fctx)
