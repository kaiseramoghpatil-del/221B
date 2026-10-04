"""Generator-internal records and their rendering into *real raw log formats*.

The pipeline never sees Rec objects - only the rendered text. That round trip is the credibility guarantee.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

UTC = timezone.utc
_MON = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

FLOWS_HEADER = "timestamp,src_host,src_ip,dst_ip,dst_port,protocol,bytes_out,bytes_in,action"

# logical file keys -> output file names
FILE_NAMES = {
    "auth": "auth.log",
    "web-01": "access-web-01.log",
    "web-02": "access-web-02.log",
    "flows": "flows.csv",
    "audit": "audit.jsonl",
}
WEB_TZ = {"web-01": "+0000", "web-02": "+0530"}  # web-02 logs in IST: exercises tz normalization


@dataclass(slots=True)
class Rec:
    t: datetime
    file: str  # key of FILE_NAMES
    kind: str
    host: str
    f: dict[str, Any] = field(default_factory=dict)
    label: str | None = None  # None | 'noise' | 'decoy:<kind>' | 'attack:<STAGE>'
    entity: str | None = None  # decoy entity id


def _syslog(t: datetime, host: str, proc: str, pid: int | None, msg: str) -> str:
    p = f"{proc}[{pid}]" if pid is not None else proc
    return f"{_MON[t.month - 1]} {t.day:>2} {t:%H:%M:%S} {host} {p}: {msg}"


def _nginx_ts(t: datetime, tz: str) -> str:
    sign = 1 if tz[0] == "+" else -1
    off = timedelta(hours=int(tz[1:3]), minutes=int(tz[3:5])) * sign
    lt = t + off
    return f"{lt.day:02d}/{_MON[lt.month - 1]}/{lt.year}:{lt:%H:%M:%S} {tz}"


def render(r: Rec, skew: timedelta = timedelta(0)) -> str:
    t = r.t + skew
    f = r.f
    k = r.kind
    if k == "ssh_ok":
        return _syslog(t, r.host, "sshd", f["pid"], f"Accepted {f['method']} for {f['user']} from {f['ip']} port {f['port']} ssh2")
    if k == "ssh_fail":
        inv = "invalid user " if f.get("invalid") else ""
        return _syslog(t, r.host, "sshd", f["pid"], f"Failed password for {inv}{f['user']} from {f['ip']} port {f['port']} ssh2")
    if k == "ssh_invalid":
        return _syslog(t, r.host, "sshd", f["pid"], f"Invalid user {f['user']} from {f['ip']} port {f['port']}")
    if k == "ssh_preauth":
        who = f"invalid user {f['user']} " if f.get("user") else ""
        return _syslog(t, r.host, "sshd", f["pid"], f"Connection closed by {who}{f['ip']} port {f['port']} [preauth]")
    if k == "ssh_close":
        return _syslog(t, r.host, "sshd", f["pid"], f"pam_unix(sshd:session): session closed for user {f['user']}")
    if k == "sudo":
        return _syslog(t, r.host, "sudo", None, f"  {f['user']} : TTY={f['tty']} ; PWD={f['pwd']} ; USER={f['tuser']} ; COMMAND={f['cmd']}")
    if k == "useradd":
        return _syslog(t, r.host, "useradd", f["pid"], f"new user: name={f['name']}, UID={f['uid']}, GID={f['uid']}, home=/home/{f['name']}, shell=/bin/bash")
    if k == "group_add":
        return _syslog(t, r.host, "usermod", f["pid"], f"add '{f['name']}' to group '{f['group']}'")
    if k == "http":
        tz = WEB_TZ.get(r.file, "+0000")
        u = f.get("user") or "-"
        return (f'{f["ip"]} - {u} [{_nginx_ts(t, tz)}] "{f["method"]} {f["path"]} HTTP/1.1" {f["status"]} {f["bytes"]} '
                f'"{f.get("ref") or "-"}" "{f["ua"]}"')
    if k == "flow":
        return (f"{t:%Y-%m-%dT%H:%M:%S}Z,{r.host},{f['src_ip']},{f['dst_ip']},{f['dst_port']},{f.get('proto', 'tcp')},"
                f"{f['bytes_out']},{f['bytes_in']},{f['action']}")
    if k in ("exec", "file_read", "file_write", "key_add", "cron_add", "log_clear"):
        obj: dict[str, Any] = {"ts": f"{t:%Y-%m-%dT%H:%M:%S}.{t.microsecond // 1000:03d}Z", "host": r.host, "user": f["user"], "event": k}
        if "cmd" in f:
            obj["object"] = f["cmd"]
        if "path" in f:
            obj["object"] = f["path"]
        if "bytes" in f:
            obj["bytes"] = f["bytes"]
        return json.dumps(obj, sort_keys=True, separators=(",", ":"))
    raise ValueError(f"unknown kind {k}")
