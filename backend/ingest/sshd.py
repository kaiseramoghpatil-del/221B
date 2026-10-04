"""Linux auth.log / syslog parser: sshd, sudo, su, useradd, usermod.

Supports the classic 'Mon DD HH:MM:SS host proc[pid]: msg' stamp (no year, no tz -> assumptions are flagged)
and the rsyslog ISO form '2026-09-30T03:12:04.123456+00:00 host proc[pid]: msg'.
"""
from __future__ import annotations

import re

from backend.core.models import Action, Category, Outcome, SourceType

from .base import EVENT, QUARANTINE, SKIP, FileCtx
from .timeutil import parse_generic_ts, syslog_to_utc

_CLASSIC = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<hms>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
    r"(?P<proc>[\w\-/.]+?)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)
_ISO = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(?P<host>\S+)\s+"
    r"(?P<proc>[\w\-/.]+?)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)

_ACCEPTED = re.compile(r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
_FAILED = re.compile(r"^Failed (?P<method>\S+) for (?P<inv>invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
_INVALID = re.compile(r"^Invalid user (?P<user>\S*) from (?P<ip>\S+)(?: port (?P<port>\d+))?")
_CLOSED = re.compile(
    r"^(?:Connection closed|Disconnected) (?:by|from) (?:(?:authenticating|invalid) user (?P<user>\S+) )?"
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+)(?: port (?P<port>\d+))?(?P<pre> \[preauth\])?"
)
_SESS_CLOSED = re.compile(r"^pam_unix\(sshd:session\): session closed for user (?P<user>\S+)")
_SUDO = re.compile(
    r"^\s*(?P<user>\S+)\s*:\s*(?:TTY=(?P<tty>\S+)\s*;\s*)?PWD=(?P<pwd>\S+)\s*;\s*USER=(?P<tuser>\S+)\s*;\s*COMMAND=(?P<cmd>.*)$"
)
_SUDO_FAIL = re.compile(r"^\s*(?P<user>\S+)\s*:\s*(?P<n>\d+) incorrect password attempts?")
_USERADD = re.compile(r"^new user: name=(?P<name>[^,\s]+)")
_USERMOD_GRP = re.compile(r"^add '(?P<name>[^']+)' to (?:shadow )?group '(?P<group>[^']+)'")
_SU = re.compile(r"^\(to (?P<tuser>\S+)\) (?P<user>\S+) on (?P<tty>\S+)")


def _draft(**kw):
    base = dict(
        tz_assumed=False, source_type=SourceType.auth, category=Category.authentication, outcome=Outcome.unknown,
        host=None, user=None, src_ip=None, dst_ip=None, dst_port=None, session_id=None, object=None,
        bytes_in=None, bytes_out=None, user_agent=None, attrs={}, parse_flags=[],
    )
    base.update(kw)
    return base


def _port(a) -> dict:
    return {"src_port": int(a["port"])} if a["port"] else {}


class SshdSyslogParser:
    name = "linux_auth_syslog"

    def detect(self, sample: list[str], filename: str) -> float:
        rows = [s for s in sample if s.strip()]
        if not rows:
            return 0.0
        ok = sum(1 for s in rows if _CLASSIC.match(s) or _ISO.match(s))
        frac = ok / len(rows)
        if frac <= 0.5:
            return frac * 0.5
        bonus = 0.1 if any(("sshd" in s or "sudo" in s) for s in rows) else 0.0
        return min(1.0, frac * 0.9 + bonus)

    def parse_line(self, line: str, line_no: int, fctx: FileCtx):
        m = _CLASSIC.match(line)
        flags: list[str] = []
        if m:
            try:
                ts = syslog_to_utc(m["mon"], int(m["day"]), m["hms"], fctx)
            except (ValueError, KeyError) as e:
                return QUARANTINE, f"bad_timestamp: {e}"
            flags += ["tz_assumed", "inferred_year"]
            ts_orig = f"{m['mon']} {m['day']} {m['hms']}"
            tz_assumed = True
        else:
            m = _ISO.match(line)
            if not m:
                return QUARANTINE, "no_syslog_prefix"
            try:
                ts, tflags, ts_orig = parse_generic_ts(m["ts"], fctx)
            except ValueError as e:
                return QUARANTINE, f"bad_timestamp: {e}"
            flags += tflags
            tz_assumed = "tz_assumed" in tflags
        host, proc, pid, msg = m["host"], m["proc"], m["pid"], m["msg"]
        sess = f"{host}:{pid}" if pid else None
        c = dict(ts_utc=ts, ts_original=ts_orig, tz_assumed=tz_assumed, host=host)

        if proc == "sshd":
            if (a := _ACCEPTED.match(msg)):
                return EVENT, _draft(**c, parse_flags=flags, action=Action.login, outcome=Outcome.success, user=a["user"],
                                     src_ip=a["ip"], dst_port=22, session_id=sess, object=a["method"], attrs=_port(a))
            if (a := _FAILED.match(msg)):
                f = flags + (["invalid_user"] if a["inv"] else [])
                return EVENT, _draft(**c, parse_flags=f, action=Action.login, outcome=Outcome.failure, user=a["user"],
                                     src_ip=a["ip"], dst_port=22, session_id=sess, object=a["method"], attrs=_port(a))
            if (a := _INVALID.match(msg)):
                return EVENT, _draft(**c, parse_flags=flags, action=Action.other, user=a["user"] or None, src_ip=a["ip"],
                                     session_id=sess, object="invalid_user", attrs=_port(a))
            if (a := _CLOSED.match(msg)):
                return EVENT, _draft(**c, parse_flags=flags, action=Action.other, user=a["user"], src_ip=a["ip"], session_id=sess,
                                     object="preauth_close" if a["pre"] else "connection_closed", attrs=_port(a))
            if (a := _SESS_CLOSED.match(msg)):
                return EVENT, _draft(**c, parse_flags=flags, action=Action.logout, outcome=Outcome.success, user=a["user"],
                                     session_id=sess)
            return SKIP, "unhandled:sshd"
        if proc == "sudo":
            if (a := _SUDO.match(msg)):
                return EVENT, _draft(**c, parse_flags=flags, category=Category.iam, action=Action.sudo, outcome=Outcome.success,
                                     user=a["user"], object=a["cmd"].strip(),
                                     attrs={"target_user": a["tuser"], "tty": a["tty"], "pwd": a["pwd"]})
            if (a := _SUDO_FAIL.match(msg)):
                return EVENT, _draft(**c, parse_flags=flags, category=Category.iam, action=Action.sudo, outcome=Outcome.failure,
                                     user=a["user"], attrs={"attempts": int(a["n"])})
            return SKIP, "unhandled:sudo"
        if proc == "su":
            if (a := _SU.match(msg)):
                return EVENT, _draft(**c, parse_flags=flags, category=Category.iam, action=Action.su, outcome=Outcome.success,
                                     user=a["user"], attrs={"target_user": a["tuser"], "tty": a["tty"]})
            return SKIP, "unhandled:su"
        if proc == "useradd":
            if (a := _USERADD.match(msg)):
                return EVENT, _draft(**c, parse_flags=flags, category=Category.iam, action=Action.useradd, outcome=Outcome.success,
                                     object=a["name"])
            return SKIP, "unhandled:useradd"
        if proc == "usermod":
            if (a := _USERMOD_GRP.match(msg)):
                return EVENT, _draft(**c, parse_flags=flags, category=Category.iam, action=Action.group_add, outcome=Outcome.success,
                                     object=f"{a['name']}:{a['group']}")
            return SKIP, "unhandled:usermod"
        return SKIP, f"unhandled:{proc}"
