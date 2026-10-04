"""Normalize: deterministic order, duplicate collapse, entities, ip->host map, sessions with hop lineage.

Order-invariant by construction: everything downstream consumes `NormalizedCase.events`, which is sorted by
(ts_utc, file_id, line_no) regardless of input order.
"""
from __future__ import annotations

import bisect
import ipaddress
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from backend.core.models import Action, Criticality, Entity, EntityType, Event, Outcome, Session, SourceType

SESSION_DEFAULT_TTL = timedelta(hours=12)  # unclosed sessions are assumed to end after this
DUP_WINDOW_LINES = 3


@dataclass
class Sess:
    id: str
    user: str
    host: str
    src_ip: str | None
    t_start: datetime
    t_end: datetime | None
    login_event_id: str
    parent: str | None = None  # session on the source host this hop came from
    event_ids: list[str] = field(default_factory=list)

    @property
    def end_or_ttl(self) -> datetime:
        return self.t_end or (self.t_start + SESSION_DEFAULT_TTL)

    def to_contract(self) -> Session:
        return Session(id=self.id, user=self.user, host=self.host, src_ip=self.src_ip, t_start=self.t_start, t_end=self.t_end,
                       login_event_id=self.login_event_id, event_ids=list(self.event_ids))


@dataclass
class NormalizedCase:
    events: list[Event]
    by_id: dict[str, Event]
    sessions: dict[str, Sess]
    session_of: dict[str, str]  # event id -> session id
    ip_to_host: dict[str, str]
    entities: dict[str, Entity]
    valid_users: set[str]  # users with at least one successful login anywhere
    dup_collapsed: int
    t_min: datetime | None
    t_max: datetime | None


_INTERNAL_NETS = [ipaddress.ip_network(n) for n in
                  ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "fc00::/7", "fe80::/10", "::1/128")]


def is_internal(ip: str | None) -> bool:
    """RFC 1918 / loopback / link-local only. NOT ipaddress.is_private, which also counts e.g. 198.18.0.0/15 and
    100.64.0.0/10 as private - those are routable-from-our-perspective external sources."""
    if not ip:
        return False
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in _INTERNAL_NETS)


def subnet24(ip: str | None) -> str | None:
    if not ip or ":" in ip:
        return ip
    parts = ip.split(".")
    return ".".join(parts[:3]) + ".0/24" if len(parts) == 4 else ip


HIGH_CRIT_HOST_HINTS = ("db", "bastion", "dc", "vault", "backup")


def _host_criticality(name: str) -> Criticality:
    n = name.lower()
    return Criticality.high if any(h in n for h in HIGH_CRIT_HOST_HINTS) else Criticality.med


def normalize(events_in: list[Event]) -> NormalizedCase:
    evs = sorted(events_in, key=lambda e: (e.ts_utc, e.file_id, e.line_no))

    # ---- adjacent duplicate collapse (forwarder retries): same file, same raw text, within a few lines
    last_seen: dict[tuple[str, str], int] = {}
    kept: list[Event] = []
    dups = 0
    for e in evs:
        k = (e.file_id, e.raw_text)
        prev = last_seen.get(k)
        if prev is not None and abs(e.line_no - prev) <= DUP_WINDOW_LINES:
            dups += 1
            continue
        last_seen[k] = e.line_no
        kept.append(e)
    evs = kept
    by_id = {e.id: e for e in evs}

    # ---- ip -> host from flow records (src_host, src_ip)
    votes: dict[str, Counter] = defaultdict(Counter)
    for e in evs:
        if e.source_type is SourceType.net and e.host and e.src_ip and is_internal(e.src_ip):
            votes[e.src_ip][e.host] += 1
    ip_to_host = {ip: c.most_common(1)[0][0] for ip, c in votes.items()}

    # ---- sessions (sshd: session_id = host:pid) + lineage
    sessions: dict[str, Sess] = {}
    open_by_sid: dict[str, Sess] = {}
    by_user_host: dict[tuple[str, str], list[Sess]] = defaultdict(list)
    counter = 0
    for e in evs:
        if e.action is Action.login and e.outcome is Outcome.success and e.user and e.host:
            counter += 1
            s = Sess(id=f"SES-{e.host}-{counter}", user=e.user, host=e.host, src_ip=e.src_ip, t_start=e.ts_utc, t_end=None,
                     login_event_id=e.id, event_ids=[e.id])
            if e.src_ip and is_internal(e.src_ip) and e.src_ip in ip_to_host:
                parent = _find_open(by_user_host.get((e.user, ip_to_host[e.src_ip]), []), e.ts_utc)
                s.parent = parent.id if parent else None
            sessions[s.id] = s
            by_user_host[(e.user, e.host)].append(s)
            if e.session_id:
                open_by_sid[e.session_id] = s
        elif e.action is Action.logout and e.session_id and e.session_id in open_by_sid:
            s = open_by_sid.pop(e.session_id)
            if s.t_end is None:
                s.t_end = e.ts_utc
            s.event_ids.append(e.id)

    # ---- attribute host activity to sessions
    session_of: dict[str, str] = {}
    ambiguous_session_events: set[str] = set()
    for s in sessions.values():
        for eid in s.event_ids:
            session_of[eid] = s.id
    for e in evs:
        if e.id in session_of or not (e.user and e.host):
            continue
        if e.action in (Action.proc_exec, Action.sudo, Action.su, Action.file_read, Action.file_write, Action.key_add,
                        Action.cron_add, Action.log_clear):
            cands = _open_sessions(by_user_host.get((e.user, e.host), []), e.ts_utc)
            if len(cands) == 1:
                session_of[e.id] = cands[0].id
                cands[0].event_ids.append(e.id)
            elif len(cands) > 1:
                # the same account has several sessions open on this host and the audit line carries no tty/pid:
                # attribution is genuinely ambiguous, so do not guess (correlation then matches on account + host only)
                ambiguous_session_events.add(e.id)

    # ---- entities
    ent: dict[str, Entity] = {}

    def touch(eid: str, etype: EntityType, t: datetime, **kw) -> None:
        x = ent.get(eid)
        if x is None:
            ent[eid] = Entity(id=eid, type=etype, first_seen=t, last_seen=t, **kw)
        else:
            if t < x.first_seen:
                x.first_seen = t
            if t > x.last_seen:
                x.last_seen = t

    for e in evs:
        if e.user:
            touch(f"user:{e.user}", EntityType.user, e.ts_utc)
        if e.host:
            touch(f"host:{e.host}", EntityType.host, e.ts_utc, internal=True, criticality=_host_criticality(e.host))
        for ip in (e.src_ip, e.dst_ip):
            if ip:
                touch(f"ip:{ip}", EntityType.ip, e.ts_utc, internal=is_internal(ip), subnet=subnet24(ip))
    valid_users = {e.user for e in evs if e.action is Action.login and e.outcome is Outcome.success and e.user}
    return NormalizedCase(events=evs, by_id=by_id, sessions=sessions, session_of=session_of, ip_to_host=ip_to_host,
                          entities=ent, valid_users=valid_users, dup_collapsed=dups,
                          t_min=evs[0].ts_utc if evs else None, t_max=evs[-1].ts_utc if evs else None)


def _open_sessions(lst: list[Sess], t: datetime) -> list[Sess]:
    """All sessions in the list that are open at time t."""
    return [s for s in lst if s.t_start <= t <= s.end_or_ttl]


def _find_open(lst: list[Sess], t: datetime) -> Sess | None:
    """Latest session (by start) that is open at time t. Lists are append-ordered by start time."""
    if not lst:
        return None
    starts = [s.t_start for s in lst]
    i = bisect.bisect_right(starts, t)
    for s in reversed(lst[:i]):
        if s.end_or_ttl >= t:
            return s
        if t - s.t_start > SESSION_DEFAULT_TTL * 2:
            break
    return None
