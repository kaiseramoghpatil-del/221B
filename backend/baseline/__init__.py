"""Baselines as *first-seen history* (UEBA-style): "novel at t" means no earlier occurrence in the data.

Policy (shown in the UI as an explicit assumption):
- A warm-up window at the start of the data builds history; no novelty signal fires inside it.
- warm-up = 12 h, or 20% of the span when the data covers less than 60 h.
- Hour-of-day profiles use the whole case (attacker activity is a small minority) - documented limitation.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from backend.core.models import Action, Outcome, SourceType
from backend.normalize import NormalizedCase, is_internal, subnet24

ARCHIVE_TOKENS = ("tar c", "tar -c", "tar czf", "tar cjf", "tar cf", "zip ", "7z a", "rar a", "gzip -r")


@dataclass
class Baselines:
    warmup_end: datetime
    policy: str
    fs_user_subnet: dict[tuple[str, str], datetime] = field(default_factory=dict)
    fs_user_host: dict[tuple[str, str], datetime] = field(default_factory=dict)
    fs_user_host_sudo: dict[tuple[str, str], datetime] = field(default_factory=dict)
    fs_host_dst: dict[tuple[str, str], datetime] = field(default_factory=dict)
    fs_user_host_archive: dict[tuple[str, str], datetime] = field(default_factory=dict)
    user_hours: dict[str, Counter] = field(default_factory=dict)
    user_entry_times: dict[str, list[datetime]] = field(default_factory=dict)  # external-source logins, time-sorted
    user_logins: Counter = field(default_factory=Counter)
    user_sudo_count: Counter = field(default_factory=Counter)

    def novel(self, table: dict, key, t: datetime) -> bool:
        first = table.get(key)
        return first is not None and first >= t and t >= self.warmup_end

    def off_hours(self, user: str, t: datetime) -> bool:
        """True if, in the user's *prior* history of entry logins (external sources only - internal hops are excluded so an
        attacker's own lateral logins cannot make their hours look normal), (almost) none fall within +-1h of this hour."""
        prior = [x for x in self.user_entry_times.get(user, []) if x < t]
        if len(prior) < 6:
            return False
        near = sum(1 for x in prior if min((x.hour - t.hour) % 24, (t.hour - x.hour) % 24) <= 1)
        return near / len(prior) < 0.06


def is_archive_cmd(cmd: str | None) -> bool:
    c = (cmd or "").lower()
    return any(tok in c for tok in ARCHIVE_TOKENS)


def build_baselines(nc: NormalizedCase) -> Baselines:
    if nc.t_min is None:
        now = datetime.now().astimezone()
        return Baselines(warmup_end=now, policy="empty")
    span = nc.t_max - nc.t_min
    if span >= timedelta(hours=60):
        warm, policy = nc.t_min + timedelta(hours=12), "first-seen history; 12h warm-up"
    else:
        warm, policy = nc.t_min + span * 0.2, "first-seen history; warm-up = first 20% of a short capture (weaker baseline)"
    b = Baselines(warmup_end=warm, policy=policy)
    hours: dict[str, Counter] = defaultdict(Counter)

    def first(table: dict, key, t: datetime) -> None:
        if key not in table:
            table[key] = t

    for e in nc.events:
        if e.action is Action.login and e.outcome is Outcome.success and e.user and e.host:
            first(b.fs_user_host, (e.user, e.host), e.ts_utc)
            if e.src_ip:
                first(b.fs_user_subnet, (e.user, subnet24(e.src_ip)), e.ts_utc)
            hours[e.user][e.ts_utc.hour] += 1
            b.user_logins[e.user] += 1
            if e.src_ip and not is_internal(e.src_ip):
                b.user_entry_times.setdefault(e.user, []).append(e.ts_utc)
        elif e.action is Action.sudo and e.outcome is Outcome.success and e.user and e.host:
            first(b.fs_user_host_sudo, (e.user, e.host), e.ts_utc)
            b.user_sudo_count[e.user] += 1
        elif e.action is Action.proc_exec and e.user and e.host and is_archive_cmd(e.object):
            first(b.fs_user_host_archive, (e.user, e.host), e.ts_utc)
        elif e.source_type is SourceType.net and e.host and e.dst_ip and not is_internal(e.dst_ip):
            first(b.fs_host_dst, (e.host, e.dst_ip), e.ts_utc)
    b.user_hours = dict(hours)
    return b
