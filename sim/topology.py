"""Synthetic enterprise: hosts, users, IP pools. Fully determined by the RNG passed in."""
from __future__ import annotations

import random
from dataclasses import dataclass, field

# External addresses come from one benchmark-range /15 for *everyone* (users, bots, attackers) so no
# detector can learn "attacker = some special range".
EXT_BASE = (198, 18)


@dataclass(frozen=True)
class Host:
    name: str
    ip: str
    role: str
    criticality: str  # low | med | high


@dataclass
class User:
    name: str
    role: str  # admin | dev | staff | service
    criticality: str
    tz_h: float  # local offset from UTC in hours
    start_h: float  # local start of working day
    end_h: float
    home_ips: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)  # servers reachable via bastion hop


@dataclass
class Topology:
    hosts: dict[str, Host]
    users: list[User]
    web_clients: list[str]
    noise_ips: list[str]
    backup_dst: str
    updates_dst: str
    scanner: Host

    def user(self, name: str) -> User:
        return next(u for u in self.users if u.name == name)


_ADMINS = ["ops.lee", "ops.rao", "ops.kim"]
_DEVS = ["a.novak", "b.ferrer", "c.okafor", "d.lindqvist", "e.haddad", "f.moreau", "g.tanaka", "h.petrov", "i.silva"]
_STAFF = [
    "j.owens", "k.adeyemi", "l.fischer", "m.costa", "n.yilmaz", "o.brandt", "p.nakamura", "q.dubois", "r.kowalski",
    "s.mehta", "t.alvarez", "u.sorensen", "v.ibrahim", "w.chen", "x.moretti", "y.ogunbanjo", "z.laurent", "a.varga",
]
_TZ = [0.0, 1.0, -5.0, 5.5, 8.0, -8.0]

HOSTS = [
    Host("bastion-01", "10.0.0.5", "bastion", "high"),
    Host("web-01", "10.0.1.10", "web", "med"),
    Host("web-02", "10.0.1.11", "web", "med"),
    Host("app-01", "10.0.1.20", "app", "med"),
    Host("db-01", "10.0.1.30", "db", "high"),
    Host("file-01", "10.0.1.40", "file", "med"),
]


class IpPool:
    def __init__(self, rng: random.Random):
        self.rng = rng
        self._used: set[str] = set()

    def ext(self) -> str:
        while True:
            ip = f"{EXT_BASE[0]}.{EXT_BASE[1] + self.rng.randrange(2)}.{self.rng.randrange(256)}.{self.rng.randrange(1, 255)}"
            if ip not in self._used:
                self._used.add(ip)
                return ip


def build_topology(rng: random.Random, pool: IpPool, n_users_cap: int | None = None) -> Topology:
    hosts = {h.name: h for h in HOSTS}
    servers = [h for h in hosts if h != "bastion-01"]
    users: list[User] = []

    def mk(name: str, role: str) -> User:
        tz = rng.choice(_TZ)
        start = rng.choice([7.5, 8.0, 8.5, 9.0, 9.5])
        crit = "high" if role == "admin" else "med" if role == "dev" else "low"
        n_home = rng.choice([1, 1, 2])
        if role == "admin":
            reach = servers
        elif role == "dev":
            reach = ["app-01", "web-01"]
        else:
            reach = ["file-01"]
        return User(name, role, crit, tz, start, start + rng.choice([8.0, 8.5, 9.0]), [pool.ext() for _ in range(n_home)], reach)

    for n in _ADMINS:
        users.append(mk(n, "admin"))
    for n in _DEVS:
        users.append(mk(n, "dev"))
    for n in _STAFF:
        users.append(mk(n, "staff"))
    if n_users_cap is not None and n_users_cap < len(users):
        keep_admin = users[:3]
        keep_dev = users[3:12][: max(3, (n_users_cap - 3) // 3)]
        keep_staff = users[12:][: max(0, n_users_cap - 3 - len(keep_dev))]
        users = keep_admin + keep_dev + keep_staff
    return Topology(
        hosts=hosts,
        users=users,
        web_clients=[pool.ext() for _ in range(500)],
        noise_ips=[pool.ext() for _ in range(900)],
        backup_dst=pool.ext(),
        updates_dst=pool.ext(),
        scanner=Host("sec-scan-01", "10.0.3.5", "scanner", "low"),
    )
