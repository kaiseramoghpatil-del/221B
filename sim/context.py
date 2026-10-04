"""Shared generation context + small helpers."""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from backend.core.models import ScenarioParams

from .records import Rec
from .topology import IpPool, Topology

UTC = timezone.utc
T0 = datetime(2026, 9, 28, 0, 0, 0, tzinfo=UTC)  # Monday 00:00 UTC
DAYS = 4  # Mon..Thu
HORIZON = T0 + timedelta(days=DAYS)

BENIGN_CMDS = [
    "ls -la", "cd /srv/app", "git pull", "tail -n 100 /var/log/app.log", "vim config.yaml", "htop", "df -h", "docker ps",
    "python manage.py check", "less /var/log/nginx/error.log", "curl -s localhost:8080/health", "grep -r TODO .", "make test",
    "journalctl -u app --since today", "psql -c 'select 1'", "free -m", "uptime", "systemctl status app",
]
SUDO_CMDS = [
    "/usr/bin/systemctl restart app", "/usr/bin/systemctl status nginx", "/usr/bin/journalctl -u app", "/usr/bin/apt update",
    "/usr/bin/tail -f /var/log/syslog", "/usr/bin/docker restart web", "/usr/bin/less /var/log/auth.log",
]


@dataclass
class Ctx:
    rng: random.Random
    pool: IpPool
    topo: Topology
    params: ScenarioParams
    recs: list[Rec] = field(default_factory=list)
    _pids: dict[str, int] = field(default_factory=dict)

    def pid(self, host: str) -> int:
        base = self._pids.get(host)
        if base is None:
            base = 1000 + self.rng.randrange(20000)
        base += self.rng.randrange(1, 40)
        if base > 65000:
            base = 1000 + self.rng.randrange(1000)
        self._pids[host] = base
        return base

    def port(self) -> int:
        return self.rng.randrange(32768, 61000)

    def add(self, **kw) -> Rec:
        r = Rec(**kw)
        self.recs.append(r)
        return r

    # ---- reusable building blocks -------------------------------------------------
    def ssh_login(self, t: datetime, host: str, user: str, ip: str, method: str = "publickey", label: str | None = None,
                  entity: str | None = None) -> int:
        pid = self.pid(host)
        self.add(t=t, file="auth", kind="ssh_ok", host=host,
                 f={"pid": pid, "user": user, "ip": ip, "port": self.port(), "method": method}, label=label, entity=entity)
        return pid

    def ssh_logout(self, t: datetime, host: str, user: str, pid: int, label: str | None = None, entity: str | None = None) -> None:
        self.add(t=t, file="auth", kind="ssh_close", host=host, f={"pid": pid, "user": user}, label=label, entity=entity)

    def ssh_fail(self, t: datetime, host: str, user: str, ip: str, invalid: bool, label: str | None = None,
                 entity: str | None = None, with_notice: bool = True) -> None:
        pid = self.pid(host)
        port = self.port()
        if invalid and with_notice:
            self.add(t=t, file="auth", kind="ssh_invalid", host=host, f={"pid": pid, "user": user, "ip": ip, "port": port},
                     label=label, entity=entity)
        self.add(t=t + timedelta(seconds=1), file="auth", kind="ssh_fail", host=host,
                 f={"pid": pid, "user": user, "ip": ip, "port": port, "invalid": invalid}, label=label, entity=entity)

    def preauth(self, t: datetime, host: str, ip: str, user: str | None = None, label: str | None = None,
                entity: str | None = None) -> None:
        self.add(t=t, file="auth", kind="ssh_preauth", host=host,
                 f={"pid": self.pid(host), "ip": ip, "port": self.port(), "user": user}, label=label, entity=entity)

    def sudo(self, t: datetime, host: str, user: str, cmd: str, tuser: str = "root", label: str | None = None,
             entity: str | None = None) -> None:
        self.add(t=t, file="auth", kind="sudo", host=host,
                 f={"user": user, "tty": f"pts/{self.rng.randrange(0, 4)}", "pwd": f"/home/{user}", "tuser": tuser, "cmd": cmd},
                 label=label, entity=entity)

    def exec(self, t: datetime, host: str, user: str, cmd: str, label: str | None = None, entity: str | None = None) -> None:
        self.add(t=t, file="audit", kind="exec", host=host, f={"user": user, "cmd": cmd}, label=label, entity=entity)

    def flow(self, t: datetime, src_host: str, src_ip: str, dst_ip: str, dst_port: int, bytes_out: int, bytes_in: int,
             action: str = "allowed", label: str | None = None, entity: str | None = None) -> None:
        self.add(t=t, file="flows", kind="flow", host=src_host,
                 f={"src_ip": src_ip, "dst_ip": dst_ip, "dst_port": dst_port, "bytes_out": bytes_out, "bytes_in": bytes_in, "action": action},
                 label=label, entity=entity)


def lerp(a: float, b: float, x: float) -> float:
    return a + (b - a) * x


def poisson(rng: random.Random, lam: float) -> int:
    if lam <= 0:
        return 0
    if lam > 60:
        return max(0, int(rng.gauss(lam, lam ** 0.5) + 0.5))
    import math

    L, k, p = math.exp(-lam), 0, 1.0
    while True:
        k += 1
        p *= rng.random()
        if p <= L:
            return k - 1
