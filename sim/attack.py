"""Attack templates. Every record carries label 'attack:<STAGE>' so truth can be reconstructed after rendering.

T1  stolen credential : (optional low-rate spray) -> quiet login as victim -> recon -> priv-esc -> persistence
                        -> lateral (bastion->app->db) -> staging -> exfil
T2  brute-force success: many failures (spread over rotating IPs) -> success -> same post-exploitation chain
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .context import T0, Ctx, lerp

EXCLUDED = ()


@dataclass
class AttackInfo:
    template: str
    entry_vector: str
    attacker_ips: list[str]
    exfil_dst: str
    victim_user: str
    victim_hosts: list[str] = field(default_factory=lambda: ["db-01"])
    pivot_hosts: list[str] = field(default_factory=lambda: ["bastion-01", "app-01"])
    t_login: datetime | None = None
    t_db_login: datetime | None = None


def _lbl(stage: str) -> str:
    return f"attack:{stage}"


def build(c: Ctx, template: str, exclude_users: tuple[str, ...]) -> AttackInfo:
    rng, s = c.rng, c.params.stealth
    topo = c.topo
    devs = [u for u in topo.users if u.role == "dev" and u.name not in exclude_users]
    victim = devs[rng.randrange(len(devs))]
    k = c.params.ip_rotation
    ips = [c.pool.ext() for _ in range(k)]
    exfil_dst = ips[-1] if rng.random() < 0.5 else c.pool.ext()
    gap_min = lerp(0.3, 75.0, s)  # typical minutes between steps

    def gap(mult: float = 1.0) -> timedelta:
        return timedelta(minutes=gap_min * mult * rng.uniform(0.5, 1.5))

    info = AttackInfo(template=template, entry_vector="stolen_credential" if template == "T1" else "bruteforce_success",
                      attacker_ips=ips, exfil_dst=exfil_dst, victim_user=victim.name)
    bastion = topo.hosts["bastion-01"]
    app = topo.hosts["app-01"]
    ent_user = f"user:{victim.name}"

    # ---- entry ------------------------------------------------------------------
    if template == "T1":
        # off-hours for the victim: 02:00-04:30 *local* on day 2
        local_h = rng.uniform(2.0, 4.5)
        t_login = T0 + timedelta(days=2, hours=local_h - victim.tz_h)
        # low-rate spray in the hours before (other usernames; never the victim)
        n_spray = round(lerp(60, 10, s))
        window = timedelta(minutes=lerp(10, 480, s))
        start = t_login - timedelta(hours=rng.uniform(0.5, 2.0)) - window
        others = [u.name for u in topo.users if u.name != victim.name]
        for i in range(n_spray):
            tt = start + window * (i / max(1, n_spray)) + timedelta(seconds=rng.uniform(0, 20))
            ip = ips[i % k]
            name = rng.choice(others) if rng.random() < 0.6 else rng.choice(["admin", "root", "ubuntu", "deploy", "test"])
            c.ssh_fail(tt, "bastion-01", name, ip, invalid=name not in others and name != "root", label=_lbl("RECON"))
        entry_ip = ips[-1]
        pid = c.ssh_login(t_login, "bastion-01", victim.name, entry_ip, method="password", label=_lbl("INITIAL_ACCESS"))
    else:  # T2 brute force that succeeds
        day_h = rng.uniform(5.0, 12.0)
        t_start = T0 + timedelta(days=2, hours=day_h)
        n_fail = round(lerp(120, 25, s))
        window = timedelta(minutes=lerp(8, 360, s))
        for i in range(n_fail):
            tt = t_start + window * (i / n_fail) + timedelta(seconds=rng.uniform(0, 5))
            c.ssh_fail(tt, "bastion-01", victim.name, ips[i % k], invalid=False, label=_lbl("RECON"))
        t_login = t_start + window + timedelta(seconds=rng.uniform(5, 40))
        entry_ip = ips[-1]
        pid = c.ssh_login(t_login, "bastion-01", victim.name, entry_ip, method="password", label=_lbl("INITIAL_ACCESS"))
    info.t_login = t_login

    t = t_login
    # ---- foothold ---------------------------------------------------------------
    for cmd in ("whoami", "id", "uname -a", "cat /etc/passwd"):
        t += gap(0.15)
        c.exec(t, "bastion-01", victim.name, cmd, label=_lbl("EXECUTION"))

    # ---- discovery --------------------------------------------------------------
    t += gap()
    c.exec(t, "bastion-01", victim.name, "ss -tulpn", label=_lbl("DISCOVERY"))
    c.exec(t + timedelta(seconds=5), "bastion-01", victim.name, "ip neigh", label=_lbl("DISCOVERY"))
    n_targets = round(lerp(30, 8, s))
    span = timedelta(minutes=lerp(2, 40, s))
    named = [h for h in topo.hosts.values() if h.name != "bastion-01"]
    extra = [f"10.0.1.{x}" for x in rng.sample(range(50, 250), max(0, n_targets - len(named)))]
    targets = [h.ip for h in named] + extra
    for i, tip in enumerate(targets[:n_targets]):
        tt = t + span * (i / max(1, n_targets))
        for port in rng.sample([22, 80, 443, 3306, 5432, 6379, 8080], 3):
            known = any(h.ip == tip for h in named)
            ok = known and port in (22, 5432, 8080, 80)
            c.flow(tt + timedelta(seconds=rng.uniform(0, 3)), "bastion-01", bastion.ip, tip, port, rng.randint(40, 120),
                   rng.randint(40, 400) if ok else 0, action="allowed" if ok else "denied", label=_lbl("DISCOVERY"))
    t += span

    # ---- privilege escalation ---------------------------------------------------
    t += gap()
    c.sudo(t, "bastion-01", victim.name, "/bin/bash", label=_lbl("PRIV_ESC"))

    # ---- persistence ------------------------------------------------------------
    t += gap(0.5)
    c.add(t=t, file="audit", kind="key_add", host="bastion-01", f={"user": victim.name, "path": "/root/.ssh/authorized_keys"}, label=_lbl("PERSISTENCE"))

    # ---- lateral movement: bastion -> app -> db ---------------------------------
    t += gap()
    app_pid = c.ssh_login(t, "app-01", victim.name, bastion.ip, method="publickey", label=_lbl("LATERAL_MOVEMENT"))
    c.flow(t, "bastion-01", bastion.ip, app.ip, 22, rng.randint(2000, 9000), rng.randint(2000, 9000), label=_lbl("LATERAL_MOVEMENT"))
    t += gap(0.8)
    t_db = t
    db_pid = c.ssh_login(t_db, "db-01", victim.name, app.ip, method="publickey", label=_lbl("LATERAL_MOVEMENT"))
    c.flow(t_db, "app-01", app.ip, topo.hosts["db-01"].ip, 22, rng.randint(2000, 9000), rng.randint(2000, 9000), label=_lbl("LATERAL_MOVEMENT"))
    info.t_db_login = t_db

    # ---- collection (db-01) -----------------------------------------------------
    t += gap(0.8)
    c.exec(t, "db-01", victim.name, "tar czf /tmp/.sys.tgz /var/lib/postgresql/dump", label=_lbl("COLLECTION"))
    vol = rng.randint(2_000_000_000, 6_000_000_000)
    c.add(t=t + timedelta(seconds=30), file="audit", kind="file_read", host="db-01",
          f={"user": victim.name, "path": "/var/lib/postgresql/dump", "bytes": vol}, label=_lbl("COLLECTION"))

    # ---- exfiltration (db-01 -> external) ---------------------------------------
    t += gap(0.8)
    chunks = round(lerp(4, 30, s))
    xspan = timedelta(minutes=lerp(15, 300, s))
    per = vol // chunks
    db = topo.hosts["db-01"]
    for i in range(chunks):
        c.flow(t + xspan * (i / chunks), "db-01", db.ip, exfil_dst, 443 if rng.random() < 0.8 else 8443,
               int(per * rng.uniform(0.7, 1.3)), rng.randint(5_000, 40_000), label=_lbl("EXFILTRATION"))
    t += xspan

    # ---- evasion / cleanup ------------------------------------------------------
    if rng.random() < 0.5:
        c.add(t=t + gap(0.3), file="audit", kind="log_clear", host="db-01", f={"user": victim.name, "path": "/var/log/auth.log"}, label=_lbl("PERSISTENCE"))
    c.ssh_logout(t + gap(0.3), "db-01", victim.name, db_pid, label=_lbl("LATERAL_MOVEMENT"))
    c.ssh_logout(t + gap(0.5), "app-01", victim.name, app_pid, label=_lbl("LATERAL_MOVEMENT"))
    c.ssh_logout(t + gap(0.8), "bastion-01", victim.name, pid, label=_lbl("INITIAL_ACCESS"))
    return info
