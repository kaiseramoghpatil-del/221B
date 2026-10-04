"""T3 - HELD-OUT template: insider data theft. Written after the detection engine was frozen; it was not tuned on it.

A legitimate employee uses their own account, during their normal working hours, from their usual home network:
bastion -> (normal hop to a host they use) -> db-01, a host they have never touched -> packs a database dump ->
sends it to an external storage address. There is no password guessing, no privilege change and no persistence.
"""
from __future__ import annotations

from datetime import timedelta

from .attack import AttackInfo, _lbl
from .context import T0, Ctx, lerp


def build_insider(c: Ctx, exclude_users: tuple[str, ...]) -> AttackInfo:
    rng, s = c.rng, c.params.stealth
    topo = c.topo
    devs = [u for u in topo.users if u.role == "dev" and u.name not in exclude_users]
    insider = devs[rng.randrange(len(devs))]
    dropsite = c.pool.ext()  # external storage endpoint
    gap = lambda mult=1.0: timedelta(minutes=lerp(2, 50, s) * mult * rng.uniform(0.6, 1.4))  # noqa: E731

    # during their own working hours on day 2, from their usual home IP
    local_h = insider.start_h + rng.uniform(1.5, 4.0)
    t = T0 + timedelta(days=2, hours=local_h - insider.tz_h)
    home = insider.home_ips[0]
    bastion, app, db = topo.hosts["bastion-01"], topo.hosts["app-01"], topo.hosts["db-01"]

    pid = c.ssh_login(t, "bastion-01", insider.name, home, method="publickey", label=_lbl("INITIAL_ACCESS"))
    for cmd in ("git pull", "ls -la"):
        t += gap(0.2)
        c.exec(t, "bastion-01", insider.name, cmd)  # ordinary activity, unlabeled

    # a normal hop to a host this developer uses every day
    t += gap(0.5)
    app_pid = c.ssh_login(t, "app-01", insider.name, bastion.ip, method="publickey", label=_lbl("LATERAL_MOVEMENT"))
    c.flow(t, "bastion-01", bastion.ip, app.ip, 22, rng.randint(2000, 9000), rng.randint(2000, 9000), label=_lbl("LATERAL_MOVEMENT"))

    # then to the database server, which they have never accessed
    t += gap()
    t_db = t
    db_pid = c.ssh_login(t_db, "db-01", insider.name, app.ip, method="publickey", label=_lbl("LATERAL_MOVEMENT"))
    c.flow(t_db, "app-01", app.ip, db.ip, 22, rng.randint(2000, 9000), rng.randint(2000, 9000), label=_lbl("LATERAL_MOVEMENT"))

    t += gap(0.6)
    vol = rng.randint(1_500_000_000, 5_000_000_000)
    c.exec(t, "db-01", insider.name, "pg_dump -Fc customers -f /tmp/export.dump", label=_lbl("COLLECTION"))
    c.add(t=t + timedelta(seconds=40), file="audit", kind="file_read", host="db-01",
          f={"user": insider.name, "path": "/var/lib/postgresql/data", "bytes": vol}, label=_lbl("COLLECTION"))
    t += gap(0.4)
    c.exec(t, "db-01", insider.name, "tar czf /tmp/export.tgz /tmp/export.dump", label=_lbl("COLLECTION"))

    t += gap(0.6)
    chunks = round(lerp(3, 20, s))
    span = timedelta(minutes=lerp(10, 180, s))
    for i in range(chunks):
        c.flow(t + span * (i / chunks), "db-01", db.ip, dropsite, 443, int(vol / chunks * rng.uniform(0.8, 1.2)), rng.randint(5_000, 40_000),
               label=_lbl("EXFILTRATION"))
    t += span
    c.ssh_logout(t + gap(0.2), "db-01", insider.name, db_pid, label=_lbl("LATERAL_MOVEMENT"))
    c.ssh_logout(t + gap(0.3), "app-01", insider.name, app_pid, label=_lbl("LATERAL_MOVEMENT"))
    c.ssh_logout(t + gap(0.5), "bastion-01", insider.name, pid, label=_lbl("INITIAL_ACCESS"))

    info = AttackInfo(template="T3", entry_vector="insider_misuse", attacker_ips=[home], exfil_dst=dropsite,
                      victim_user=insider.name, victim_hosts=["db-01"], pivot_hosts=["bastion-01", "app-01"])
    info.t_login = T0 + timedelta(days=2, hours=local_h - insider.tz_h)
    info.t_db_login = t_db
    return info
