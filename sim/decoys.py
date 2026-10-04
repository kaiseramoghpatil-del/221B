"""Decoys: benign behaviours that *look* like attacks. Each is labeled in ground truth.

loud_bruteforce   - thousands of failures from one IP, never succeeds         (D01 look-alike)
periodic_scanner  - internal vuln scanner sweeping hosts nightly              (D07 look-alike)
admin_sudo_burst  - sysadmin runs many sudo commands, adds a user             (D06 look-alike)
scheduled_backup  - multi-GB transfer to a fixed external dest daily          (D09/D10 look-alike)
traveling_user    - dev logs in successfully from a brand-new IP, office hours (D04 look-alike)
"""
from __future__ import annotations

from datetime import timedelta

from .context import DAYS, T0, Ctx, SUDO_CMDS
from .benign import NOISE_USERS

GUESS_USERS = ["root", "admin", "ubuntu", "deploy", "oracle", "test", "user", "postgres"]


def add_all(c: Ctx) -> dict:
    return {
        "loud_bruteforce": loud_bruteforce(c),
        "periodic_scanner": periodic_scanner(c),
        "admin_sudo_burst": admin_sudo_burst(c),
        "scheduled_backup": scheduled_backup(c),
        "traveling_user": traveling_user(c),
    }


def loud_bruteforce(c: Ctx) -> str:
    rng = c.rng
    ip = c.pool.ext()
    start = T0 + timedelta(days=1, hours=10, minutes=rng.randint(0, 40))
    n = int(2500 * c.params.scale * min(c.params.noise, 2.0))
    real_users = [u.name for u in c.topo.users[:8]]
    t = start
    for _ in range(n):
        t += timedelta(seconds=rng.uniform(1.0, 4.0))
        name = rng.choice(GUESS_USERS + real_users)
        invalid = name not in ("root", *real_users)
        c.ssh_fail(t, "bastion-01", name, ip, invalid=invalid, label="decoy:loud_bruteforce", entity=f"ip:{ip}")
    return ip


def periodic_scanner(c: Ctx) -> str:
    rng = c.rng
    sc = c.topo.scanner
    targets = [h for h in c.topo.hosts.values()]
    ports = [22, 80, 443, 3306, 5432, 6379, 8080, 9200]
    for d in range(DAYS):
        t = T0 + timedelta(days=d, hours=3, seconds=rng.randint(0, 30))
        for rep in range(3):
            for h in targets:
                for p in ports:
                    t += timedelta(seconds=rng.uniform(0.3, 2.0))
                    open_ = (p in (22, 80, 443)) and h.role in ("bastion", "web") or (p == 5432 and h.role == "db") or (p == 8080 and h.role == "app")
                    c.flow(t, sc.name, sc.ip, h.ip, p, rng.randint(40, 120), 0 if not open_ else rng.randint(40, 400),
                           action="allowed" if open_ else "denied", label="decoy:periodic_scanner", entity=f"ip:{sc.ip}")
        for h in targets[:4]:
            c.preauth(t + timedelta(seconds=rng.randint(1, 30)), h.name, sc.ip, label="decoy:periodic_scanner", entity=f"ip:{sc.ip}")
    return sc.ip


def admin_sudo_burst(c: Ctx) -> str:
    rng = c.rng
    admin = next(u for u in c.topo.users if u.role == "admin")
    t = T0 + timedelta(days=1, hours=14, minutes=rng.randint(0, 30))
    ent = f"user:{admin.name}"
    pid = c.ssh_login(t, "app-01", admin.name, c.topo.hosts["bastion-01"].ip, label="decoy:admin_sudo_burst", entity=ent)
    tt = t
    for i in range(18):
        tt += timedelta(seconds=rng.randint(10, 40))
        c.sudo(tt, "app-01", admin.name, rng.choice(SUDO_CMDS), label="decoy:admin_sudo_burst", entity=ent)
    tt += timedelta(seconds=20)
    c.add(t=tt, file="auth", kind="useradd", host="app-01", f={"pid": c.pid("app-01"), "name": "n.hire", "uid": 1900}, label="decoy:admin_sudo_burst", entity=ent)
    c.add(t=tt + timedelta(seconds=2), file="auth", kind="group_add", host="app-01", f={"pid": c.pid("app-01"), "name": "n.hire", "group": "developers"},
          label="decoy:admin_sudo_burst", entity=ent)
    c.ssh_logout(tt + timedelta(minutes=2), "app-01", admin.name, pid, label="decoy:admin_sudo_burst", entity=ent)
    return admin.name


def scheduled_backup(c: Ctx) -> str:
    rng = c.rng
    fh = c.topo.hosts["file-01"]
    for d in range(DAYS):
        t = T0 + timedelta(days=d, hours=2, minutes=rng.randint(0, 5))
        c.exec(t, "file-01", "backup", f"tar czf /backup/daily-{(T0 + timedelta(days=d)):%Y%m%d}.tgz /srv/share", label="decoy:scheduled_backup", entity="host:file-01")
        total = rng.randint(3_000_000_000, 6_000_000_000)
        chunks = 4
        for i in range(chunks):
            c.flow(t + timedelta(minutes=5 + i * 6, seconds=rng.randint(0, 30)), "file-01", fh.ip, c.topo.backup_dst, 443,
                   total // chunks, rng.randint(10_000, 80_000), label="decoy:scheduled_backup", entity="host:file-01")
    return c.topo.backup_dst


def traveling_user(c: Ctx) -> str:
    rng = c.rng
    devs = [u for u in c.topo.users if u.role == "dev"]
    u = devs[rng.randrange(len(devs))]
    ip = c.pool.ext()
    t = T0 + timedelta(days=2, hours=u.start_h + 1.2 - u.tz_h)
    ent = f"user:{u.name}"
    pid = c.ssh_login(t, "bastion-01", u.name, ip, method="password", label="decoy:traveling_user", entity=ent)
    for i in range(rng.randint(3, 8)):
        c.exec(t + timedelta(minutes=2 + 5 * i), "bastion-01", u.name, rng.choice(["ls -la", "git pull", "df -h", "uptime"]), label="decoy:traveling_user", entity=ent)
    c.ssh_logout(t + timedelta(minutes=70), "bastion-01", u.name, pid, label="decoy:traveling_user", entity=ent)
    return u.name
