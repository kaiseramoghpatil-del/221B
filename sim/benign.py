"""Benign background: user sessions, web traffic, internet SSH noise, service flows."""
from __future__ import annotations

import math
from datetime import timedelta

from .context import BENIGN_CMDS, DAYS, SUDO_CMDS, T0, Ctx, poisson

PATHS = [
    ("/", 25), ("/index.html", 8), ("/login", 6), ("/api/v1/items", 14), ("/api/v1/items/42", 8), ("/static/app.js", 10),
    ("/static/app.css", 8), ("/health", 6), ("/api/v1/search?q=alpha", 5), ("/about", 3), ("/favicon.ico", 4), ("/robots.txt", 2),
    ("/api/v1/orders", 5), ("/products", 4),
]
UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/118.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
    "curl/8.1.2", "python-requests/2.31.0", "Googlebot/2.1 (+http://www.google.com/bot.html)",
]
NOISE_USERS = ["admin", "root", "test", "oracle", "ubuntu", "user", "postgres", "git", "ftpuser", "pi", "guest", "support", "deploy2", "jenkins"]


def _weighted(rng, items):
    total = sum(w for _, w in items)
    x = rng.random() * total
    for v, w in items:
        x -= w
        if x <= 0:
            return v
    return items[-1][0]


def _diurnal(hour_utc: int) -> float:
    return 0.35 + 0.65 * (0.5 + 0.5 * math.sin((hour_utc - 6) / 24 * 2 * math.pi))


def add_user_sessions(c: Ctx, skip_users: tuple[str, ...] = ()) -> None:
    rng = c.rng
    sessions_scale = max(1, round(c.params.scale))
    for u in c.topo.users:
        if u.name in skip_users:
            continue
        for d in range(DAYS):
            for _ in range(rng.choice([1, 2, 2, 3]) * sessions_scale if u.role != "staff" else rng.choice([1, 1, 2])):
                local = min(max(rng.gauss(u.start_h + 1.5, 1.6), 6.0), 19.5)
                t = T0 + timedelta(days=d, hours=local - u.tz_h)
                ip = u.home_ips[0] if rng.random() < 0.85 or len(u.home_ips) == 1 else u.home_ips[1]
                if rng.random() < 0.04:  # typo before success
                    for i in range(rng.choice([1, 2])):
                        c.ssh_fail(t - timedelta(seconds=40 * (i + 1)), "bastion-01", u.name, ip, invalid=False)
                pid = c.ssh_login(t, "bastion-01", u.name, ip, method=rng.choice(["publickey", "publickey", "password"]))
                dur = timedelta(minutes=rng.randint(25, 300))
                for _ in range(rng.randint(2, 14)):
                    c.exec(t + timedelta(seconds=rng.randint(20, int(dur.total_seconds()))), "bastion-01", u.name, rng.choice(BENIGN_CMDS))
                hops = []
                if u.role != "staff" and rng.random() < 0.7:
                    hops.append(rng.choice(u.hosts))
                elif u.role == "staff" and rng.random() < 0.4:
                    hops.append("file-01")
                for h in hops:
                    th = t + timedelta(minutes=rng.randint(2, 20))
                    hp = c.ssh_login(th, h, u.name, c.topo.hosts["bastion-01"].ip, method="publickey")
                    hd = timedelta(minutes=rng.randint(5, 90))
                    for _ in range(rng.randint(2, 10)):
                        c.exec(th + timedelta(seconds=rng.randint(10, int(hd.total_seconds()))), h, u.name, rng.choice(BENIGN_CMDS))
                    # devs sometimes sudo on app hosts (baseline for first-time-sudo detection); admins often
                    n_sudo = rng.randint(2, 8) if u.role == "admin" else (rng.randint(1, 2) if (u.role == "dev" and h == "app-01" and rng.random() < 0.25) else 0)
                    for _ in range(n_sudo):
                        c.sudo(th + timedelta(seconds=rng.randint(30, int(hd.total_seconds()))), h, u.name, rng.choice(SUDO_CMDS))
                    c.ssh_logout(th + hd, h, u.name, hp)
                c.ssh_logout(t + dur, "bastion-01", u.name, pid)


def add_web(c: Ctx) -> None:
    rng = c.rng
    clients = c.topo.web_clients
    for host, base in (("web-01", 220), ("web-02", 140)):
        for h in range(DAYS * 24):
            n = poisson(rng, base * c.params.scale * _diurnal(h % 24))
            for _ in range(n):
                t = T0 + timedelta(hours=h, seconds=rng.random() * 3600)
                r = rng.random()
                status = 200 if r < 0.86 else 304 if r < 0.92 else 301 if r < 0.95 else 404 if r < 0.995 else 500
                path = _weighted(rng, PATHS) if status != 404 else rng.choice(["/wp-login.php", "/old/page", "/missing.png", "/.env", "/admin"])
                c.add(t=t, file=host, kind="http", host=host, f={
                    "ip": rng.choice(clients), "user": None, "method": "GET" if rng.random() < 0.93 else "POST", "path": path,
                    "status": status, "bytes": int(rng.lognormvariate(7.5, 1.2)) if status in (200, 304) else rng.randint(150, 600),
                    "ref": None, "ua": rng.choice(UAS)}, label="benign")


def add_internet_ssh_noise(c: Ctx) -> None:
    """Constant background of internet bots failing against the exposed bastion (realistic haystack)."""
    rng = c.rng
    ips = c.topo.noise_ips
    for h in range(DAYS * 24):
        for _ in range(poisson(rng, 14 * c.params.noise * c.params.scale)):
            ip = rng.choice(ips)
            t = T0 + timedelta(hours=h, seconds=rng.random() * 3600)
            burst = rng.randint(1, 3) if rng.random() < 0.8 else rng.randint(6, 18)
            for i in range(burst):
                tt = t + timedelta(seconds=i * rng.randint(2, 6))
                user = rng.choice(NOISE_USERS)
                invalid = user != "root"
                c.ssh_fail(tt, "bastion-01", user, ip, invalid=invalid, label="noise")
                if invalid:
                    c.preauth(tt + timedelta(seconds=3), "bastion-01", ip, user=user, label="noise")


def add_service_flows(c: Ctx) -> None:
    rng = c.rng
    hosts = c.topo.hosts
    pairs = [("web-01", "app-01", 8080, 2_000_000), ("web-02", "app-01", 8080, 1_300_000), ("app-01", "db-01", 5432, 900_000)]
    for step in range(DAYS * 24 * 12):  # every 5 minutes
        t = T0 + timedelta(minutes=5 * step) + timedelta(seconds=rng.randint(0, 20))
        for src, dst, port, mean in pairs:
            b = int(rng.lognormvariate(math.log(mean * c.params.scale), 0.6))
            c.flow(t, src, hosts[src].ip, hosts[dst].ip, port, b, int(b * rng.uniform(0.2, 1.4)), label="benign")
        if step % 12 == 0:  # hourly package/update check from app-01 to a fixed external endpoint
            c.flow(t, "app-01", hosts["app-01"].ip, c.topo.updates_dst, 443, rng.randint(20_000, 90_000), rng.randint(200_000, 900_000), label="benign")
