"""Credential-access detectors: D01 brute force, D02 spray / distributed, D03 success-after-failures,
D04 new-source login (with the D05 off-hours modifier)."""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import timedelta

from backend.core.models import Action, Event, Outcome, PredicateName as PN, RuleMeta, Stage
from backend.normalize import is_internal, subnet24

from .base import DetectCtx, Detector, P, clamp, fmt_dur, mk_signal

FAST_WINDOW = timedelta(minutes=10)
FAST_MIN = 20
SLOW_PER_USER_MIN = 12
CAMPAIGN_GAP = timedelta(hours=2)
TYPO_WINDOW = timedelta(minutes=5)


def _failures(ctx: DetectCtx) -> list[Event]:
    return [e for e in ctx.nc.events if e.action is Action.login and e.outcome is Outcome.failure and e.src_ip]


def _typo_ids(ctx: DetectCtx) -> set[str]:
    """Failures followed within 5 min by a success for the same user from the same IP = typos, not attacks."""
    succ: dict[tuple[str, str], list] = defaultdict(list)
    for e in ctx.nc.events:
        if e.action is Action.login and e.outcome is Outcome.success and e.user and e.src_ip:
            succ[(e.user, e.src_ip)].append(e.ts_utc)
    out = set()
    for e in _failures(ctx):
        for t in succ.get((e.user, e.src_ip), ()):
            if timedelta(0) <= t - e.ts_utc <= TYPO_WINDOW:
                out.add(e.id)
                break
    return out


def _campaigns(evs: list[Event], gap: timedelta) -> list[list[Event]]:
    out: list[list[Event]] = []
    for e in evs:
        if out and e.ts_utc - out[-1][-1].ts_utc <= gap:
            out[-1].append(e)
        else:
            out.append([e])
    return out


def _max_rate(evs: list[Event], window: timedelta) -> int:
    best, j = 0, 0
    for i in range(len(evs)):
        while evs[i].ts_utc - evs[j].ts_utc > window:
            j += 1
        best = max(best, i - j + 1)
    return best


# ----------------------------------------------------------------------------- D01
D01 = Detector("D01", "Brute-force login attempts", Stage.RECON, RuleMeta(
    level="medium", tags=["attack.credential_access", "attack.t1110.001"],
    falsepositives=["Internet background scanning of exposed SSH", "Misconfigured service retrying a stale password"],
    references=["MITRE ATT&CK T1110.001 Password Guessing"]), run=lambda ctx: _d01(ctx))


def _d01(ctx: DetectCtx):
    typos = _typo_ids(ctx)
    by_ip: dict[str, list[Event]] = defaultdict(list)
    for e in _failures(ctx):
        if e.id not in typos:
            by_ip[e.src_ip].append(e)
    succ_by_ip: dict[str, list[Event]] = defaultdict(list)
    for e in ctx.nc.events:
        if e.action is Action.login and e.outcome is Outcome.success and e.src_ip:
            succ_by_ip[e.src_ip].append(e)
    out = []
    for ip, evs in sorted(by_ip.items()):
        for camp in _campaigns(evs, CAMPAIGN_GAP):
            rate = _max_rate(camp, FAST_WINDOW)
            per_user = Counter(e.user for e in camp)
            top_user, top_n = per_user.most_common(1)[0]
            if rate < FAST_MIN and top_n < SLOW_PER_USER_MIN:
                continue
            t0, t1 = camp[0].ts_utc, camp[-1].ts_utc
            later_ok = [s for s in succ_by_ip.get(ip, []) if t0 <= s.ts_utc <= t1 + timedelta(hours=24)]
            valid = sorted(u for u in per_user if u in ctx.nc.valid_users)
            hosts = sorted({e.host for e in camp if e.host})
            out.append(mk_signal(
                D01, f"{ip}|{t0.isoformat()}", camp,
                entities=[f"ip:{ip}"] + [f"host:{h}" for h in hosts] + ([f"user:{top_user}"] if top_n >= SLOW_PER_USER_MIN else []),
                severity=0.25 + 0.45 * clamp(len(camp) / 1000), confidence=0.9, rarity=0.3,
                template="{n} failed logins from {ip} against {n_users} account(s) over {dur} (peak {rate}/10 min); {n_success} later successes from this IP",
                params={"n": len(camp), "ip": ip, "n_users": len(per_user), "dur": fmt_dur((t1 - t0).total_seconds()), "rate": rate,
                        "n_success": len(later_ok)},
                features={"failures": len(camp), "distinct_users": len(per_user), "valid_users_targeted": valid[:20],
                          "peak_10m": rate, "top_user": top_user, "top_user_failures": top_n, "mode": "fast" if rate >= FAST_MIN else "slow",
                          "successes_from_ip_after": len(later_ok), "src_ip": ip}))
    return out


# ----------------------------------------------------------------------------- D02
D02 = Detector("D02", "Password spray / distributed guessing", Stage.RECON, RuleMeta(
    level="medium", tags=["attack.credential_access", "attack.t1110.003"],
    falsepositives=["Shared NAT egress where many users mistype passwords", "SSO outage causing many failures"],
    references=["MITRE ATT&CK T1110.003 Password Spraying"]), run=lambda ctx: _d02(ctx))


def _d02(ctx: DetectCtx):
    typos = _typo_ids(ctx)
    fails = [e for e in _failures(ctx) if e.id not in typos]
    valid = ctx.nc.valid_users
    out = []
    # (a) one IP, many *valid* accounts, few tries each
    by_ip: dict[str, list[Event]] = defaultdict(list)
    for e in fails:
        by_ip[e.src_ip].append(e)
    for ip, evs in sorted(by_ip.items()):
        for camp in _campaigns(evs, CAMPAIGN_GAP):
            per_user = Counter(e.user for e in camp)
            vu = sorted(u for u in per_user if u in valid)
            if len(vu) >= 3 and _max_rate(camp, FAST_WINDOW) < FAST_MIN and max(per_user.values()) < SLOW_PER_USER_MIN:
                t0, t1 = camp[0].ts_utc, camp[-1].ts_utc
                out.append(mk_signal(
                    D02, f"spray|{ip}|{t0.isoformat()}", camp, entities=[f"ip:{ip}"] + [f"user:{u}" for u in vu],
                    severity=0.5, confidence=0.8, rarity=0.7,
                    template="{ip} tried {n_valid} real account names ({n} attempts) over {dur} - a password spray",
                    params={"ip": ip, "n_valid": len(vu), "n": len(camp), "dur": fmt_dur((t1 - t0).total_seconds())},
                    features={"mode": "spray", "src_ips": [ip], "valid_users_targeted": vu, "attempts": len(camp)}))
    # (b) one valid account, many IPs (distributed guessing) and (c) many IPs x many valid accounts (distributed spray)
    vf = sorted((e for e in fails if e.user in valid), key=lambda e: e.ts_utc)
    for camp in _campaigns(vf, timedelta(hours=6)):
        ips = Counter(e.src_ip for e in camp)
        users = Counter(e.user for e in camp)
        if len(ips) < 3:
            continue
        small_ips = sorted(ip for ip, n in ips.items() if n <= 10)
        sub = [e for e in camp if e.src_ip in small_ips]
        if len(small_ips) >= 3:
            emitted_distributed = False
            for u, n in users.most_common():
                ue = [e for e in sub if e.user == u]
                uips = sorted({e.src_ip for e in ue})
                if len(uips) >= 3 and len(ue) >= 6:
                    out.append(mk_signal(
                        D02, f"dist|{u}|{ue[0].ts_utc.isoformat()}", ue, entities=[f"user:{u}"] + [f"ip:{i}" for i in uips[:40]],
                        severity=0.55, confidence=0.8, rarity=0.8,
                        template="{n} failed logins against {user} from {n_ips} different IPs (each ≤10 tries) - distributed guessing",
                        params={"n": len(ue), "user": u, "n_ips": len(uips)},
                        features={"mode": "distributed", "src_ips": uips, "target_user": u, "attempts": len(ue)}))
                    emitted_distributed = True
            if len(small_ips) >= 5 and len({e.user for e in sub}) >= 4 and not emitted_distributed:
                out.append(mk_signal(
                    D02, f"dspray|{sub[0].ts_utc.isoformat()}", sub,
                    entities=[f"ip:{i}" for i in small_ips[:40]] + [f"user:{u}" for u in sorted({e.user for e in sub})][:20],
                    severity=0.5, confidence=0.7, rarity=0.8,
                    template="{n_ips} IPs each made a few attempts against {n_users} real accounts within {dur} - a distributed spray",
                    params={"n_ips": len(small_ips), "n_users": len({e.user for e in sub}),
                            "dur": fmt_dur((sub[-1].ts_utc - sub[0].ts_utc).total_seconds())},
                    features={"mode": "distributed_spray", "src_ips": small_ips, "attempts": len(sub)}))
    return out


# ----------------------------------------------------------------------------- D03
D03 = Detector("D03", "Successful login after repeated failures", Stage.INITIAL_ACCESS, RuleMeta(
    level="high", tags=["attack.initial_access", "attack.t1078", "attack.t1110"],
    falsepositives=["User who forgot a password and then remembered it (typo pattern is filtered)"],
    references=["MITRE ATT&CK T1078 Valid Accounts"]), run=lambda ctx: _d03(ctx))


def _d03(ctx: DetectCtx):
    typos = _typo_ids(ctx)
    fails = [e for e in _failures(ctx) if e.id not in typos]
    by_user: dict[str, list[Event]] = defaultdict(list)
    by_ip: dict[str, list[Event]] = defaultdict(list)
    for e in fails:
        if e.user:
            by_user[e.user].append(e)
        by_ip[e.src_ip].append(e)
    out = []
    for e in ctx.nc.events:
        if not (e.action is Action.login and e.outcome is Outcome.success and e.user and e.src_ip) or is_internal(e.src_ip):
            continue
        uf = [f for f in by_user.get(e.user, []) if timedelta(0) < e.ts_utc - f.ts_utc <= timedelta(hours=12)]
        ipf = [f for f in by_ip.get(e.src_ip, []) if timedelta(0) < e.ts_utc - f.ts_utc <= timedelta(hours=24)]
        # failures against the account only count if this success comes from one of the failing IPs
        # (otherwise: a user who was merely *targeted* by someone else's brute force, logging in normally)
        if len(uf) >= 5 and e.src_ip not in {f.src_ip for f in uf}:
            uf = []
        if len(uf) < 5 and len(ipf) < 5:
            continue
        sess = ctx.session(e)
        basis = sorted({f.id: f for f in (*uf, *ipf)}.values(), key=lambda x: x.ts_utc)
        out.append(mk_signal(
            D03, e.id, [e], context_events=basis[-30:], entities=[f"user:{e.user}", f"ip:{e.src_ip}", f"host:{e.host}"],
            severity=0.75, confidence=0.85, rarity=0.8, crit=ctx.crit(e.host),
            template="{user} logged in to {host} from {ip} after {n_user} failures against the account and {n_ip} failures from that IP",
            params={"user": e.user, "host": e.host, "ip": e.src_ip, "n_user": len(uf), "n_ip": len(ipf)},
            produces=[P(PN.credential_compromised, e.ts_utc, user=e.user),
                      P(PN.has_access, e.ts_utc, user=e.user, host=e.host, session=sess, via=e.src_ip)],
            features={"anchor": True, "login_event": e.id, "session": sess, "src_ip": e.src_ip, "failures_user": len(uf), "failures_ip": len(ipf),
                      "consumes_ips": sorted(_focused_ips(uf, by_ip, e.user) | {e.src_ip}),
                      "consumes_users": sorted({f.user for f in ipf if f.user} | {e.user})}))
    return out


def _focused_ips(uf: list[Event], by_ip: dict[str, list[Event]], user: str) -> set[str]:
    """IPs whose failed attempts concentrated on this account (rotation infrastructure), not broad brute-forcers."""
    out = set()
    for ip in {f.src_ip for f in uf}:
        targets = {x.user for x in by_ip.get(ip, [])}
        if len(targets) <= 3 and sum(1 for f in uf if f.src_ip == ip) >= 1:
            out.add(ip)
    return out


# ----------------------------------------------------------------------------- D04 (+ D05 off-hours modifier)
D04 = Detector("D04", "Login from a never-seen source", Stage.INITIAL_ACCESS, RuleMeta(
    level="medium", tags=["attack.initial_access", "attack.t1078"],
    falsepositives=["Travel or new home ISP", "New VPN egress"],
    references=["MITRE ATT&CK T1078 Valid Accounts"]), run=lambda ctx: _d04(ctx))


def _d04(ctx: DetectCtx):
    b = ctx.b
    out = []
    for e in ctx.nc.events:
        if not (e.action is Action.login and e.outcome is Outcome.success and e.user and e.src_ip) or is_internal(e.src_ip):
            continue
        sub = subnet24(e.src_ip)
        if b.user_logins[e.user] < 3 or not b.novel(b.fs_user_subnet, (e.user, sub), e.ts_utc):
            continue
        off = b.off_hours(e.user, e.ts_utc)
        sess = ctx.session(e)
        # Off-hours + new source = anchor. New source during normal hours is a *weak* anchor: its access only becomes
        # attacker-held if a strong signal inside that same session later depends on it (resolved in correlation).
        produces = [P(PN.has_access, e.ts_utc, user=e.user, host=e.host, session=sess, via=e.src_ip)]
        out.append(mk_signal(
            D04, e.id, [e], entities=[f"user:{e.user}", f"ip:{e.src_ip}", f"host:{e.host}"],
            severity=0.55 if off else 0.2, confidence=0.7 if off else 0.5, rarity=0.9, crit=ctx.crit(e.host),
            template="{user} logged in to {host} from {ip} - a network never seen for this account" + (" - at an unusual hour for them (D05)" if off else ""),
            params={"user": e.user, "host": e.host, "ip": e.src_ip},
            produces=produces, features={"anchor": off, "weak_anchor": not off, "login_event": e.id, "session": sess, "src_ip": e.src_ip, "subnet": sub, "off_hours": off,
                                         "prior_logins": b.user_logins[e.user]}))
    return out


DETECTORS = [D01, D02, D03, D04]
