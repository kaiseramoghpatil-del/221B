"""Network detectors: D07 internal scanning, D10 exfiltration. Both suppress *periodic* look-alikes
(nightly scanner, scheduled backup) and record why, so the UI can show 'not flagged' with evidence."""
from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from backend.core.models import Event, Outcome, PredicateName as PN, RuleMeta, SourceType, Stage
from backend.normalize import is_internal

from .base import DetectCtx, Detector, P, fmt_dur, mk_signal

SCAN_WINDOW = timedelta(minutes=30)
SCAN_MIN_TARGETS = 12
EXFIL_MIN_BYTES = 100_000_000
EXFIL_GAP = timedelta(hours=2)


def _flows(ctx: DetectCtx) -> list[Event]:
    return [e for e in ctx.nc.events if e.source_type is SourceType.net and e.host and e.dst_ip]


def _time_of_day_close(a, b, minutes: int = 90) -> bool:
    da = (a.hour * 60 + a.minute)
    db = (b.hour * 60 + b.minute)
    d = abs(da - db)
    return min(d, 1440 - d) <= minutes


# ----------------------------------------------------------------------------- D07
D07 = Detector("D07", "Internal network scanning", Stage.DISCOVERY, RuleMeta(
    level="medium", tags=["attack.discovery", "attack.t1046"],
    falsepositives=["Authorised vulnerability scanner (periodic - suppressed with evidence)", "Monitoring health checks"],
    references=["MITRE ATT&CK T1046 Network Service Discovery"]), run=lambda ctx: _d07(ctx))


def _d07(ctx: DetectCtx):
    by_src: dict[str, list[Event]] = defaultdict(list)
    for e in _flows(ctx):
        if is_internal(e.dst_ip) and is_internal(e.src_ip):
            by_src[e.host].append(e)
    out = []
    for host, evs in sorted(by_src.items()):
        campaigns: list[list[Event]] = []
        j = 0
        i = 0
        while i < len(evs):
            while evs[i].ts_utc - evs[j].ts_utc > SCAN_WINDOW:
                j += 1
            win = evs[j:i + 1]
            if len({(e.dst_ip, e.dst_port) for e in win}) >= SCAN_MIN_TARGETS:
                # grow the campaign while flows keep coming within the window
                k = i
                while k + 1 < len(evs) and evs[k + 1].ts_utc - evs[k].ts_utc <= timedelta(minutes=5):
                    k += 1
                campaigns.append(evs[j:k + 1])
                i = k + 1
                j = i
                continue
            i += 1
        prior: list[list[Event]] = []
        for camp in campaigns:
            t0 = camp[0].ts_utc
            targets = {(e.dst_ip, e.dst_port) for e in camp}
            denied = sum(1 for e in camp if e.outcome is Outcome.failure)
            periodic = [p for p in prior if timedelta(hours=20) <= t0 - p[0].ts_utc <= timedelta(days=8) and _time_of_day_close(t0, p[0].ts_utc)]
            prior.append(camp)
            if t0 < ctx.b.warmup_end or periodic:
                ctx.notes.append({"kind": "periodic_scanner" if periodic else "warmup_pattern", "entity": f"host:{host}",
                                  "src_ip": camp[0].src_ip, "t": t0, "targets": len(targets), "event_ids": [e.id for e in camp[:20]],
                                  "reason": (f"same sweep seen on {len(periodic)} earlier day(s) at the same time of day - scheduled scanner"
                                             if periodic else "pattern observed during the baseline warm-up window")})
                continue
            out.append(mk_signal(
                D07, f"{host}|{t0.isoformat()}", camp, entities=[f"host:{host}", f"ip:{camp[0].src_ip}"], severity=0.5, confidence=0.75,
                rarity=0.8, crit=ctx.crit(host),
                template="{host} probed {n} internal host:port pairs in {dur} ({denied} refused)",
                params={"host": host, "n": len(targets), "dur": fmt_dur((camp[-1].ts_utc - t0).total_seconds()), "denied": denied},
                requires=[P(PN.has_access, t0, host=host), P(PN.foothold, t0, host=host)],
                produces=[P(PN.discovered, t0, src=host)],
                features={"targets": len(targets), "denied": denied, "src_ip": camp[0].src_ip}))
    return out


# ----------------------------------------------------------------------------- D10
D10 = Detector("D10", "Large transfer to a never-seen external destination", Stage.EXFILTRATION, RuleMeta(
    level="critical", tags=["attack.exfiltration", "attack.t1048"],
    falsepositives=["New SaaS / backup destination being onboarded", "Large software release upload"],
    references=["MITRE ATT&CK T1048 Exfiltration Over Alternative Protocol"]), run=lambda ctx: _d10(ctx))


def _d10(ctx: DetectCtx):
    b = ctx.b
    groups: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for e in _flows(ctx):
        if not is_internal(e.dst_ip) and (e.bytes_out or 0) > 0:
            groups[(e.host, e.dst_ip)].append(e)
    out = []
    for (host, dst), evs in sorted(groups.items()):
        bursts: list[list[Event]] = []
        for e in evs:
            if bursts and e.ts_utc - bursts[-1][-1].ts_utc <= EXFIL_GAP:
                bursts[-1].append(e)
            else:
                bursts.append([e])
        for burst in bursts:
            total = sum(e.bytes_out or 0 for e in burst)
            if total < EXFIL_MIN_BYTES:
                continue
            t0 = burst[0].ts_utc
            novel = b.novel(b.fs_host_dst, (host, dst), t0)
            if not novel:
                ctx.notes.append({"kind": "known_destination_transfer", "entity": f"host:{host}", "dst": dst, "t": t0, "bytes": total,
                                  "event_ids": [e.id for e in burst[:20]],
                                  "reason": f"{total / 1e9:.1f} GB to {dst}, a destination this host has used before (first seen {b.fs_host_dst.get((host, dst))})"})
                continue
            out.append(mk_signal(
                D10, f"{host}|{dst}|{t0.isoformat()}", burst, entities=[f"host:{host}", f"ip:{dst}"], severity=0.85, confidence=0.85,
                rarity=0.95, crit=ctx.crit(host),
                template="{host} sent {gb} GB to {dst} over {dur} in {n} transfers - a destination it had never contacted",
                params={"host": host, "gb": round(total / 1e9, 2), "dst": dst, "dur": fmt_dur((burst[-1].ts_utc - t0).total_seconds()), "n": len(burst)},
                requires=[P(PN.staged, t0, host=host), P(PN.has_access, t0, host=host), P(PN.privileged, t0, host=host)],
                produces=[P(PN.exfiltrated, t0, host=host, dst=dst)],
                features={"bytes": total, "dst": dst, "transfers": len(burst), "confirmed_impact": True}))
    return out


DETECTORS = [D07, D10]
