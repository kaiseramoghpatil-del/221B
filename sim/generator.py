"""Scenario generator: (seed, params) -> raw log files (bytes) + hidden ground truth.

Pipeline: build records -> apply log loss -> sort -> render to raw text -> duplicates / shuffle / malformed
junk -> final numbering -> ground-truth refs expressed as (file, line). Deterministic for a given seed+params.
"""
from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import datetime, timedelta

from backend.core.models import (GroundTruth, ScenarioParams, Stage, TruthDecoy, TruthGap, TruthRef,
                                 TruthStage)

from . import attack, benign, decoys
from .context import Ctx
from .records import FILE_NAMES, FLOWS_HEADER, Rec, render
from .topology import IpPool, build_topology

GENERATOR_VERSION = "1"


@dataclass
class Scenario:
    seed: int
    params: ScenarioParams
    files: dict[str, bytes]  # file name -> content
    truth: GroundTruth


def _junk(rng: random.Random, line: str) -> str:
    r = rng.random()
    if r < 0.5 and len(line) > 12:
        return line[: rng.randint(5, len(line) - 3)]  # truncated write
    if r < 0.8:
        return "".join(rng.choice("\x01\x02 ?#@!%^&*()_+{}|<>~`") for _ in range(rng.randint(8, 40)))
    return "kernel: [ 1234.56789] ??? corrupted entry"


def generate(seed: int, params: ScenarioParams | None = None) -> Scenario:
    params = params or ScenarioParams()
    rng = random.Random(seed * 1_000_003 + 17)
    pool = IpPool(rng)
    cap = None if params.scale >= 1.0 else max(8, int(30 * params.scale / 1.0))
    topo = build_topology(rng, pool, n_users_cap=cap)
    c = Ctx(rng=rng, pool=pool, topo=topo, params=params)

    decoy_info: dict[str, str] = {}
    if params.with_decoys:
        decoy_info = decoys.add_all(c)
    exclude = tuple(v for k, v in decoy_info.items() if k in ("traveling_user", "admin_sudo_burst"))
    benign.add_user_sessions(c)
    benign.add_web(c)
    benign.add_internet_ssh_noise(c)
    benign.add_service_flows(c)

    info = None
    if params.template in ("T1", "T2"):
        info = attack.build(c, params.template, exclude)

    recs = c.recs
    truth_gaps: list[TruthGap] = []

    # ---- log loss --------------------------------------------------------------------
    if info and params.log_loss > 0:
        p = params.log_loss
        kept: list[Rec] = []
        dropped_by_host: dict[str, list[Rec]] = {}
        win_lo = info.t_db_login - timedelta(minutes=5)
        win_hi = info.t_db_login + timedelta(minutes=30)
        silent = p >= 0.1
        for r in recs:
            drop = False
            if silent and r.file == "auth" and r.host == "db-01" and win_lo <= r.t <= win_hi:
                drop = True  # the whole db-01 auth log goes silent around the lateral login
            elif (r.label or "").startswith("attack:") and r.host in ("db-01", "app-01") and r.kind in ("ssh_ok", "exec", "sudo", "ssh_close") \
                    and not (r.label or "").endswith("INITIAL_ACCESS"):
                drop = rng.random() < p / 2
            if drop:
                dropped_by_host.setdefault(r.host, []).append(r)
            else:
                kept.append(r)
        recs = kept
        for host, lst in sorted(dropped_by_host.items()):
            truth_gaps.append(TruthGap(kind="silent_window" if (silent and host == "db-01") else "dropped_events", host=host,
                                       source="auth" if any(r.file == "auth" for r in lst) else "audit",
                                       t_start=min(r.t for r in lst), t_end=max(r.t for r in lst), n_dropped=len(lst)))

    # ---- order + render --------------------------------------------------------------
    order = sorted(range(len(recs)), key=lambda i: (recs[i].t, i))
    skew = timedelta(seconds=params.clock_skew_s)
    jitter_w = 20.0 * params.shuffle
    by_file: dict[str, list[tuple[float, str, int]]] = {k: [] for k in FILE_NAMES}
    for i in order:
        r = recs[i]
        text = render(r, skew if r.file == "audit" else timedelta(0))
        key = (r.t + (skew if r.file == "audit" else timedelta(0))).timestamp()
        if jitter_w:
            key += rng.uniform(-jitter_w, jitter_w)
        by_file[r.file].append((key, text, i))

    files: dict[str, bytes] = {}
    ref_of: dict[int, TruthRef] = {}
    line_counts: dict[str, int] = {}
    n_rendered = 0
    for fkey, rows in by_file.items():
        if not rows:
            continue
        if jitter_w:
            rows.sort(key=lambda x: x[0])
        name = FILE_NAMES[fkey]
        out: list[tuple[str, int | None]] = []
        if fkey == "flows":
            out.append((FLOWS_HEADER, None))
        for _, text, idx in rows:
            out.append((text, idx))
            n_rendered += 1
            if params.dup_rate and rng.random() < params.dup_rate:
                out.append((text, None))
            if params.malformed_rate and rng.random() < params.malformed_rate:
                out.append((_junk(rng, text), None))
        for ln, (_, idx) in enumerate(out, 1):
            if idx is not None and idx not in ref_of:
                ref_of[idx] = TruthRef(file=name, line=ln)
        files[name] = ("\n".join(t for t, _ in out) + "\n").encode("utf-8")
        line_counts[name] = len(out)

    # ---- ground truth ----------------------------------------------------------------
    stage_recs: dict[str, list[int]] = {}
    decoy_recs: dict[tuple[str, str], list[int]] = {}
    for i, r in enumerate(recs):
        lab = r.label or ""
        if lab.startswith("attack:"):
            stage_recs.setdefault(lab.split(":", 1)[1], []).append(i)
        elif lab.startswith("decoy:"):
            decoy_recs.setdefault((lab.split(":", 1)[1], r.entity or ""), []).append(i)

    stages: list[TruthStage] = []
    for st in Stage:
        idxs = stage_recs.get(st.value)
        if not idxs:
            continue
        ts = [recs[i].t for i in idxs]
        hosts = sorted({recs[i].host for i in idxs})
        stages.append(TruthStage(
            stage=st, t_start=min(ts), t_end=max(ts), host=hosts[0] if len(hosts) == 1 else ",".join(hosts),
            actor_user=info.victim_user if info else None, refs=[ref_of[i] for i in idxs if i in ref_of]))
    tds = [TruthDecoy(entity=ent, kind=kind, refs=[ref_of[i] for i in idxs if i in ref_of])
           for (kind, ent), idxs in sorted(decoy_recs.items())]

    all_t = [r.t for r in recs]
    truth = GroundTruth(
        scenario_id=f"scn-{seed}-{params.template}", seed=seed, template=params.template, params=params,
        entry_vector=info.entry_vector if info else None,
        attacker_ips=list(info.attacker_ips) if info else [],
        exfil_dst_ips=[info.exfil_dst] if info else [],
        compromised_users=[info.victim_user] if info else [],
        victim_hosts=list(info.victim_hosts) if info else [],
        pivot_hosts=list(info.pivot_hosts) if info else [],
        stages=stages, decoys=tds, gaps=truth_gaps, files=line_counts, n_events_rendered=n_rendered,
        t_start=min(all_t), t_end=max(all_t),
    )
    return Scenario(seed=seed, params=params, files=files, truth=truth)
