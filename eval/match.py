"""Reveal: compare 221B's verdict with the hidden ground truth, plus two baselines on the same signals.

B0 naive   - every detector hit is its own alert (what a per-rule SIEM shows)
B1 time    - alerts grouped purely by time proximity (gap <= 30 min), no entity/predicate reasoning
B2 221B    - predicate-correlated incidents
"""
from __future__ import annotations

from datetime import timedelta

from backend.core.ids import event_id
from backend.core.models import EntityRole, GroundTruth, MatchResult, Scorecard, STAGE_ORDER
from backend.pipeline import Analysis
from backend.views import CaseViews

B1_GAP = timedelta(minutes=30)


def truth_event_ids(truth: GroundTruth, a: Analysis) -> tuple[set[str], dict[str, set[str]]]:
    fid_by_name = {name: fid for fid, name in a.ingest.file_names.items()}
    all_ids: set[str] = set()
    by_stage: dict[str, set[str]] = {}
    for st in truth.stages:
        ids = {event_id(fid_by_name[r.file], r.line) for r in st.refs if r.file in fid_by_name}
        by_stage[st.stage.value] = ids
        all_ids |= ids
    return all_ids, by_stage


def _match(kind: str, truth: set[str], pred: set[str]) -> MatchResult:
    return MatchResult(kind=kind, truth=sorted(truth), predicted=sorted(pred), hits=sorted(truth & pred), misses=sorted(truth - pred),
                       false_positives=sorted(pred - truth))


def _kendall(pred_order: list[str], true_order: list[str]) -> float | None:
    common = [s for s in true_order if s in pred_order]
    if len(common) < 2:
        return None
    pos = {s: pred_order.index(s) for s in common}
    conc = disc = 0
    for i in range(len(common)):
        for j in range(i + 1, len(common)):
            if pos[common[i]] < pos[common[j]]:
                conc += 1
            else:
                disc += 1
    tau = (conc - disc) / (conc + disc)
    return round((tau + 1) / 2, 3)


def reveal(truth: GroundTruth, a: Analysis, v: CaseViews) -> tuple[list[MatchResult], Scorecard]:
    attack_ids, by_stage = truth_event_ids(truth, a)
    sigs = a.signal_by_id
    ev_by_id = a.nc.by_id

    entry_ips = {ev_by_id[e].src_ip for e in by_stage.get("INITIAL_ACCESS", set()) if e in ev_by_id and ev_by_id[e].src_ip
                 and ev_by_id[e].action.value == "login" and ev_by_id[e].outcome.value == "success"}
    top = v.incidents[0] if v.incidents else None
    roles = {s.entity.id: s.role for s in v.suspects if top and s.entity.id in top.entities}
    pred_ips = {e[3:] for e, r in roles.items() if r is EntityRole.attacker_infra}
    pred_users = {e[5:] for e, r in roles.items() if r is EntityRole.compromised_account}
    pred_victims = {e[5:] for e, r in roles.items() if r is EntityRole.victim_host}

    matches = [
        _match("entry_ip", entry_ips, pred_ips & entry_ips if pred_ips & entry_ips else pred_ips),
        _match("attacker_infrastructure", set(truth.attacker_ips) | set(truth.exfil_dst_ips), pred_ips),
        _match("compromised_account", set(truth.compromised_users), pred_users),
        _match("data_stolen_from", set(truth.victim_hosts), pred_victims),
    ]
    true_entities = {f"ip:{x}" for x in truth.attacker_ips + truth.exfil_dst_ips} | {f"user:{u}" for u in truth.compromised_users}
    false_suspects = [e for e, r in roles.items() if r in (EntityRole.attacker_infra, EntityRole.compromised_account) and e not in true_entities]

    def attack_signal(sid: str) -> bool:
        return any(r.event_id in attack_ids for r in sigs[sid].evidence)

    purity = None
    stage_recall_221b = None
    order_acc = None
    if top:
        purity = round(sum(attack_signal(i) for i in top.signal_ids) / len(top.signal_ids), 3)
        true_stages = [s.stage.value for s in sorted(truth.stages, key=lambda s: s.t_start)]
        pred_stages = list(dict.fromkeys(st.stage.value for st in top.steps))
        stage_recall_221b = round(len(set(true_stages) & set(pred_stages)) / max(1, len(true_stages)), 3)
        order_acc = _kendall(pred_stages, true_stages)
    gap_recall = None
    if truth.gaps:
        flagged_hosts = {g.host for i in v.incidents for g in i.gaps if g.host}
        gap_recall = round(sum(1 for g in truth.gaps if g.host in flagged_hosts) / len(truth.gaps), 3)

    # ---- baselines on the same detector output
    naive = [n for n in v.naive]
    naive_attack = sum(1 for n in naive if attack_signal(n.signal_id))
    b0 = {"alerts": len(naive), "alerts_on_attack": naive_attack, "precision": round(naive_attack / max(1, len(naive)), 3)}
    ordered = sorted((sigs[n.signal_id] for n in naive), key=lambda s: s.t_start)
    groups: list[list] = []
    for s in ordered:
        if groups and s.t_start - groups[-1][-1].t_end <= B1_GAP:
            groups[-1].append(s)
        else:
            groups.append([s])
    true_stage_set = {s.stage.value for s in truth.stages}
    best = max(groups, key=lambda g: sum(attack_signal(x.id) for x in g), default=[])
    b1 = {"groups": len(groups),
          "best_group_purity": round(sum(attack_signal(x.id) for x in best) / max(1, len(best)), 3) if best else 0.0,
          "best_group_stage_recall": round(len({x.stage_hint.value for x in best if attack_signal(x.id)} & true_stage_set) / max(1, len(true_stage_set)), 3) if best else 0.0}
    b2 = {"incidents": len(v.incidents), "purity": purity or 0.0, "stage_recall": stage_recall_221b or 0.0}

    card = Scorecard(
        attacker_ip_recall=round(len(matches[0].hits) / max(1, len(matches[0].truth)), 3) if matches[0].truth else None,
        compromised_user_recall=round(len(matches[2].hits) / max(1, len(matches[2].truth)), 3) if matches[2].truth else None,
        false_suspect_count=len(false_suspects), stage_order_accuracy=order_acc, cluster_purity=purity,
        alert_compression=round(len(a.signals) / max(1, len(v.incidents)), 1) if v.incidents else None, gap_recall=gap_recall,
        runtime_ms=sum(a.timings_ms.values()),
        baselines={"B0_naive_alerts": b0, "B1_time_window": b1, "B2_221B": b2})
    return matches, card
