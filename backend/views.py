"""Case views: everything the UI reads, precomputed once per analysis (all contract models)."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from backend.core.models import (AttackGraph, Dismissal, Entity, EntityRole, EntityType, Funnel, Incident, IncidentDetail, LinkKind,
                                 NaiveAlert, ScoreBreakdown, ScoreItem, Suspect)
from backend.correlate import strength
from backend.explain import caveats, dismissals, step_claims
from backend.pipeline import Analysis
from backend.reconstruct import reconstruct

ROLE_ORDER = [EntityRole.attacker_infra, EntityRole.compromised_account, EntityRole.pivot_host, EntityRole.victim_host,
              EntityRole.noisy_benign, EntityRole.unknown]
NAIVE_MIN_SEVERITY = 0.3


@dataclass
class CaseViews:
    funnel: Funnel
    incidents: list[Incident]
    watchlist: list[Incident]
    details: dict[str, IncidentDetail]
    graphs: dict[str, AttackGraph]
    suspects: list[Suspect]
    dismissals: list[Dismissal]
    naive: list[NaiveAlert]
    signals_by_event: dict[str, list[str]] = field(default_factory=dict)


def _breakdown(inc: Incident, a: Analysis) -> ScoreBreakdown:
    sigs = a.signal_by_id
    kap = a.corr.kappas.get(inc.id, {})
    items = sorted((ScoreItem(signal_id=i, strength=round(strength(sigs[i]), 4), consequence_factor=kap.get(i, 1.0),
                              contribution=round(strength(sigs[i]) * kap.get(i, 1.0), 4)) for i in inc.signal_ids),
                   key=lambda x: -x.contribution)
    ids = set(inc.signal_ids)
    mine = [l for l in a.corr.links if l.signal_b in ids]
    pred = sum(1 for l in mine if l.kind is LinkKind.predicate)
    n_stages = len(set(inc.stages_covered))
    return ScoreBreakdown(
        incident_id=inc.id, items=items, bonuses={"stage_progression": round(0.03 * max(0, n_stages - 2), 3)} if inc.status.value == "incident" else {},
        final=inc.score, confidence=inc.confidence,
        confidence_parts={"links_backed_by_predicates": round(pred / max(1, len(mine)), 3),
                          "mean_detector_confidence": round(sum(sigs[i].confidence for i in ids) / len(ids), 3),
                          "logging_gaps": len(inc.gaps)})


def _entity(a: Analysis, eid: str) -> Entity:
    ent = a.nc.entities.get(eid)
    if ent:
        return ent
    kind = eid.split(":", 1)[0]
    return Entity(id=eid, type=EntityType(kind) if kind in ("user", "ip", "host") else EntityType.host)


def build_views(a: Analysis) -> CaseViews:
    sigs = a.signal_by_id
    incidents, details, graphs, role_maps = [], {}, {}, {}
    gap_signal = {g.id: sid for sid, g in a.corr.gaps_by_signal.items()}
    for inc in a.corr.incidents:
        inc2, graph, role_map = reconstruct(inc, sigs, a.corr, a.nc)
        incidents.append(inc2)
        graphs[inc2.id] = graph
        role_maps[inc2.id] = role_map
    watch = []
    for w in a.corr.watchlist:
        w2, graph, _ = reconstruct(w, sigs, a.corr, a.nc)
        watch.append(w2)
        graphs[w2.id] = graph
    incident_entities = {e for i in incidents for e in i.entities if not e.startswith("host:")}
    dism = dismissals(a.corr, sigs, a.detect_ctx.notes, incident_entities)

    for inc in incidents + watch:
        member = set(inc.signal_ids)
        claims = step_claims(inc, inc.steps, sigs, gap_signal)
        if inc.status.value == "incident":
            claims += caveats(inc, a.baselines.policy, a.corr.ambiguous, sigs)
        details[inc.id] = IncidentDetail(
            incident=inc, claims=claims, score_breakdown=_breakdown(inc, a),
            dismissals=dism if inc.status.value == "incident" else [],
            signals=[sigs[i] for i in inc.signal_ids],
            links=[l for l in a.corr.links if l.signal_b in member or l.signal_a in member])

    # ---- suspects: entity risk ledger (chain score first, cumulative raw risk as the second lens)
    by_entity: dict[str, list] = defaultdict(list)
    for s in a.signals:
        for e in s.entities:
            by_entity[e].append(s)
    suspects: list[Suspect] = []
    seen = set()
    for inc in incidents:
        for eid, role in sorted(role_maps[inc.id].items(), key=lambda kv: (ROLE_ORDER.index(kv[1]), kv[0])):
            if eid in seen:
                continue
            seen.add(eid)
            in_inc = [sigs[i] for i in inc.signal_ids if eid in sigs[i].entities]
            suspects.append(_suspect(a, eid, role, inc.score, by_entity[eid], in_inc))
    for w in watch[:6]:
        lead = max((sigs[i] for i in w.signal_ids), key=strength)
        eid = next((e for e in lead.entities if e.startswith(("ip:", "user:"))), None)
        if not eid or eid in seen:
            continue
        seen.add(eid)
        role = EntityRole.noisy_benign if lead.detector in ("D01", "D02") else EntityRole.unknown
        suspects.append(_suspect(a, eid, role, w.score, by_entity[eid], [sigs[i] for i in w.signal_ids]))

    naive = sorted((NaiveAlert(signal_id=s.id, detector=s.detector, title=s.title,
                               entity=next((e for e in s.entities if not e.startswith("host:")), s.entities[0] if s.entities else ""),
                               t=s.t_start, severity=round(s.severity, 3))
                    for s in a.signals if s.severity >= NAIVE_MIN_SEVERITY), key=lambda n: (-n.severity, n.t))
    linked = {l.signal_a for l in a.corr.links} | {l.signal_b for l in a.corr.links}
    funnel = Funnel(events=len(a.nc.events), signals=len(a.signals), linked_signals=len(linked), incidents=len(incidents),
                    watchlist=len(watch))
    sbe: dict[str, list[str]] = defaultdict(list)
    for s in a.signals:
        for r in s.evidence:
            sbe[r.event_id].append(s.id)
    return CaseViews(funnel=funnel, incidents=incidents, watchlist=watch, details=details, graphs=graphs, suspects=suspects,
                     dismissals=dism, naive=naive, signals_by_event=dict(sbe))


def _suspect(a: Analysis, eid: str, role: EntityRole, chain_score: float, all_sigs: list, in_inc: list) -> Suspect:
    cum = 0.0
    ledger = []
    for s in sorted(all_sigs, key=lambda s: s.t_start)[:60]:
        cum += strength(s)
        ledger.append((s.t_start, round(cum, 3)))
    return Suspect(entity=_entity(a, eid), role=role, chain_score=chain_score, risk_ledger=ledger,
                   distinct_stages=len({s.stage_hint for s in in_inc}), signal_ids=[s.id for s in in_inc])
