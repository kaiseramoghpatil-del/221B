"""Reconstruct: incident -> ordered attack steps, scenario-template title, entry hypotheses, attack graph + replay.

Steps group consecutive signals of the same stage on the same target. Edges between steps carry the predicate
instances that justified them (from correlation), so every arrow in the UI can say *why* it exists.
"""
from __future__ import annotations

from collections import defaultdict

from backend.core.ids import short
from backend.core.models import (AttackGraph, AttackStep, Criticality, EntityRole, EntityType, GraphEdge, GraphNode,
                                 Hypothesis, Incident, LinkKind, ReplayFrame, Signal, Stage, STAGE_ORDER)
from backend.correlate import Correlation, strength
from backend.normalize import NormalizedCase, is_internal

# Declarative scenario templates (Fusion-style "A following B"): ordered stage requirements -> title.
TEMPLATES: list[tuple[str, str, list[Stage], set[str]]] = [
    ("spray_then_valid_login_exfil", "Password spray → valid-password login → lateral movement → data exfiltration",
     [Stage.RECON, Stage.INITIAL_ACCESS, Stage.LATERAL_MOVEMENT, Stage.EXFILTRATION], {"SPRAY_THEN_VALID"}),
    ("stolen_credential_exfil", "Stolen credential → lateral movement → data exfiltration",
     [Stage.INITIAL_ACCESS, Stage.LATERAL_MOVEMENT, Stage.EXFILTRATION], {"D04"}),
    ("bruteforce_exfil", "Password guessing → break-in → lateral movement → data exfiltration",
     [Stage.RECON, Stage.INITIAL_ACCESS, Stage.LATERAL_MOVEMENT, Stage.EXFILTRATION], {"D01", "D02", "D03"}),
    ("account_takeover_exfil", "Account takeover → data exfiltration", [Stage.INITIAL_ACCESS, Stage.EXFILTRATION], set()),
    ("account_takeover_lateral", "Account takeover → lateral movement", [Stage.INITIAL_ACCESS, Stage.LATERAL_MOVEMENT], set()),
    ("root_persistence", "Account takeover → root access → persistence", [Stage.INITIAL_ACCESS, Stage.PRIV_ESC, Stage.PERSISTENCE], set()),
]


def _primary_host(s: Signal) -> str | None:
    hosts = [e for e in s.entities if e.startswith("host:")]
    if s.detector == "D08" and s.features.get("src_host"):
        dst = [h for h in hosts if h != f"host:{s.features['src_host']}"]
        return dst[0] if dst else (hosts[0] if hosts else None)
    return hosts[0] if hosts else None


def _actor(s: Signal) -> str | None:
    if s.stage_hint in (Stage.RECON, Stage.EXFILTRATION):
        ext = [e for e in s.entities if e.startswith("ip:") and not is_internal(e[3:])]
        if ext:
            return ext[0]
    users = [e for e in s.entities if e.startswith("user:")]
    if users:
        return users[0]
    ext = [e for e in s.entities if e.startswith("ip:") and not is_internal(e[3:])]
    return ext[0] if ext else None


def match_template(signals: list[Signal]) -> tuple[str | None, str]:
    ordered = sorted(signals, key=lambda s: s.t_start)
    stages = [s.stage_hint for s in ordered]
    dets = {s.detector for s in ordered}
    entries = [s for s in ordered if s.stage_hint is Stage.INITIAL_ACCESS]
    if entries and all(int(s.features.get("failures_user", 0) or 0) < 5 for s in entries if s.detector == "D03")             and any(s.stage_hint is Stage.RECON for s in ordered):
        dets = dets | {"SPRAY_THEN_VALID"}  # the IP sprayed other accounts, then logged in to one it never guessed
    for sid, title, need, needs_det in TEMPLATES:
        it = iter(stages)
        if all(any(x == st for x in it) for st in need) and (not needs_det or needs_det & dets):
            if sid == "stolen_credential_exfil" and dets & {"D03"}:
                continue  # an explicit break-in after failures is the brute-force story, not a stolen credential
            return sid, title
    first = min(stages, key=lambda x: STAGE_ORDER[x])
    last = max(stages, key=lambda x: STAGE_ORDER[x])
    return None, f"Multi-stage intrusion ({first.value.replace('_', ' ').lower()} → {last.value.replace('_', ' ').lower()})"


def build_steps(inc: Incident, sigs: dict[str, Signal], corr: Correlation) -> list[AttackStep]:
    members = sorted((sigs[i] for i in inc.signal_ids), key=lambda s: (s.t_start, STAGE_ORDER[s.stage_hint]))
    groups: list[list[Signal]] = []
    for s in members:
        if groups and groups[-1][-1].stage_hint is s.stage_hint and _primary_host(groups[-1][-1]) == _primary_host(s) \
                and s.detector != "D08":
            groups[-1].append(s)
        else:
            groups.append([s])
    member_ids = set(inc.signal_ids)
    incoming = defaultdict(list)
    for l in corr.links:
        if l.signal_b in member_ids:
            incoming[l.signal_b].append(l)
    steps = []
    for i, g in enumerate(groups):
        ids = [s.id for s in g]
        evs = []
        for s in g:
            evs.extend(r.event_id for r in s.evidence if r.role.value == "supports")
        just = [l.via for s in g for l in incoming[s.id] if l.kind is LinkKind.predicate and l.via is not None and l.signal_a not in ids]
        inferred = any(l.kind is LinkKind.soft for s in g for l in incoming[s.id])
        steps.append(AttackStep(
            id=short("STEP", inc.id, str(i)), order=i + 1, stage=g[0].stage_hint, t_start=g[0].t_start, t_end=max(s.t_end for s in g),
            actor_entity=_actor(g[0]), target_entity=_primary_host(g[0]), signal_ids=ids, event_ids=list(dict.fromkeys(evs))[:60],
            edge_justification=just[:6], inferred=inferred, summary_count=sum(int(s.features.get("evidence_total", 1)) for s in g)))
    return steps


def entry_hypotheses(inc: Incident, sigs: dict[str, Signal], corr: Correlation) -> list[Hypothesis]:
    entries = [sigs[i] for i in inc.signal_ids if sigs[i].stage_hint is Stage.INITIAL_ACCESS]
    if not entries:
        return []
    out_deg = defaultdict(int)
    for l in corr.links:
        if l.kind is LinkKind.predicate:
            out_deg[l.signal_a] += 1
    by_login: dict[str, list[Signal]] = defaultdict(list)
    for s in entries:
        by_login[s.features.get("login_event") or s.id].append(s)
    raw = []
    for key, group in by_login.items():
        lead = max(group, key=strength)
        weight = sum(strength(s) for s in group) * (1 + sum(out_deg[s.id] for s in group))
        p = lead.explanation_params
        dets = {s.detector for s in group}
        lead_fu = max(int(s.features.get("failures_user", 0) or 0) for s in group)
        how = ("a valid password, from an IP that had been spraying other accounts" if "D03" in dets and lead_fu < 5 else
               "password guessing against this account that succeeded" if "D03" in dets else
               "a valid password used from a network never seen for this account")
        raw.append((weight, Hypothesis(id=short("H", inc.id, key), description=f"{p.get('user')} entered {p.get('host')} from {p.get('ip')} via {how}",
                                       signal_ids=[s.id for s in group], probability=0.0)))
    total = sum(w for w, _ in raw) or 1.0
    hyps = sorted(((w / total, h) for w, h in raw), key=lambda x: -x[0])
    return [h.model_copy(update={"probability": round(p, 3)}) for p, h in hyps[:3]]


def roles(inc: Incident, sigs: dict[str, Signal], steps: list[AttackStep]) -> dict[str, EntityRole]:
    r: dict[str, EntityRole] = {}
    for s in (sigs[i] for i in inc.signal_ids):
        for e in s.entities:
            if e.startswith("ip:") and not is_internal(e[3:]):
                r[e] = EntityRole.attacker_infra
            elif e.startswith("user:") and s.stage_hint in (Stage.INITIAL_ACCESS, Stage.PRIV_ESC, Stage.LATERAL_MOVEMENT):
                r[e] = EntityRole.compromised_account
    for st in steps:
        if st.stage in (Stage.LATERAL_MOVEMENT,) and st.target_entity:
            r.setdefault(st.target_entity, EntityRole.pivot_host)
        if st.stage in (Stage.COLLECTION, Stage.EXFILTRATION) and st.target_entity:
            r[st.target_entity] = EntityRole.victim_host
        if st.stage is Stage.INITIAL_ACCESS and st.target_entity:
            r.setdefault(st.target_entity, EntityRole.pivot_host)
    return r


_EDGE_LABEL = {
    Stage.RECON: "guessed passwords", Stage.INITIAL_ACCESS: "logged in", Stage.EXECUTION: "ran recon commands",
    Stage.PRIV_ESC: "became root", Stage.PERSISTENCE: "planted persistence", Stage.DISCOVERY: "scanned the network",
    Stage.LATERAL_MOVEMENT: "hopped", Stage.COLLECTION: "staged data", Stage.EXFILTRATION: "sent data out",
}


def build_graph(inc: Incident, sigs: dict[str, Signal], steps: list[AttackStep], nc: NormalizedCase,
                role_map: dict[str, EntityRole]) -> AttackGraph:
    nodes: dict[str, GraphNode] = {}
    edges: list[GraphEdge] = []
    frames: list[ReplayFrame] = []

    def node(eid: str, stage: Stage, t) -> str:
        if eid not in nodes:
            etype = EntityType(eid.split(":", 1)[0]) if eid.split(":", 1)[0] in ("user", "ip", "host") else EntityType.host
            ent = nc.entities.get(eid)
            nodes[eid] = GraphNode(id=eid, type=etype, label=eid.split(":", 1)[1], role=role_map.get(eid, EntityRole.unknown), stage=stage,
                                   first_seen=t, criticality=ent.criticality if ent else Criticality.med)
            return eid
        return ""

    for st in steps:
        lead = max((sigs[i] for i in st.signal_ids), key=strength)
        added_nodes: list[str] = []
        new_edges: list[str] = []
        ext_ips = sorted({e for i in st.signal_ids for e in sigs[i].entities if e.startswith("ip:") and not is_internal(e[3:])})
        host = st.target_entity
        src, dst, label = None, None, _EDGE_LABEL[st.stage]
        if st.stage in (Stage.RECON, Stage.INITIAL_ACCESS):
            src = ext_ips[0] if ext_ips else st.actor_entity
            dst = host or (f"host:{lead.explanation_params.get('host')}" if lead.explanation_params.get("host") else None)
            if st.stage is Stage.RECON:
                label = f"{lead.features.get('failures') or lead.features.get('attempts') or st.summary_count} failed logins"
            else:
                label = f"logged in as {(st.actor_entity or '').split(':', 1)[-1]}" if st.actor_entity and st.actor_entity.startswith("user:") else "logged in"
                user = next((e for i in st.signal_ids for e in sigs[i].entities if e.startswith("user:")), None)
                if user:
                    added_nodes.append(node(user, st.stage, st.t_start))
        elif st.stage is Stage.LATERAL_MOVEMENT:
            src = f"host:{lead.features['src_host']}" if lead.features.get("src_host") else None
            dst = host
            label = f"ssh as {(st.actor_entity or '').split(':', 1)[-1]}"
        elif st.stage is Stage.EXFILTRATION:
            src = host
            dst = next((e for e in ext_ips), None)
            gb = lead.explanation_params.get("gb")
            label = f"{gb} GB out" if gb is not None else label
        else:
            src = st.actor_entity if st.actor_entity and st.actor_entity.startswith("user:") else None
            dst = host
        for eid in (src, dst):
            if eid:
                added_nodes.append(node(eid, st.stage, st.t_start))
        if src and dst and src != dst:
            eid = short("EDGE", st.id)
            edges.append(GraphEdge(id=eid, source=src, target=dst, label=label, t_start=st.t_start, t_end=st.t_end,
                                   count=max(1, st.summary_count or 1), inferred=st.inferred,
                                   predicate=st.edge_justification[0].name.value if st.edge_justification else None,
                                   event_ids=st.event_ids[:20]))
            new_edges.append(eid)
        frames.append(ReplayFrame(t=st.t_start, nodes_added=[n for n in added_nodes if n], edges_added=new_edges, active_stage=st.stage))
    return AttackGraph(incident_id=inc.id, nodes=list(nodes.values()), edges=edges, frames=frames)


def reconstruct(inc: Incident, sigs: dict[str, Signal], corr: Correlation, nc: NormalizedCase):
    steps = build_steps(inc, sigs, corr)
    scenario_id, title = match_template([sigs[i] for i in inc.signal_ids])
    hyps = entry_hypotheses(inc, sigs, corr)
    role_map = roles(inc, sigs, steps)
    inc2 = inc.model_copy(update={"steps": steps, "title": title if inc.status.value == "incident" else inc.title,
                                  "scenario_id": scenario_id if inc.status.value == "incident" else None, "entry_hypotheses": hyps})
    graph = build_graph(inc2, sigs, steps, nc, role_map)
    return inc2, graph, role_map
