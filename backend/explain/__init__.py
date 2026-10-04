"""Explain: deterministic claims (each cites events), dismissals ("not flagged, and why"), caveats.

No LLM on this path. Every Claim carries >= 1 EvidenceRef that exists in the case (tested invariant).
"""
from __future__ import annotations

from collections import defaultdict

from backend.core.ids import short
from backend.core.models import (AttackStep, Claim, ClaimType, Dismissal, EvidenceRef, EvidenceRole, Incident, IncidentStatus,
                                 Signal, Stage)
from backend.correlate import Correlation, strength

CLAIM_TYPE = {
    Stage.INITIAL_ACCESS: ClaimType.ENTRY, Stage.PRIV_ESC: ClaimType.ESCALATION, Stage.LATERAL_MOVEMENT: ClaimType.PIVOT,
    Stage.COLLECTION: ClaimType.STAGING, Stage.EXFILTRATION: ClaimType.EXFIL,
}


def render(s: Signal) -> str:
    try:
        return s.explanation_template.format(**s.explanation_params)
    except (KeyError, IndexError, ValueError):
        return s.title


def step_claims(inc: Incident, steps: list[AttackStep], sigs: dict[str, Signal], gap_signal: dict[str, str]) -> list[Claim]:
    out = []
    for st in steps:
        group = [sigs[i] for i in st.signal_ids]
        lead = max(group, key=strength)
        text = render(lead)
        others = [s for s in group if s is not lead]
        if others:
            extra = "; ".join(dict.fromkeys(render(s) for s in others))
            text = f"{text}. Also: {extra}"
        ev: list[EvidenceRef] = []
        seen = set()
        for s in [lead, *others]:
            for r in s.evidence:
                if r.event_id not in seen and r.role is EvidenceRole.supports:
                    seen.add(r.event_id)
                    ev.append(r)
        out.append(Claim(id=short("C", st.id), incident_id=inc.id, type=CLAIM_TYPE.get(st.stage, ClaimType.ACTION), text=text,
                         facts={"stage": st.stage.value, "detectors": [s.detector for s in group], **lead.explanation_params},
                         evidence=ev[:24], confidence=round(sum(s.confidence for s in group) / len(group), 3), step_id=st.id))
    for g in inc.gaps:
        src = sigs[gap_signal[g.id]] if g.id in gap_signal else max((sigs[i] for i in inc.signal_ids), key=lambda s: s.t_start)
        anchor_ev = [EvidenceRef(event_id=r.event_id, role=EvidenceRole.context, note="the step whose prerequisite is missing")
                     for r in src.evidence[:3]]
        out.append(Claim(id=short("C", g.id), incident_id=inc.id, type=ClaimType.GAP, text=g.description, facts={"kind": g.kind},
                         evidence=anchor_ev, confidence=0.5))
    return out


def dismissals(corr: Correlation, sigs: dict[str, Signal], notes: list[dict], incident_entities: set[str]) -> list[Dismissal]:
    out: list[Dismissal] = []
    # 1) watchlist items: loud but inconsequential
    for w in corr.watchlist:
        lead = max((sigs[i] for i in w.signal_ids), key=strength)
        ent = next((e for e in lead.entities if e.startswith("ip:")), None) if lead.detector in ("D01", "D02") else \
            next((e for e in lead.entities if e.startswith("user:")), lead.entities[0] if lead.entities else w.id)
        if ent in incident_entities:
            continue
        reasons = [render(lead)]
        if lead.detector == "D01":
            n_ok = lead.features.get("successes_from_ip_after", 0)
            reasons.append(f"{n_ok} successful logins from this IP afterwards" if n_ok else "no successful login from this IP, before or after")
            reasons.append("nothing that happened later in the logs depends on it")
            would = "any successful login from this IP, or later activity by an account it targeted"
        elif w.watchlist_priority and w.watchlist_priority.value == "high":
            reasons.append("confirmed impact, but no second attack stage is connected to it - kept on the high-priority watchlist")
            would = "a correlated access or follow-on step (it would then become an incident)"
        else:
            reasons.append(w.watchlist_reason or "single-stage finding")
            would = "a correlated second attack stage"
        out.append(Dismissal(id=short("D", w.id), entity=ent, decision="watchlist", reasons=reasons,
                             counter_evidence=[EvidenceRef(event_id=r.event_id, role=EvidenceRole.contradicts) for r in lead.evidence[:6]],
                             would_flag_if=would))
    # 2) suppressed look-alikes recorded by detectors (periodic scanner, known backup destination)
    grouped: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for n in notes:
        if n["kind"] in ("periodic_scanner", "known_destination_transfer"):
            grouped[(n["kind"], n["entity"])].append(n)
    for (kind, ent), ns in sorted(grouped.items()):
        if kind == "periodic_scanner":
            reasons = [f"{ent.split(':', 1)[1]} swept {ns[0]['targets']}+ internal ports {len(ns)} more time(s) at the same time of day",
                       "the same sweep appears every night - a scheduled vulnerability scanner",
                       "no login, privilege change or data movement is connected to it"]
            would = "a sweep at an unusual time, from a different host, or followed by access to a scanned host"
        else:
            gb = sum(n["bytes"] for n in ns) / 1e9
            reasons = [f"{gb:.1f} GB sent to {ns[0]['dst']} across {len(ns)} transfer window(s)",
                       "the destination was already used by this host before - a recurring backup",
                       "no compromised account or session touched this host"]
            would = "a transfer to a destination this host has never used"
        ev = [EvidenceRef(event_id=eid, role=EvidenceRole.contradicts) for eid in ns[0]["event_ids"][:6]]
        out.append(Dismissal(id=short("D", kind, ent), entity=ent, decision="not_flagged", reasons=reasons, counter_evidence=ev,
                             would_flag_if=would))
    # 3) weak anchors never confirmed (new network during normal hours, nothing followed) - the most recent few
    weak_shown = 0
    for s in sorted(sigs.values(), key=lambda x: x.t_start, reverse=True):
        if weak_shown >= 3:
            break
        if s.detector == "D04" and s.features.get("weak_anchor") and s.id not in corr.active_signals:
            ent = next((e for e in s.entities if e.startswith("user:")), None)
            if not ent or ent in incident_entities:
                continue
            out.append(Dismissal(
                id=short("D", s.id), entity=ent, decision="not_flagged",
                reasons=[render(s), "it happened during this person's normal working hours",
                         "nothing privileged, persistent or data-moving happened in that session"],
                counter_evidence=[EvidenceRef(event_id=r.event_id, role=EvidenceRole.contradicts) for r in s.evidence[:3]],
                would_flag_if="root access, persistence or bulk data access inside that session"))
            weak_shown += 1
    return out


def caveats(inc: Incident, policy: str, ambiguous: dict[str, list[str]], sigs: dict[str, Signal]) -> list[Claim]:
    out = [Claim(id=short("C", inc.id, "baseline"), incident_id=inc.id, type=ClaimType.CAVEAT,
                 text=f"Baseline: {policy}. 'Never seen' means never seen earlier in these logs.", evidence=[
                     EvidenceRef(event_id=sigs[inc.signal_ids[0]].evidence[0].event_id, role=EvidenceRole.context)], confidence=1.0)]
    amb = [sid for sid in ambiguous if inc.t_start <= sigs[sid].t_start <= inc.t_end]
    for sid in amb[:3]:
        s = sigs[sid]
        out.append(Claim(id=short("C", inc.id, sid), incident_id=inc.id, type=ClaimType.CAVEAT,
                         text=f"Not attributed: {render(s)} - several accounts ({', '.join(ambiguous[sid])}) had access to that host at the time.",
                         evidence=[EvidenceRef(event_id=r.event_id, role=EvidenceRole.context) for r in s.evidence[:3]], confidence=0.5))
    return out
