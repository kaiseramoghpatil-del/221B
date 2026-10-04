"""Correlation semantics with hand-built signals: predicate links, no-bypass admission, weak anchors, gap bridges."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from backend.core.models import (EvidenceRef, IncidentStatus, LinkKind, PredicateInstance, PredicateName as PN, RuleMeta, Signal,
                                 Stage, WatchlistPriority)
from backend.correlate import correlate

T0 = datetime(2026, 9, 30, 3, 0, tzinfo=timezone.utc)
META = RuleMeta(level="high")


def P(name, minute, **args):
    return PredicateInstance(name=name, args=args, t=T0 + timedelta(minutes=minute))


def sig(sid, det, stage, minute, *, ents, sev=0.8, conf=0.8, rar=0.8, req=(), prod=(), **feat):
    t = T0 + timedelta(minutes=minute)
    return Signal(id=sid, detector=det, title=det, stage_hint=stage, entities=list(ents), t_start=t, t_end=t, severity=sev,
                  confidence=conf, rarity=rar, requires=list(req), produces=list(prod), rule_meta=META, features=dict(feat),
                  evidence=[EvidenceRef(event_id=f"E-{sid}")], explanation_template="x", explanation_params={})


ENDS = {"S0": T0 + timedelta(hours=2), "S1": T0 + timedelta(hours=2), "S9": T0 + timedelta(hours=2)}


def anchor(minute=0, session="S0", weak=False):
    return sig("A", "D04", Stage.INITIAL_ACCESS, minute, ents=["user:alice", "ip:198.18.9.9", "host:bastion-01"], sev=0.55,
               prod=[P(PN.has_access, minute, user="alice", host="bastion-01", session=session)], anchor=not weak, weak_anchor=weak)


def test_predicate_link_admits_two_stage_incident():
    priv = sig("B", "D06", Stage.PRIV_ESC, 10, ents=["user:alice", "host:bastion-01"],
               req=[P(PN.has_access, 10, user="alice", host="bastion-01", session="S0")],
               prod=[P(PN.privileged, 10, user="alice", host="bastion-01", session="S0")])
    c = correlate([anchor(), priv], ENDS)
    assert len(c.incidents) == 1 and not c.watchlist
    inc = c.incidents[0]
    assert inc.status is IncidentStatus.incident and set(inc.stages_covered) == {Stage.INITIAL_ACCESS, Stage.PRIV_ESC}
    link = next(l for l in c.links if l.signal_b == "B")
    assert link.kind is LinkKind.predicate and link.via.name is PN.has_access


def test_requirement_scoped_to_session_does_not_match_other_session():
    other = sig("B", "D06", Stage.PRIV_ESC, 10, ents=["user:alice", "host:bastion-01"],
                req=[P(PN.has_access, 10, user="alice", host="bastion-01", session="S9")])
    c = correlate([anchor(), other], ENDS)
    assert not c.incidents


def test_confirmed_impact_single_stage_is_high_priority_watchlist_not_incident():
    exfil = sig("X", "D10", Stage.EXFILTRATION, 30, ents=["host:db-01", "ip:203.0.113.5"], sev=0.85,
                req=[P(PN.staged, 30, host="db-01")], prod=[P(PN.exfiltrated, 30, host="db-01", dst="203.0.113.5")], confirmed_impact=True)
    c = correlate([exfil], ENDS)
    assert not c.incidents, "no bypass: a single stage is never an Incident"
    assert len(c.watchlist) == 1 and c.watchlist[0].watchlist_priority is WatchlistPriority.high


def test_consequences_do_not_propagate_without_prerequisites():
    """A routine hop whose source session is not attacker-held must not hand 'access' to the next signal."""
    hop = sig("H", "D08", Stage.LATERAL_MOVEMENT, 5, ents=["user:bob", "host:app-01"], sev=0.15,
              req=[P(PN.has_access, 5, user="bob", host="bastion-01", session="S9")],
              prod=[P(PN.has_access, 5, user="bob", host="app-01", session="S1")], informational=True)
    priv = sig("B", "D06", Stage.PRIV_ESC, 10, ents=["user:bob", "host:app-01"], sev=0.4,
               req=[P(PN.has_access, 10, user="bob", host="app-01", session="S1")])
    c = correlate([hop, priv], ENDS)
    assert not c.incidents


def test_weak_anchor_needs_a_strong_dependent_signal():
    weak_dep = sig("B", "D06", Stage.PRIV_ESC, 10, ents=["user:alice", "host:bastion-01"], sev=0.4, conf=0.8, rar=0.85,
                   req=[P(PN.has_access, 10, user="alice", host="bastion-01", session="S0")])
    assert not correlate([anchor(weak=True), weak_dep], ENDS).incidents
    strong_dep = sig("C", "D06", Stage.PRIV_ESC, 10, ents=["user:alice", "host:bastion-01"], sev=0.8,
                     req=[P(PN.has_access, 10, user="alice", host="bastion-01", session="S0")])
    c = correlate([anchor(weak=True), strong_dep], ENDS)
    assert len(c.incidents) == 1 and "A" in c.active_signals


def test_gap_bridge_attaches_but_never_counts_for_admission():
    """Anchor + a signal whose prerequisite is missing from the logs: bridged with a GAP, but only 1 predicate stage."""
    staged = sig("S", "D09", Stage.COLLECTION, 40, ents=["user:alice", "host:db-01"], sev=0.6,
                 req=[P(PN.has_access, 40, user="alice", host="db-01")], prod=[P(PN.staged, 40, host="db-01")])
    c = correlate([anchor(), staged], ENDS)
    assert not c.incidents and c.watchlist
    assert "S" in c.gaps_by_signal and c.gaps_by_signal["S"].missing_predicate.name is PN.has_access
    assert any(l.kind is LinkKind.soft and l.reason.startswith("inferred_via_gap") for l in c.links)


def test_gap_bridged_chain_joins_the_incident_with_a_recorded_gap():
    priv = sig("B", "D06", Stage.PRIV_ESC, 10, ents=["user:alice", "host:bastion-01"],
               req=[P(PN.has_access, 10, user="alice", host="bastion-01", session="S0")],
               prod=[P(PN.privileged, 10, user="alice", host="bastion-01", session="S0")])
    staged = sig("S", "D09", Stage.COLLECTION, 40, ents=["user:alice", "host:db-01"], sev=0.6,
                 req=[P(PN.has_access, 40, user="alice", host="db-01")], prod=[P(PN.staged, 40, host="db-01")])
    exfil = sig("X", "D10", Stage.EXFILTRATION, 50, ents=["host:db-01", "ip:203.0.113.5"], sev=0.85,
                req=[P(PN.staged, 50, host="db-01")], prod=[P(PN.exfiltrated, 50, host="db-01")], confirmed_impact=True)
    c = correlate([anchor(), priv, staged, exfil], ENDS)
    assert len(c.incidents) == 1
    inc = c.incidents[0]
    assert set(inc.signal_ids) == {"A", "B", "S", "X"} and len(inc.gaps) == 1
    assert any(l.signal_a == "S" and l.signal_b == "X" and l.kind is LinkKind.predicate for l in c.links)


def test_recon_linked_to_the_access_it_enabled():
    spray = sig("R", "D02", Stage.RECON, -60, ents=["ip:198.18.9.9"], sev=0.5, src_ips=["198.18.9.9"], valid_users_targeted=["bob"])
    c = correlate([spray, anchor()], ENDS)
    assert len(c.incidents) == 1 and set(c.incidents[0].signal_ids) == {"R", "A"}
