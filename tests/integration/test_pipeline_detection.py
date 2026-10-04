"""End-to-end detection against generated scenarios (hidden truth is used only for assertions)."""
from __future__ import annotations

import pytest

from backend.core.models import ScenarioParams, Stage
from backend.ingest import IngestContext, ingest_files
from backend.pipeline import analyze
from sim.generator import generate


def run(seed, **kw):
    sc = generate(seed, ScenarioParams(scale=kw.pop("scale", 0.3), **kw))
    res = ingest_files(list(sc.files.items()), IngestContext(case_id="t"))
    return sc, analyze(res)


@pytest.mark.parametrize("seed,template,kw", [
    (21, "T1", {}), (22, "T2", {}), (23, "T1", {"ip_rotation": 20, "stealth": 0.9}),
    (24, "T2", {"ip_rotation": 8, "stealth": 1.0}), (25, "T1", {"log_loss": 0.3}),
])
def test_attack_is_one_incident_with_the_intruder(seed, template, kw):
    sc, a = run(seed, template=template, **kw)
    tr = sc.truth
    assert len(a.corr.incidents) == 1, [i.title for i in a.corr.incidents]
    inc = a.corr.incidents[0]
    ents = set(inc.entities)
    assert f"user:{tr.compromised_users[0]}" in ents
    assert any(f"ip:{ip}" in ents for ip in tr.attacker_ips)
    assert {Stage.INITIAL_ACCESS, Stage.LATERAL_MOVEMENT, Stage.EXFILTRATION} <= set(inc.stages_covered)
    loud = next(d.entity for d in tr.decoys if d.kind == "loud_bruteforce")
    assert loud not in ents, "the loud decoy must not be pulled into the incident"


def test_clean_scenario_has_no_incident_and_decoys_are_explained():
    sc, a = run(26, template="T0")
    assert a.corr.incidents == []
    kinds = {n["kind"] for n in a.detect_ctx.notes}
    assert {"periodic_scanner", "known_destination_transfer"} <= kinds


def test_loud_bruteforce_is_watchlisted_not_incident():
    sc, a = run(27, template="T1", scale=1.0)
    loud = next(d.entity for d in sc.truth.decoys if d.kind == "loud_bruteforce")
    assert any(loud in w.entities for w in a.corr.watchlist)
    assert all(loud not in i.entities for i in a.corr.incidents)


def test_pipeline_is_order_invariant():
    sc = generate(28, ScenarioParams(scale=0.2))
    res = ingest_files(list(sc.files.items()), IngestContext(case_id="t"))
    a = analyze(res)
    res.events.reverse()
    b = analyze(res)
    assert [(i.id, sorted(i.signal_ids)) for i in a.corr.incidents] == [(i.id, sorted(i.signal_ids)) for i in b.corr.incidents]
    assert [s.id for s in a.signals] == [s.id for s in b.signals]
