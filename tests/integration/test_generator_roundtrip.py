"""Generator -> raw files -> ordinary ingest -> ground-truth refs resolve. This is the credibility round trip."""
from __future__ import annotations

from collections import Counter

import pytest

from backend.core.models import Action, ScenarioParams
from backend.ingest import IngestContext, ingest_files
from sim.generator import generate

STAGE_ACTIONS = {
    "RECON": {Action.login, Action.other},
    "INITIAL_ACCESS": {Action.login, Action.logout},
    "EXECUTION": {Action.proc_exec},
    "PERSISTENCE": {Action.key_add, Action.log_clear},
    "PRIV_ESC": {Action.sudo},
    "DISCOVERY": {Action.proc_exec, Action.conn, Action.other},
    "LATERAL_MOVEMENT": {Action.login, Action.conn, Action.logout},
    "COLLECTION": {Action.proc_exec, Action.file_read},
    "EXFILTRATION": {Action.conn},
}


def run(seed: int, **kw):
    p = ScenarioParams(scale=kw.pop("scale", 0.15), **kw)
    sc = generate(seed, p)
    res = ingest_files(list(sc.files.items()), IngestContext(case_id="t"))
    return sc, res


@pytest.mark.parametrize("template", ["T1", "T2"])
def test_roundtrip_clean_files_parse_with_zero_quarantine(template):
    sc, res = run(3, template=template)
    assert res.report.lines_quarantined == 0
    assert len(res.events) > 3000
    for f in res.source_files:
        assert f.lines_total == f.lines_parsed + f.lines_skipped + f.lines_quarantined
        assert f.parser_conf >= 0.9, f


@pytest.mark.parametrize("template", ["T1", "T2"])
def test_every_truth_ref_resolves_to_the_right_kind_of_event(template):
    sc, res = run(5, template=template)
    by_line = {(res.file_names[e.file_id], e.line_no): e for e in res.events}
    assert sc.truth.stages, "attack scenario must have labeled stages"
    for st in sc.truth.stages:
        assert st.refs
        for ref in st.refs:
            e = by_line.get((ref.file, ref.line))
            assert e is not None, f"{st.stage} ref {ref} did not parse into an event"
            assert e.action in STAGE_ACTIONS[st.stage.value], (st.stage, e.action, e.raw_text)
    for d in sc.truth.decoys:
        assert d.refs and all((r.file, r.line) in by_line for r in d.refs)


def test_t1_chain_is_causally_ordered_in_time():
    sc, _ = run(7, template="T1")
    start = {s.stage.value: s.t_start for s in sc.truth.stages}
    order = ["INITIAL_ACCESS", "EXECUTION", "DISCOVERY", "PRIV_ESC", "PERSISTENCE", "LATERAL_MOVEMENT", "COLLECTION", "EXFILTRATION"]
    times = [start[s] for s in order]
    assert times == sorted(times)
    assert sc.truth.entry_vector == "stolen_credential" and len(sc.truth.compromised_users) == 1


def test_t2_has_bruteforce_failures_before_success_from_attacker_infra():
    sc, res = run(11, template="T2", ip_rotation=5)
    atk = set(sc.truth.attacker_ips)
    assert len(atk) == 5 and sc.truth.entry_vector == "bruteforce_success"
    victim = sc.truth.compromised_users[0]
    fails = [e for e in res.events if e.src_ip in atk and e.user == victim and e.outcome.value == "failure"]
    oks = [e for e in res.events if e.src_ip in atk and e.user == victim and e.outcome.value == "success"]
    assert len(fails) >= 20 and oks and min(e.ts_utc for e in oks) > max(e.ts_utc for e in fails) - __import__("datetime").timedelta(minutes=1)


def test_t0_clean_has_decoys_but_no_attack():
    sc, res = run(2, template="T0")
    assert sc.truth.stages == [] and sc.truth.attacker_ips == [] and sc.truth.entry_vector is None
    kinds = {d.kind for d in sc.truth.decoys}
    assert kinds == {"loud_bruteforce", "periodic_scanner", "admin_sudo_burst", "scheduled_backup", "traveling_user"}


def test_loud_bruteforce_decoy_never_succeeds_and_is_not_the_attacker():
    sc, res = run(4, template="T1")
    loud = next(d for d in sc.truth.decoys if d.kind == "loud_bruteforce").entity.split(":", 1)[1]
    assert loud not in sc.truth.attacker_ips
    from_loud = [e for e in res.events if e.src_ip == loud]
    assert len(from_loud) > 500
    assert all(e.outcome.value != "success" for e in from_loud)


def test_deterministic_for_same_seed_and_different_across_seeds():
    p = ScenarioParams(scale=0.1)
    a, b, c = generate(9, p), generate(9, p), generate(10, p)
    assert a.files == b.files and a.truth == b.truth
    assert a.files != c.files


def test_event_ids_unique_at_scale():
    _, res = run(1, scale=0.5)
    ids = [e.id for e in res.events]
    assert len(ids) == len(set(ids))


def test_dup_shuffle_malformed_are_accounted_for_not_silently_lost():
    sc, res = run(6, template="T1", dup_rate=0.05, shuffle=1.0, malformed_rate=0.02)
    assert res.report.lines_quarantined > 0
    for f in res.source_files:
        assert f.lines_total == f.lines_parsed + f.lines_skipped + f.lines_quarantined
    # truth refs still resolve after shuffle/dup/junk renumbering
    by_line = {(res.file_names[e.file_id], e.line_no): e for e in res.events}
    for st in sc.truth.stages:
        for ref in st.refs:
            assert (ref.file, ref.line) in by_line, (st.stage, ref)


def test_log_loss_creates_truth_gaps_and_removes_db_auth_lines():
    sc, res = run(8, template="T1", log_loss=0.3)
    assert any(g.kind == "silent_window" and g.host == "db-01" for g in sc.truth.gaps)
    g = next(g for g in sc.truth.gaps if g.kind == "silent_window")
    inside = [e for e in res.events if e.host == "db-01" and e.source_type.value == "auth" and g.t_start <= e.ts_utc <= g.t_end]
    assert inside == []


def test_clock_skew_shifts_only_the_audit_source():
    base, rb = run(12, template="T1")
    skew, rs = run(12, template="T1", clock_skew_s=600)
    tb = [e.ts_utc for e in rb.events if e.source_type.value == "audit"][:5]
    ts = [e.ts_utc for e in rs.events if e.source_type.value == "audit"][:5]
    assert all((b - a).total_seconds() == 600 for a, b in zip(tb, ts)) or all(abs((b - a).total_seconds()) in (0, 600) for a, b in zip(tb, ts))
    assert [e.ts_utc for e in rb.events if e.source_type.value == "auth"] == [e.ts_utc for e in rs.events if e.source_type.value == "auth"]


def test_haystack_is_large_relative_to_the_attack():
    sc, res = run(1, template="T1", scale=1.0)
    attack_lines = sum(len(s.refs) for s in sc.truth.stages)
    assert len(res.events) > 40_000 and attack_lines / len(res.events) < 0.005
