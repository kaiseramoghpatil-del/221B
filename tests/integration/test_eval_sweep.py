"""The benchmark harness itself: deterministic scenario choice, per-run scoring, aggregation into the contract."""
from __future__ import annotations

from backend.core.models import EvalReport
from eval.sweep import aggregate, run_one, scenario_for


def test_scenario_choice_is_deterministic_and_tiered():
    assert scenario_for(5, 0.2) == scenario_for(5, 0.2)
    tiers = {scenario_for(s, 0.2)[0] for s in range(1, 60)}
    templates = {scenario_for(s, 0.2)[1]["template"] for s in range(1, 60)}
    assert tiers == {"easy", "medium", "hard"} and templates == {"T0", "T1", "T2"}
    hard = next(p for s in range(1, 200) for t, p in [scenario_for(s, 0.2)] if t == "hard")
    assert hard["ip_rotation"] >= 10 and hard["log_loss"] >= 0.1


def test_run_one_scores_attack_and_clean_and_aggregates_into_contract():
    attack_seed = next(s for s in range(1, 200) if scenario_for(s, 0.2)[1]["template"] != "T0")
    clean_seed = next(s for s in range(1, 200) if scenario_for(s, 0.2)[1]["template"] == "T0")
    rows = [run_one((attack_seed, 0.2)), run_one((clean_seed, 0.2))]
    atk, clean = rows
    assert atk["clean"] is False and atk["detected"] is True and atk["account_ok"] is True
    assert clean["clean"] is True and clean["false_incidents"] == 0
    agg = aggregate(rows)
    report = EvalReport.model_validate({"generated_at": "2026-10-04T00:00:00+00:00", "pipeline_version": "t", "n_scenarios": 2,
                                        "seeds": [attack_seed, clean_seed], **agg, "misses": []})
    b2 = report.metrics["B2_221B"]
    assert b2["detection_rate"] == 1.0 and b2["clean_runs_with_false_incident"] == 0.0
    assert report.metrics["B0_naive_alerts"]["units_to_review_per_run"] > b2["units_to_review_per_run"]
