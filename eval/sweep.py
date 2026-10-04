"""Benchmark sweep: run 221B on many generated scenarios and compare with two baselines on the same detector output.

    python -m eval.sweep --seeds 1..300 --scale 0.35 --workers 8

Each seed deterministically picks a template (T0 clean 20%, T1 stolen credential 40%, T2 brute force 40%) and a
difficulty tier:
  easy    stealth 0-0.3, one attacker IP, clean logs
  medium  stealth 0.3-0.7, 1-3 IPs, some duplicates / shuffled lines
  hard    stealth 0.7-1, 10-40 rotating IPs, 10-30% log loss, clock skew, malformed lines

Writes docs/benchmark.json (contract EvalReport, served at /api/eval/latest) and docs/benchmark.md.
Honesty note: the detectors were developed against this generator. Results show internal consistency and robustness
to the difficulty knobs, not real-world accuracy.
"""
from __future__ import annotations

import argparse
import json
import random
import statistics
import time
from concurrent.futures import ProcessPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT_JSON = ROOT / "docs" / "benchmark.json"
OUT_MD = ROOT / "docs" / "benchmark.md"


def scenario_for(seed: int, scale: float, templates: tuple[str, ...] | None = None) -> tuple[str, dict]:
    rng = random.Random(seed * 7919 + 3)
    template = rng.choices(["T0", "T1", "T2"], weights=[2, 4, 4])[0]
    if templates:
        template = templates[seed % len(templates)]
    tier = rng.choice(["easy", "medium", "hard"])
    p: dict = {"template": template, "scale": scale, "noise": round(rng.uniform(0.6, 2.0), 2)}
    if tier == "easy":
        p.update(stealth=round(rng.uniform(0.0, 0.3), 2), ip_rotation=1)
    elif tier == "medium":
        p.update(stealth=round(rng.uniform(0.3, 0.7), 2), ip_rotation=rng.choice([1, 2, 3]),
                 dup_rate=rng.choice([0.0, 0.03]), shuffle=rng.choice([0.0, 0.5]))
    else:
        p.update(stealth=round(rng.uniform(0.7, 1.0), 2), ip_rotation=rng.choice([10, 20, 40]),
                 log_loss=rng.choice([0.1, 0.2, 0.3]), clock_skew_s=rng.choice([-600, 300, 600]),
                 dup_rate=0.03, shuffle=0.5, malformed_rate=0.01)
    return tier, p


def run_one(args: tuple) -> dict:
    seed, scale = args[0], args[1]
    templates = args[2] if len(args) > 2 else None
    from backend.core.models import ScenarioParams
    from backend.ingest import IngestContext, ingest_files
    from backend.pipeline import analyze
    from backend.views import build_views
    from eval.match import reveal
    from sim.generator import generate

    tier, p = scenario_for(seed, scale, templates)
    params = ScenarioParams(**p)
    t0 = time.perf_counter()
    sc = generate(seed, params)
    res = ingest_files(list(sc.files.items()), IngestContext(case_id=f"bench-{seed}"))
    a = analyze(res)
    v = build_views(a)
    elapsed = int((time.perf_counter() - t0) * 1000)
    matches, card = reveal(sc.truth, a, v)
    m = {x.kind: x for x in matches}
    base = card.baselines
    row = {
        "seed": seed, "template": p["template"], "tier": tier, "params": {k: v_ for k, v_ in p.items() if k != "scale"},
        "events": len(a.nc.events), "signals": len(a.signals), "incidents": len(v.incidents), "watchlist": len(v.watchlist),
        "runtime_ms": elapsed, "b0_alerts": base["B0_naive_alerts"]["alerts"], "b0_precision": base["B0_naive_alerts"]["precision"],
        "b1_groups": base["B1_time_window"]["groups"], "b1_stage_recall": base["B1_time_window"]["best_group_stage_recall"],
        "b1_purity": base["B1_time_window"]["best_group_purity"],
    }
    if p["template"] == "T0":
        row.update(clean=True, false_incidents=len(v.incidents),
                   why=("; ".join(i.title for i in v.incidents) if v.incidents else None))
        return row
    victim = sc.truth.compromised_users[0]
    hit = [i for i in v.incidents if f"user:{victim}" in i.entities]
    row.update(
        clean=False, detected=bool(hit), entry_ok=bool(m["entry_ip"].truth) and not m["entry_ip"].misses,
        account_ok=not m["compromised_account"].misses and bool(m["compromised_account"].hits),
        victim_ok=not m["data_stolen_from"].misses and bool(m["data_stolen_from"].hits),
        false_suspects=card.false_suspect_count, extra_incidents=len(v.incidents) - len(hit),
        stage_order=card.stage_order_accuracy, purity=card.cluster_purity, stage_recall=base["B2_221B"]["stage_recall"],
        gap_recall=card.gap_recall, stages_found=len(hit[0].stages_covered) if hit else 0,
    )
    truth_ents = {f"user:{u}" for u in sc.truth.compromised_users} | {f"ip:{x}" for x in sc.truth.exfil_dst_ips}
    row["surfaced_on_watchlist"] = bool(not hit and any(
        w.watchlist_priority is not None and w.watchlist_priority.value == "high" and truth_ents & set(w.entities) for w in v.watchlist))
    if not hit:
        row["why"] = ("no incident; the data theft was surfaced as a high-priority watchlist item" if row["surfaced_on_watchlist"]
                      else "no incident contains the compromised account; watchlist: " + "; ".join(w.title for w in v.watchlist[:4]))
    elif row["extra_incidents"]:
        row["why"] = "extra incident(s): " + "; ".join(i.title for i in v.incidents if i not in hit)
    elif not row["entry_ok"]:
        row["why"] = f"entry IP not identified (truth {m['entry_ip'].truth}, said {m['entry_ip'].predicted})"
    elif row["false_suspects"]:
        n = row["false_suspects"]
        row["why"] = f"{n} innocent {'entity' if n == 1 else 'entities'} named alongside the real attacker"
    return row


def _mean(xs) -> float | None:
    xs = [float(x) for x in xs if x is not None]
    return round(statistics.mean(xs), 4) if xs else None


def aggregate(rows: list[dict]) -> dict:
    atk = [r for r in rows if not r["clean"]]
    clean = [r for r in rows if r["clean"]]

    def system_metrics(rs_atk, rs_clean) -> dict[str, dict[str, float]]:
        out = {
            "B2_221B": {
                "detection_rate": _mean(r["detected"] for r in rs_atk),
                "surfaced_on_watchlist_only": _mean(r.get("surfaced_on_watchlist", False) for r in rs_atk),
                "entry_ip_accuracy": _mean(r["entry_ok"] for r in rs_atk),
                "account_accuracy": _mean(r["account_ok"] for r in rs_atk),
                "victim_host_accuracy": _mean(r["victim_ok"] for r in rs_atk),
                "stage_recall": _mean(r["stage_recall"] for r in rs_atk),
                "stage_order_accuracy": _mean(r["stage_order"] for r in rs_atk),
                "purity": _mean(r["purity"] for r in rs_atk),
                "gap_recall": _mean(r["gap_recall"] for r in rs_atk),
                "false_suspects_per_run": _mean(r["false_suspects"] for r in rs_atk),
                "extra_incidents_per_attack_run": _mean(r["extra_incidents"] for r in rs_atk),
                "clean_runs_with_false_incident": _mean(r["false_incidents"] > 0 for r in rs_clean),
                "units_to_review_per_run": _mean(r["incidents"] for r in rs_atk + rs_clean),
            },
            "B0_naive_alerts": {
                "units_to_review_per_run": _mean(r["b0_alerts"] for r in rs_atk + rs_clean),
                "precision": _mean(r["b0_precision"] for r in rs_atk),
            },
            "B1_time_window": {
                "units_to_review_per_run": _mean(r["b1_groups"] for r in rs_atk + rs_clean),
                "stage_recall": _mean(r["b1_stage_recall"] for r in rs_atk),
                "purity": _mean(r["b1_purity"] for r in rs_atk),
            },
        }
        return {k: {mk: mv for mk, mv in v.items() if mv is not None} for k, v in out.items()}

    by_tier = {}
    for t in ("easy", "medium", "hard"):
        ra = [r for r in atk if r["tier"] == t]
        rc = [r for r in clean if r["tier"] == t]
        if ra or rc:
            by_tier[t] = {"runs": float(len(ra) + len(rc)), **system_metrics(ra, rc)["B2_221B"]}
    by_template = {}
    for tp in ("T0", "T1", "T2", "T3"):
        ra = [r for r in atk if r["template"] == tp]
        rc = [r for r in clean if r["template"] == tp]
        if ra or rc:
            by_template[tp] = {"runs": float(len(ra) + len(rc)), **system_metrics(ra, rc)["B2_221B"]}
    sm = system_metrics(atk, clean)
    sm["B2_221B"]["median_runtime_ms"] = float(statistics.median(r["runtime_ms"] for r in rows))
    sm["B2_221B"]["median_events"] = float(statistics.median(r["events"] for r in rows))
    sm["counts"] = {"attack_runs": float(len(atk)), "clean_runs": float(len(clean))}
    return {"metrics": sm, "by_tier": by_tier, "by_template": by_template}


def write_md(report: dict, rows: list[dict]) -> str:
    m = report["metrics"]
    b2, b0, b1 = m["B2_221B"], m["B0_naive_alerts"], m["B1_time_window"]
    pct = lambda x: "n/a" if x is None else f"{x * 100:.1f}%"
    lines = [
        "# 221B benchmark", "",
        f"Generated {report['generated_at']} - pipeline {report['pipeline_version']} - {report['n_scenarios']} scenarios "
        f"({int(m['counts']['attack_runs'])} attacks, {int(m['counts']['clean_runs'])} clean). Reproduce: `python -m eval.sweep`.", "",
        "> Honesty note: the detectors were developed against this scenario generator. These numbers measure consistency and",
        "> robustness to the difficulty knobs (stealth, IP rotation, log loss, clock skew, malformed lines), not real-world accuracy.", "",
        "## 221B on attack scenarios", "",
        "| Metric | Value |", "|---|---|",
        f"| Compromised account found inside an incident | {pct(b2.get('detection_rate'))} |",
        f"| Entry IP identified | {pct(b2.get('entry_ip_accuracy'))} |",
        f"| Host the data was taken from identified | {pct(b2.get('victim_host_accuracy'))} |",
        f"| Attack stages recovered | {pct(b2.get('stage_recall'))} |",
        f"| Steps in the right order | {pct(b2.get('stage_order_accuracy'))} |",
        f"| Incident signals that are real attack (purity) | {pct(b2.get('purity'))} |",
        f"| Injected log gaps flagged | {pct(b2.get('gap_recall'))} |",
        f"| Innocent entities accused per run | {b2.get('false_suspects_per_run')} |",
        f"| Extra incidents per attack run | {b2.get('extra_incidents_per_attack_run')} |",
        f"| Clean runs with a false incident | {pct(b2.get('clean_runs_with_false_incident'))} |",
        f"| Median end-to-end time | {b2.get('median_runtime_ms', 0) / 1000:.1f} s for {int(b2.get('median_events', 0)):,} events |", "",
        "## Same detector output, three readings", "",
        "| Reading | Things to review per run | Attack stages in the best unit | Purity |", "|---|---|---|---|",
        f"| B0 every hit is an alert | {b0.get('units_to_review_per_run')} | (one alert = one stage) | {pct(b0.get('precision'))} precision |",
        f"| B1 group hits close in time | {b1.get('units_to_review_per_run')} | {pct(b1.get('stage_recall'))} | {pct(b1.get('purity'))} |",
        f"| **221B predicate-linked incidents** | {b2.get('units_to_review_per_run')} | {pct(b2.get('stage_recall'))} | {pct(b2.get('purity'))} |", "",
        "## By difficulty", "", "| Tier | Runs | Detection | Entry IP | Stages | Gaps flagged | Clean false-incident |", "|---|---|---|---|---|---|---|",
    ]
    for t, d in report["by_tier"].items():
        lines.append(f"| {t} | {int(d['runs'])} | {pct(d.get('detection_rate'))} | {pct(d.get('entry_ip_accuracy'))} | "
                     f"{pct(d.get('stage_recall'))} | {pct(d.get('gap_recall'))} | {pct(d.get('clean_runs_with_false_incident'))} |")
    lines += ["", "## Misses and imperfections", ""]
    if not report["misses"]:
        lines.append("None in this sweep.")
    for x in report["misses"]:
        lines.append(f"- seed {x['seed']} ({x['template']}, {x['tier']}): {x['why']}")
    return "\n".join(lines) + "\n"


def main() -> None:
    import sys

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # Windows consoles default to cp1252
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", default="1..300")
    ap.add_argument("--scale", type=float, default=0.35)
    ap.add_argument("--workers", type=int, default=0)
    ap.add_argument("--templates", default="", help="comma list to restrict templates, e.g. T3 for the held-out test")
    ap.add_argument("--name", default="benchmark", help="output basename under docs/")
    a = ap.parse_args()
    templates = tuple(t for t in a.templates.split(",") if t) or None
    global OUT_JSON, OUT_MD
    OUT_JSON = ROOT / "docs" / f"{a.name}.json"
    OUT_MD = ROOT / "docs" / f"{a.name}.md"
    lo, hi = (int(x) for x in a.seeds.split(".."))
    seeds = list(range(lo, hi + 1))
    import os

    from backend.core.ids import PIPELINE_VERSION

    workers = a.workers or max(1, (os.cpu_count() or 2) - 1)
    t = time.time()
    with ProcessPoolExecutor(max_workers=workers) as ex:
        rows = list(ex.map(run_one, [(s, a.scale, templates) for s in seeds], chunksize=4))
    agg = aggregate(rows)
    misses = [{"seed": r["seed"], "template": r["template"], "tier": r["tier"], "params": r["params"], "why": r["why"]}
              for r in rows if r.get("why")]
    report = {"generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "pipeline_version": PIPELINE_VERSION,
              "n_scenarios": len(rows), "seeds": seeds, **agg, "misses": misses}
    from backend.core.models import EvalReport

    EvalReport.model_validate(report)  # contract check
    OUT_JSON.write_text(json.dumps(report, indent=1), encoding="utf-8")
    OUT_MD.write_text(write_md(report, rows), encoding="utf-8")
    print(f"{len(rows)} scenarios in {time.time() - t:.0f}s with {workers} workers -> {OUT_JSON.name}, {OUT_MD.name}")
    print(json.dumps(agg["metrics"], indent=1))
    for x in misses[:20]:
        print("  MISS", x["seed"], x["template"], x["tier"], x["why"])


if __name__ == "__main__":
    main()
