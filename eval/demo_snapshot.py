"""Freeze the demo case's analysed results for the start screen.

The landing page replays these stored numbers and lines; it never claims to analyse anything live.
Run after any pipeline change:  python -m eval.demo_snapshot
Writes frontend/src/data/demoCase.json.
"""
from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from backend.api.app import app

DEMO = {"seed": 1, "params": {"template": "T1"}}  # must match DEMO_SEED in frontend/src/views/Intake.tsx
OUT = Path(__file__).resolve().parents[1] / "frontend" / "src" / "data" / "demoCase.json"


def proof() -> dict:
    """Headline numbers from the stored benchmark reports (docs/benchmark*.json)."""
    docs = OUT.parents[3] / "docs"
    main_ = json.loads((docs / "benchmark.json").read_text(encoding="utf-8"))["metrics"]
    held = json.loads((docs / "benchmark_heldout.json").read_text(encoding="utf-8"))["metrics"]
    n_atk, n_clean, n_held = (int(main_["counts"]["attack_runs"]), int(main_["counts"]["clean_runs"]),
                              int(held["counts"]["attack_runs"]))
    return {
        "attack_runs": n_atk, "found": round(main_["B2_221B"]["detection_rate"] * n_atk),
        "clean_runs": n_clean, "clean_flagged": round(main_["B2_221B"]["clean_runs_with_false_incident"] * n_clean),
        "heldout_runs": n_held, "heldout_reconstructed": round(held["B2_221B"]["detection_rate"] * n_held),
        "heldout_watchlisted": round(held["B2_221B"]["surfaced_on_watchlist_only"] * n_held),
    }


def main() -> None:
    c = TestClient(app)
    cid = c.post("/api/scenarios", json=DEMO).json()["case_id"]
    summary = c.get(f"/api/cases/{cid}/summary").json()
    inc = next(i for i in c.get(f"/api/cases/{cid}/incidents").json()["incidents"] if i["status"] == "incident")
    detail = c.get(f"/api/cases/{cid}/incidents/{inc['id']}").json()
    claims = {cl["step_id"]: cl for cl in detail["claims"] if cl.get("step_id")}
    entry = next(cl for cl in detail["claims"] if cl["type"] == "ENTRY")["facts"]
    exfil = next((cl for cl in detail["claims"] if cl["type"] == "EXFIL"), None)

    steps, log = [], []
    for s in detail["incident"]["steps"]:
        ctx = c.get(f"/api/cases/{cid}/events/{s['event_ids'][0]}", params={"context": 2}).json()
        host = (s["target_entity"] or s["actor_entity"] or "").split(":", 1)[-1]
        steps.append({"order": s["order"], "stage": s["stage"], "host": host, "t": s["t_start"],
                      "text": claims.get(s["id"], {}).get("text", ""), "events": s["summary_count"]})
        # real neighbouring lines from the same file, with the evidence line marked
        log += [{"line": ln, "step": None} for ln in ctx["before"][-2:]]
        log.append({"line": ctx["event"]["raw_text"], "step": s["order"]})
        log += [{"line": ln, "step": None} for ln in ctx["after"][:1]]

    snap = {
        "seed": DEMO["seed"], "template": DEMO["params"]["template"],
        "funnel": summary["funnel"],
        "window": {"start": summary["parse_report"]["t_min"], "end": summary["parse_report"]["t_max"]},
        "parse": {k: summary["parse_report"][k] for k in ("lines_total", "lines_skipped", "lines_quarantined")},
        "incident": {"title": detail["incident"]["title"], "confidence": detail["incident"]["confidence"],
                     "t_start": detail["incident"]["t_start"], "t_end": detail["incident"]["t_end"],
                     "user": entry.get("user"), "entry_ip": entry.get("ip"), "entry_host": entry.get("host"),
                     "gb_out": exfil["facts"].get("gb") if exfil else None,
                     "hosts": sorted({s["host"] for s in steps if s["host"] and not s["host"][0].isdigit()})},
        "steps": steps,
        "log": log,
        "proof": proof(),
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(snap, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
