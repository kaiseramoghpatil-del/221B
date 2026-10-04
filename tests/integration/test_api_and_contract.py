"""API smoke tests + contract-freeze guard."""
from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from backend.api.app import app
from backend.core.models import CONTRACT_VERSION

client = TestClient(app)
ROOT = Path(__file__).resolve().parents[2]


def test_contract_is_frozen():
    """If this fails you changed the API/model contract. Bump CONTRACT_VERSION, run scripts/export_contract.py,
    regenerate frontend types, and commit the new contract/openapi.json deliberately."""
    frozen = json.loads((ROOT / "contract" / "openapi.json").read_text(encoding="utf-8"))
    live = json.loads(json.dumps(app.openapi(), sort_keys=True))
    assert live == frozen
    assert frozen["info"]["version"] == CONTRACT_VERSION


def test_health():
    r = client.get("/api/health")
    assert r.status_code == 200 and r.json()["contract_version"] == CONTRACT_VERSION


def test_scenario_to_summary_events_and_context():
    r = client.post("/api/scenarios", json={"seed": 5, "params": {"template": "T1", "scale": 0.1}})
    assert r.status_code == 200
    cid = r.json()["case_id"]
    s = client.get(f"/api/cases/{cid}/summary").json()
    assert s["status"] == "ready" and s["funnel"]["events"] > 1000
    assert s["parse_report"]["lines_quarantined"] == 0 and s["scenario_seed"] == 5
    page = client.get(f"/api/cases/{cid}/events", params={"outcome": "success", "action": "sudo", "limit": 5}).json()
    assert page["total"] > 0 and len(page["events"]) <= 5
    eid = page["events"][0]["id"]
    ctx = client.get(f"/api/cases/{cid}/events/{eid}", params={"context": 3}).json()
    assert ctx["event"]["id"] == eid and ctx["file_name"] == "auth.log" and len(ctx["before"]) <= 3
    assert ctx["event"]["raw_text"] not in ctx["before"]


def test_upload_roundtrip_with_unknown_file_is_visible_not_silent():
    line = "Sep 30 03:12:04 h sshd[2]: Accepted password for a from 1.1.1.1 port 1 ssh2\n" * 3
    r = client.post("/api/cases", files=[("files", ("auth.log", line.encode())), ("files", ("junk.bin", b"hello\nworld\n"))])
    cid = r.json()["case_id"]
    s = client.get(f"/api/cases/{cid}/summary").json()
    # 3 identical adjacent lines: all parsed, then collapsed as forwarder duplicates by normalize
    assert s["parse_report"]["events_total"] == 3 and s["funnel"]["events"] == 1
    assert s["parse_report"]["lines_quarantined"] == 2


def test_truth_only_via_reveal_and_views_are_served():
    cid = client.post("/api/scenarios", json={"seed": 21, "params": {"scale": 0.3}}).json()["case_id"]
    summ = client.get(f"/api/cases/{cid}/summary").json()
    assert "truth" not in json.dumps(summ).lower() and summ["funnel"]["incidents"] == 1
    incs = client.get(f"/api/cases/{cid}/incidents", params={"status": "incident"}).json()["incidents"]
    iid = incs[0]["id"]
    detail = client.get(f"/api/cases/{cid}/incidents/{iid}").json()
    event_ids = {e for cl in detail["claims"] for e in [r["event_id"] for r in cl["evidence"]]}
    assert all(cl["evidence"] for cl in detail["claims"]), "every claim cites evidence"
    for eid in list(event_ids)[:5]:
        assert client.get(f"/api/cases/{cid}/events/{eid}").status_code == 200
    graph = client.get(f"/api/cases/{cid}/incidents/{iid}/replay").json()
    node_ids = {n["id"] for n in graph["nodes"]}
    assert graph["edges"] and all(e["source"] in node_ids and e["target"] in node_ids for e in graph["edges"])
    assert client.get(f"/api/cases/{cid}/suspects").json()["suspects"]
    rv = client.post(f"/api/cases/{cid}/reveal").json()
    assert rv["truth"]["compromised_users"] and rv["scorecard"]["compromised_user_recall"] == 1.0
    assert client.get("/api/cases/nope/summary").status_code == 404


def test_scenario_params_are_capped_by_contract():
    r = client.post("/api/scenarios", json={"seed": 1, "params": {"ip_rotation": 999}})
    assert r.status_code == 422


def test_identical_scenario_requests_share_one_case_and_store_is_bounded():
    from backend.store.memory import CaseStore
    from backend.core.models import CaseSource
    body = {"seed": 77, "params": {"template": "T0", "scale": 0.05}}
    a = client.post("/api/scenarios", json=body).json()["case_id"]
    b = client.post("/api/scenarios", json=body).json()["case_id"]
    assert a == b
    store = CaseStore(limit=2)
    ids = [store.create(f"c{i}", CaseSource.upload).case_id for i in range(3)]
    assert store.get(ids[0]) is None and store.get(ids[2]) is not None
