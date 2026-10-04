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
    assert s["funnel"]["events"] == 3 and s["parse_report"]["lines_quarantined"] == 2


def test_truth_is_not_leaked_and_pending_endpoints_declare_501():
    cid = client.post("/api/scenarios", json={"seed": 1, "params": {"scale": 0.05}}).json()["case_id"]
    assert "truth" not in json.dumps(client.get(f"/api/cases/{cid}/summary").json()).lower()
    assert client.get(f"/api/cases/{cid}/incidents").status_code == 501
    assert client.post(f"/api/cases/{cid}/reveal").status_code == 501
    assert client.get("/api/cases/nope/summary").status_code == 404


def test_scenario_params_are_capped_by_contract():
    r = client.post("/api/scenarios", json={"seed": 1, "params": {"ip_rotation": 999}})
    assert r.status_code == 422
