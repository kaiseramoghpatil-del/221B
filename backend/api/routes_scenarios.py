"""The ONLY api module allowed to import sim/: the server invokes the generator as a *data source*,
then feeds the produced bytes through the same ingestion path as any upload."""
from __future__ import annotations

import os

from fastapi import APIRouter

from backend.core.models import CaseCreated, CaseSource, ScenarioRequest
from backend.store.memory import STORE
from sim.generator import generate

from .deps import run_ingest

router = APIRouter(prefix="/api", tags=["scenarios"])

# Small hosts: cap the size of generated cases (e.g. MAX_SCALE=0.6 keeps a case near 150 MB).
MAX_SCALE = float(os.environ.get("MAX_SCALE", "3.0"))


@router.post("/scenarios", response_model=CaseCreated)
def create_scenario(req: ScenarioRequest) -> CaseCreated:
    params = req.params
    if params.scale > MAX_SCALE:
        params = params.model_copy(update={"scale": MAX_SCALE})
    key = f"{req.seed}|{params.model_dump_json()}"
    existing = STORE.find_scenario(key)
    if existing is not None:  # same seed + params: identical data, reuse the analysed case
        return CaseCreated(case_id=existing.case_id)
    sc = generate(req.seed, params)
    rec = STORE.create(name=f"Scenario seed {req.seed} ({params.template})", source=CaseSource.scenario, scenario_key=key)
    rec.truth = sc.truth  # hidden until /reveal
    rec.scenario_seed = req.seed
    rec.scenario_params = params
    run_ingest(rec, list(sc.files.items()), assume_year=None)
    return CaseCreated(case_id=rec.case_id)
