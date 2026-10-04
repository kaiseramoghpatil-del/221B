"""The ONLY api module allowed to import sim/: the server invokes the generator as a *data source*,
then feeds the produced bytes through the same ingestion path as any upload."""
from __future__ import annotations

from fastapi import APIRouter

from backend.core.models import CaseCreated, CaseSource, ScenarioRequest
from backend.store.memory import STORE
from sim.generator import generate

from .deps import run_ingest

router = APIRouter(prefix="/api", tags=["scenarios"])


@router.post("/scenarios", response_model=CaseCreated)
def create_scenario(req: ScenarioRequest) -> CaseCreated:
    sc = generate(req.seed, req.params)
    rec = STORE.create(name=f"Scenario seed {req.seed} ({req.params.template})", source=CaseSource.scenario)
    rec.truth = sc.truth  # hidden until /reveal
    rec.scenario_seed = req.seed
    rec.scenario_params = req.params
    run_ingest(rec, list(sc.files.items()), assume_year=None)
    return CaseCreated(case_id=rec.case_id)
