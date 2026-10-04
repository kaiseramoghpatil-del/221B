"""The ONLY api module allowed to import sim/: the server invokes the generator as a *data source*,
then feeds the produced bytes through the same ingestion path as any upload."""
from __future__ import annotations

import os
import threading

from fastapi import APIRouter

from backend.core.models import CaseCreated, CaseSource, ScenarioParams, ScenarioRequest
from backend.store.memory import STORE
from sim.generator import generate

from .deps import run_ingest

router = APIRouter(prefix="/api", tags=["scenarios"])

# Small hosts: cap the size of generated cases (e.g. MAX_SCALE=0.6 keeps a case near 150 MB).
MAX_SCALE = float(os.environ.get("MAX_SCALE", "3.0"))

# The start screen's demo case. It is exempt from MAX_SCALE (so it matches the landing page's numbers),
# analysed once at startup (see app.py) and pinned in memory, so opening it is instant even on a slow host.
DEMO = ScenarioRequest(seed=1, params=ScenarioParams(template="T1"))

_inflight: dict[str, threading.Event] = {}
_inflight_lock = threading.Lock()


@router.post("/scenarios", response_model=CaseCreated)
def create_scenario(req: ScenarioRequest) -> CaseCreated:
    is_demo = req == DEMO
    params = req.params
    if params.scale > MAX_SCALE and not is_demo:
        params = params.model_copy(update={"scale": MAX_SCALE})
    key = f"{req.seed}|{params.model_dump_json()}"
    while True:
        existing = STORE.find_scenario(key)
        if existing is not None:  # same seed + params: identical data, reuse the analysed case
            return CaseCreated(case_id=existing.case_id)
        with _inflight_lock:
            busy = _inflight.get(key)
            if busy is None:  # nobody is analysing this one: we will
                done = _inflight[key] = threading.Event()
                break
        busy.wait()  # someone else is analysing the same case: wait for it instead of doing it twice
    try:
        return _analyse(req.seed, params, key, is_demo)
    finally:
        with _inflight_lock:
            _inflight.pop(key, None)
        done.set()


def _analyse(seed: int, params: ScenarioParams, key: str, pinned: bool) -> CaseCreated:
    sc = generate(seed, params)
    rec = STORE.create(name=f"Scenario seed {seed} ({params.template})", source=CaseSource.scenario, scenario_key=key, pinned=pinned)
    rec.truth = sc.truth  # hidden until /reveal
    rec.scenario_seed = seed
    rec.scenario_params = params
    run_ingest(rec, list(sc.files.items()), assume_year=None)
    return CaseCreated(case_id=rec.case_id)
