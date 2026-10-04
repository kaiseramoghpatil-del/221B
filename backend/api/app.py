from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from backend.core.ids import PIPELINE_VERSION
from backend.core.models import CONTRACT_VERSION, Health

from .routes_cases import router as cases_router
from .routes_scenarios import router as scenarios_router

app = FastAPI(title="221B", version=CONTRACT_VERSION, description="Forensic incident reconstruction API (contract v" + CONTRACT_VERSION + ")")
app.include_router(cases_router)
app.include_router(scenarios_router)


@app.get("/api/health", response_model=Health, tags=["meta"])
def health() -> Health:
    return Health(pipeline_version=PIPELINE_VERSION)


_DIST = Path(__file__).resolve().parents[2] / "frontend" / "dist"
if _DIST.is_dir():  # single deploy unit: the API also serves the built SPA
    app.mount("/", StaticFiles(directory=_DIST, html=True), name="spa")
