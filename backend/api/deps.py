from __future__ import annotations

from fastapi import HTTPException

from backend.core.models import CaseSource, CaseStatus, ProgressEvent
from backend.ingest import IngestContext, ingest_files
from backend.store.memory import STORE, CaseRecord


def get_case(case_id: str) -> CaseRecord:
    rec = STORE.get(case_id)
    if rec is None:
        raise HTTPException(404, f"unknown case {case_id}")
    return rec


def not_implemented(what: str) -> HTTPException:
    return HTTPException(501, f"{what}: not implemented yet (contract frozen; engine stage pending)")


def run_ingest(rec: CaseRecord, files: list[tuple[str, bytes]], assume_year: int | None = None) -> None:
    rec.status = CaseStatus.parsing
    try:
        rec.ingest = ingest_files(files, IngestContext(case_id=rec.case_id, assume_year=assume_year))
        n = len(rec.ingest.events)
        rec.progress.append(ProgressEvent(case_id=rec.case_id, stage="ingest",
                                          counts={"events": n, "quarantined": rec.ingest.report.lines_quarantined}))
        # downstream stages (normalize..explain) plug in here; until then the case is 'ready' with a funnel of events only
        rec.status = CaseStatus.ready
        rec.progress.append(ProgressEvent(case_id=rec.case_id, stage="done", counts={"events": n}))
    except Exception as exc:  # surface, never crash the server
        rec.status = CaseStatus.failed
        rec.error = f"{type(exc).__name__}: {exc}"
        rec.progress.append(ProgressEvent(case_id=rec.case_id, stage="error", message=rec.error))
