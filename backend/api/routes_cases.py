from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, File, Query, UploadFile
from fastapi.responses import PlainTextResponse, StreamingResponse

from backend.core.models import (CaseCreated, CaseSource, CaseSummary, DismissalList, EntityProfile, EventContext,
                                 EventsPage, EvalReport, AttackGraph, IncidentDetail, IncidentList, NaiveView,
                                 ReplayFrame, RevealResponse, SuspectList)
from backend.store.memory import STORE

from .deps import get_case, not_implemented, run_ingest

router = APIRouter(prefix="/api", tags=["cases"])


@router.post("/cases", response_model=CaseCreated)
async def upload_case(files: list[UploadFile] = File(...), name: str | None = Query(default=None)) -> CaseCreated:
    rec = STORE.create(name=name or (files[0].filename if files else "upload"), source=CaseSource.upload)
    payload = [(f.filename or "file", await f.read()) for f in files]
    run_ingest(rec, payload)
    return CaseCreated(case_id=rec.case_id)


@router.get("/cases/{case_id}/summary", response_model=CaseSummary)
def summary(case_id: str) -> CaseSummary:
    return get_case(case_id).summary()


@router.get("/cases/{case_id}/progress")
async def progress(case_id: str):
    rec = get_case(case_id)

    async def gen():
        sent = 0
        for _ in range(600):
            while sent < len(rec.progress):
                yield f"data: {json.dumps(rec.progress[sent].model_dump(mode='json'))}\n\n"
                sent += 1
            if rec.status.value in ("ready", "failed"):
                return
            await asyncio.sleep(0.2)

    return StreamingResponse(gen(), media_type="text/event-stream")


@router.get("/cases/{case_id}/incidents", response_model=IncidentList)
def incidents(case_id: str, status: str | None = Query(default=None, pattern="^(incident|watchlist)$")) -> IncidentList:
    get_case(case_id)
    raise not_implemented("incidents")


@router.get("/cases/{case_id}/incidents/{incident_id}", response_model=IncidentDetail)
def incident_detail(case_id: str, incident_id: str) -> IncidentDetail:
    get_case(case_id)
    raise not_implemented("incident detail")


@router.get("/cases/{case_id}/incidents/{incident_id}/replay", response_model=AttackGraph)
def replay(case_id: str, incident_id: str) -> AttackGraph:
    get_case(case_id)
    raise not_implemented("replay")


@router.get("/cases/{case_id}/suspects", response_model=SuspectList)
def suspects(case_id: str) -> SuspectList:
    get_case(case_id)
    raise not_implemented("suspects")


@router.get("/cases/{case_id}/dismissals", response_model=DismissalList)
def dismissals(case_id: str) -> DismissalList:
    get_case(case_id)
    raise not_implemented("dismissals")


@router.get("/cases/{case_id}/naive", response_model=NaiveView)
def naive(case_id: str) -> NaiveView:
    get_case(case_id)
    raise not_implemented("naive view")


@router.get("/cases/{case_id}/events", response_model=EventsPage)
def events(case_id: str, q: str | None = None, host: str | None = None, user: str | None = None, ip: str | None = None,
           action: str | None = None, outcome: str | None = None, cursor: int = 0, limit: int = Query(default=100, le=500)) -> EventsPage:
    rec = get_case(case_id)
    evs = rec.ingest.events if rec.ingest else []
    ql = q.lower() if q else None

    def keep(e) -> bool:
        return ((host is None or e.host == host) and (user is None or e.user == user) and (ip is None or ip in (e.src_ip, e.dst_ip))
                and (action is None or e.action.value == action) and (outcome is None or e.outcome.value == outcome)
                and (ql is None or ql in e.raw_text.lower()))

    sel = [e for e in evs if keep(e)]
    page = sel[cursor: cursor + limit]
    nxt = str(cursor + limit) if cursor + limit < len(sel) else None
    return EventsPage(case_id=case_id, events=page, next_cursor=nxt, total=len(sel))


@router.get("/cases/{case_id}/events/{event_id}", response_model=EventContext)
def event_context(case_id: str, event_id: str, context: int = Query(default=5, ge=0, le=25)) -> EventContext:
    rec = get_case(case_id)
    ev = next((e for e in (rec.ingest.events if rec.ingest else []) if e.id == event_id), None)
    if ev is None:
        from fastapi import HTTPException
        raise HTTPException(404, f"unknown event {event_id}")
    lines = rec.ingest.lines_by_file[ev.file_id]
    i = ev.line_no - 1
    return EventContext(event=ev, before=lines[max(0, i - context): i], after=lines[i + 1: i + 1 + context], line_no=ev.line_no,
                        file_name=rec.ingest.file_names[ev.file_id])


@router.get("/cases/{case_id}/entities/{etype}/{eid}", response_model=EntityProfile)
def entity(case_id: str, etype: str, eid: str) -> EntityProfile:
    get_case(case_id)
    raise not_implemented("entity profile")


@router.post("/cases/{case_id}/reveal", response_model=RevealResponse)
def reveal(case_id: str) -> RevealResponse:
    rec = get_case(case_id)
    if rec.truth is None:
        from fastapi import HTTPException
        raise HTTPException(409, "reveal is only available for generated scenarios")
    raise not_implemented("reveal scorecard (needs analysis pipeline)")


@router.get("/cases/{case_id}/report.md", response_class=PlainTextResponse)
def report(case_id: str) -> str:
    get_case(case_id)
    raise not_implemented("report export")


@router.get("/eval/latest", response_model=EvalReport)
def eval_latest() -> EvalReport:
    raise not_implemented("benchmark report")
