"""In-memory case store (scaffold). SQLite persistence replaces this behind the same interface."""
from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field

from backend.core.models import (CaseSource, CaseStatus, CaseSummary, Funnel, GroundTruth, ProgressEvent,
                                 ScenarioParams)
from backend.core.ids import PIPELINE_VERSION
from backend.ingest import IngestResult
from typing import Any


@dataclass
class CaseRecord:
    case_id: str
    name: str
    source: CaseSource
    status: CaseStatus = CaseStatus.created
    ingest: IngestResult | None = None
    truth: GroundTruth | None = None  # held server-side; only exposed by /reveal
    scenario_seed: int | None = None
    scenario_params: ScenarioParams | None = None
    error: str | None = None
    progress: list[ProgressEvent] = field(default_factory=list)
    analysis: Any = None  # backend.pipeline.Analysis
    views: Any = None  # backend.views.CaseViews

    def summary(self) -> CaseSummary:
        n = len(self.ingest.events) if self.ingest else 0
        funnel = self.views.funnel if self.views is not None else Funnel(events=n)
        return CaseSummary(
            case_id=self.case_id, name=self.name, source=self.source, status=self.status, pipeline_version=PIPELINE_VERSION,
            scenario_seed=self.scenario_seed, scenario_params=self.scenario_params, funnel=funnel,
            parse_report=self.ingest.report if self.ingest else None, error=self.error,
        )


class CaseStore:
    def __init__(self) -> None:
        self._cases: dict[str, CaseRecord] = {}
        self._lock = threading.Lock()

    def create(self, name: str, source: CaseSource) -> CaseRecord:
        rec = CaseRecord(case_id="case-" + uuid.uuid4().hex[:8], name=name, source=source)
        with self._lock:
            self._cases[rec.case_id] = rec
        return rec

    def get(self, case_id: str) -> CaseRecord | None:
        return self._cases.get(case_id)

    def all(self) -> list[CaseRecord]:
        return list(self._cases.values())


STORE = CaseStore()
