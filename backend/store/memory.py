"""In-memory case store with a bounded LRU (a 49k-event case holds ~225 MB; small hosts have 512 MB).

CASE_LIMIT (env, default 6): how many analysed cases are kept. The least recently used one is evicted.
Identical scenario requests (same seed + params) reuse the existing case instead of re-analysing.
"""
from __future__ import annotations

import gc
import os
import threading
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any

from backend.core.ids import PIPELINE_VERSION
from backend.core.models import (CaseSource, CaseStatus, CaseSummary, Funnel, GroundTruth, ProgressEvent,
                                 ScenarioParams)
from backend.ingest import IngestResult

CASE_LIMIT = max(1, int(os.environ.get("CASE_LIMIT", "6")))


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
    scenario_key: str | None = None

    def summary(self) -> CaseSummary:
        n = len(self.ingest.events) if self.ingest else 0
        funnel = self.views.funnel if self.views is not None else Funnel(events=n)
        return CaseSummary(
            case_id=self.case_id, name=self.name, source=self.source, status=self.status, pipeline_version=PIPELINE_VERSION,
            scenario_seed=self.scenario_seed, scenario_params=self.scenario_params, funnel=funnel,
            parse_report=self.ingest.report if self.ingest else None, error=self.error,
        )


class CaseStore:
    def __init__(self, limit: int = CASE_LIMIT) -> None:
        self._cases: OrderedDict[str, CaseRecord] = OrderedDict()
        self._by_scenario: dict[str, str] = {}
        self._lock = threading.Lock()
        self.limit = limit

    def create(self, name: str, source: CaseSource, scenario_key: str | None = None) -> CaseRecord:
        rec = CaseRecord(case_id="case-" + uuid.uuid4().hex[:8], name=name, source=source, scenario_key=scenario_key)
        with self._lock:
            self._cases[rec.case_id] = rec
            if scenario_key:
                self._by_scenario[scenario_key] = rec.case_id
            evicted = False
            while len(self._cases) > self.limit:
                old_id, old = self._cases.popitem(last=False)
                if old.scenario_key and self._by_scenario.get(old.scenario_key) == old_id:
                    del self._by_scenario[old.scenario_key]
                evicted = True
        if evicted:
            gc.collect()
        return rec

    def get(self, case_id: str) -> CaseRecord | None:
        with self._lock:
            rec = self._cases.get(case_id)
            if rec is not None:
                self._cases.move_to_end(case_id)  # LRU touch
            return rec

    def find_scenario(self, key: str) -> CaseRecord | None:
        with self._lock:
            cid = self._by_scenario.get(key)
        rec = self.get(cid) if cid else None
        return rec if rec is not None and rec.status is CaseStatus.ready else None

    def all(self) -> list[CaseRecord]:
        return list(self._cases.values())


STORE = CaseStore()
