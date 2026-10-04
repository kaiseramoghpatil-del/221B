"""run_pipeline: ingest -> normalize -> baseline -> detect -> correlate (-> reconstruct/score/explain next)."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable

from backend.baseline import Baselines, build_baselines
from backend.core.models import Signal
from backend.correlate import Correlation, correlate
from backend.detect import run_detectors
from backend.detect.base import DetectCtx
from backend.ingest import IngestContext, IngestResult, ingest_files
from backend.normalize import NormalizedCase, normalize


@dataclass
class Analysis:
    ingest: IngestResult
    nc: NormalizedCase
    baselines: Baselines
    signals: list[Signal]
    detect_ctx: DetectCtx
    corr: Correlation
    timings_ms: dict[str, int] = field(default_factory=dict)

    @property
    def signal_by_id(self) -> dict[str, Signal]:
        return {s.id: s for s in self.signals}


def analyze(ingest: IngestResult, progress: Callable[[str, dict], None] | None = None, disabled: set[str] | None = None) -> Analysis:
    t = {}
    mark = time.perf_counter()

    def tick(name: str, counts: dict | None = None):
        nonlocal mark
        now = time.perf_counter()
        t[name] = int((now - mark) * 1000)
        mark = now
        if progress:
            progress(name, counts or {})

    nc = normalize(ingest.events)
    tick("normalize", {"events": len(nc.events), "sessions": len(nc.sessions), "duplicates_collapsed": nc.dup_collapsed})
    b = build_baselines(nc)
    tick("baseline", {})
    signals, dctx = run_detectors(nc, b, disabled)
    tick("detect", {"signals": len(signals)})
    ends = {sid: s.end_or_ttl for sid, s in nc.sessions.items()}
    corr = correlate(signals, ends)
    tick("correlate", {"incidents": len(corr.incidents), "watchlist": len(corr.watchlist), "links": len(corr.links)})
    return Analysis(ingest=ingest, nc=nc, baselines=b, signals=signals, detect_ctx=dctx, corr=corr, timings_ms=t)


def analyze_files(files: list[tuple[str, bytes]], case_id: str = "case", **kw) -> Analysis:
    return analyze(ingest_files(files, IngestContext(case_id=case_id)), **kw)
