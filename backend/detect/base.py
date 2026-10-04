"""Detector framework: context, signal construction, predicate helpers.

Every detector declares Sigma-style metadata (level, tags, falsepositives) and, per signal, the predicates it
`requires` (prerequisites) and `produces` (consequences). Correlation is driven entirely by these.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable

from backend.baseline import Baselines
from backend.core.ids import short
from backend.core.models import (Criticality, EvidenceRef, EvidenceRole, Event, PredicateInstance, PredicateName, RuleMeta,
                                 Signal, Stage)
from backend.normalize import NormalizedCase

EVIDENCE_CAP = 40
CRIT_MULT = {Criticality.low: 1.0, Criticality.med: 1.0, Criticality.high: 1.35}


@dataclass
class DetectCtx:
    nc: NormalizedCase
    b: Baselines
    notes: list[dict[str, Any]] = field(default_factory=list)  # dismissal notes: suppressed look-alikes, with evidence

    def session(self, e: Event) -> str | None:
        return self.nc.session_of.get(e.id)

    def crit(self, host: str | None) -> float:
        if not host:
            return 1.0
        ent = self.nc.entities.get(f"host:{host}")
        return CRIT_MULT.get(ent.criticality, 1.0) if ent else 1.0


@dataclass(frozen=True)
class Detector:
    id: str
    title: str
    stage: Stage
    meta: RuleMeta
    run: Callable[[DetectCtx], list[Signal]]


def P(name: PredicateName, t: datetime | None = None, **args: str | None) -> PredicateInstance:
    return PredicateInstance(name=name, args={k: v for k, v in args.items() if v is not None}, t=t)


def evidence(events: list[Event], role: EvidenceRole = EvidenceRole.supports) -> list[EvidenceRef]:
    if len(events) <= EVIDENCE_CAP:
        pick = events
    else:  # first, last and an even sample in between
        step = len(events) / (EVIDENCE_CAP - 2)
        pick = [events[0]] + [events[int(i * step)] for i in range(1, EVIDENCE_CAP - 2)] + [events[-1]]
    seen: set[str] = set()
    out = []
    for e in pick:
        if e.id not in seen:
            seen.add(e.id)
            out.append(EvidenceRef(event_id=e.id, role=role))
    return out


def clamp(x: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, x))


def mk_signal(det: Detector, key: str, events: list[Event], *, entities: list[str], severity: float, confidence: float,
              template: str, params: dict[str, Any], requires: list[PredicateInstance] | None = None,
              produces: list[PredicateInstance] | None = None, features: dict[str, Any] | None = None, rarity: float = 0.5,
              crit: float = 1.0, stage: Stage | None = None, title: str | None = None,
              context_events: list[Event] | None = None) -> Signal:
    """`events` are the primary evidence and define the signal's time span; `context_events` (e.g. the failures
    that preceded a successful login) are attached as context evidence without moving the signal in time."""
    events = sorted(events, key=lambda e: (e.ts_utc, e.file_id, e.line_no))
    ctx_ev = sorted(context_events or [], key=lambda e: (e.ts_utc, e.file_id, e.line_no))
    feats = dict(features or {})
    feats.setdefault("evidence_total", len(events) + len(ctx_ev))
    return Signal(
        id=short("S", det.id, key), detector=det.id, title=title or det.title, stage_hint=stage or det.stage,
        entities=sorted(set(entities)), t_start=events[0].ts_utc, t_end=events[-1].ts_utc, severity=clamp(severity),
        confidence=clamp(confidence), rarity=clamp(rarity), criticality_mult=max(1.0, crit), requires=requires or [],
        produces=produces or [], rule_meta=det.meta, features=feats,
        evidence=evidence(events) + (evidence(ctx_ev, EvidenceRole.context) if ctx_ev else []),
        explanation_template=template, explanation_params=params,
    )


def fmt_dur(seconds: float) -> str:
    s = int(seconds)
    if s < 120:
        return f"{s}s"
    if s < 7200:
        return f"{s // 60} min"
    return f"{s / 3600:.1f} h"
