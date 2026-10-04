"""Detector registry + runner."""
from __future__ import annotations

from backend.baseline import Baselines
from backend.core.models import Signal
from backend.normalize import NormalizedCase

from . import credential, host, network
from .base import DetectCtx, Detector

REGISTRY: list[Detector] = [*credential.DETECTORS, *network.DETECTORS[:1], *host.DETECTORS, *network.DETECTORS[1:]]


def run_detectors(nc: NormalizedCase, b: Baselines, disabled: set[str] | None = None) -> tuple[list[Signal], DetectCtx]:
    ctx = DetectCtx(nc=nc, b=b)
    out: list[Signal] = []
    for d in REGISTRY:
        if disabled and d.id in disabled:
            continue
        out.extend(d.run(ctx))
    out.sort(key=lambda s: (s.t_start, s.detector, s.id))
    return out, ctx
