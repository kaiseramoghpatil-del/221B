"""Enforce the 'no shared types' credibility rule: the pipeline must never import the generator."""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PIPELINE_PKGS = ["ingest", "normalize", "baseline", "detect", "correlate", "reconstruct", "score", "explain", "store", "core"]
IMPORT = re.compile(r"^\s*(?:from|import)\s+(sim|eval)\b", re.M)


def test_pipeline_modules_never_import_sim():
    bad = []
    for pkg in PIPELINE_PKGS:
        for f in (ROOT / "backend" / pkg).rglob("*.py"):
            if IMPORT.search(f.read_text(encoding="utf-8")):
                bad.append(str(f.relative_to(ROOT)))
    assert not bad, bad


def test_only_the_scenarios_route_imports_sim_in_api():
    offenders = []
    for f in (ROOT / "backend" / "api").rglob("*.py"):
        if f.name != "routes_scenarios.py" and re.search(r"^\s*(?:from|import)\s+sim\b", f.read_text(encoding="utf-8"), re.M):
            offenders.append(f.name)
    assert not offenders, offenders


def test_sim_depends_only_on_the_shared_contract():
    for f in (ROOT / "sim").rglob("*.py"):
        for m in re.finditer(r"^\s*from\s+backend\.([\w.]+)\s+import", f.read_text(encoding="utf-8"), re.M):
            assert m.group(1).startswith("core.models"), f"{f.name} imports backend.{m.group(1)}"
