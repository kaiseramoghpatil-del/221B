"""Regenerate contract/openapi.json from the FastAPI app. Run after any intentional contract change
(and bump CONTRACT_VERSION in backend/core/models.py)."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from backend.api.app import app  # noqa: E402

out = ROOT / "contract" / "openapi.json"
out.write_text(json.dumps(app.openapi(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(f"wrote {out} ({out.stat().st_size} bytes)")
