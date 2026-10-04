# 221B API & data contract - FROZEN v1.0.0

Source of truth: `backend/core/models.py` (Pydantic v2). The HTTP surface is `backend/api/*`; the machine-readable
contract is `contract/openapi.json`; TypeScript types are generated into `frontend/src/api/types.ts`.

## Rules
1. **Do not change a model field or route without a deliberate contract bump.**
   `tests/integration/test_api_and_contract.py::test_contract_is_frozen` fails if the live OpenAPI differs from `contract/openapi.json`.
2. To change it on purpose: edit models -> bump `CONTRACT_VERSION` -> `python scripts/export_contract.py` ->
   `cd frontend && npm run types` -> commit all three together.
3. Additive, optional fields are preferred over breaking changes.
4. Engine (backend) and UI (frontend) are built independently against this contract. Endpoints whose engine stage is
   not built yet return **501** but already declare their final response model.

## Status of endpoints (scaffold)
| Endpoint | State |
|---|---|
| `GET /api/health`, `POST /api/cases`, `POST /api/scenarios`, `GET /api/cases/{id}/summary`, `/progress` (SSE), `/events`, `/events/{eid}` | implemented (ingest only) |
| `/incidents`, `/incidents/{iid}`, `/incidents/{iid}/replay`, `/suspects`, `/dismissals`, `/naive`, `/entities/..`, `/reveal`, `/report.md`, `/api/eval/latest` | contract frozen, **501** until engine stages land |

## Notable contract decisions
- Event IDs are `E-` + 12 hex (sha1 of `file_id|line_no`); stable across re-ingest of identical bytes.
- `Incident.status` is `incident` (>= 2 distinct stages joined by predicate links - no bypass) or `watchlist`;
  `watchlist_priority=high` marks a confirmed-impact single-stage finding.
- `ScenarioParams` ranges are the only knobs the UI may expose (validated server-side; out-of-range -> 422).
- Ground truth is never in `CaseSummary`; it is returned only by `POST /cases/{id}/reveal`.
