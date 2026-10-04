# 221B

**Find the intruder in your logs, and see the proof line by line.**
ALGOTHON'26 · ALG-CYBER-01 "Find the Intruder"

221B reads raw authentication, web, network and audit logs and turns tens of thousands of events into a single
reconstructed attack: who got in, from where, how they moved, what they took. Every sentence of the verdict
links to the exact log lines that prove it, and a built-in answer key lets anyone check the verdict against
ground truth on cases nobody prepared in advance.

```
Raw security events → suspicious signals → correlated entities → reconstructed attack sequence
                    → identified intruder → evidence-backed explanation → live verification
```

---

## The problem

Thousands of security events can hide an attacker among normal activity. Per-rule tools flag isolated events,
and the loudest source usually wins attention. In practice the real intruder is often quiet. A stolen password
used once at 3 a.m. looks unremarkable next to a bot hammering SSH all afternoon.

The bonus criterion asks for exactly this: *connect multiple events and explain the likely attack sequence
instead of flagging isolated events only.*

## The approach

1. **Ingest anything readable.** Linux `auth.log` (sshd, sudo, su, useradd, usermod), nginx/Apache access logs,
   and generic CSV / JSON-lines with an ECS-style alias map. Every line becomes an event, an explained skip, or a
   quarantined row with a reason. Nothing is silently dropped.
2. **Normalize.** Stable event IDs, duplicate collapse, an IP→host map learned from flow logs, and SSH sessions
   stitched together with their hop lineage (bastion → app → db).
3. **Detect** with 11 deterministic, explainable detectors (brute force, spray, success-after-failures,
   new-source login, privilege escalation, recon commands, internal scanning, lateral movement, staging,
   exfiltration, persistence). Each declares Sigma-style metadata (level, ATT&CK tags, known false positives)
   and the **predicates it requires and produces** (`has_access(user, host)`, `privileged`, `staged`, …).
4. **Correlate by prerequisites, not by time.** A signal is linked to an earlier one only when the earlier one
   established what the later one needed (the Ning–Cui–Reeves prerequisite/consequence model). Consequences only
   propagate when prerequisites hold, so an engineer's routine hop never hands "attacker access" to anything.
   When a prerequisite is missing from the logs, 221B records a **gap** instead of hiding it.
5. **Admit incidents strictly.** An incident requires **at least two distinct attack stages connected by
   correlation predicates**. Everything else is a Watchlist item, or explained and cleared.
6. **Explain.** Deterministic, template-based claims, each citing its evidence. The system also says what
   looked suspicious and why it is *not* the intruder (a loud brute-forcer that never got in, a nightly scanner,
   a recurring backup).
7. **Verify.** Generated scenarios keep their ground truth hidden; "Reveal the answer key" scores the verdict.
   A benchmark sweep compares 221B against two baselines on the same detector output.

No LLM is involved in detection, correlation, scoring or explanation.

## What you see

- **Verdict:** one sentence, for example "h.petrov's account was taken over from 198.19.76.39 and used to reach db-01; 3.6 GB left for the same address." It sits above a facts box (got in, active for, hosts reached, data out, confidence).
- **Evidence funnel:** 48,753 events › 141 detector hits › 11 linked › 1 incident.
- **Exhibit A, attack path:** places (rows) × stages (columns) with a replayable thread through the attacker's steps.
- **Exhibit B, session timeline:** a waterfall on a real clock, with hops nested under their parent session and deleted-log stretches hatched.
- **Exhibit C, "Looked suspicious, but isn't the intruder":** each decoy cleared with evidence.
- **Findings:** numbered steps. Each opens an evidence drawer with the rule card and the raw `file:line` source lines in context.
- **Isolated alerts view:** the same detector output as a per-rule console would show it, for contrast.
- **Answer key:** for generated cases, truth against verdict, plus the three-way baseline comparison.
- **How it was tested** (`/?page=verify`): the benchmark, with every imperfection reproducible by seed.

## Results (benchmark of 300 generated cases)

`python -m eval.sweep --seeds 1..300` → `docs/benchmark.md`, `docs/benchmark.json`

| | Value |
|---|---|
| Intruder's account found inside an incident | 252 / 252 |
| Exact entry IP named | 252 / 252 |
| Clean weeks wrongly reported as an intrusion | 0 / 48 |
| Attack stages recovered / in the right order | 96% / 99.7% |
| Incident signals that are real attack (purity) | 98% |
| Deliberately deleted log stretches flagged | 91% |

| Same detector output read as… | Items to review per case | Attack stages in the best item |
|---|---|---|
| every hit is an alert | 25.6 | one per alert |
| hits grouped by time (30 min) | 16.2 | 47% |
| **221B incidents** | **0.85** | **96%** |

> **Read this honestly.** The detectors were developed against this same scenario generator. These numbers show
> consistency and robustness to the difficulty knobs (stealth, 1–40 rotating IPs, 10–30% log loss, clock skew,
> duplicated, shuffled and corrupted lines). They are **not** a real-world accuracy figure, and no held-out attack
> pattern has been evaluated yet (see Limitations).

## Run it

Requirements: Python 3.11+, Node 20+.

```bash
cd 221b
pip install -e ".[dev]"
cd frontend && npm ci && npm run build && cd ..        # builds the UI into frontend/dist
python -m uvicorn backend.api.app:app --port 8221       # API + UI on http://localhost:8221
```

Development: `cd frontend && npm run dev` (Vite on :5173, proxies `/api` to :8221).

Other commands:

```bash
python -m pytest                                   # 72 tests
python -m sim.cli --seed 1 --template T1 --out data/demo_case   # write a scenario's raw logs + truth.json to disk
python -m eval.sweep --seeds 1..300                # benchmark (about 4 min on 8 cores)
python scripts/export_contract.py                  # regenerate contract/openapi.json after a deliberate contract change
```

Try it in the UI: **Open demo case** (seed 1), or **Generate a case nobody has seen** with any number, then
**Reveal the answer key**. **Investigate your own logs** accepts auth.log / access logs / CSV / JSONL.

## Architecture

```
 uploaded logs ─┐                        ┌─ sim/ generator (seed, knobs) ──► truth.json (hidden)
                ▼                        ▼  raw-format files only, no shared types
 INGEST  format sniffing · parsers · quarantine · parse report                      (backend/ingest)
 NORMALIZE  order · dedupe · ip→host · sessions + hop lineage                       (backend/normalize)
 BASELINE  first-seen history · warm-up · prior-login hour profile                  (backend/baseline)
 DETECT  D01–D11 · Sigma-style metadata · requires / produces predicates            (backend/detect)
 CORRELATE  predicate forward-chaining · gap bridges · ≥2-stage admission           (backend/correlate)
 RECONSTRUCT  steps · scenario-template titles · entry hypotheses · attack graph    (backend/reconstruct)
 EXPLAIN  evidence-cited claims · dismissals · caveats                              (backend/explain)
                ▼
 FastAPI (contract v1.0.0, contract/openapi.json)  ──►  React UI (frontend/)
                ▼
 REVEAL / BENCHMARK  verdict vs hidden truth · B0 / B1 baselines                    (eval/)
```

Key decisions and their reasons are in `docs/SPEC.md`; the research behind them is in `docs/RESEARCH.md`; the
UI rationale is in `docs/DESIGN.md`. A test enforces that the pipeline never imports the generator.

**Stack:** Python (standard library only in the engine), FastAPI, Pydantic v2, pytest + Hypothesis; React 18, Vite,
TypeScript, Tailwind CSS v4; Archivo and JetBrains Mono fonts (bundled via Fontsource). In-memory case store.

## Testing

72 tests:
- **Parsers:** golden lines for every parser, including awkward real-world lines.
- **Generator round trip:** every ground-truth line must parse into the right kind of event, under duplicates, shuffling, corruption, clock skew and log loss.
- **Property tests:** ingest never crashes and accounts for every line; normalize and the full pipeline are order-invariant.
- **Correlation:** no-bypass admission, session scoping, weak anchors, gap bridges, the ambiguity guard.
- **End to end:** detection on T1/T2/clean scenarios, API, contract freeze, and the benchmark harness itself.

The property tests found two real bugs during development, now fixed: blank-line accounting, and a parser crash on non-numeric byte counts.

## Prior art and credits

221B reimplements published ideas; no third-party security code or rule text is included.

- **Correlation model:** prerequisite/consequence alert correlation (Ning, Cui & Reeves, ACM CCS 2002).
- **Incident admission:** two or more stages, after Microsoft Sentinel Fusion's multistage incidents.
- **Risk ledger:** per-entity risk aggregation with distinct-tactic counting, after Splunk ES risk-based alerting.
- **Entity-pivot alert grouping and time-only baseline:** *Graph-Based Alert Contextualisation in SOCs* (arXiv 2509.12923).
- **Rule metadata:** Sigma rule format (SigmaHQ).
- **Forensic timeline:** Timesketch.
- **Event-log gap analysis:** Chainsaw.
- **Session waterfall:** Jaeger / OpenTelemetry trace views.
- **Event vocabulary:** Elastic Common Schema and OCSF.
- **Attack-sequence modelling:** CTID Attack Flow.

MITRE ATT&CK® tactic and technique names: © 2026 The MITRE Corporation. This work is reproduced and distributed
with the permission of The MITRE Corporation.

## AI assistance and data disclosure

- **AI assistance:** built during the event with AI coding assistance (Claude Code), used for design, implementation, tests and documentation. The team reviewed and directed the work and is responsible for it.
- **Data:** all scenario data is synthetic, produced by this repository's own generator (`sim/`). No third-party dataset is included or required.
- **External APIs:** none at runtime.
- **Third-party packages:** the open-source libraries listed in `pyproject.toml` and `frontend/package.json`, under their own licenses.

## Limitations and future work

- **No held-out evaluation yet.** All benchmark scenarios come from the generator the detectors were developed against. An attack pattern the detectors were not designed around, and labelled public data, are the next steps.
- **Single-stage blind spots by design.** An intruder who does only one thing (for example a valid-password login during normal hours followed by nothing suspicious) stays on the Watchlist or is cleared. A stolen-credential login during the victim's normal hours becomes an anchor only if a strong signal follows in that same session.
- **Known false-positive shape.** An administrator logging in at an odd hour from a new network and touching hosts for the first time can form an extra incident: 3 of 300 benchmark cases.
- **Concurrent sessions.** When the victim and the intruder use the same account on the same host at the same time, audit activity cannot be attributed to a session; 221B leaves it unattributed rather than guessing (1 of 300 cases still names an innocent address).
- **Baseline assumptions.** "Never seen" means never seen earlier in the supplied logs, after a 12-hour warm-up. Short captures get a weaker baseline, and the UI says so.
- **Formats.** No Windows EVTX parser yet. Year-less syslog timestamps borrow the year from other files (flagged on every affected event).
- **Storage.** The case store is in memory; restarting the server forgets cases.
