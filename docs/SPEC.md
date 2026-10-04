# 221B — Architecture & Product Specification
**ALGOTHON'26 · ALG-CYBER-01 "Find the Intruder"** · spec **v1.1** (research-informed; pre-implementation). Prior art, licensing and rationale for v1.1 changes: see `RESEARCH.md`. Change list: §21.

> Raw security events → suspicious signals → correlated entities → reconstructed attack sequence → identified intruder → evidence-backed explanation → live verification.

---

## 0. What the source material actually says (verbatim extraction)

### 0.1 ALG-CYBER-01 (problem statement PDF)
- **Overview:** "Thousands of security events can hide an attacker among normal activity. Build a system that identifies suspicious behavior from logs."
- **What to build:** "Analyze authentication, network or server logs to identify suspicious users/IPs, connect related events and create an incident timeline."
- **Must have (6):** Log ingestion · Anomaly detection/rules · Suspicious user/IP detection · Event grouping · Incident timeline · Evidence.
- **Innovation / Bonus:** "Connect multiple events and explain the likely attack sequence instead of flagging isolated events only."
- **Suggested tech:** Python, log analysis, anomaly detection, rules/ML, dashboard, database/search.
- **Judging focus:** "Detection quality, evidence, correlation across events and explainability."
- **Stated inputs/data:** **None.** Unlike DATA-01 ("Teams receive a large dataset"), CYBER-01 never says logs are supplied, nor in what format. → We must (a) bring our own data, (b) tolerate whatever the organizers might announce.

### 0.2 Common submission expectations (all 12 PS)
Working project with deployed demo where practical · source repo with clear README · **architecture diagram and explanation of major technical decisions** · demonstration of the core workflow · **testing evidence and handling of important edge cases** · **known limitations and future improvements** · **disclosure of external APIs, datasets and AI-assisted components** · equivalent technologies allowed.

### 0.3 Rubric
| Weight | Category |
|---|---|
| 30% | Functionality & Completion — "Does the core solution actually work?" |
| 20% | Technical Implementation — quality, architecture, appropriate technology |
| 20% | Innovation & Problem Understanding — originality and depth |
| 15% | UX / Presentation — clarity, usability, demo quality |
| 15% | Testing, Edge Cases & Reliability — robustness beyond the happy path |

### 0.4 Rule Book constraints that touch architecture or risk disqualification
| Rule | Consequence for us |
|---|---|
| 10:00 start · dev ends 22:00 · **submit by 23:00** · late = may be rejected | Hard freeze at 21:30. No new features after. Submit by 22:30. |
| Team ≤ 2; collusion to circumvent team size = DQ | Two humans max (AI doesn't count, but disclose it). |
| "Do not submit a project substantially completed before the hackathon"; disclose pre-existing code/templates | **Fresh repo created today**, `git init` now, commit early/often (timestamps are our evidence). Disclose scaffolding (Vite template, UI libs). |
| AI tools allowed; must disclose; "responsible for originality, functionality, accuracy and licensing" | README "AI & third-party disclosure" section. |
| Submitted project accessible to judges; private repos/broken links hurt | **Public repo + deployed URL that needs no login**; verify from an incognito window. |
| README must explain problem, solution, features, setup, technologies | Written from template at hour 9. |
| Only the final submitted version is evaluated | Tag `submission-v1`; don't push breaking changes after. |
| Public datasets must comply with licenses | Loghub (optional sanity check) is research/academic-use: **do not redistribute in repo**, fetch via script, disclose. Our own synthetic data is original. |
| Using MITRE ATT&CK names/IDs in the product | ATT&CK terms require the notice: "© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation." → UI footer + README. |
| Third-party security tools/rules (Hayabusa AGPLv3, Chainsaw GPL-3.0, Elastic rules ELv2, Wazuh GPLv2) | **Reimplement patterns; vendor no security-tool code or rule text.** Prior-art credits in README (see RESEARCH.md §10). |
| No attacking/overloading hackathon systems | Tool is purely defensive and offline: parses files, generates synthetic logs. No scanning anything. |
| Results 5 Oct 20:30; certificates subject to completion criteria | Submit properly even if the build is imperfect. |

### 0.5 Architectural consequences (derived, not assumed)
1. **No supplied data ⇒ we own the generator ⇒ we own ground truth.** This is both our biggest credibility gap (synthetic) and our biggest differentiator (provable detection). Design both sides on purpose.
2. **Unknown log formats ⇒ pluggable parsers + a generic mapper.** If the organizers (or a judge) hand us a file, it must ingest or fail *visibly*.
3. **"Evidence" is a must-have, not a nice-to-have** — it is one of six required features *and* a judging focus. Provenance is a first-class data structure, not a UI garnish.
4. **The bonus is about the *unit of output***: the product's primary object is an **Incident with an attack chain**, never an alert.
5. **Rubric 15% Testing** + "testing evidence" requirement ⇒ the evaluation harness is a shipped product feature (the "Verify" view), not a hidden folder.

---

## 1. Product definition

**Name:** **221B** — forensic incident reconstruction.

**One-line value:** *Give it a pile of logs; it tells you who got in, how, what they touched, and shows the proof line by line — and then proves it's not bluffing on a scenario you pick.*

**Core experience:** An investigation room, not an alert console. The user sees a single reconstructed breach with a verdict, a replayable attack path, and a dossier whose every sentence links to raw log lines.

**How it differs from a SIEM / anomaly dashboard**
| Typical submission | 221B |
|---|---|
| Flat list of anomalies (IsolationForest scores, table) | Incidents with ordered attack chains; alerts are intermediate only |
| "Suspicious IP" = loudest IP | Scoring rewards **consequence** (what happened *after* the signal), so loud-but-harmless sources rank low |
| Only says what it flagged | Explains **what it did NOT flag and why** (decoys, benign scanners, backup jobs) |
| LLM summary of anomalies | Deterministic claims; each carries evidence IDs; LLM (optional) can only rephrase and is validator-checked |
| Canned demo data | **Live verification**: generate an unseen scenario from a seed, analyze, reveal hidden answer key, show scorecard; plus a pre-run benchmark with honest misses |
| Hidden uncertainty | Confidence, alternate entry hypotheses, and **log gaps** are surfaced |

---

## 2. Primary user flows

1. **First launch** → Intake screen. Hero line: "Which one of these 1,847 alerts is the breach?" Three entry points: **Open demo case** (pre-baked, instant), **Drop log files**, **Generate scenario** (seed + difficulty sliders).
2. **Ingestion** → files land → format auto-detection per file → progress (SSE) → **Parse Report**: formats detected, lines parsed, N quarantined (with reasons), duplicates collapsed, time-skew flags. Nothing is silently dropped.
3. **Analysis** → pipeline stages animate as a funnel: `events → signals → linked signals → incidents`. Counts are real.
4. **Investigation Room** → ranked incident list (usually 1–3), verdict card for the top one.
5. **Attack reconstruction** → Replay view: stage-column graph + scrubber + kill-chain bar; narrative claims advance in sync.
6. **Intruder identification** → Suspects panel with *roles*: attacker infrastructure (IP), compromised account (user), pivot hosts, victim hosts, data touched. Entry vector with confidence and runner-up hypothesis.
7. **Evidence inspection** → click any evidence chip `[E-4f2a9c1d]` → drawer with raw line, ±5 lines context, the rule that fired, thresholds, baseline-vs-observed numbers.
8. **"Not flagged" tab** → dismissals with counter-evidence (e.g. "203.0.113.9: 4,812 failed logins, **0 successes**, no follow-on activity → noisy but unsuccessful").
9. **Naive-vs-reconstructed toggle** → top-bar switch re-renders the same data as flat isolated alerts, to make the bonus visually obvious.
10. **Bonus functionality** → alternate hypotheses, gap detection ("no sshd logs 03:41–04:07 on db-01 — chain has a hole here"), attack-stage coverage.
11. **Final verification** → *Verify* view: (a) "Reveal answer key" on the current scenario → match/miss per entity & stage + scorecard; (b) benchmark sweep table; (c) test-suite status; (d) limitations.
12. **Export** → incident report (Markdown; print-CSS PDF if time).

---

## 3. Application structure (UI)

**Stack:** Vite + React + TypeScript + Tailwind, served as static files by the FastAPI process (single deploy unit). No Next.js (SSR buys nothing here). Graph is **custom SVG + framer-motion** with a deterministic layered layout (no force-directed hairballs).

**Three top-level views + one drawer**
1. **Intake** (`/`) — launcher, parse report.
2. **Investigation Room** (`/case/:id`) — the product.
3. **Verify** (`/case/:id/verify`, plus `/verify` global benchmark) — proof & reliability.
4. **Evidence Drawer** — slide-over, available everywhere.
(*Methods/Architecture* is a static section inside Verify, so judges find the architecture diagram + limitations without leaving the app.)

**Investigation Room layout**
```
┌──────────────────────────────────────────────────────────────────────────────┐
│ FUNNEL STRIP   212,340 events ▸ 1,847 signals ▸ 31 linked ▸ 1 incident       │
│                                        [ Reconstructed ◉ | Naive alerts ○ ]  │
├───────────────┬──────────────────────────────────────────┬───────────────────┤
│ INCIDENTS     │ ATTACK REPLAY                            │ DOSSIER           │
│ ▸ INC-1  0.94 │ kill-chain bar: RECON·ACCESS·ESC·LAT·…   │ VERDICT card      │
│   INC-2  0.31 │                                          │  intruder / entry │
│               │ [stage columns, entity nodes, labeled    │  dwell / impact   │
│ SUSPECTS      │  edges, animate with scrubber]           │  confidence       │
│ ip 185.x  atk │                                          │ Tabs:             │
│ usr mkessler  │ ──●────────●──────────●─────  ▶ 03:12    │  Narrative        │
│   (comprom.)  │ SESSION WATERFALL (spans, pivots, marks) │  Score waterfall  │
│ host db-01    │                                          │  Not flagged      │
│   (victim)    │                                          │  Gaps/Caveats     │
└───────────────┴──────────────────────────────────────────┴───────────────────┘
```
**What a judge must grasp in 10 seconds:** the verdict card — *"Intruder: 185.220.x.x · entered 03:12 via stolen credential `mkessler` · reached `db-01` · 4.2 GB left at 04:51 · confidence 94%"* — and the funnel (212k → 1).

**v1.1 UI additions (from RESEARCH.md):**
- **Session-span waterfall** (Jaeger/Zipkin-style) replaces per-entity lanes: each session is a bar; a pivot is a child bar starting inside its parent; signals are markers on spans; repeated events collapse into a single "×11" summary edge/marker.
- **Incident title** comes from the matched scenario template (e.g. "Credential compromise → lateral movement → data exfiltration"), not an ID; unmatched chains are titled generically ("Multi-stage intrusion (unclassified)").
- **Suspects panel = entity risk ledger:** per-entity cumulative risk, distinct-stage count, host/user criticality badge, role (attacker infra / compromised account / pivot / victim). Sorted by chain-based score; ledger is the secondary lens.
- **Watchlist tab** next to Incidents: single-stage clusters (e.g. the loud never-succeeding brute-forcer) with the reason they were *not* promoted.
- **Event rows show signal chips** (detector-tagged events); Evidence Drawer shows the rule's `level`, `tags`, and `falsepositives` ("how this could be benign").
- **Footer:** ATT&CK copyright notice; link to Methods → prior art.

**Visual identity:** "forensic dossier." Near-black ink background, warm paper-white for dossier text, **one** signal color (vermilion) reserved for the compromise path. Type: serif for narrative headings, UI sans, mono for all evidence/log text. No neon, no Matrix rain, no globe. (Run `frontend-design` and `web-design-guidelines` skills on it at hour ~8.)

---

## 4. Backend architecture

**Stack:** Python 3.12 · FastAPI · Pydantic v2 · SQLite (+FTS5 for raw-line search) · pandas for vectorized detectors · uvicorn · single process, background thread per analysis with SSE progress. *Rejected:* Postgres, DuckDB, Kafka, Celery, microservices (all add setup risk with zero rubric payoff at ≤250k events).

**Pipeline (pure, deterministic, idempotent stages; each emits typed artifacts with provenance):**

```
Ingest ─► Normalize ─► Baseline ─► Detect ─► Correlate ─► Reconstruct ─► Score ─► Explain ─► Serve
```

| Module | Responsibility | In → Out |
|---|---|---|
| `ingest/` | Format detection (sniff N lines → parser confidence), line parsing, quarantine. | files → `RawEvent[]`, `QuarantineRow[]`, `ParseReport` |
| `normalize/` | UTC time normalization (per-source tz, skew flags), stable event IDs, dedupe, entity extraction (user/ip/host), session stitching. | `RawEvent[]` → `Event[]`, `Entity[]`, `Session[]` |
| `baseline/` | Per-entity behavioral profiles + rarity models (see §7). | `Event[]` → `Baselines` |
| `detect/` | Detector registry; each detector is `run(ctx) -> Signal[]`; every signal lists evidence event IDs and the features that triggered it. | `Event[]`,`Baselines` → `Signal[]` |
| `correlate/` | Entity graph, **predicate forward-chaining** (`requires/produces`), soft links, ActorCluster resolution, incident admission (≥2 stages) / Watchlist. | `Signal[]`,`Session[]` → `Incident[]` (unordered) |
| `reconstruct/` | Stage mapping, causal chain/DAG, entry-point hypotheses, gap detection, blast radius. | `Incident` → `Incident` with `AttackStep[]` |
| `score/` | Signal strength, consequence weighting, incident score, confidence. | → scores + `ScoreBreakdown` |
| `explain/` | Claims (templated), dismissals ("not flagged"), caveats; optional LLM rephrase + validator. | → `Claim[]`, `Dismissal[]` |
| `store/` | SQLite persistence, FTS5, evidence lookups. | — |
| `api/` | REST + SSE, serves SPA. | — |
| `sim/` | Scenario generator emitting **raw-format log files** + hidden `truth.json`. | `(seed, params)` → files + truth |
| `eval/` | Matches predictions to truth, computes metrics, sweeps seeds, baselines B0 (naive) / B1 (time-only) / B2 (221B). | → `report.json/md` |

**Design rule:** the generator writes logs in *real raw text formats* (sshd lines, nginx combined, CSV) and the pipeline ingests them exactly as an outsider's file. The pipeline never imports generator types. This kills the "you graded your own homework with shared data structures" objection.

---

## 5. Data model

All IDs are stable/deterministic so truth files, tests, and UI links survive re-runs.

```
Case(id, name, source: upload|scenario, scenario_seed?, scenario_params?, created_at, pipeline_version)

SourceFile(id, case_id, name, sha1, detected_format, parser_conf, lines_total, lines_parsed, lines_quarantined)

# Event vocabulary is ECS-aligned (docs/ecs_mapping.md): category ∈ {authentication, network, file, process, web, iam},
# outcome ∈ {success, failure, unknown}; field names map to ECS (source.ip, destination.ip, user.name, host.name, event.action).
Event(id "E-"+sha1(file_id|line_no)[:12], case_id, file_id, line_no,
      ts_utc, ts_original, tz_assumed, source_type[auth|web|net|fw|sys],
      host, user, src_ip, dst_ip, dst_port, session_id?,
      action[login|logout|sudo|su|useradd|group_add|http|conn|file_read|file_write|proc_exec|cron_add|key_add|log_clear|…],
      outcome[success|failure|unknown], object (path/url/service/cmd),
      bytes_in, bytes_out, user_agent?,
      raw_text, parse_flags[inferred_year|tz_assumed|skew_suspect|dup_collapsed|…])

QuarantineRow(file_id, line_no, raw_text, reason)

Entity(id "user:mkessler"|"ip:185.220.1.4"|"host:db-01"|"cluster:A1", type[user|ip|host|actor_cluster],
       first_seen, last_seen, attrs{role?, internal?, subnet?, criticality[low|med|high]?})
ActorCluster(id, member_ips[], linkage_evidence[{kind[ua|subnet|target_set|cadence|cred_list], weight}], total_weight)
                                             # v1.1: weighted entity resolution for IP rotation / distributed spray

Session(id, user, host, src_ip, t_start, t_end?, login_event_id, event_ids[])      # stitched

Baseline(entity_id, kind, stats{...})        # e.g. user login-hours histogram, usual src /24s, usual hosts,
                                             # host outbound-bytes median/MAD, sudo frequency

Signal(id "S-…", detector, stage_hint, entities[], t_start, t_end,
       severity (0..1), confidence (0..1), rarity (0..1), criticality_mult (≥1),
       requires[PredicateInstance], produces[PredicateInstance],        # v1.1: prerequisite/consequence model
       rule_meta{level, tags[], falsepositives[], references[]},        # v1.1: Sigma-style metadata
       features{}, evidence[EvidenceRef], explanation_template, explanation_params{})

PredicateInstance(name[credential_compromised|has_access|privileged|foothold|discovered|staged|exfiltrated|persisted],
                  args{user?, host?, ip?, resource?, dst?}, t)          # closed vocabulary (~8)

Link(signal_a, signal_b, kind[predicate|soft], via PredicateInstance?,   # hard link == predicate satisfaction
     reason[shared_session|ip_to_account|account_to_host|pivot_host|temporal_only…], weight)

Incident(id "INC-…", title, scenario_id?, signals[], entities[], t_start, t_end, steps[AttackStep],
         stages_covered[],                      # Incident ⇒ len(distinct stages) ≥ 2, all joined by predicate links
         watchlist_priority[normal|high]?,      # only when status=watchlist; high = confirmed-impact single-stage finding
         watchlist_reason?,
         score, confidence, entry_hypotheses[Hypothesis], gaps[Gap], status[incident|watchlist])

AttackStep(id, order, stage, t_start, t_end, actor_entity, target_entity, signal_ids[],
           event_ids[], edge_justification (predicate `via` instances))

Hypothesis(id, kind[entry], description, signal_ids[], probability)

Claim(id, incident_id, type[ENTRY|ACTION|PIVOT|ESCALATION|STAGING|EXFIL|GAP|CAVEAT|DISMISSAL],
      text, facts{}, evidence[EvidenceRef], confidence, step_id?)

Dismissal(id, entity, decision="not_flagged", reasons[], counter_evidence[EvidenceRef], would_flag_if)

EvidenceRef(event_id, role[supports|context|contradicts], note?)

ScoreBreakdown(incident_id, items[{signal_id, strength, consequence_factor, contribution}], bonuses[...], final)

-- verification side --
Scenario(id, seed, params{stealth, ip_rotation, noise, log_loss, clock_skew, dup_rate, attack_template}, n_events)
GroundTruth(scenario_id, attacker_ips[], compromised_users[], victim_hosts[],
            stages[{stage, t_start, t_end, event_refs[(file,line)]}], decoys[{entity, kind}])
EvalResult(scenario_id, metrics{...}, per_entity_matches, per_stage_matches, runtime_ms)
```

**Provenance chain:** `raw line → Event → Signal.evidence → AttackStep.signal_ids → Incident → Claim.evidence → Verdict`. Nothing exists in the UI that can't be walked back to a line.

---

## 6. API / module boundaries

**Contract-first.** Pydantic models in `core/models.py` → FastAPI emits OpenAPI → `openapi-typescript` generates TS types. **Freeze this by hour ~1.5**; engine and UI then build in parallel (UI against a saved `fixtures/demo_case.json` produced by an early stub pipeline).

```
POST /api/cases                         multipart files → {case_id}
POST /api/scenarios                     {seed, params} → {case_id}          # truth held server-side
GET  /api/cases/{id}/progress           SSE: stage, counts
GET  /api/cases/{id}/summary            funnel counts, parse report, quarantine summary
GET  /api/cases/{id}/incidents          ranked; ?status=incident|watchlist (watchlist = sub-threshold clusters with reasons)
GET  /api/cases/{id}/incidents/{iid}    steps, claims, hypotheses, gaps, score breakdown
GET  /api/cases/{id}/incidents/{iid}/replay   precomputed ReplayFrame[] (nodes/edges added per t)
GET  /api/cases/{id}/suspects           entities (incl. actor_clusters) with roles, chain score, risk ledger, criticality
GET  /api/cases/{id}/dismissals         "not flagged" + counter-evidence
GET  /api/cases/{id}/naive              flat per-signal alerts (baseline view)
GET  /api/cases/{id}/events             search (FTS5) + filters + cursor
GET  /api/cases/{id}/events/{eid}       event + ±N context lines + producing rule(s)
GET  /api/cases/{id}/entities/{type}/{id}   profile: baseline vs observed + mini timeline
POST /api/cases/{id}/reveal             scenario cases only → truth + per-entity/stage match + scorecard
GET  /api/eval/latest                   benchmark report (precomputed)
GET  /api/cases/{id}/report.md          export
```

**Internal interfaces** (all pure functions over typed models, unit-testable without HTTP):
```
parse(files)                   -> ParseResult
normalize(ParseResult)         -> NormalizedStore
build_baselines(store)         -> Baselines
detect(store, baselines)       -> list[Signal]            # Detector Protocol: name, stage_hint, run(ctx)
correlate(store, signals)      -> list[IncidentDraft]
reconstruct(store, draft)      -> Incident
score(incident, baselines)     -> Incident + ScoreBreakdown
explain(incident, store)       -> claims, dismissals
run_pipeline(case)             -> orchestrates the above, emits progress
```

---

## 7. Detection strategy (multi-signal, explainable)

**Principle:** many cheap, individually-weak, *explainable* detectors; the correlation layer — not any one detector — decides what matters. No detector output is shown as a verdict.

### 7.1 Detector catalog
| ID | Detector | Logic (deterministic) | Stage | Benign look-alike & guard |
|---|---|---|---|---|
| D01 | **Brute force** | ≥N failed auth, same src→same user/host, window W (N adaptive vs. baseline failure rate) | Recon / Cred. access | Typos: low N, single user, quickly followed by success from *same usual* IP → down-weight |
| D02 | **Spray / distributed** | one IP: many users, ≤k tries each; **or** many IPs each ≤k tries against the same target in W′ | Recon | Shared NAT: IP in baseline for many users |
| D03 | **Auth success after failures (pivot)** | success for U from X shortly after failures from X, or after failures against U from an IP cluster | **Initial access** | Typo-then-success from user's usual IP → rarity guard |
| D04 | **New-source login** | success for U from source (/24, or geo if available) with high surprisal in U's baseline | Initial access | Frequent travelers (high baseline source entropy) → down-weight |
| D05 | **Off-hours activity** | activity outside user's circular-hour profile, weighted by action sensitivity | (modifier) | Shift workers (profile handles) |
| D06 | **Privilege escalation** | first-time sudo/su-root, group add, new admin, useradd | Priv. esc. | Sysadmin burst: users with high baseline sudo frequency → low weight (**decoy**) |
| D07 | **Internal recon** | internal src touching ≥N distinct hosts/ports/paths in W (fw/auth/web 404s) | Discovery | Scheduled scanner: periodicity + no follow-on + dismissed with evidence (**decoy**) |
| D08 | **Lateral movement** | login to H by U from internal host S where (U,S→H) edge is new; chains S1→S2→S3 | Lateral | Admin jump-host usage in baseline |
| D09 | **Staging / collection** | mass file reads, archive creation (tar/zip/7z cmds), sensitive path access vs. baseline | Collection | Backup jobs (periodic, known account) |
| D10 | **Exfiltration** | outbound bytes (host/user) robust-z > k to dest not in baseline, off-hours | Exfiltration | Scheduled backup to known dest (**decoy**) → dismissal |
| D11 | **Persistence / evasion** | new authorized_keys, cron, account, auditd stop, log truncation | Persistence | Change windows from context |
| D12 | **Web attack patterns** *(optional)* | SQLi/traversal/webshell paths, scanner UAs in access logs | Initial access | Pen-test UA allowlist |

### 7.2 Anomaly layer (rubric: "Anomaly detection/rules")
- **Rarity (surprisal) model:** smoothed counts over `(user,src /24)`, `(user,host)`, `(host,dest)` → −log p. Used by D03/D04/D08/D10.
- **Robust stats:** median/MAD z-scores for volumes (bytes, failures/hr, file reads).
- **Circular-hour profiles** per user for D05.
- **Baseline policy:** (a) if the case has a known attack-free lead-in (generator guarantees ≥24h), baseline = lead-in; (b) else whole-dataset robust stats under an *explicit, UI-visible* "attacker is a small minority" assumption. **Known weakness:** baseline poisoning by a long-dwell attacker — listed in Limitations.
- **Optional experimental:** IsolationForest as a *corroborating* feature, flagged "experimental", default off. If time is tight, **cut** (adds opaque score, no rubric gain).

### 7.3 The central idea: consequence weighting
A signal's weight depends on what *follows* it through predicate links. Failed brute force with no success → κ=0.2. Same brute force followed by success → escalate → lateral → exfil → κ=1.0. This is what makes the loud decoy rank low *by construction*, not by hand-tuning.

> **Lineage (credit it, don't claim invention):** consequence weighting integrates (a) prerequisite/consequence alert correlation (Ning–Cui–Reeves 2002), (b) Splunk-style per-entity risk aggregation with its distinct-tactic threshold, and (c) Sentinel Fusion's multi-stage incident rule. Pure RBA-style *summation* is deliberately **not** the incident score — a loud decoy games it.

### 7.4 Detector contract (v1.1)
Every detector, code or YAML, must declare:
```
id, title, stage_hint, level, tags[], falsepositives[], references[]       # Sigma-style metadata → shown in the Evidence Drawer
requires[]  : predicate patterns that must already hold for the signal to be a *consequential* step
produces[]  : predicate instances the signal establishes (bound to its entities & time)
```
| Detector | requires | produces |
|---|---|---|
| D01 brute force | — | — (reconnaissance only; no consequence by itself) |
| D02 spray / distributed | — | — |
| D03 success after failures | — (links *back* to D01/D02 by entity) | `credential_compromised(user)`, `has_access(user, host, via_ip)` |
| D04 new-source login | — | `has_access(user, host, via_ip)` |
| D06 privilege escalation | `has_access(user, host)` | `privileged(user, host)` |
| D07 internal recon | `has_access(user, host)` or `foothold(host)` | `discovered(src, targets)` |
| D08 lateral movement | `has_access(user, host_src)` | `has_access(user, host_dst, via host_src)` |
| D09 staging | `has_access` or `privileged` on host | `staged(host, resource)` |
| D10 exfiltration | `has_access`/`privileged`/`staged` on host | `exfiltrated(host, dst, bytes)` |
| D11 persistence | `has_access(user, host)` | `persisted(host, mechanism)` |

**Criticality modifier:** hosts/users carry `criticality ∈ {low, med, high}` (db, bastion, admin accounts = high; set in scenario topology, or via optional context file for uploads, default `med`). Signal strength is multiplied by `criticality_mult` (1.0 / 1.15 / 1.35). Splunk/Elastic both weigh asset/identity priority; ours makes "blast radius" meaningful.

---

## 8. Correlation strategy

**Dimensions and how each is used**
| Dimension | Mechanism |
|---|---|
| Time | Adaptive window τ (default 6h, widening when chain has predicate links); soft-edge cut Δ=30 min. Time alone = **soft** link only. |
| Identity | `user` across sources (auth user, web basic-auth user, process owner). Alias map (e.g. `DOMAIN\user`, `user@corp`). |
| IP | Source IP → login success as user ⇒ **IP→account** predicate (`has_access`). Same /24 + same UA/cadence ⇒ linkage evidence toward an `ActorCluster` (IP rotation). |
| Host | Account → host (session) ⇒ `has_access(user,host)`; host-originated outbound login ⇒ **pivot** edge (`has_access` via host). |
| Session | Successful login opens a Session; subsequent events by (user,host) until logout/timeout are attributed to the session and thus to its originating `src_ip` → **actor thread**. |
| Privilege | Priv-change inside a session upgrades the session's actor privilege; later actions weigh more. |
| Data/volume | Staging on H followed by outbound bytes from H within window ⇒ `staged`→`exfiltrated` predicate link. |

**Algorithm**
1. Build entity graph from sessions and events (nodes: user/ip/host; edges carry event IDs).
2. **Predicate forward-chaining (v1.1, replaces ad-hoc hard-link rules).** Process signals in time order. Each signal's `produces[]` instances are added to a working set; a signal B is **hard-linked** to signal A iff A produced a predicate instance that satisfies one of B's `requires[]` (same bound entities, A.t ≤ B.t, within the adaptive window τ). The link stores `via` = that predicate instance, so every chain edge reads: *"D10 exfiltration from db-01 requires `has_access(mkessler, db-01)` — established by D08 at 03:41."* This is the Ning–Cui–Reeves model with a closed ~8-predicate vocabulary.
3. **Soft links** (shared entity + temporal proximity, no predicate) may only *attach* a low-weight signal to an incident; they never bridge two incidents. Cut soft edges whose gap exceeds Δ (default 30 min; entity-pivot grouping, per arXiv 2509.12923).
4. **Clustering & admission.** Union-find over **predicate links only**. **Definition (locked):** *An Incident requires ≥ 2 distinct attack stages connected by valid correlation predicates* (Sentinel Fusion rule). There is **no bypass**: a single-stage cluster is never an Incident, however severe. Everything else becomes a **Watchlist** item (`status=watchlist`): displayed, explained ("4,812 failures, 0 successes, no follow-on"), never silently dropped. A single-stage cluster containing a **confirmed-impact** signal (successful privilege escalation or exfiltration) is a **high-priority Watchlist item** (`watchlist_priority=high`): pinned to the top of the Watchlist and flagged in the UI, but still not an Incident. If later evidence (e.g. a second stage linked via a predicate) arrives, it is promoted.
5. **Causal-compatibility check:** stage order must be non-contradictory (Persistence/Discovery may appear anywhere after Initial Access; Exfiltration before any Initial Access ⇒ split).
6. **Weighted entity resolution → `ActorCluster` (v1.1).** To attribute IP rotation and distributed spray to one actor without a predicate link, sum linkage evidence between IPs: shared UA fingerprint, same /24, identical target set, matching cadence, shared credential list. Hand-set weights; merge into an `ActorCluster` when total ≥ threshold. ActorCluster is an *entity-level* attribution (shown in Suspects, collapses 40 IPs into one "attacker infrastructure" node); it never merges **incidents** by itself — incidents still require predicate links via the compromised account/session.
7. **Scenario templates (≈5, v1.1).** After chaining, match the ordered stage sequence against small declarative templates ("A following B", Fusion-style) — e.g. `credential_compromise → lateral_movement → data_exfiltration`, `bruteforce_success → persistence → exfiltration`, `web_exploit → webshell → pivot`. A match supplies the **incident title**, a confidence bonus and the narrative skeleton. No match ⇒ generic title ("emerging" path); the chain is still fully reconstructed.

**Event grouping (must-have):** Events → Signals (grouped by detector) → Incidents (grouped by correlation). Every level is browsable.

**Time robustness:** all ordering uses `ts_utc` with `(source, line_no)` as tie-break; pipeline is **order-invariant** (shuffle input → same output; property-tested). Per-source skew estimation (optional): align via matched auth pairs; otherwise flag `skew_suspect`.

---

## 9. Attack reconstruction

1. **Stage mapping:** every signal carries a `stage_hint` from a fixed taxonomy aligned to ATT&CK tactic names: `RECON → INITIAL_ACCESS → EXECUTION/FOOTHOLD → PERSISTENCE → PRIV_ESC → DISCOVERY → LATERAL_MOVEMENT → COLLECTION → EXFILTRATION`.
2. **Step formation:** within an incident, group signals by `(stage, actor, target host)` and time adjacency → `AttackStep`.
3. **Chain/DAG:** edge `step_i → step_j` exists only if justified by a **predicate link** (e.g. `has_access` via same session, `has_access` via pivot from host A, `staged` on H then `exfiltrated` from H). Edge justification is stored and shown on hover. Unjustified temporal adjacency is drawn **dashed** (visibly weaker).
4. **Entry hypotheses:** candidate initial-access signals → probability from (strength × predicate-linked downstream support). Top-2 reported; if margin < θ, the UI says "two plausible entry points."
5. **Initial-compromise designation:** earliest compromised entity on the winning hypothesis (account/host), with entry vector label (stolen credential / brute-force success / web exploit / unknown).
6. **Gap detection (v1.1: two mechanisms).**
   - **Unsatisfied prerequisite (primary):** a signal whose `requires[]` has no producer in the log (e.g. D10 exfil from db-01 as mkessler, but nothing establishes `has_access(mkessler, db-01)`) emits a `GAP` claim with the *hypothesized missing predicate*: "access to db-01 is implied but not logged — possible missing source or an unlogged technique." The edge is drawn dashed; confidence is reduced.
   - **Log silence (secondary, Chainsaw-style gap analysis):** if a host's source goes silent for > expected-rate interval around a chain edge, emit `GAP`: "no `auth` events from db-01 03:41–04:07 — possible missing log source; continuity inferred."
   *Honesty about holes is a feature.* Eval measures **gap-recall** against injected log loss.
6b. **Summary edges (KAIROS-style):** repeated identical edges collapse into one with count and time range ("×11 failed logins, 03:01–03:09"); the raw events remain one click away.
7. **Blast radius:** hosts reached, accounts used, volume exfiltrated, data paths touched.
8. **Dwell time:** first malicious signal → last.
9. **Replay frames:** precompute `ReplayFrame[t] = {nodes_added, edges_added, active_stage, claim_id}` so the frontend only plays them.

---

## 10. Evidence model

- `EvidenceRef{event_id, role, note}`; roles: `supports`, `context`, `contradicts`.
- **Every `Signal`, `AttackStep`, `Claim`, `Dismissal` carries evidence.** Invariant (tested): *no Claim without ≥1 existing event ID.*
- **Claims are structured** (`type`, `facts{}`, `evidence[]`), rendered from templates:
  > "At 03:12:04Z `185.220.x.x` authenticated to `web-01` as `mkessler` after 11 failed attempts over 9 min. `[E-4f2a9c1d]` `[E-91c0aa17]`"
- **Evidence chips** in text → **Evidence Drawer**: raw line (mono), ±5 context lines, parsed fields, the producing detector with thresholds and baseline-vs-observed numbers ("`mkessler` has logged in from 3 /24s in 41 days; this one: never seen; surprisal 11.3 bits").
- **Counter-evidence is shown**: `contradicts` refs and Dismissals.
- **Optional LLM layer:** input = the Claims JSON only; output = prose paragraph. **Validator:** every IP/user/host/number/time in the output must be in the allowed fact set, every sentence must keep ≥1 evidence ID; fail ⇒ fall back to template text. LLM is **off the critical path**; narrative is cached for demo cases. LLM never classifies, scores, or picks the attacker.

---

## 11. Bonus-criterion strategy (not an afterthought)

Bonus text: *"Connect multiple events and explain the likely attack sequence instead of flagging isolated events only."*

| Requirement fragment | Where it's built in |
|---|---|
| "Connect multiple events" | `correlate/` predicate-link graph (prerequisite/consequence chaining); Event→Signal→Incident hierarchy |
| "explain the likely attack sequence" | `reconstruct/` ordered `AttackStep` chain with justified edges + templated narrative |
| "likely" (uncertainty) | Entry hypotheses with probabilities, confidence, caveats, gaps |
| "instead of flagging isolated events only" | Primary UI object is the Incident; flat alerts exist only behind the **Naive** toggle, side-by-side proof |
| Prove it's better | Benchmark compares full pipeline vs. naive per-signal baseline on identical scenarios (alert compression, false-suspect rate, chain-order accuracy) |

---

## 12. Testing & reliability architecture

**Principle:** tests are built alongside the code and the headline results ship *inside the app* (Verify view).

| Layer | What | Notes |
|---|---|---|
| **Unit — parsers** | Golden lines per format incl. odd ones (IPv6, missing year, `Invalid user`, `message repeated N times`, UTF-8 junk) | quarantine, don't crash |
| **Unit — detectors** | Positive + negative fixtures per detector (incl. its benign look-alike) | |
| **Unit — normalize** | tz handling, dedupe, session stitching, stable IDs | |
| **Unit — correlation** | soft-only links never merge incidents; predicate link required; ≥2-stage admission vs Watchlist; ActorCluster never merges incidents; unsatisfied prerequisite ⇒ GAP | |
| **Property tests** (Hypothesis) | Order invariance (shuffle input ⇒ identical output); duplicate-injection idempotence; adding unrelated noise doesn't change top incident; every Claim has valid evidence; scores ∈ [0,1] | |
| **Integration** | Fixed seeds → golden snapshot of incident entities/steps | regenerate deliberately |
| **Adversarial scenarios** | low-and-slow (1 try/hr) · 40-IP distributed spray · IP rotation after success · valid account at normal hours (hard; expect lower confidence) · loud never-succeeding brute-forcer · benign periodic scanner · sysadmin sudo burst · backup job big transfer · traveling user · 20% log loss · ±7 min clock skew · 5% duplicates · shuffled order · 1% malformed lines · truncated file · mixed timezones · 100k-line single-IP flood · empty file · **clean (no attack)** | |
| **Ambiguity tests** | two plausible entry points ⇒ top-2 reported, confidence lower than on clean-cut cases | calibration sanity |
| **Eval sweep** | `python -m eval.sweep --seeds 1..300 --tiers easy,med,hard` vs **B0 naive per-signal**, **B1 time-window-only grouping**, **B2 221B** | outputs `docs/benchmark.md` + JSON consumed by the app |
| **Metrics** | attacker-IP recall · compromised-account recall · false-suspect rate · incident precision · **stage-order accuracy** (Kendall τ) · alert compression · **cluster purity** (share of an incident's signals that belong to the true attack) · **gap-recall** (injected log loss flagged as GAP) · time-to-detect · runtime · *breakdown by stealth tier and per template* | **Publish misses honestly** |
| **Reproducibility** | seeded RNG, pinned versions, `pipeline_version` stamp, `make bench` | |
| **Public-data sanity** *(optional)* | (a) **Loghub OpenSSH**: parser robustness only (no attack labels). (b) *Stretch:* a slice of **AIT Log Data Set v2.0** (auth + Apache logs, **line-level attack labels**; CC BY-NC-SA 4.0; whole set is 130.6 GB — only if a small slice is practical). Never committed; fetch-script; attribution in README | 30–60-min item, cut first |
| **E2E UI** | one Playwright smoke: open demo case → play replay → open evidence drawer → reveal | + `agent-browser` screenshots for README |

**Runtime targets:** parse+analyze 200k events < 15 s; replay interaction 60 fps on ≤ 30 nodes.

---

## 13. Scenario generator & live verification (the differentiator)

**`sim/` produces**
- Topology: ~12 hosts (bastion, web, app, db, file, workstations) with `criticality` (db/bastion = high), 30–60 users with role, criticality (admins = high) & working-hour profiles, ≥ 24 h of attack-free lead-in.
- Benign background: diurnal logins, cron/backups, web traffic, typos, VPN/travel, admin sessions.
- **Decoys (labeled in truth):** loud never-succeeding brute-forcer · periodic benign vuln scanner · sysadmin sudo burst · big scheduled backup · traveling user.
- **Attack templates (parametrized):** `T1` stolen-credential → quiet login → recon → priv-esc → lateral → staging → exfil · `T2` brute-force success on exposed SSH → persistence → lateral → exfil · `T3` web exploit → webshell → pivot *(important/optional)* · `T0` **clean** (no attack).
- **Difficulty knobs:** `stealth` (rate), `ip_rotation` (#IPs), `noise`, `log_loss %`, `clock_skew`, `dup_rate`, `shuffle`.
- **Outputs:** raw log files in native formats (+ `truth.json`, stored server-side, never visible to the pipeline). Truth references `(file, line)` pairs ⇒ stable event IDs.
- Deterministic: `random.Random(seed)`; ≤ 5 s for 200k events.

**Live-seed flow:** judge states a number → `POST /api/scenarios` → ingest/analyze → verdict → `POST /reveal` → side-by-side *Predicted vs Truth*: attacker IPs ✔/✘, compromised accounts ✔/✘, stage order, per-stage event overlap, alert compression, vs. B0/B1 baselines.

**Safety net:** run 2–5k seeds before the demo; fix every failure class; cap sliders at validated ranges; rehearse the miss path ("here is exactly where we fall short").

---

## 14. Scope control

### Absolutely essential (done by hour ~8; this is the minimum that still wins points)
- Pydantic models + OpenAPI contract; SQLite store
- Parsers: **sshd/auth.log**, **nginx/apache access**, **generic CSV/JSON (alias mapping)**; quarantine + parse report
- Normalize: UTC, stable IDs, dedupe, sessions
- Baselines: hour profile, source rarity, robust volume stats
- Detectors: D01, D02, D03, D04, D06, D07, D08, D10 (+D05 cheap)
- Correlation (predicate links + soft links, ≥2-stage admission/Watchlist), stage mapping, chain, scoring, claims with evidence
- Generator: T1 + T2 + clean, 5 decoys, difficulty knobs, truth
- UI: Intake · Investigation Room (funnel, incident list, suspects, replay, timeline, dossier, evidence drawer) · Reveal
- README + architecture diagram + limitations + AI/dataset disclosure · deploy

### Important (if the essentials are green)
- Benchmark sweep + B0/B1 baselines + **Verify** view
- Incident admission rule (≥2 stages) + Watchlist tab; scenario templates (≈5); entity risk ledger + criticality; ActorCluster
- Detector rule metadata (`falsepositives`) in Evidence Drawer; ECS mapping doc
- "Not flagged" dismissals with counter-evidence
- Entry hypotheses top-2; gap detection
- D09, D11; firewall/netflow CSV parser
- Property tests + adversarial suite
- Markdown report export; SSE progress; Naive/Reconstructed toggle
- `T3` template

### Optional
Attack-Flow-style JSON export · AIT-LDS slice validation · YAML rule loader for simple detectors · LLM narrative rephrase + validator · Windows Security parser · MITRE tooltips · impossible-travel with GeoIP · Loghub sanity check · PDF export · manual column-mapper UI · live-stream mode · D12

### Cut immediately when time gets tight (in this order)
1. LLM layer · 2. Live-stream mode · 3. Extra parsers · 4. D12/impossible-travel · 5. Entity profile pages · 6. PDF export · 7. IsolationForest (already off) · 8. Any *new* UI polish beyond replay + dossier

### Risk-reducing architectural decisions
Single process & SQLite · static SPA served by API · deterministic engine · contract-first with fixture JSON (UI never blocked) · generator emits real raw formats · demo case pre-baked into the Docker image · LLM off by default · feature flags per detector · `git init` now & commit hourly (also the "pre-existing code" defense).

### Things deliberately *removed* from the design
ML/deep anomaly detection as primary · LLM-as-detector / chat-with-logs · force-directed graph · world map/globe · live Kafka-style streaming · Postgres/Redis/Celery · multi-tenant/auth · containment actions · mobile layout.

---

## 15. Rubric mapping

| Rubric | Weight | What demonstrates it |
|---|---|---|
| Functionality & Completion | 30% | All six must-haves live: ingestion (3 formats + parse report), rules+anomaly detectors, suspect users/IPs with roles, event→signal→incident grouping, incident timeline, evidence drawer. Deployed, no-login demo. Works on uploads *and* generated scenarios. |
| Technical Implementation | 20% | Staged deterministic pipeline; session stitching; predicate-based correlation (prerequisite/consequence model); consequence-weighted scoring with waterfall; order-invariant & idempotent; contract-first API; architecture diagram. |
| Innovation & Problem Understanding | 20% | Incident-first design; "not flagged and why"; honest gaps/alternate hypotheses; live seeded verification with hidden answer key; naive-vs-reconstructed proof. Directly the stated bonus. |
| UX / Presentation | 15% | Verdict card readable in 10 s; replay + scrubber; sentence→raw-line evidence chips; forensic-dossier identity; 90-s video + rehearsed 4-min demo. |
| Testing, Edge Cases & Reliability | 15% | Verify view: benchmark over hundreds of seeds with misses shown; adversarial suite; property tests; quarantine of malformed input; clean-scenario false-positive rate; reproducibility stamp. |

---

## 16. Technical risks & failure modes

| # | Risk | Where it bites | Mitigation baked into design |
|---|---|---|---|
| 1 | **Synthetic-data circularity** ("you wrote both sides") | Judging | Generator → raw files → ordinary parser; truth hidden; randomized templates; adversarial knobs; judge-supplied seed; optional real-log sanity; accept arbitrary uploads |
| 2 | **Live seed fails** | Demo | Pre-sweep thousands of seeds; cap sliders to validated ranges; rehearsed graceful-miss narration; pre-baked demo case as fallback |
| 3 | Organizer logs in an unknown format | Functionality | Parser registry + generic CSV/JSON alias mapper; visible quarantine; (optional) column-mapper UI |
| 4 | False incident merges | Detection quality | Predicate link required; ≥2-stage admission; soft links only attach; ActorCluster is entity-level only |
| 5 | Baseline poisoning / no clean window | Detection quality | Lead-in baseline in scenarios; explicit assumption + limitation otherwise |
| 6 | Over-fitting detectors to own generator | Credibility | Held-out template (e.g. `T3`) never used for tuning; report per-template results |
| 7 | Hairball graph / UI clutter | UX | Incident subgraph only (≤ ~25 nodes), layered stage-column layout, deterministic positions |
| 8 | Scope explosion (12 detectors × UI × generator) | Completion | Essential/important/optional/cut tiers; kill-rule at hour 5 checkpoint |
| 9 | LLM hallucination / latency / key limits | Demo | Off critical path; validator; template fallback; cached narratives |
| 10 | Performance on 200k events | Demo | Pre-compiled regex, batch inserts, vectorized detectors, stage caching; perf test in suite |
| 11 | Deploy failure / broken public link | Judging (functionality) | Single Docker image with baked demo case; deploy skeleton in first hour; incognito check; local-run + video fallback |
| 12 | Cyber-literacy gap in judges | Judging | Plain-English claims; ATT&CK names only as small tags; verdict card first |
| 13 | "Just another dashboard" perception | Judging | Whodunit demo flow; Naive toggle; Verify view; evidence-by-sentence |
| 14 | Rule/license issues | Disqualification | Fresh repo + hourly commits; disclosures; Loghub not redistributed |
| 15 | Many competitors ship an LLM "attack story" (Elastic Attack Discovery-style) that looks similar at first glance | Judging (innovation) | Lead with what an LLM wrapper can't do: predicate-justified chains, Watchlist/"not flagged" explanations, GAP findings, live seed reveal, B0/B1/B2 benchmark; README "Prior art" shows we know the lineage |

---

## 17. Recommended project structure

```
Algothon Hackathon/221b/
├─ README.md                  # problem, solution, features, setup, tech, disclosures, limitations
├─ Dockerfile  Makefile  pyproject.toml
├─ docs/
│  ├─ SPEC.md                 # this file
│  ├─ RESEARCH.md             # prior art, licensing, rationale
│  ├─ ecs_mapping.md          # event vocabulary mapping
│  ├─ architecture.md + .png  # diagram + decisions
│  ├─ benchmark.md            # generated by eval.sweep
│  └─ limitations.md
├─ backend/
│  ├─ core/        models.py (Pydantic contract), ids.py, config.py
│  ├─ ingest/      registry.py, sshd.py, web_access.py, generic_csv.py, generic_json.py, [fw.py, winsec.py]
│  ├─ normalize/   time.py, dedupe.py, entities.py, sessions.py
│  ├─ baseline/    profiles.py, rarity.py
│  ├─ detect/      base.py (rule metadata + requires/produces), d01_bruteforce.py … d11_persistence.py, registry.py, rules/*.yaml (optional)
│  ├─ correlate/   predicates.py (requires/produces engine), links.py, cluster.py, actor_cluster.py, admission.py
│  ├─ reconstruct/ stages.py, chain.py, templates.py (scenario templates), hypotheses.py, gaps.py, replay.py
│  ├─ score/       scoring.py
│  ├─ explain/     claims.py, dismissals.py, narrative_llm.py (optional)
│  ├─ store/       db.py, schema.sql
│  ├─ api/         app.py, routes_*.py, sse.py
│  └─ pipeline.py
├─ sim/            topology.py, background.py, decoys.py, attacks/{t0_clean,t1_stolen_cred,t2_bruteforce,t3_web}.py,
│                  writers/ (sshd, nginx, csv), truth.py, cli.py
├─ eval/           match.py, metrics.py (purity, gap-recall), baselines.py (B0 naive, B1 time-only), sweep.py, report.py
├─ tests/          unit/, property/, integration/, adversarial/, golden/
├─ frontend/       src/{views,components,graph,state,api(generated types)}, fixtures/demo_case.json
├─ data/           demo_case/ (baked), seeds/validated_seeds.json     # no third-party datasets committed
└─ scripts/        fetch_loghub.py (optional), make_demo_case.py
```

---

## 18. Build plan (clock hours from 10:00)

| When | Goal | Gate |
|---|---|---|
| 0:00–0:45 | `git init`; scaffold; **freeze contract** (models + OpenAPI); deploy skeleton to public URL | skeleton live |
| 0:45–2:30 | Generator (T1+T2+clean+decoys+truth, raw-format writers) ‖ sshd/web/CSV parsers | files generate & parse |
| 2:30–5:00 | Normalize, baselines, essential detectors, correlation, reconstruction, scoring, claims; `eval` harness + first sweep. **In parallel:** UI against fixture JSON (shell, funnel, dossier, evidence drawer) | pipeline finds attacker on T1 |
| **5:00 checkpoint** | generator → detect → timeline → reveal works end-to-end. **If not: stop adding features.** | |
| 5:00–8:00 | Replay graph + scrubber + timeline lanes; Verify view; dismissals; hypotheses; adversarial + property tests; sweep tuning (held-out T3) | benchmark published |
| 8:00–9:30 | Naive toggle, gaps, report export, polish (frontend-design / web-design-guidelines passes), pre-sweep thousands of seeds | |
| 9:30–10:00 (21:30–22:00 wall) | **Freeze.** README, architecture diagram, 90-s video, deploy verification (incognito) | tag `submission-v1` |
| 22:00–23:00 | Submission buffer only. **Submit by 22:30.** | |

---

## 19. Final architecture (end to end)

```
 INPUTS                                                                     
 ┌────────────────────┐   ┌─────────────────────────────┐                   
 │ uploaded log files │   │ sim/ generator (seed+knobs)  │──► truth.json ──────────────┐
 │ auth.log · nginx · │   │ T0/T1/T2/T3 + decoys + noise │   (hidden, server-side)     │
 │ CSV · JSONL        │   └──────────────┬───────────────┘                             │
 └─────────┬──────────┘                  │ raw-format files (no shared types)          │
           └──────────────┬──────────────┘                                             │
                          ▼                                                            │
 ┌────────────────────────────────────────────────────────────────────────────┐        │
 │ INGEST   format sniff → parser registry → RawEvents  (+ quarantine, parse report)│   │
 └──────────────────────────────────┬─────────────────────────────────────────┘        │
                                    ▼                                                  │
 ┌────────────────────────────────────────────────────────────────────────────┐        │
 │ NORMALIZE   UTC · stable event IDs · dedupe · entities · session stitching     │        │
 └──────────────────────────────────┬─────────────────────────────────────────┘        │
                                    ▼                                                  │
 ┌──────────────────────┐   ┌──────────────────────────────────────────────┐          │
 │ BASELINE profiles,   │──►│ DETECT  D01..D11 → Signals (+evidence, features)│          │
 │ rarity, robust stats │   └──────────────────────┬───────────────────────┘          │
 └──────────────────────┘                          ▼                                   │
 ┌────────────────────────────────────────────────────────────────────────────┐        │
 │ CORRELATE  entity graph · predicate chaining (requires/produces) · ≥2 stages   │        │
 │            → Incidents (else Watchlist) · ActorCluster · scenario templates    │        │
 └──────────────────────────────────┬─────────────────────────────────────────┘        │
                                    ▼                                                  │
 ┌────────────────────────────────────────────────────────────────────────────┐        │
 │ RECONSTRUCT  stage map · justified chain/DAG · entry hypotheses · gaps · replay│        │
 └──────────────────────────────────┬─────────────────────────────────────────┘        │
                                    ▼                                                  │
 ┌────────────────────────────────────────────────────────────────────────────┐        │
 │ SCORE  strength × consequence · stage bonus · confidence · waterfall           │        │
 └──────────────────────────────────┬─────────────────────────────────────────┘        │
                                    ▼                                                  │
 ┌────────────────────────────────────────────────────────────────────────────┐        │
 │ EXPLAIN  Claims{evidence} · Dismissals · Caveats · (opt) LLM rephrase+validator│        │
 └──────────────────────────────────┬─────────────────────────────────────────┘        │
                                    ▼                                                  │
              SQLite (+FTS5)  ◄──►  FastAPI (REST + SSE)  ──►  React SPA               │
                                    │                         Investigation Room       │
                                    │                         Evidence Drawer          │
                                    ▼                         Verify                   │
                          ┌───────────────────┐                                        │
                          │ VERDICT           │◄───────── POST /reveal ◄───────────────┘
                          │ intruder · entry  │   compare predicted vs truth → scorecard
                          │ chain · confidence│   eval.sweep → benchmark.md (+ B0/B1)
                          └───────────────────┘
```

---

## 20. Self-critique (what I'm least sure about)
- **Detector count vs. time.** Eight essential detectors + generator + UI + eval in ~9 working hours is tight even with Claude Code. The 5:00 checkpoint is the safety valve; the order of cuts is in §14.
- **Geo/ASN realism.** Without a GeoIP DB, "new source" uses /24 rarity only. Fine for the rubric; "impossible travel" is therefore optional.
- **Calibration.** Confidence numbers are hand-built; the benchmark may reveal over-confidence. Show a small reliability table rather than claiming calibration.
- **Biggest hole in the story:** judges may still discount synthetic data. The live-seed reveal, the real-format round-trip, optional Loghub sanity check, and any organizer-supplied log are the answers — none is bulletproof. Say so in Limitations.

---

## 21. Changelog v1.0 → v1.1 (research-driven; rationale in RESEARCH.md §8, §11)

| # | Change | Where | Why |
|---|---|---|---|
| 1 | "Hard link" now **defined** as predicate satisfaction (`requires/produces`, ~8-predicate vocabulary) | §5, §7.4, §8, §9 | Ning–Cui–Reeves; makes edges self-explaining, testable, and gives gap detection for free |
| 2 | **Gap detection** = unsatisfied prerequisite (+ log-silence heuristic) | §9 | Principled; matches Chainsaw's gap analysis precedent |
| 3 | **Incident = ≥ 2 distinct stages joined by predicate links; no bypass.** Else **Watchlist**; confirmed-impact single-stage findings = **high-priority Watchlist** (clarified by owner, v1.1.1) | §8, §3 | Sentinel Fusion rule; cleanly handles the loud decoy |
| 4 | **Scenario templates** (~5) name incidents + add confidence; generic chaining stays as the "emerging" path | §8, §3 | Fusion "A following B" scenarios; judge comprehension |
| 5 | **Entity risk ledger**, distinct-stage count, **criticality** modifier | §3, §5, §7.4 | Splunk RBA / Elastic; secondary lens only (RBA summation is gameable) |
| 6 | **ActorCluster** weighted entity resolution (IP rotation / spray) | §5, §8 | Fraud/ER pattern; v1 would have fragmented distributed attacks |
| 7 | Detector **rule metadata** incl. `falsepositives` | §5, §7.4 | Sigma schema; feeds "how this could be benign" |
| 8 | **ECS-aligned** event vocabulary; detector-tagged events | §5, §3 | Industry vocabulary; Timesketch analyzers/tags |
| 9 | **Session-span waterfall** timeline + summary edges | §3, §9 | Jaeger-style readability; KAIROS-style summary graphs |
| 10 | Eval: **B1 time-only baseline**, **cluster purity**, **gap-recall**; AIT-LDS (stretch) replaces Loghub as "real data" check | §12, §13, §14 | arXiv 2509.12923 framing; Loghub has no labels |
| 11 | ATT&CK notice; prior-art credits; no third-party security code vendored | §0.4, §17 | Licensing (RESEARCH.md §10) |
| 12 | New risk row: competitors' LLM "attack story" lookalikes | §16 | Competitive analysis |

**Unchanged:** problem, product name, pipeline stages, tech stack, deterministic-core principle, generator/truth/reveal design, essential/important/optional/cut structure, 12-hour plan.

### v1.1.1 (implementation kickoff clarifications)
- **Admission rule locked** as above (no confirmed-impact bypass; high-priority Watchlist instead).
- **Event ID width 8 → 12 hex.** 8 hex (32 bits) gives ~4–5 expected collisions at 200k events (birthday bound); 12 hex makes it negligible. Display may truncate.
- **AIT-LDS stays a stretch goal only**; no early-hackathon time.
- `backend/` never imports `sim/` except `backend/api/routes_scenarios.py` (the server invoking the generator as a *data source*); enforced by a test. `sim/` may import the shared contract `backend.core.models` (params + truth only).
