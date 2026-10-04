# 221B — Research: Prior Art, Proven Patterns, and What to Steal

**Purpose:** ground 221B's architecture in established security engineering before any code is written; identify where `SPEC.md` should change; avoid reinventing solved problems; avoid license mistakes.
**Date of research:** 2026-10-04 (ALGOTHON'26 day). Companion: `SPEC.md` (updated to v1.1 as a result of this document).

---

## 1. Executive summary

1. **The problem 221B attacks is a well-studied one with a name: *alert/event correlation and attack-scenario reconstruction*.** The industry answer (Splunk risk-based alerting, Microsoft Sentinel Fusion, Elastic Attack Discovery) is the same shape as our spec: *low-level detections → entity-mapped, stage-tagged findings → aggregated incidents*. The academic answer (prerequisite/consequence correlation, graph-based alert grouping, provenance-graph reconstruction) is also the same shape. **Our spec is directionally right; it is not novel in structure, and we should say so.** Our originality is in *integration, evidence discipline, and live verifiability*, not in inventing correlation.
2. **Five research findings change the spec materially** (details in §8 and §11):
   - **Formalize "hard links" as prerequisite/consequence predicates** (Ning–Cui–Reeves). Every detector declares what it `requires` and `produces` over entities (e.g. `has_access(user,host)`). Chain edges become *predicate satisfactions* — explainable by construction — and **gap detection falls out for free** (an unsatisfied prerequisite *is* a missing-log hypothesis).
   - **Incident admission rule** from Sentinel Fusion: an incident = **≥ 2 distinct kill-chain stages joined by correlation predicates**; single-stage clusters (the loud brute-forcer) go to a visible *Watchlist*, not the incident list. *(Owner clarification: no bypass — a confirmed-impact single-stage finding is a **high-priority Watchlist** item.)*
   - **Entity-level risk ledger** from Splunk RBA as a second lens (risk by entity over time, distinct-tactic count), plus **asset/identity criticality** as a risk modifier — while keeping chain-based scoring, because naive RBA *summation* is exactly what a loud decoy exploits.
   - **Weighted entity resolution** (fraud-style linkage) for attacker infrastructure: IP-rotation and distributed spray are resolved into an `ActorCluster` by summed linkage evidence, while *incident* merging still needs a predicate/hard link.
   - **Better baselines in eval:** add a **time-window-only grouping baseline** and **cluster purity** metric. A 2025 graph-alert-contextualisation paper reports 81.6% purity for entity-pivot grouping vs 30.4% for time-only — we should reproduce that *shape* of result on our own scenarios.
3. **Competitive reality check:** the cyber-log hackathon entries I could find are consistent with the prior suspicion — threshold rules (">10 failed logins", ">10 404s"), Isolation Forest, a chart dashboard, sometimes an LLM or blockchain buzzword. The *obvious* AI-assisted upgrade (feed alerts to an LLM, get an "attack story") is exactly what Elastic ships commercially as Attack Discovery, so expect many teams to do it. **Our differentiator must therefore be what an LLM wrapper cannot do: deterministic, evidence-checked chains and live verifiability.**
4. **Licensing:** the safe path is *reimplement patterns, copy no code*. Several of the best tools are copyleft or source-available (Hayabusa AGPLv3, Chainsaw GPL-3.0, Elastic detection-rules ELv2, Wazuh core GPLv2). Standards and schemas (OCSF, ECS, Attack Flow) are Apache-2.0 and safe to align with. ATT&CK use requires a copyright notice in the product.
5. **Better external-validity data than Loghub exists:** the **AIT Log Data Set v2.0** ships *ground-truth labels by log line number* with auth and Apache logs (CC BY-NC-SA 4.0). It is huge (130.6 GB compressed across eight datasets), so it's a stretch goal, not a plan.

---

## 2. Research sources and verification status

Legend: **[F]** = page fetched/read today · **[S]** = search-result summary only · **[K]** = background knowledge, *not* re-verified today (treat as hypothesis).

| # | Source | Status | Used for |
|---|---|---|---|
| 1 | ALGOTHON'26 Rule Book & CYBER-01 statement (project PDFs) | [F] | constraints, rubric (see SPEC §0) |
| 2 | Microsoft Learn — *Advanced multistage attack detection (Fusion)* — learn.microsoft.com/azure/sentinel/fusion | [F] | incident definition, tactic+entity mapping requirement, scenario templates |
| 3 | Splunk ES — *Risk scoring / risk-based alerting* — help.splunk.com (ES 8.4) | [F] + [S] | risk objects, intermediate findings, modifiers, thresholds, tactic-count rule |
| 4 | Elastic Security — *Attack Discovery* docs/blog | [S] | LLM-based alert→attack-chain narrative; asset criticality as input |
| 5 | Ning, Cui, Reeves — *Constructing attack scenarios through correlation of intrusion alerts*, ACM CCS 2002 (TR-2002-13) | [S] | prerequisites/consequences model |
| 6 | *Graph-Based Alert Contextualisation in SOCs* — arXiv 2509.12923 | [F] | entity-pivot alert graphs; purity 81.63% vs 30.35% time-only; AIT-LDS eval |
| 7 | KAIROS (arXiv 2308.05034), UNICORN (2001.01525) | [S] | provenance-graph IDS; compact summary graphs for reconstruction |
| 8 | OCR-APT — arXiv 2510.15188 | [F] | deterministic subgraph extraction + LLM narrative grounded in subgraph |
| 9 | HOLMES (IEEE S&P 2019), POIROT, ATLAS | [K] | TTP-mapped scenario graphs; query-graph alignment |
| 10 | Timesketch (Google) — github.com/google/timesketch | [F]+[S] | forensic timeline, tags, analyzers, stories; Apache-2.0 |
| 11 | Hayabusa (Yamato Security) | [F]+[S] | Sigma-based timeline generation; AGPLv3 code / DRL 1.1 rules |
| 12 | Chainsaw (WithSecure) | [F] | Sigma hunt/search; "analyse" incl. event-log **gap** detection; GPL-3.0 |
| 13 | Sigma rule format (SigmaHQ) | [S] | rule metadata schema; MIT code, DRL 1.1 rules |
| 14 | OCSF (ocsf.io) | [S] | normalized schema, authentication class; Apache-2.0 |
| 15 | Elastic Common Schema (ECS) | [S] | field/enum vocabulary; Apache-2.0 |
| 16 | CTID **Attack Flow** — github.com/center-for-threat-informed-defense/attack-flow | [F] | attack-sequence data model (action/asset/condition/operator); Apache-2.0 |
| 17 | MITRE ATT&CK Terms of Use | [F] | required notice |
| 18 | Elastic `detection-rules` repo | [F] | ELv2 — *do not copy* |
| 19 | Wazuh / Security Onion licenses | [S] | Wazuh core GPLv2; Security Onion reported as ELv2 (secondary source — verify before relying) |
| 20 | Loghub (logpai) | [S] | research/academic use, cite repo+paper; **no attack labels** |
| 21 | AIT Log Data Set v2.0 — zenodo.org/records/5789064 | [F] | line-level attack labels; CC BY-NC-SA 4.0; 130.6 GB |
| 22 | Splunk BOTS, LANL Unified Host & Network, DARPA OpTC | [S] | candidate datasets (see §10) |
| 23 | Hackathon entries: LogDefend.AI (Devfolio, AceHack 3.0), SentinelShield (Peerlist), Chagu (DEV), DEV log-analysis post | [F]/[S] | competitive pattern evidence |
| 24 | Survey: *AI-Driven Security Alert Screening and Alert Fatigue Mitigation in SOCs* — arXiv 2605.08316 | surfaced, **not read** | listed for later; no claims drawn |
| 25 | Jaeger/Zipkin trace waterfalls; OpenTelemetry span model; Splink/Fellegi–Sunter linkage; W3C PROV | [K] | UX pattern / linkage weights / provenance vocabulary |

**Honest limits:** I did not find a *verified list of winning* cyber hackathon projects. The competitive section is built from a thin sample of public entries plus the structure of the problem; it should be read as informed inference, not data.

---

## 3. Industry architecture findings

### 3.1 Microsoft Sentinel — Fusion (multistage attack detection) [F]
- **Solves:** alert fatigue; finds attacks visible only as combinations across kill-chain stages.
- **Pipeline:** source signals (product alerts, anomaly rules, scheduled analytics rules) → ML correlation engine → **Fusion incident**. Incidents "comprise two or more alerts or activities… low-volume, high-fidelity, high-severity." Trained on 30 days of history (per-environment baseline).
- **Data structures:** every contributing scheduled rule **must carry kill-chain tactics and entity mapping** to participate. Incidents live in a separate store from alerts (`SecurityIncident` vs `SecurityAlert`).
- **Representation:** scenario-named incidents built from "*X following Y*" templates (e.g. "Mass file download *following* suspicious sign-in"); plus an "emerging threats" mode for unknown combinations.
- **Explainability:** the incident name *is* the explanation (scenario template); contributing alerts listed.
- **Adapt (inspired pattern):** (a) **incident admission = ≥ 2 stages**; (b) **tactic + entity mapping mandatory on every Signal** (we already planned it — now enforced); (c) **declarative "A following B" scenario templates** used to *name* incidents and add confidence, with generic graph linking as the "emerging threats" fallback; (d) separate alert and incident stores.
- **Do NOT copy:** the ML engine (opaque, trained on tenant data) and cloud-product-specific scenarios. Proprietary — architecture informs, nothing to copy.

### 3.2 Splunk Enterprise Security — Risk-Based Alerting (RBA) [F]
- **Solves:** too many low-fidelity alerts; shifts from alert-per-detection to risk-per-entity.
- **Pipeline:** detections write **intermediate findings** (`entity`, `entity_type`, `risk_score`, `risk_message`, + ATT&CK tactic/technique) into a **risk index** → **risk incident rules** aggregate by entity over a window (default: score > 100 in 24 h; **> 3 distinct ATT&CK tactics in 7 days**) → notable finding.
- **Data structures:** risk object (system/user), **risk modifiers** (asset/identity priority), **risk factors** (multipliers on findings), thresholds.
- **Evidence:** analysts drill into contributing events from the risk object; scoring drivers visible over time.
- **Adapt (inspired pattern):** an **entity risk ledger** view (per-entity cumulative risk with contributing signals); **distinct-stage count** as a first-class incident feature; **asset/identity criticality** modifier (db/bastion/admin accounts weigh more).
- **Critique (important):** pure summation is *exactly what a loud decoy games* — 4,800 failed logins sum to huge risk. RBA's tactic-count threshold is the industry's patch for that. Our **chain/consequence weighting** is a stronger fix; keep it, use RBA as the second lens.
- **Do NOT copy:** index-and-SPL implementation; their rule content.

### 3.3 Elastic Security — Attack Discovery [S]
- **Solves:** triage by correlating alerts into attack chains with an LLM.
- **Pipeline:** select alerts via hybrid search → LLM groups into "discoveries" with narrative, involved users/hosts, ATT&CK mapping, possible threat actor; considers severity, risk scores, asset criticality.
- **Lesson for competition:** the *LLM-groups-alerts-into-a-story* approach is a shipped commercial feature, and trivially reproducible by any AI-assisted team. It is **not** a differentiator — and its weakness (nondeterministic, unverified grouping) is our wedge.
- **Adapt:** asset criticality as input (see 3.2). **Reject:** LLM as grouping/decision engine.

### 3.4 Timesketch (Google, Apache-2.0) [F]+[S]
- **Solves:** collaborative forensic timeline analysis.
- **Architecture:** web server + OpenSearch (events) + PostgreSQL (metadata) + Redis/Celery (async analyzers); ingestion of CSV/JSONL and Plaso output; **analyzers** that tag events; **stories** (narrative anchored to saved views); sketches; comments/stars; Neo4j graph view added later.
- **Adapt (inspired pattern):** **detectors tag events** (so any event row shows which signals/rules touched it → timeline filterable by tag); **dossier = story** anchored to event queries/IDs; CSV/JSONL generic ingest.
- **Reject:** the stack (OpenSearch+Postgres+Redis+Celery — overkill for ≤250k events), multi-user collaboration, Neo4j.

### 3.5 EDR/XDR incident graphs (Defender XDR, CrowdStrike-style "process trees") [K]
- Incident = alerts merged by shared entities (device, user, IP, file), shown as an **alert story / attack-path graph**, with "automatic investigation" tying entities to evidence.
- **Adapt:** entity-first incident merge (we have), "alert story" panel (we have: dossier). **Reject:** endpoint telemetry (process trees) — our input is auth/web/network logs.

### 3.6 Hayabusa / Chainsaw (Sigma-based fast forensics) [F]
- **Solve:** turn Windows event logs into a prioritized timeline/hunt results using Sigma rules.
- **Output pattern:** chronological timeline with **severity, rule reference, ATT&CK tactic**; Chainsaw also has an **"analyse" mode that detects event-log gaps** (a direct precedent for our gap detection).
- **Adapt (inspired):** the **timeline row shape** (time · host · user · rule · severity · tactic · evidence link); log-gap detection as a first-class forensic feature.
- **Do NOT copy:** code — Hayabusa is **AGPLv3**, Chainsaw **GPL-3.0**. Their Sigma-derived **rules** are DRL 1.1 (permissive with attribution) but target Windows EVTX, not our Linux/web inputs.

### 3.7 Sigma (SigmaHQ) [S]
- Generic YAML detection-rule format: `title, id, status, description, logsource, detection (selection/filter/condition), fields, falsepositives, level, tags`. Code MIT; rules under **DRL 1.1**.
- **Adapt (inspired pattern):** use Sigma's **rule metadata schema for *every* detector** — especially `falsepositives` and `level`/`tags` — so each signal can display "*why this could be benign*" (feeds the "Not flagged" and confidence UX). Optionally express the simple match-style detectors (privilege escalation, persistence, web patterns) as small YAML rules.
- **Reject:** a full Sigma engine/backends — they compile to SIEM query languages, not in-memory Python; large time sink for no rubric gain.

### 3.8 Schemas: OCSF and ECS (both Apache-2.0) [S]
- Normalized event vocabularies (OCSF authentication class: activity, status, user, endpoints; ECS `event.category/type/action/outcome`, `source.ip`, `user.name`, `host.name`).
- **Adapt:** align our `Event` **enumerations and field vocabulary with ECS** (categories: authentication / network / file / process / web / iam; outcome: success / failure / unknown) and ship a one-page mapping. Signals "we speak the industry's language" to judges for near-zero cost.
- **Reject:** adopting a full OCSF/ECS implementation or tooling.

### 3.9 Attack Flow (CTID, Apache-2.0) [F]
- Data model for **sequences of adversary behaviours** (objects: *action, asset, condition, operator*; STIX-based JSON schema; builder GUI).
- **Adapt (optional):** export an incident's chain as **Attack-Flow-style JSON** (steps→actions, entities→assets, branches→conditions/operators). Cheap credibility; **verify the exact schema at implementation time** — I confirmed the object names and license, not the full field list.

### 3.10 Observability tracing (Jaeger/Zipkin/OpenTelemetry) [K]
- A trace is a DAG of **spans** (start, duration, parent) rendered as a **waterfall**; known-readable UX for nested time/causality.
- **Adapt:** render the investigation timeline as a **session-span waterfall** — each session is a bar; a pivot is a child bar starting inside its parent; signals are markers on spans. Replaces bespoke "entity lanes" with a pattern engineers already read at a glance.

### 3.11 Fraud / entity resolution [K]
- Link records referring to the same actor via **weighted shared identifiers** (device, card, IP, phone); Fellegi–Sunter-style evidence weights summed against a threshold; blocking to limit comparisons; connected components → clusters.
- **Adapt:** an `ActorCluster` entity resolved by summed linkage weights (same UA fingerprint, same /24, same target set, cadence similarity, shared credential list). This is the principled answer to **IP rotation and distributed spray**. **Reject:** probabilistic training/EM; hand-set weights are fine.

---

## 4. Academic / technical findings

### 4.1 Prerequisite/consequence alert correlation — Ning, Cui, Reeves (CCS 2002) [S]
- **Idea:** model each attack/alert type ("hyper-alert") with **prerequisites** (conditions required for success) and **consequences** (conditions it establishes). Alert A links to B if a consequence of A satisfies a prerequisite of B, A precedes B. The result is a **correlation graph** = attack scenario.
- **Why it matters:** it gives "hard link" a *definition*, makes chain edges self-explaining, handles **missing detections** (an unsatisfied prerequisite signals something unseen), and is tiny to implement (forward chaining over a handful of predicates).
- **Adapt (inspired pattern):** `requires[] / produces[]` on every detector (see SPEC §5/§8).
- **Don't copy:** their formal predicate language/toolkit; ours is a closed vocabulary of ~8 predicates.

### 4.2 Graph-based alert contextualisation (arXiv 2509.12923, 2025) [F]
- **Approach:** alerts are nodes; link consecutive alerts sharing "timeline-defining" properties (user, IP, host); cut edges whose time gap exceeds Δ; groups = subgraphs. Graph Matching Networks compare groups to historical incidents.
- **Result:** cluster **purity 81.63% vs 30.35%** for time-only grouping on the AIT-LDS v2.0 alert set (2.66 M alerts, 8 scenarios). GMN scale problems >1,400 nodes.
- **Adapt:** (a) validates **entity-pivot linking over time-only**; (b) gives us **evaluation vocabulary** — *purity* and a *time-only baseline*; (c) the Δ-cut rule is a sane default for soft links.
- **Reject:** GMNs/neural matching — overkill, opaque, unnecessary for 12 h.

### 4.3 Provenance-graph intrusion detection and reconstruction — UNICORN, KAIROS, HOLMES, POIROT, ATLAS [S]/[K]
- **KAIROS:** GNN encoder–decoder over temporal provenance graphs; **reconstructs attack footprints as compact summary graphs**. **UNICORN:** graph sketching for runtime APT detection without signatures. **HOLMES** [K]: maps low-level provenance to ATT&CK-like TTPs and builds a **high-level scenario graph** with a noise-tolerant score. **POIROT** [K]: aligns an attack *query graph* from threat reports to the provenance graph.
- **Adapt (inspired):** the **summary-graph idea** — compress repeated edges (11 failed logins → one edge "×11, 03:01–03:09"); HOLMES-style **TTP→stage→scenario** layering (we have it); score tolerant of missing steps.
- **Reject:** GNNs, whole-system provenance capture (needs host audit data we don't have), query-graph alignment.

### 4.4 LLM-assisted reconstruction — OCR-APT (arXiv 2510.15188) [F]
- Deterministic anomalous-subgraph extraction → LLM turns *the extracted subgraph* into an attack story; hallucination controlled by grounding generation in the subgraph.
- **Adapt:** confirms our **deterministic core + constrained LLM** architecture and the validator idea. **Strengthen:** our validator is stricter (fact allow-list + per-sentence evidence IDs).

### 4.5 Log anomaly detection (DeepLog, LogBERT, template mining/Drain) [K]
- Sequence models over parsed log templates; useful for system-fault logs, weak for sparse, adversarial auth logs without labelled training data.
- **Reject:** as the core. **Maybe adapt:** *template mining* only for web/syslog grouping — not needed for sshd/nginx formats. Skip.

---

## 5. Open-source project findings (reuse view)

| Project | What it offers | Reuse verdict |
|---|---|---|
| Timesketch (Apache-2.0) | Timeline UX, analyzers→tags, stories | **Pattern only.** Stack is heavy; don't embed. |
| Attack Flow (Apache-2.0) | Chain data model + builder | **Pattern + optional export format.** Could use their JSON schema if time; verify first. |
| Sigma (MIT code / DRL 1.1 rules) | Rule schema, huge rule corpus | **Schema pattern.** Individual rules reusable with DRL attribution if ported. No engine. |
| Hayabusa (AGPLv3 code / DRL rules) | Timeline format, rule corpus | **Pattern only; no code.** |
| Chainsaw (GPL-3.0) | Hunt/search, log-gap analysis | **Pattern only; no code.** |
| Wazuh (core GPLv2) | Decoders/rules for auth logs, active-response ideas | **Pattern only.** Don't copy decoders/rules. |
| Elastic detection-rules (ELv2) | Rule library | **Do not copy.** Reading for ideas is fine. |
| Security Onion (reported ELv2 — verify) | Full SOC distro | Not applicable. |
| OCSF / ECS (Apache-2.0) | Schemas | **Align vocabulary.** |

Python libraries we *might* use (all permissive in my understanding [K], verify at install): FastAPI, Pydantic, pandas, NumPy, networkx (optional for graph ops), Hypothesis (property tests), pytest. Frontend: React, Vite, Tailwind, framer-motion (MIT). **No security-tool code is vendored.**

---

## 6. Hackathon / competitive findings

Evidence gathered (thin; see limits in §2):
- **LogDefend.AI** (Devfolio, AceHack 3.0, Apr 2024): Django, ML + NLP, charts; positioned as accessible log analysis for website owners; deliverables = charts, doc, slide deck. [F]
- **SentinelShield** (Peerlist): real-time WAF/security dashboard reading live server logs; **rule-based + Isolation Forest**; "built in 24 hours." [S]
- **Chagu** (DEV): "AI-driven" autonomous detection/response; **blockchain for tamper-proof audit trail.** [S]
- **DEV tutorial-style log tool:** fixed-threshold rules (>10 failed logins; >10 404s; >5 server errors per IP). [S]

**Recurring patterns (the baseline we must beat):**
1. Fixed-threshold rules per event type — each flags isolated IPs.
2. Isolation Forest/one-class model → anomaly table + chart.
3. Real-time dashboard with counters and a world map.
4. "AI" bolt-on: LLM summary or chatbot; sometimes blockchain "tamper-proofing" as a buzzword.
5. Demo on a *single canned log file* with no ground truth and no false-positive analysis.
6. Graph visuals that render nodes/edges with no causal justification.

**What we infer about the field (inference, not data):** with ~700 AI-assisted teams, many CYBER-01 entries will be a polished version of (1)–(4) plus an LLM "attack narrative" (the Elastic-style move). They will look good and be unverifiable.

**Where 221B is meaningfully different, grounded in the research:**
| Typical entry | 221B | Research backing |
|---|---|---|
| Isolated anomalies | Incidents with predicate-justified chains, ≥2-stage admission | Fusion; Ning et al. |
| Loudest = most suspicious | Consequence-weighted; loud-no-success → Watchlist with explanation | RBA critique; Fusion |
| LLM decides/groups | Deterministic core; LLM only rephrases, validated | OCR-APT grounding; Elastic as cautionary precedent |
| No ground truth | Seeded scenarios, hidden answer key, line-level truth, purity/recall vs time-only and naive baselines | arXiv 2509.12923 metric framing |
| Hides gaps | Gap = unsatisfied prerequisite, reported as a finding | Ning et al.; Chainsaw gap analysis |
| Canned demo | Judge-chosen seed + live reveal | (our own; no precedent found) |

**Do not reproduce** any specific submission; they are cited for pattern awareness only.

---

## 7. Pattern-by-pattern comparison

| Pattern | Source | Value to rubric | Cost (12 h) | Class | Decision |
|---|---|---|---|---|---|
| Prerequisite/consequence predicates | Ning et al. | Correlation, explainability, gaps | Low–Med | Inspired | **ADOPT (core)** |
| ≥2-stage incident admission + Watchlist | Fusion | Detection quality, FP control | Low | Inspired | **ADOPT** |
| Declarative scenario templates ("A following B") for naming/confidence | Fusion | Judge comprehension, explainability | Low | Inspired | **ADOPT (small set ~5)** |
| Entity risk ledger + distinct-stage count | Splunk RBA | UX, scoring | Low–Med | Inspired | **ADOPT** |
| Asset/identity criticality modifier | Splunk, Elastic | Realism, blast radius | Low | Inspired | **ADOPT** |
| Weighted entity resolution → ActorCluster | Fraud/ER | Handles IP rotation/spray | Med | Inspired | **ADOPT (hand-weighted)** |
| Time-only baseline + purity metric | arXiv 2509.12923 | Testing, innovation proof | Low | Inspired | **ADOPT** |
| Summary-edge aggregation in graph | KAIROS | UX clarity | Low | Inspired | **ADOPT** |
| Sigma-style rule metadata (`falsepositives`, `level`, `tags`) | Sigma | Explainability | Low | Inspired | **ADOPT** |
| YAML rules for simple detectors | Sigma | Extensibility optics | Med | Inspired | Optional |
| ECS-aligned vocabulary | ECS/OCSF | Credibility | Low | Open standard | **ADOPT** |
| Detector-tagged events | Timesketch | Evidence UX | Low | Inspired | **ADOPT** |
| Session-span waterfall timeline | Jaeger-style | UX clarity | Med | Inspired | **ADOPT** |
| Attack-Flow-style JSON export | CTID | Standards credibility | Low–Med | Open source (Apache) | Optional |
| Log-gap detection | Chainsaw, Ning | Reliability, honesty | Low (given predicates) | Inspired | **ADOPT** |
| Labeled real dataset check (AIT-LDS) | AIT | External validity | High (size) | Open data (NC-SA) | Stretch |
| LLM narrative w/ grounding + validator | OCR-APT | Presentation | Low–Med | Inspired | Optional (as planned) |
| GNN/GMN/Isolation-Forest-as-core | KAIROS/arXiv/commons | — | High | — | **REJECT** |
| Full Sigma engine / SIEM stack | Sigma/Timesketch/Wazuh | — | High | — | **REJECT** |

---

## 8. Recommended patterns for 221B (and exact spec impact)

1. **Predicate-based correlation.** Closed vocabulary of ~8 predicates over entities:
   `credential_compromised(user)`, `has_access(user, host, via_ip)`, `privileged(user, host)`, `discovered(src, targets)`, `staged(host, resource)`, `exfiltrated(host, dst, bytes)`, `persisted(host, mechanism)`, `foothold(host)`.
   Each detector declares `requires[]` and `produces[]`. A **hard link A→B** exists iff A produces a predicate instance that satisfies B's requirement (same entities, A before B). *SPEC §5, §8, §9 updated.*
2. **Gap detection = unsatisfied prerequisite.** If D10 (exfil from db-01 as mkessler) requires `has_access(mkessler, db-01)` and nothing in the log supplies it, emit a `GAP` claim ("access to db-01 is implied but not logged") plus the log-silence heuristic. *SPEC §9.*
3. **Incident admission rule (locked):** an Incident requires ≥2 distinct attack stages connected by valid correlation predicates. Everything else → **Watchlist** (still displayed, explained, never silently dropped); a confirmed-impact single-stage finding is a **high-priority Watchlist** item, not an Incident. *SPEC §8, §3.*
4. **Scenario templates (≈5)** — declarative ordered patterns used to *name* incidents and add confidence (e.g. "Credential compromise → lateral movement → data exfiltration"). Generic predicate chaining handles unmatched sequences ("emerging"). *SPEC §9.*
5. **Entity risk ledger + criticality.** Per-entity risk timeline and distinct-stage count in the Suspects panel; host/user `criticality` (db, bastion, admin) multiplies severity. Chain scoring stays primary. *SPEC §5, §7, §3.*
6. **ActorCluster entity resolution** by weighted linkage (shared UA fingerprint, /24, target set, cadence, credential list). Incident *merging* still needs a predicate link. *SPEC §8.*
7. **Rule metadata on every detector** (`level`, `tags`, `falsepositives`, `references`) → shown in the evidence drawer and "Not flagged". *SPEC §7.*
8. **ECS-aligned event vocabulary** + mapping table. *SPEC §5.*
9. **Detector-tagged events** (event rows show contributing signal chips; timeline filters by tag). *SPEC §3, §5.*
10. **Session-span waterfall** timeline and **summary edges** in the replay graph. *SPEC §3, §9.*
11. **Evaluation upgrades:** baselines **B0 naive per-signal**, **B1 time-window-only grouping**, **B2 221B**; add **cluster purity**, **incident precision**, **gap-recall** (did we flag the log-loss we injected?). *SPEC §12, §13.*
12. **Compliance footer:** ATT&CK copyright notice; dataset/attribution section. *SPEC §0.4, README.*

---

## 9. Patterns explicitly rejected (and why)

| Rejected | Why |
|---|---|
| GNN/Graph Matching Networks (KAIROS, arXiv 2509.12923) | Opaque, needs training data, scalability caveats the paper itself reports; zero explainability gain over predicates. |
| Isolation Forest / autoencoders as the core | Produces the "anomaly table" every competitor ships; unexplainable; poor on adversarial sparse auth data. (Allowed only as a default-off corroborating feature.) |
| LLM as grouping/attack-identification engine (Elastic Attack Discovery style) | Nondeterministic, unverifiable, and the obvious thing every AI-assisted team will do. OCR-APT shows even research systems keep the LLM downstream of deterministic extraction. |
| Embedding Timesketch/OpenSearch/Postgres/Redis/Celery | 12 h budget; all infra, no rubric gain. |
| Full Sigma engine / pySigma backends | Targets SIEM query languages, not in-memory Python; heavy; marginal value. |
| Whole-system provenance/process-tree modelling | Needs endpoint audit data; our inputs are auth/web/network logs. |
| Pure risk-sum scoring (RBA-style) as the incident score | Gamed by loud, unsuccessful sources. Kept only as a secondary lens. |
| World map / threat-intel feeds / live streaming | Buzzword features, no support from the problem statement or research. |
| Blockchain "tamper-proof logs" | Seen in competing entries as a buzzword; irrelevant to detection quality. |
| Copying any rule corpus (Elastic ELv2, Wazuh GPL) | License risk. |

---

## 10. Licensing / attribution notes

| Item | License | What we may do | Obligation |
|---|---|---|---|
| Sigma rule format & code | MIT (code) · DRL 1.1 (rules) | Reuse schema ideas; port individual rules | Attribute rule authors if any rule text is ported |
| Hayabusa | **AGPLv3** code · DRL 1.1 rules | Ideas only; port DRL rules with attribution | **Do not copy code** (network copyleft) |
| Chainsaw | **GPL-3.0** | Ideas only | Do not copy code |
| Wazuh core | **GPLv2** (OSSEC-derived) | Ideas only | Do not copy decoders/rules |
| Elastic detection-rules | **Elastic License v2** | Read for ideas | **Do not copy** |
| Security Onion | reported ELv2 (secondary source) | N/A | verify if ever relevant |
| Timesketch | Apache-2.0 | Ideas; could reuse with notice | Preserve notices if code reused (we won't) |
| Attack Flow | Apache-2.0 | Use schema/format if exporting | Preserve notice, state changes |
| OCSF, ECS | Apache-2.0 | Align vocabulary | Cite in docs |
| MITRE ATT&CK | Royalty-free with notice | Use tactic/technique names/IDs | Include: *"© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation."* |
| Loghub | Research/academic use; **cite repo + paper** | Optional parser-robustness check | Don't redistribute in repo; cite Zhu et al., ISSRE 2023 |
| **AIT Log Data Set v2.0** | **CC BY-NC-SA 4.0** | Optional validation slice (non-commercial hackathon use) | Attribute; share-alike on derivatives; don't redistribute data |
| Splunk BOTS | CC0-style per Splunk blog, needs Splunk to load | Not planned | — |
| DARPA OpTC | "approved for public release" | Not planned (endpoint-level) | — |
| LANL Unified Host & Network | terms not verified | Not planned | — |
| Competitor hackathon projects | — | Study only | **Never reproduce** |

**Process rules:** (1) no third-party security code vendored; (2) every borrowed *idea* gets a one-line credit in README → "Prior art & inspirations"; (3) AI-assistance disclosure per Rule Book §4/§5; (4) the scenario generator, detectors, correlator, UI are written from scratch during the event.

---

## 11. Final architectural recommendations

**Keep (research confirms):** staged deterministic pipeline; entity-mapped, stage-tagged Signals; Incidents separate from Signals; deterministic core with a constrained, validated LLM downstream; baselines per environment; evidence IDs everywhere; seeded scenarios with hidden truth.

**Change (research-driven, now in SPEC v1.1):**
1. **Predicate-based hard links** (`requires/produces`) replace ad-hoc "hard link reasons".
2. **Gap = unsatisfied prerequisite** (plus log-silence heuristic).
3. **Incident admission ≥2 stages**, otherwise **Watchlist**.
4. **Scenario templates** for naming/confidence; generic chaining for the unknown.
5. **Entity risk ledger + criticality** as a second lens.
6. **ActorCluster** (weighted entity resolution) for IP rotation/spray.
7. **Rule metadata** incl. `falsepositives` on every detector.
8. **ECS-aligned vocabulary**; detector-tagged events.
9. **Session-span waterfall** + summary edges.
10. **Eval:** B0/B1/B2 baselines, purity, gap-recall; AIT-LDS (stretch) replaces Loghub as the "real data" check since it has line-level labels.
11. **Compliance:** ATT&CK notice, prior-art credits.

**Where I challenge my own SPEC v1:**
- "Hard link" was undefined hand-waving → now defined (predicates).
- "≥1 hard link to merge" left **distributed spray** fragmented and said nothing about *campaign-level* attribution → fixed by ActorCluster.
- The consequence-weighting idea is **not novel** — it's RBA-meets-Fusion-meets-Ning. We should *cite* that lineage and claim integration, not invention.
- Loghub as the real-data check had **no labels**, so it could not support any quantitative claim → replaced.
- We lacked a **time-only baseline**; without it, "correlation helps" isn't demonstrated.
- Unverified in this pass: Hayabusa's full output profile, Attack Flow's exact schema, Security Onion's license, pySigma's license, the content of the arXiv alert-fatigue survey. None are on the critical path.

**Residual risks (research did not remove them):** synthetic-data skepticism; detector count vs time; hand-set weights uncalibrated; AIT-LDS too large to use practically in-event.

---

## 12. What 221B should steal from the world

1. **Prerequisites → consequences as the correlation primitive** (Ning–Cui–Reeves, 2002). Every chain edge is a satisfied predicate; every hole is an unsatisfied one.
2. **Incidents ≠ alerts, and an incident needs ≥ 2 kill-chain stages** (Sentinel Fusion). Single-stage noise goes to a Watchlist.
3. **Tactic + entity mapping mandatory on every finding** (Fusion, Splunk RBA) — enforced in the Signal schema.
4. **"A following B" scenario templates to name incidents** (Fusion) — judges read "Credential theft followed by data exfiltration," not "INC-0017."
5. **Risk per entity, over time, with distinct-stage counts** (Splunk RBA) — as the Suspects lens, not the incident score.
6. **Asset/identity criticality as a risk modifier** (Splunk, Elastic) — makes blast radius mean something.
7. **Entity-pivot grouping beats time-only grouping — prove it** (arXiv 2509.12923): ship the time-only baseline and report purity.
8. **Weighted entity resolution for actor attribution** (fraud/ER) — resolves rotating IPs into one `ActorCluster`.
9. **Deterministic extraction, then LLM narrates only what was extracted** (OCR-APT; Elastic as the cautionary opposite).
10. **Summary graphs: collapse repeated edges** (KAIROS) — "×11 failed logins" is one edge, not eleven.
11. **Detectors tag events; the story is anchored to events** (Timesketch analyzers/tags/stories).
12. **Log-gap detection as a forensic feature** (Chainsaw `analyse`) — reported as a finding, not hidden.
13. **Sigma-style rule metadata, especially `falsepositives`** — every signal explains how it could be benign.
14. **Waterfall timelines for nested causality** (Jaeger/Zipkin) — sessions as spans, pivots as children.
15. **Speak the standards** (ECS/OCSF vocabulary, ATT&CK tags with notice, optional Attack-Flow-style export) — cheap credibility with security-literate judges.

---

*Sources (URLs):* learn.microsoft.com/en-us/azure/sentinel/fusion · help.splunk.com/en/splunk-enterprise-security-8/administer/8.4/risk-based-alerting · elastic.co/guide/en/security/current/attack-discovery.html · arxiv.org/html/2509.12923v2 · arxiv.org/pdf/2308.05034 · arxiv.org/pdf/2001.01525 · arxiv.org/pdf/2510.15188 · dx.doi.org/10.1145/586110.586144 · github.com/google/timesketch · github.com/Yamato-Security/hayabusa · github.com/WithSecureLabs/chainsaw · github.com/SigmaHQ/sigma · spdx.org/licenses/DRL-1.0 · github.com/ocsf · github.com/elastic/ecs · github.com/center-for-threat-informed-defense/attack-flow · attack.mitre.org/resources/legal-and-branding/terms-of-use/ · github.com/elastic/detection-rules · github.com/logpai/loghub · zenodo.org/records/5789064 · devfolio.co/projects/logdefendai-c686 · peerlist.io/dnyaneshwar55/project/sentinelshield · dev.to/taimax13/building-chagu-… · dev.to/atenahfr/how-i-built-a-log-analysis-tool-to-detect-network-anomalies-45ed
