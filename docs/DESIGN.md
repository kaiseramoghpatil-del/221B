# 221B — UI design plan

## Concept
**A forensic report you can interrogate.** The screen reads like the first page of a professional incident-response
report: the governing finding first, the exhibits that prove it, then numbered findings in which every sentence cites
log lines. It is light and calm on purpose. Most log tools ship a dark neon "SOC" dashboard, so 221B
should look like the work product of a serious forensic practice, not a game HUD.

Borrowed patterns (interaction and information hierarchy only, no visual copying):
| Source | Pattern taken |
|---|---|
| Big Four forensic / IR reports (secondary) | Governing thought first (the verdict sentence), "exhibits" with plain titles, numbered findings, a facts box, plain-English "why it matters" |
| Elastic Security / Sentinel incidents | Incident → entities → evidence hierarchy; incident vs alert separation; the Watchlist |
| Splunk ES risk-based alerting | Suspects as an entity risk ledger (role, chain score, risk over time) |
| Attack Flow | Attack sequence drawn as a left-to-right flow, not a hairball |
| Jaeger / OpenTelemetry | Waterfall: sessions as time-scaled bars, hops nested under their parent session |
| Timesketch | Every event row tagged by the detectors that touched it; story anchored to events |
| Sigma / Hayabusa / Chainsaw | Rule card (level, ATT&CK tags, false positives, references) next to the raw line, file:line provenance |

## Tokens
| Name | Hex | Role |
|---|---|---|
| Paper | `#F6F7F8` | app background (cool neutral, not cream) |
| Sheet | `#FFFFFF` | exhibit surfaces |
| Graphite | `#1C2128` | primary ink |
| Slate | `#5B6573` | secondary ink, axis labels |
| Rule | `#DCE0E5` | hairlines, lanes |
| Breach | `#B4152B` | **only** the attacker's path, attacker entities and the verdict's key nouns |
| Watch | `#9A6100` | watchlist / caution |
| Cleared | `#2F7D6D` | dismissed decoys, verified answer-key matches |

Type: **Archivo Variable** throughout (width axis is the expressive tool): the verdict headline at 75% width / 700,
section titles at 85% / 600, body at 100% / 400, figures at 75% with tabular numerals. **JetBrains Mono** only where
the content is literally machine text: raw log lines, file:line, event IDs, IPs.

## Layout (≥1280px)
```
┌ 221B  case name                    [ Reconstructed | Isolated alerts ]   Reveal answer key ┐
│ 48,753 events  ›  141 detector hits  ›  12 linked  ›  1 incident                           │
├──────────────┬─────────────────────────────────────────────────┬───────────────────────────┤
│ Incidents    │ VERDICT (one sentence, 75% width, 40px)         │ Findings                  │
│ Watchlist    │ Entry · Dwell · Hosts · Data out · Confidence   │  1 Password spray  [35]   │
│ Suspects     ├─────────────────────────────────────────────────┤  2 Entry          [1]    │
│  ledger      │ Exhibit A — Attack path (entity rows × stage    │  …                        │
│  sparklines  │ columns, one crimson thread, scrubber)          │ Gaps & caveats            │
│              ├─────────────────────────────────────────────────┤ Not flagged, and why      │
│              │ Exhibit B — Session timeline (waterfall)        │ How the score was built   │
└──────────────┴─────────────────────────────────────────────────┴───────────────────────────┘
Evidence drawer slides over the right column: claim → rule card → raw lines with context.
```
Everything is left-aligned. Below 1100px the columns stack: verdict, exhibits, findings, rail.

## Principles
1. **One bold thing:** the attack-path exhibit with its single crimson thread. Everything else stays quiet.
2. **Color is meaning:** crimson only for the attacker, amber for the watchlist, green for cleared/verified. No stage rainbow; stages are shown by position.
3. **Every sentence is clickable proof:** each finding opens its raw log lines.
4. **Plain words first, jargon second:** stage names in plain English, with the ATT&CK tactic as a small secondary tag.
5. **One orchestrated motion:** the replay. Nothing else animates on its own; `prefers-reduced-motion` disables it.

## Self-review against generic defaults (what changed)
- *Dark UI with a single neon accent* was the obvious move for "cyber" (and the spec v1 plan). **Changed** to a light report aesthetic. It is more legible on a projector and differentiates us from SOC dashboards.
- *Vermilion accent* → **crimson `#B4152B`** used only semantically, never decoratively.
- *All-caps eyebrows, "A · B" meta strings, mono for small labels* → **removed.** Facts sit in a grid with real labels; mono only for machine text.
- *Identical rounded cards* → **exhibits** (titled, ruled sections) and **lists**, with radius 4px on interactive controls only.
- *Numbered markers* are kept **only** for findings, because the findings really are an ordered attack sequence.
