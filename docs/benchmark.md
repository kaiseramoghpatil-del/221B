# 221B benchmark

Generated 2026-10-04T08:38:45+00:00 - pipeline 0.1.0 - 300 scenarios (252 attacks, 48 clean). Reproduce: `python -m eval.sweep`.

> Honesty note: the detectors were developed against this scenario generator. These numbers measure consistency and
> robustness to the difficulty knobs (stealth, IP rotation, log loss, clock skew, malformed lines), not real-world accuracy.

## 221B on attack scenarios

| Metric | Value |
|---|---|
| Compromised account found inside an incident | 100.0% |
| Entry IP identified | 100.0% |
| Host the data was taken from identified | 100.0% |
| Attack stages recovered | 96.2% |
| Steps in the right order | 99.7% |
| Incident signals that are real attack (purity) | 98.2% |
| Injected log gaps flagged | 91.0% |
| Innocent entities accused per run | 0.0079 |
| Extra incidents per attack run | 0.0119 |
| Clean runs with a false incident | 0.0% |
| Median end-to-end time | 5.3 s for 22,110 events |

## Same detector output, three readings

| Reading | Things to review per run | Attack stages in the best unit | Purity |
|---|---|---|---|
| B0 every hit is an alert | 25.57 | (one alert = one stage) | 37.5% precision |
| B1 group hits close in time | 16.2333 | 47.1% | 91.9% |
| **221B predicate-linked incidents** | 0.85 | 96.2% | 98.2% |

## By difficulty

| Tier | Runs | Detection | Entry IP | Stages | Gaps flagged | Clean false-incident |
|---|---|---|---|---|---|---|
| easy | 103 | 100.0% | 100.0% | 100.0% | n/a | 0.0% |
| medium | 107 | 100.0% | 100.0% | 99.5% | n/a | 0.0% |
| hard | 90 | 100.0% | 100.0% | 87.2% | 91.0% | 0.0% |

## Misses and imperfections

- seed 93 (T2, easy): extra incident(s): Account takeover → lateral movement
- seed 162 (T2, easy): extra incident(s): Account takeover → lateral movement
- seed 239 (T1, easy): extra incident(s): Account takeover → lateral movement
- seed 292 (T2, medium): 1 innocent entity named alongside the real attacker
