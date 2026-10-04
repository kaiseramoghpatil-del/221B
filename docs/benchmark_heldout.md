# 221B benchmark

Generated 2026-10-04T11:03:36+00:00 - pipeline 0.1.0 - 90 scenarios (90 attacks, 0 clean). Reproduce: `python -m eval.sweep`.

> Honesty note: the detectors were developed against this scenario generator. These numbers measure consistency and
> robustness to the difficulty knobs (stealth, IP rotation, log loss, clock skew, malformed lines), not real-world accuracy.

## 221B on attack scenarios

| Metric | Value |
|---|---|
| Compromised account found inside an incident | 0.0% |
| Entry IP identified | 0.0% |
| Host the data was taken from identified | 0.0% |
| Attack stages recovered | 1.1% |
| Steps in the right order | 100.0% |
| Incident signals that are real attack (purity) | 0.0% |
| Injected log gaps flagged | 0.0% |
| Innocent entities accused per run | 0.0444 |
| Extra incidents per attack run | 0.0222 |
| Clean runs with a false incident | n/a |
| Median end-to-end time | 12.3 s for 22,072 events |

## Same detector output, three readings

| Reading | Things to review per run | Attack stages in the best unit | Purity |
|---|---|---|---|
| B0 every hit is an alert | 21.6889 | (one alert = one stage) | 17.5% precision |
| B1 group hits close in time | 14.8889 | 64.7% | 90.2% |
| **221B predicate-linked incidents** | 0.0222 | 1.1% | 0.0% |

## By difficulty

| Tier | Runs | Detection | Entry IP | Stages | Gaps flagged | Clean false-incident |
|---|---|---|---|---|---|---|
| easy | 34 | 0.0% | 0.0% | 0.0% | n/a | n/a |
| medium | 27 | 0.0% | 0.0% | 1.8% | n/a | n/a |
| hard | 29 | 0.0% | 0.0% | 1.7% | 0.0% | n/a |

## Misses and imperfections

- seed 1001 (T3, hard): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1002 (T3, medium): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1003 (T3, medium): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1004 (T3, hard): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1005 (T3, easy): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1006 (T3, hard): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1007 (T3, hard): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1008 (T3, medium): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1009 (T3, hard): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1010 (T3, easy): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1011 (T3, medium): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1012 (T3, medium): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1013 (T3, easy): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1014 (T3, easy): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1015 (T3, hard): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1016 (T3, easy): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1017 (T3, medium): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1018 (T3, medium): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1019 (T3, easy): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1020 (T3, hard): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1021 (T3, medium): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1022 (T3, easy): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1023 (T3, easy): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1024 (T3, medium): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1025 (T3, medium): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1026 (T3, medium): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1027 (T3, hard): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1028 (T3, hard): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1029 (T3, medium): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1030 (T3, easy): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1031 (T3, hard): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1032 (T3, easy): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1033 (T3, medium): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1034 (T3, medium): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1035 (T3, medium): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1036 (T3, medium): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1037 (T3, hard): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1038 (T3, hard): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1039 (T3, easy): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1040 (T3, hard): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1041 (T3, hard): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1042 (T3, easy): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1043 (T3, hard): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1044 (T3, hard): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1045 (T3, hard): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1046 (T3, easy): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1047 (T3, hard): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1048 (T3, medium): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1049 (T3, hard): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1050 (T3, easy): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1051 (T3, medium): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1052 (T3, easy): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1053 (T3, medium): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1054 (T3, medium): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1055 (T3, easy): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1056 (T3, easy): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1057 (T3, easy): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1058 (T3, easy): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1059 (T3, easy): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1060 (T3, hard): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1061 (T3, easy): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1062 (T3, easy): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1063 (T3, easy): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1064 (T3, medium): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1065 (T3, easy): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1066 (T3, easy): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1067 (T3, medium): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1068 (T3, easy): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1069 (T3, hard): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1070 (T3, easy): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1071 (T3, hard): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1072 (T3, easy): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1073 (T3, easy): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1074 (T3, medium): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1075 (T3, hard): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1076 (T3, medium): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1077 (T3, medium): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1078 (T3, hard): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1079 (T3, easy): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1080 (T3, easy): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1081 (T3, hard): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1082 (T3, medium): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1083 (T3, hard): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1084 (T3, easy): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1085 (T3, easy): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1086 (T3, hard): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1087 (T3, hard): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1088 (T3, easy): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1089 (T3, hard): no incident; the data theft was surfaced as a high-priority watchlist item
- seed 1090 (T3, medium): no incident; the data theft was surfaced as a high-priority watchlist item
