# 221B

Forensic incident reconstruction for ALGOTHON'26 **ALG-CYBER-01 - Find the Intruder**.

> Raw security events -> suspicious signals -> correlated entities -> reconstructed attack sequence -> identified intruder -> evidence-backed explanation -> live verification.

Status: scaffold. Specification: `docs/SPEC.md` (v1.1.1). Prior art & licensing: `docs/RESEARCH.md`.
The full README (problem, solution, features, setup, tech, AI/dataset disclosure, limitations) is written at the end per the rule book.

## Quick start (dev)
```
pip install -e ".[dev]"
python -m sim.cli --seed 1 --template T1 --out data/demo_case   # generate a scenario (raw logs + hidden truth.json)
python -m pytest
python -m uvicorn backend.api.app:app --port 8221
```
