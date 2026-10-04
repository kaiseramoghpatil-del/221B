.PHONY: test gen api bench contract
test:
	python -m pytest
gen:
	python -m sim.cli --seed 1 --template T1 --out data/demo_case
api:
	python -m uvicorn backend.api.app:app --reload --port 8221
contract:
	python scripts/export_contract.py
bench:
	python -m eval.sweep --seeds 1..300
