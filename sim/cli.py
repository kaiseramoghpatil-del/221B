"""python -m sim.cli --seed 1 --template T1 --out data/demo_case"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from backend.core.models import ScenarioParams

from .generator import generate


def main() -> None:
    ap = argparse.ArgumentParser(description="221B scenario generator")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--template", default="T1", choices=["T0", "T1", "T2"])
    ap.add_argument("--stealth", type=float, default=0.5)
    ap.add_argument("--ip-rotation", type=int, default=1)
    ap.add_argument("--noise", type=float, default=1.0)
    ap.add_argument("--log-loss", type=float, default=0.0)
    ap.add_argument("--clock-skew", type=int, default=0)
    ap.add_argument("--dup-rate", type=float, default=0.0)
    ap.add_argument("--shuffle", type=float, default=0.0)
    ap.add_argument("--malformed", type=float, default=0.0)
    ap.add_argument("--scale", type=float, default=1.0)
    ap.add_argument("--no-decoys", action="store_true")
    ap.add_argument("--out", default="data/scenario")
    a = ap.parse_args()
    params = ScenarioParams(template=a.template, stealth=a.stealth, ip_rotation=a.ip_rotation, noise=a.noise, log_loss=a.log_loss,
                            clock_skew_s=a.clock_skew, dup_rate=a.dup_rate, shuffle=a.shuffle, malformed_rate=a.malformed,
                            scale=a.scale, with_decoys=not a.no_decoys)
    t = time.time()
    sc = generate(a.seed, params)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    for name, data in sc.files.items():
        (out / name).write_bytes(data)
    (out / "truth.json").write_text(sc.truth.model_dump_json(indent=2), encoding="utf-8")
    print(json.dumps({"out": str(out), "seconds": round(time.time() - t, 2), "files": sc.truth.files,
                      "attacker_ips": sc.truth.attacker_ips, "victim": sc.truth.compromised_users}, indent=2))


if __name__ == "__main__":
    main()
