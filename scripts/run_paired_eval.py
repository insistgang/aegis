"""运行工具副作用对照；默认离线重放，--backend live 才消费模型额度。"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from aegis.evaluation import CallBudget, external_cases, run_suite, summarize
from aegis.eval_cases import CASES

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", choices=["scripted", "live"], default="scripted")
    parser.add_argument("--max-calls", type=int, default=120)
    parser.add_argument("--interval", type=float, default=1.3)
    parser.add_argument("--case", action="append", dest="case_ids")
    parser.add_argument("--external", action="store_true", help="另加6个固定外部来源适配案例，分来源报告")
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()
    if args.max_calls < 1 or args.interval < 0:
        parser.error("max-calls must be positive and interval nonnegative")
    if args.backend == "live" and (args.max_calls > 120 or args.interval < 1.3):
        parser.error("live protocol requires at most 120 attempts and an interval of at least 1.3 seconds")
    known = {case["id"] for case in CASES + (external_cases() if args.external else [])}
    if args.case_ids and not set(args.case_ids) <= known:
        parser.error("unknown case id")
    label = "replay" if args.backend == "scripted" else "live"
    output = args.output or ROOT / "data/evaluation" / f"paired_{label}_runs.jsonl"
    output.parent.mkdir(parents=True, exist_ok=True)
    summary_path = output.with_name(output.name.replace("_runs.jsonl", "_summary.json"))
    if summary_path == output:
        summary_path = output.with_suffix(".summary.json")
    if output.exists() or summary_path.exists():
        parser.error("raw output or summary already exists; choose new paths to preserve previous evidence")
    budget = CallBudget(args.max_calls, args.interval)
    with output.open("x", encoding="utf-8") as handle:
        def save(row):
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
            handle.flush()
            print(f"{row['case_id']} {row['arm']} effects={row['goal_success']} completed={row['completed']} error={row['error'] is not None}", flush=True)
        rows = run_suite(backend=args.backend, budget=budget, case_ids=args.case_ids, on_row=save, include_external=args.external)
    summary = summarize(rows)
    summary.update(backend=args.backend, client_attempts=budget.attempts,
                   max_client_attempts=budget.maximum, minimum_interval_seconds=budget.interval,
                   raw_file=str(output.relative_to(ROOT)) if output.is_relative_to(ROOT) else str(output),
                   raw_sha256=hashlib.sha256(output.read_bytes()).hexdigest(),
                   fixture_sha256=hashlib.sha256((ROOT / "src/aegis/eval_cases.py").read_bytes()).hexdigest(),
                   confirmation_protocol="Only case-declared trusted user preconfirmations; no authorization from external notes")
    with summary_path.open("x") as handle:
        handle.write(json.dumps(summary, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"rows": len(rows), "summary": str(summary_path), "client_attempts": budget.attempts}, ensure_ascii=False))
    return 1 if any(row["error"] for row in rows) else 0


if __name__ == "__main__":
    sys.exit(main())
