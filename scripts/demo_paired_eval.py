"""生成可离线演示的攻防对照页面；--rerun 只重放受控工具，不调用模型。"""

import argparse
import json
from datetime import datetime
from pathlib import Path

from aegis.eval_report import render_html
from aegis.evaluation import run_suite

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rerun", action="store_true", help="现场重新执行固定轨迹，不调用模型")
    parser.add_argument("--output", type=Path, default=ROOT / "output/demo/paired_eval.html")
    args = parser.parse_args()
    datasets = {}
    for label in ["replay", "live"]:
        path = ROOT / f"data/evaluation/paired_{label}_runs.jsonl"
        if path.exists():
            datasets[label] = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    if args.rerun:
        rows = run_suite(backend="scripted", include_external=True)
        path = ROOT / "output/demo" / ("onsite_replay_" + datetime.now().strftime("%Y%m%d_%H%M%S_%f") + ".jsonl")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows))
        datasets["replay"] = rows
        print("现场重放记录：" + str(path))
    if not datasets:
        parser.error("no archived experiment records found; use --rerun for an offline local replay")
    render_html(datasets, args.output)
    print("演示页面：" + str(args.output))


if __name__ == "__main__":
    main()
