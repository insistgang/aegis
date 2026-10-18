"""一万条语料的逐条核对。测试只调用这里，避免和用例文件各写一套。"""

from __future__ import annotations

import json
from pathlib import Path

from aegis.detect import analyze
from aegis.guard import _content_decision
from aegis.model import model_card, score
from aegis.models import Channel

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "data" / "corpus" / "injection_10k.jsonl"
ORACLE = ROOT / "data" / "corpus" / "row_oracle.json"


def load_rows() -> list[dict]:
    return [json.loads(line) for line in CORPUS.read_text(encoding="utf-8").splitlines() if line.strip()]


def channel_of(name: str) -> Channel:
    try:
        return Channel(name)
    except ValueError:
        return Channel.RESOURCE


def rule_decision(row: dict) -> str:
    findings = analyze(row["text"], row["channel"], row["id"]).findings
    decision = _content_decision(findings, channel=channel_of(row["channel"]), op="read")
    return decision.value


def model_bit(text: str, threshold: float) -> int:
    return int(score(text) >= threshold)


def freeze() -> None:
    threshold = float(model_card()["threshold"])
    oracle = {}
    for row in load_rows():
        oracle[row["id"]] = {
            "m": model_bit(row["text"], threshold),
            "d": rule_decision(row),
        }
    ORACLE.write_text(json.dumps(oracle, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    print(f"wrote {len(oracle)} rows to {ORACLE}")


if __name__ == "__main__":
    freeze()
