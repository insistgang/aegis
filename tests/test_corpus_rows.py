"""一万条合成文本逐条测试。每条都跑规则结论和字符模型分数。"""

import json

import pytest

from tests.corpus_checks import CORPUS, ORACLE, load_rows, model_bit, rule_decision
from aegis.model import model_card

ROWS = {row["id"]: row for row in load_rows()}
EXPECTED = json.loads(ORACLE.read_text(encoding="utf-8"))
IDS = sorted(ROWS)
THRESHOLD = float(model_card()["threshold"])


def _assert_row_contract(row: dict) -> None:
    assert row["label"] in (0, 1)
    assert row["split"] in {"train", "val", "test"}
    assert f".{row['split']}." in row["template_id"]
    assert row["text"].strip()
    lowered = row["text"].lower()
    assert "akia" not in lowered
    assert "begin private key" not in lowered
    assert "ghp_" not in lowered


@pytest.mark.parametrize("row_id", IDS)
def test_each_corpus_text(row_id: str):
    row = ROWS[row_id]
    expected = EXPECTED[row_id]
    _assert_row_contract(row)
    assert rule_decision(row) == expected["d"]
    assert model_bit(row["text"], THRESHOLD) == expected["m"]


def test_corpus_files_cover_every_text_once():
    assert len(ROWS) == 10000
    assert set(EXPECTED) == set(ROWS)
    assert CORPUS.name == "injection_10k.jsonl"


def test_test_split_oracle_matches_published_confusion():
    metrics = model_card()["metrics"]["test"]
    true_positive = false_positive = true_negative = false_negative = 0
    for row in ROWS.values():
        if row["split"] != "test":
            continue
        predicted = EXPECTED[row["id"]]["m"]
        label = int(row["label"])
        if predicted and label:
            true_positive += 1
        elif predicted and not label:
            false_positive += 1
        elif label:
            false_negative += 1
        else:
            true_negative += 1
    assert (true_positive, false_positive, true_negative, false_negative) == (
        metrics["tp"],
        metrics["fp"],
        metrics["tn"],
        metrics["fn"],
    )
