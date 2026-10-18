"""只用训练集拟合字符模型，按验证集挑权重，测试集只评一次。"""

from __future__ import annotations

import json
import random
import time
from pathlib import Path

from aegis.model import DIM, _weights, features, score

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "data" / "corpus" / "injection_10k.jsonl"
MODEL = ROOT / "src" / "aegis" / "data" / "injection_model.json"


def _load() -> list[dict]:
    rows = []
    with CORPUS.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def _sigmoid(value: float) -> float:
    if value >= 20:
        return 1.0
    if value <= -20:
        return 0.0
    import math

    return 1.0 / (1.0 + math.exp(-value))


def _predict(weights: list[float], bias: float, feats: dict[int, float]) -> float:
    total = bias + sum(weights[key] * value for key, value in feats.items())
    return _sigmoid(total)


def _metrics(rows: list[tuple[dict[int, float], int]], weights: list[float], bias: float, threshold: float) -> dict:
    tp = fp = tn = fn = 0
    for feats, label in rows:
        pred = _predict(weights, bias, feats) >= threshold
        if pred and label:
            tp += 1
        elif pred and not label:
            fp += 1
        elif label:
            fn += 1
        else:
            tn += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "count": len(rows),
        "attack": tp + fn,
        "benign": tn + fp,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
    }


# 这四句是产品里已经固定的良性说法，阈值不能把它们标成注入。
BENIGN_FLOOR = (
    "请总结这份接口文档的认证方式。",
    "Ignore previous versions of the API when migrating.",
    "密钥管理的做法是不要把密钥写进仓库。",
    "帮我看一下 README 的安装步骤。",
)


def _select_threshold(rows: list[tuple[dict[int, float], int]], weights: list[float], bias: float) -> tuple[dict, float]:
    """只在同时满足两条约束的阈值里取 F1 最高者，同分取更高阈值。

    约束：验证集误报率不超过 1%；四句固定良性文本的概率至少比阈值低 0.02。
    不把未检查约束的 0.5 当作默认入选。
    """
    floor = [features(text) for text in BENIGN_FLOOR]
    valid: list[tuple[float, dict]] = []
    for step in range(10, 51, 5):
        threshold = step / 100
        if any(_predict(weights, bias, feats) + 0.02 >= threshold for feats in floor):
            continue
        current = _metrics(rows, weights, bias, threshold)
        if current["false_positive_rate"] > 0.01:
            continue
        valid.append((threshold, current))
    if not valid:
        return _metrics(rows, weights, bias, 0.5), 0.5
    threshold, current = max(valid, key=lambda item: (item[1]["f1"], item[0]))
    return current, threshold


def _pack(split_rows: list[dict]) -> list[tuple[dict[int, float], int, str, str]]:
    packed = []
    for row in split_rows:
        packed.append((features(row["text"]), int(row["label"]), row["lang"], row["surface"]))
    return packed


def train() -> dict:
    rows = _load()
    grouped = {name: [row for row in rows if row["split"] == name] for name in ("train", "val", "test")}
    packed = {name: _pack(grouped[name]) for name in grouped}
    positives = sum(label for _, label, _, _ in packed["train"])
    total = len(packed["train"])
    weight_for = {1: 0.5 * total / positives, 0: 0.5 * total / (total - positives)}
    weights = [0.0] * DIM
    bias = 0.0
    learning_rate = 0.6
    l2 = 1e-4
    best = (weights[:], bias, -1.0, 0, 0.5)
    order = list(range(total))
    for epoch in range(1, 16):
        random.Random(7 + epoch).shuffle(order)
        rate = learning_rate * (0.95 ** (epoch - 1))
        for index in order:
            feats, label, _, _ = packed["train"][index]
            pred = _predict(weights, bias, feats)
            grad = (pred - label) * weight_for[label]
            for key, value in feats.items():
                weights[key] -= rate * (grad * value + l2 * weights[key])
            bias -= rate * grad
        val_rows = [(feats, label) for feats, label, _, _ in packed["val"]]
        current, threshold = _select_threshold(val_rows, weights, bias)
        score_key = current["f1"]
        if score_key > best[2]:
            best = (weights[:], bias, score_key, epoch, threshold)
    chosen, chosen_bias, _, chosen_epoch, chosen_threshold = best

    _weights.cache_clear()
    payload = {
        "name": "char-ngram-logreg",
        "dim": DIM,
        "grams": [2, 3, 4],
        "threshold": chosen_threshold,
        "train_size": len(grouped["train"]),
        "bias": round(chosen_bias, 6),
        "weights": [round(value, 6) for value in chosen],
        "metrics": {},
    }
    MODEL.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    _weights.cache_clear()

    def counts(name: str, plain_only: bool = False, lang: str | None = None) -> dict:
        tp = fp = tn = fn = 0
        for row in grouped[name]:
            if plain_only and row["surface"] != "plain":
                continue
            if lang is not None and row["lang"] != lang:
                continue
            pred = score(row["text"]) >= chosen_threshold
            label = int(row["label"])
            if pred and label:
                tp += 1
            elif pred and not label:
                fp += 1
            elif label:
                fn += 1
            else:
                tn += 1
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        fpr = fp / (fp + tn) if fp + tn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        return {
            "count": tp + fp + tn + fn,
            "attack": tp + fn,
            "benign": tn + fp,
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "false_positive_rate": round(fpr, 4),
        }

    payload["metrics"] = {
        "corpus_count": len(rows),
        "split_by": "template_id",
        "selection": "max_val_f1_fpr_at_most_0.01_and_benign_floor_margin_0.02",
        "epoch": chosen_epoch,
        "threshold": chosen_threshold,
        "train": counts("train"),
        "val": counts("val"),
        "test": counts("test"),
        "test_plain": counts("test", plain_only=True),
        "test_by_lang": {lang: counts("test", lang=lang) for lang in ("zh", "en", "ja", "ru")},
    }
    MODEL.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    _weights.cache_clear()
    sample = [row["text"] for row in grouped["test"][:200]]
    started = time.perf_counter()
    for _ in range(5):
        for text in sample:
            score(text)
    elapsed_ms = (time.perf_counter() - started) * 1000 / (5 * len(sample))
    card = json.loads(MODEL.read_text(encoding="utf-8"))
    card["metrics"]["latency_ms"] = round(elapsed_ms, 3)
    MODEL.write_text(json.dumps(card, ensure_ascii=False), encoding="utf-8")
    _weights.cache_clear()
    printable = {"threshold": card["threshold"]}
    printable.update({key: card["metrics"][key] for key in ("epoch", "train", "val", "test", "test_plain", "test_by_lang", "latency_ms")})
    print(json.dumps(printable, ensure_ascii=False, indent=2))
    return card


if __name__ == "__main__":
    train()
