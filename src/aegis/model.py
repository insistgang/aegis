"""字符 n-gram 逻辑回归。只输出注入概率，不单独决定放行或阻断。"""

from __future__ import annotations

import hashlib
import json
import math
from functools import lru_cache
from pathlib import Path

from aegis.normalize import normalize

DIM = 2048
_PATH = Path(__file__).resolve().parent / "data" / "injection_model.json"


def _bucket(gram: str) -> int:
    digest = hashlib.md5(gram.encode("utf-8")).hexdigest()[:8]
    return int(digest, 16) % DIM


def features(text: str) -> dict[int, float]:
    folded = normalize(text or "").folded
    if not folded:
        return {}
    counts: dict[int, float] = {}
    padded = f"^{folded}$"
    for size in (2, 3, 4):
        if len(padded) < size:
            continue
        for index in range(len(padded) - size + 1):
            bucket = _bucket(padded[index : index + size])
            counts[bucket] = counts.get(bucket, 0.0) + 1.0
    norm = math.sqrt(sum(value * value for value in counts.values())) or 1.0
    return {key: value / norm for key, value in counts.items()}


@lru_cache(maxsize=1)
def _weights() -> tuple[list[float], float]:
    raw = json.loads(_PATH.read_text(encoding="utf-8"))
    return list(raw["weights"]), float(raw["bias"])


def score(text: str) -> float:
    """返回 0 到 1 的注入概率。权重文件缺失时返回 0。"""
    if not _PATH.exists():
        return 0.0
    weights, bias = _weights()
    total = bias
    for key, value in features(text).items():
        total += weights[key] * value
    if total >= 20:
        return 1.0
    if total <= -20:
        return 0.0
    return 1.0 / (1.0 + math.exp(-total))


def model_card() -> dict:
    if not _PATH.exists():
        return {"name": "char-ngram-logreg", "ready": False}
    raw = json.loads(_PATH.read_text(encoding="utf-8"))
    return {
        "name": raw.get("name", "char-ngram-logreg"),
        "ready": True,
        "dim": raw.get("dim", DIM),
        "grams": raw.get("grams", [2, 3, 4]),
        "threshold": raw.get("threshold", 0.5),
        "train_size": raw.get("train_size"),
        "metrics": raw.get("metrics", {}),
    }
