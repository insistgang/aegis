"""原文与审计 token 的无损来源映射，可注入宿主自己的 tokenizer。"""

from __future__ import annotations

import hashlib
import re
from bisect import bisect_left, bisect_right
from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class Token:
    id: str | int
    start: int
    end: int


class Tokenizer(Protocol):
    name: str

    def tokenize(self, text: str) -> list[Token]: ...


class UnicodeAuditTokenizer:
    """包含空白和标点的审计分词，不代表任何服务商的模型或计费分词。"""

    name = "aegis-unicode-v1"
    _pattern = re.compile(r"[\u3400-\u9fff]|[^\W\u3400-\u9fff]+|\s+|[^\w\s]", re.UNICODE)

    def tokenize(self, text: str) -> list[Token]:
        return [Token(i, m.start(), m.end()) for i, m in enumerate(self._pattern.finditer(text))]


class SourceRegistry:
    def __init__(self, tokenizer: Tokenizer | None = None) -> None:
        self.tokenizer = tokenizer or UnicodeAuditTokenizer()
        if not isinstance(self.tokenizer.name, str) or not self.tokenizer.name:
            raise ValueError("tokenizer 必须提供非空的版本名称")
        self.records: dict[str, dict] = {}
        self._bounds: dict[str, tuple[list[int], list[int]]] = {}

    def register(self, text: str, *, source_id: str, channel: str) -> str:
        tokens = list(self.tokenizer.tokenize(text))
        covered = 0
        for token in tokens:
            if not (0 <= token.start <= covered <= token.end <= len(text) and token.end > token.start):
                raise ValueError("tokenizer 必须按顺序无缺口覆盖原文，并提供原文字符偏移")
            covered = token.end
        if covered != len(text):
            raise ValueError("tokenizer 未覆盖完整原文")
        ref = f"source-{len(self.records) + 1}"
        self.records[ref] = {
            "id": ref,
            "source_id": source_id,
            "channel": channel,
            "tokenizer": self.tokenizer.name,
            "chars": len(text),
            "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
            "span_id": None,
            "tokens": [
                {"id": token.id, "index": i, "start": token.start, "end": token.end, "source_ref": ref}
                for i, token in enumerate(tokens)
            ],
        }
        self._bounds[ref] = ([t.start for t in tokens], [t.end for t in tokens])
        return ref

    def interval(self, ref: str, start: int, end: int) -> dict:
        source = self.records[ref]
        if not (0 <= start < end <= source["chars"]):
            raise ValueError("来源字符范围越界")
        starts, ends = self._bounds[ref]
        return {
            "source_ref": ref,
            "source_id": source["source_id"],
            "channel": source["channel"],
            "char_start": start,
            "char_end": end,
            "token_start": bisect_right(ends, start),
            "token_end": bisect_left(starts, end),
            "tokenizer": source["tokenizer"],
        }

    def export(self) -> list[dict]:
        return list(self.records.values())
