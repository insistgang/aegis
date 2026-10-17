"""把绕过变形折回可比对的文本，并保留回到原文的下标。"""

from __future__ import annotations

import base64
import re
import unicodedata
from dataclasses import dataclass, field

ZERO_WIDTH = set("\u200b\u200c\u200d\u2060\ufeff\u180e\u00ad")
BIDI = set("\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")

# 只折叠与拉丁字母同形、且常被用来改写指令的字符。
HOMOGLYPHS = str.maketrans(
    {
        "а": "a",
        "е": "e",
        "о": "o",
        "р": "p",
        "с": "c",
        "у": "y",
        "х": "x",
        "і": "i",
        "ї": "i",
        "ј": "j",
        "ѕ": "s",
        "һ": "h",
        "ԁ": "d",
        "ɡ": "g",
        "ο": "o",
        "ν": "v",
    }
)

_COMMENT_PATTERNS = (
    re.compile(r"/\*([\s\S]*?)\*/"),
    re.compile(r"<!--([\s\S]*?)-->"),
    re.compile(r"(?m)^\s*#\s?([^\n]*)$"),
    re.compile(r"(?m)^\s*//\s?([^\n]*)$"),
)
_BASE64_PATTERN = re.compile(r"(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{24,}={0,2})(?![A-Za-z0-9+/])")
_CASE_WORD = re.compile(r"[A-Za-z]{5,}")
_SPLIT_LATIN = re.compile(r"(?:[A-Za-z]\s){6,}[A-Za-z]")


@dataclass
class Normalized:
    original: str
    plain: str
    folded: str
    fold_map: list[int]
    despaced: str
    despace_map: list[int]
    plain_despaced: str
    plain_despace_map: list[int]
    comments: list[tuple[int, int, str]] = field(default_factory=list)
    decoded: list[tuple[int, int, str]] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)


def _keep_despace(char: str) -> bool:
    if char.isalnum():
        return True
    code = ord(char)
    return (
        0x4E00 <= code <= 0x9FFF
        or 0x3040 <= code <= 0x30FF
        or 0x0400 <= code <= 0x04FF
        or 0xAC00 <= code <= 0xD7AF
    )


def normalize(text: str) -> Normalized:
    original = text or ""
    techniques: list[str] = []
    if any(char in ZERO_WIDTH for char in original):
        techniques.append("zero_width")
    if any(char in BIDI for char in original):
        techniques.append("bidi")
    if _SPLIT_LATIN.search(original):
        techniques.append("char_split")
    for word in _CASE_WORD.findall(original):
        switches = sum(
            word[index].isupper() != word[index - 1].isupper()
            for index in range(1, len(word))
            if word[index].isalpha() and word[index - 1].isalpha()
        )
        if switches >= 3:
            techniques.append("case_mix")
            break

    plain_chars: list[str] = []
    fold_map: list[int] = []
    changed_compat = False
    for index, char in enumerate(original):
        if char in ZERO_WIDTH or char in BIDI:
            continue
        compat = unicodedata.normalize("NFKC", char)
        if compat != char:
            changed_compat = True
        for item in compat.casefold():
            plain_chars.append(item)
            fold_map.append(index)
    if changed_compat:
        techniques.append("compatibility")
    plain = "".join(plain_chars)
    # 同形折叠单独放一层。西里尔正文仍留在 plain 上，避免把俄语指令拆掉。
    folded = plain.translate(HOMOGLYPHS)
    if folded != plain:
        techniques.append("homoglyph")

    despaced, despace_map = _despace(folded, fold_map)
    plain_despaced, plain_despace_map = _despace(plain, fold_map)
    comments = _comments(original)
    decoded = _decode_base64(original)
    if comments:
        techniques.append("comment_embed")
    if decoded:
        techniques.append("encoded_payload")
    joined = _join_quoted(original)
    if joined != original:
        techniques.append("string_concat")
    return Normalized(
        original=original,
        plain=plain,
        folded=folded,
        fold_map=fold_map,
        despaced=despaced,
        despace_map=despace_map,
        plain_despaced=plain_despaced,
        plain_despace_map=plain_despace_map,
        comments=comments,
        decoded=decoded,
        techniques=techniques,
    )


def _despace(text: str, mapping: list[int]) -> tuple[str, list[int]]:
    chars: list[str] = []
    indexes: list[int] = []
    for index, char in enumerate(text):
        if _keep_despace(char):
            chars.append(char)
            indexes.append(mapping[index])
    return "".join(chars), indexes


def _comments(text: str) -> list[tuple[int, int, str]]:
    found: list[tuple[int, int, str]] = []
    for pattern in _COMMENT_PATTERNS:
        for match in pattern.finditer(text):
            body = match.group(1).strip()
            if body:
                found.append((match.start(1), match.end(1), body))
    return found


def _decode_base64(text: str) -> list[tuple[int, int, str]]:
    found: list[tuple[int, int, str]] = []
    for match in _BASE64_PATTERN.finditer(text):
        blob = match.group(1)
        try:
            raw = base64.b64decode(blob, validate=True)
            decoded = raw.decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        letters = sum(char.isalpha() for char in decoded)
        if letters >= 8 and all(char.isprintable() or char.isspace() for char in decoded):
            found.append((match.start(1), match.end(1), decoded))
    return found


def _join_quoted(text: str) -> str:
    current = text
    for _ in range(4):
        updated = re.sub(r"'([^']{0,24})'\s*'\s*([^']{0,24})'", r"\1\2", current)
        updated = re.sub(r'"([^"]{0,24})"\s*\+\s*"([^"]{0,24})"', r"\1\2", updated)
        updated = re.sub(r"'([^']{0,24})'\s*\+\s*'([^']{0,24})'", r"\1\2", updated)
        if updated == current:
            return current
        current = updated
    return current


def span_from_map(mapping: list[int], start: int, end: int) -> tuple[int | None, int | None]:
    if not mapping or start is None or end is None or start >= end or start >= len(mapping):
        return None, None
    end = min(end, len(mapping))
    return mapping[start], mapping[end - 1] + 1
