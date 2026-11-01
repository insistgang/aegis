"""会话内秘密的来源采集和有界可逆表示；不保存全局秘密缓存。"""

from __future__ import annotations

import base64
import json
import re
from urllib.parse import quote, quote_plus, unquote, unquote_plus

from aegis.redact import redact

_CREDENTIAL_KEY = re.compile(
    r"(?i)(?:secret|password|passwd|token|credential|api[_-]?key|access[_-]?key|private[_-]?key|authorization)"
)
_ASSIGNMENT = re.compile(
    r"^[ \t]*(?:export[ \t]+)?([\w.-]+)[ \t]*[:=][ \t]*"
    r'(?:"((?:\\.|[^"\\])*)"|\'((?:\\.|[^\'\\])*)\'|([^\r\n]*))',
    re.MULTILINE,
)
_MAX_TRANSFORM_INPUT = 16_384
_MAX_VARIANT_LENGTH = 65_536
_ESCAPE = re.compile(r"\\(?:u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8}|x[0-9a-fA-F]{2}|[\"'\\/bfnrt])")
_QUOTED = re.compile(r'''"((?:\\.|[^"\\])*)"|'((?:\\.|[^'\\])*)' ''', re.VERBOSE)


def _unescape(text: str) -> str:
    def decode(match: re.Match) -> str:
        value = match[0][1:]
        if value[:1] in {"u", "U", "x"}:
            codepoint = int(value[1:], 16)
            return chr(codepoint) if codepoint <= 0x10FFFF else match[0]
        return {"b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t"}.get(value, value)

    return _ESCAPE.sub(decode, text)


def _strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            if isinstance(key, str):
                yield key
            yield from _strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _strings(item)


def _text_views(text: str) -> set[str]:
    """只解析数据和字符转义，不执行拼接表达式、shell 或 Python。"""
    views = {text}
    try:
        views.add("".join(_strings(json.loads(text))))
    except (ValueError, TypeError, RecursionError):
        pass
    current = text
    for _ in range(2):
        current = _unescape(current)
        views.update((current, unquote(current), unquote_plus(current)))
        literals = [match[1] if match[1] is not None else match[2] for match in _QUOTED.finditer(current)]
        if literals:
            views.add("".join(_unescape(item) for item in literals))
        try:
            views.add("".join(_strings(json.loads(current))))
        except (ValueError, TypeError, RecursionError):
            pass
    # Joining escaped fragments can itself reveal a new escape/encoding boundary.
    for _ in range(2):
        for view in tuple(views):
            views.update((_unescape(view), unquote(view), unquote_plus(view),
                          re.sub(r"[0-9a-fA-F]{8,}", lambda match: match[0].lower(), view),
                          view.replace("\r", "").replace("\n", "")))
    return views


def credential_values(text: str) -> list[str]:
    """只拆出凭据字段值，避免将 PORT、注释或普通段落变成秘密。"""
    found: list[str] = []

    def add(value) -> None:
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            value = str(value)
        if isinstance(value, str) and value.strip() and value not in found:
            found.append(value)

    def walk(value, credential: bool = False) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                walk(item, credential or bool(_CREDENTIAL_KEY.search(str(key))))
        elif isinstance(value, list):
            for item in value:
                walk(item, credential)
        elif credential:
            add(value)

    try:
        walk(json.loads(text))
    except (ValueError, TypeError, RecursionError):
        pass
    for match in _ASSIGNMENT.finditer(text):
        if not _CREDENTIAL_KEY.search(match[1]):
            continue
        value = match[2] if match[2] is not None else match[3]
        if value is None:
            value = re.split(r"\s+[;#]", match[4], maxsplit=1)[0].strip()
        elif match[2] is not None:
            value = _unescape(value)
        add(value)
    return found


def secret_variants(needles: list[str]) -> list[str]:
    """检查至多两层标准编码；每层输入至多 16 KiB，输出至多 64 KiB。"""
    found: set[str] = set()
    for needle in needles:
        if not needle or not needle.strip():
            continue
        found.add(needle)
        frontier = {needle}
        for _ in range(2):
            following: set[str] = set()
            for value in frontier:
                if len(value) > _MAX_TRANSFORM_INPUT:
                    continue
                raw = value.encode("utf-8", errors="surrogatepass")
                if len(raw) > _MAX_TRANSFORM_INPUT:
                    continue
                standard = base64.b64encode(raw).decode()
                urlsafe = base64.urlsafe_b64encode(raw).decode()
                percent = "".join(f"%{byte:02X}" for byte in raw)
                encoded = (
                    standard, standard.rstrip("="), urlsafe, urlsafe.rstrip("="),
                    raw.hex(), raw.hex().upper(), quote(value, safe="", errors="surrogatepass"),
                    quote_plus(value, safe="", errors="surrogatepass"), percent, percent.lower(),
                    json.dumps(value, ensure_ascii=True)[1:-1],
                    json.dumps(value, ensure_ascii=False)[1:-1],
                )
                following.update(item for item in encoded if len(item) <= _MAX_VARIANT_LENGTH and item not in found)
            found.update(following)
            frontier = following
    return sorted(found, key=len, reverse=True)


def contains_taint(text: str, needles: list[str]) -> bool:
    return _contains_variants(text, secret_variants(needles))


def _contains_variants(text: str, values: list[str]) -> bool:
    if any(next(_matches(text, value), None) is not None for value in values):
        return True
    return bool(values) and any(next(_matches(view, value), None) is not None for view in _text_views(text) for value in values)


def _matches(text: str, value: str):
    """短凭据只命中标量/词元边界，不能变成普通长词的子串。"""
    start = text.find(value)
    while start >= 0:
        end = start + len(value)
        left_word = start > 0 and (text[start - 1].isalnum() or text[start - 1] == "_")
        right_word = end < len(text) and (text[end].isalnum() or text[end] == "_")
        if len(value) >= 8 or not (left_word or right_word):
            yield start, end
        start = text.find(value, start + 1)


def _map_strings(value, visit):
    if isinstance(value, str):
        return visit(value)
    if isinstance(value, dict):
        pairs = [(visit(key) if isinstance(key, str) else key, _map_strings(item, visit)) for key, item in value.items()]
        return _unique_keys(pairs)
    if isinstance(value, (list, tuple)):
        return [_map_strings(item, visit) for item in value]
    return value


def _unique_keys(pairs):
    result = {}
    for key, item in pairs:
        candidate = key
        index = 2
        while candidate in result:
            candidate = f"{key} [{index}]"
            index += 1
        result[candidate] = item
    return result


def _redact_split(value, variants: list[str]):
    """擦除参与跨字段拼接的片段，同时保留其他字段的普通文字。"""
    leaves = list(_strings(value))
    if len(leaves) < 2 or not variants:
        return value
    joined = "".join(leaves)
    intervals: list[tuple[int, int]] = []
    offset = 0
    for leaf in leaves:
        intervals.append((offset, offset + len(leaf)))
        offset += len(leaf)
    marked: set[int] = set()
    for variant in variants:
        for start, end in _matches(joined, variant):
            marked.update(index for index, (left, right) in enumerate(intervals) if left < end and right > start)
    if not marked and _contains_variants(joined, variants):
        marked.update(range(len(leaves)))
    if not marked:
        return value
    index = 0

    def replace(text: str) -> str:
        nonlocal index
        result = "«redacted»" if index in marked else text
        index += 1
        return result

    return _map_strings(value, replace)


def redact_taint(value, needles: list[str]):
    """递归生成脱敏副本；仅调用期间生成变体，不向全局或磁盘保存秘密。"""
    variants = secret_variants(needles)

    def clean_string(text: str) -> str:
        for variant in variants:
            if len(variant) < 8:
                # 不将秘密插入正则表达式，防止 Python 的全局正则缓存留存凭据。
                pieces: list[str] = []
                offset = 0
                for start, end in _matches(text, variant):
                    if start < offset:
                        continue
                    pieces.extend((text[offset:start], "«redacted»"))
                    offset = end
                text = "".join(pieces) + text[offset:]
            else:
                text = text.replace(variant, "«redacted»")
        if _contains_variants(text, variants):
            return "«redacted»"
        return redact(text)

    def clean(item):
        if isinstance(item, str):
            return clean_string(item)
        if isinstance(item, dict):
            # Preserve unchanged public keys first; rewritten keys receive unique suffixes.
            pairs = [(key, clean_string(key) if isinstance(key, str) else key, clean(child)) for key, child in item.items()]
            result = {key: child for old, key, child in pairs if old == key}
            for old, key, child in pairs:
                if old == key:
                    continue
                candidate, index = key, 2
                while candidate in result or candidate in item:
                    candidate = f"{key} [{index}]"
                    index += 1
                result[candidate] = child
            return _redact_split(result, variants)
        if isinstance(item, (list, tuple)):
            return _redact_split([clean(child) for child in item], variants)
        return item

    return clean(value)
