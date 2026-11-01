"""导出轨迹时抹掉密钥材料。会话内匹配仍使用原始文本，不写入公开报告。"""

from __future__ import annotations

import re

SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("private_key", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")),
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("github_token", re.compile(r"ghp_[A-Za-z0-9]{20,}")),
    ("github_pat", re.compile(r"github_pat_[A-Za-z0-9_]{20,}")),
    ("slack_token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("api_key", re.compile(r"sk-[A-Za-z0-9]{20,}")),
    ("aws_secret_field", re.compile(r"(?i)aws_secret_access_key\s*=\s*\S+")),
]

_REDACT_PATTERN = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----"
    r"|-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"
    r"|AKIA[0-9A-Z]{16}"
    r"|ghp_[A-Za-z0-9]{20,}"
    r"|github_pat_[A-Za-z0-9_]{20,}"
    r"|xox[baprs]-[A-Za-z0-9-]{10,}"
    r"|sk-[A-Za-z0-9]{20,}"
    r"|(?i:aws_secret_access_key\s*=\s*\S+)"
)


def contains_secret(text: str) -> bool:
    if not text:
        return False
    return any(pattern.search(text) for _, pattern in SECRET_PATTERNS)


def secret_needles(text: str) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    if not text:
        return found
    for kind, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            needle = match.group(0)
            if len(needle) >= 8:
                found.append((kind, needle))
    return found


def redact(value):
    if isinstance(value, str):
        return _REDACT_PATTERN.sub("«redacted»", value)
    if isinstance(value, dict):
        return {key: redact(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, tuple):
        return [redact(item) for item in value]
    return value
