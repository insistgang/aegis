"""把 shell 命令折成可比对的形态，只输出危险类别，不执行命令。"""

from __future__ import annotations

import re
import unicodedata

_ZERO = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff\u180e\u00ad"), None)

_DOWNLOAD_PIPE = re.compile(
    r"\b(?:curl|wget|fetch|iwr|invoke-webrequest)\b[^|&;\n]{0,200}\|\s*(?:ba)?sh\b"
    r"|\b(?:curl|wget|fetch|iwr)\b[^|&;\n]{0,200}\|\s*(?:bash|zsh|dash|powershell|pwsh|iex|python3?)\b"
)
_DOWNLOAD_CHAIN = re.compile(
    r"\b(?:curl|wget|fetch)\b[^|&;\n]{0,200}(?:;|&&)\s*(?:ba)?sh\b"
    r"|\b(?:curl|wget|fetch)\b[^|&;\n]{0,220}(?:;|&&)\s*(?:bash|zsh)\b"
)
_DECODE_EXEC = re.compile(
    r"\bbase64\b[^|;]{0,48}-d\b[^|;]{0,48}\|\s*(?:ba)?sh\b"
    r"|\bbase64\b[^|;]{0,48}--decode\b[^|;]{0,48}\|\s*(?:ba)?sh\b"
    r"|\bopenssl\b[^|;]{0,48}\b-d\b[^|;]{0,48}\|\s*(?:ba)?sh\b"
)
_SUBST = re.compile(r"\$\(\s*(?:curl|wget|fetch)\b|`\s*(?:curl|wget|fetch)\b")
_EVAL_DECODE = re.compile(r"\beval\b")
_PY_EXEC = re.compile(r"\b(?:exec|os\.system|subprocess)\b")
_PY_NET = re.compile(r"(?:urllib|urlopen|requests|base64)")
_PY_C = re.compile(r"\bpython3?\b\s+-c\b")
_DESTRUCTIVE = (
    re.compile(r"\brm\s+-rf\s+/(?:\s|$)"),
    re.compile(r"\bmkfs(?:\.\w+)?\b"),
    re.compile(r"\bdd\s+if=/dev/(?:sd|nvme|disk)"),
    re.compile(r":\(\)\s*\{"),
)


def normalize_shell(command: str) -> str:
    text = unicodedata.normalize("NFKC", command or "")
    text = text.translate(_ZERO)
    text = text.replace("\\\n", "")
    text = re.sub(r"\$\{IFS\}|\$IFS", " ", text, flags=re.IGNORECASE)

    def _ansi(match: re.Match[str]) -> str:
        inner = match.group(1)
        return re.sub(r"\\x([0-9a-fA-F]{2})", lambda item: chr(int(item.group(1), 16)), inner)

    text = re.sub(r"\$'([^']*)'", _ansi, text)
    for _ in range(6):
        updated = re.sub(r"([A-Za-z])''([A-Za-z])", r"\1\2", text)
        if updated == text:
            break
        text = updated
    for _ in range(4):
        updated = re.sub(r"'([^']*)'\s*'([^']*)'", r"\1\2", text)
        updated = re.sub(r'"([^"]*)"\s*"([^"]*)"', r"\1\2", updated)
        if updated == text:
            break
        text = updated
    text = text.replace("'", "").replace('"', "")
    text = re.sub(r"\\([A-Za-z|&;])", r"\1", text)
    text = re.sub(r"[ \t]+", " ", text)
    return text.casefold().strip()


def command_classes(command: str) -> list[str]:
    if not command or not str(command).strip():
        return []
    folded = normalize_shell(str(command))
    found: list[str] = []
    if _DOWNLOAD_PIPE.search(folded):
        found.append("download_pipe")
    if _DOWNLOAD_CHAIN.search(folded):
        found.append("download_exec_chain")
    if _DECODE_EXEC.search(folded):
        found.append("decode_exec")
    if _SUBST.search(folded):
        found.append("command_subst_download")
    if _EVAL_DECODE.search(folded) and ("base64" in folded or "curl" in folded or "wget" in folded):
        found.append("decode_exec")
    if _PY_C.search(folded) and _PY_EXEC.search(folded) and _PY_NET.search(folded):
        found.append("decode_exec")
    if any(pattern.search(folded) for pattern in _DESTRUCTIVE):
        found.append("destructive")
    # 保序去重
    unique: list[str] = []
    for item in found:
        if item not in unique:
            unique.append(item)
    return unique


def extract_command(args: dict | None) -> str:
    if not args:
        return ""
    for key in ("command", "cmd", "script", "cmdline"):
        value = args.get(key)
        if isinstance(value, str) and value.strip():
            return value
    argv = args.get("argv")
    if isinstance(argv, list) and argv:
        return " ".join(str(item) for item in argv)
    return ""
