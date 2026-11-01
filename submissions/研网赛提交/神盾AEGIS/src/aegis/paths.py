"""路径规范化与 glob。不访问文件系统，避免被不存在的路径或符号链接拖垮。"""

from __future__ import annotations

import os
import re

_WRITE_MARKERS = (
    "/.ssh/",
    "/.aws/",
    "/.gnupg/",
    "/.kube/",
    "/etc/cron",
    "/cron.d/",
    "/launchagents/",
    "/launchdaemons/",
    "/systemd/system/",
    "/systemd/user/",
)

_READ_DIR_MARKERS = ("/.ssh/", "/.aws/", "/.gnupg/", "/.kube/")
_READ_NAMES = {"credentials", "credentials.json", "id_rsa", "id_ed25519", "id_ecdsa"}


def variants(path: str) -> list[str]:
    if not path:
        return []
    raw = str(path).strip().strip('"').strip("'").replace("\\", "/")
    expanded = os.path.normpath(os.path.expanduser(raw)).replace("\\", "/")
    forms = {raw, expanded}
    home = os.path.expanduser("~").replace("\\", "/")
    if expanded == home or expanded.startswith(home + "/"):
        forms.add("~" + expanded[len(home) :])
    return [item for item in forms if item]


def glob_match(pattern: str, path: str) -> bool:
    path = path.replace("\\", "/")
    pattern = pattern.replace("\\", "/")
    regex = ["^"]
    index = 0
    while index < len(pattern):
        if pattern.startswith("**/", index):
            regex.append("(?:.*/)*")
            index += 3
        elif pattern.startswith("**", index):
            regex.append(".*")
            index += 2
        elif pattern[index] == "*":
            regex.append("[^/]*")
            index += 1
        else:
            regex.append(re.escape(pattern[index]))
            index += 1
    regex.append("$")
    return re.fullmatch("".join(regex), path) is not None


def any_glob(patterns: list[str], paths: list[str]) -> bool:
    return any(glob_match(pattern, path) for pattern in patterns for path in paths)


def _norm_slashes(path: str) -> str:
    text = path.replace("\\", "/")
    if not text.startswith("/") and not text.startswith("~"):
        text = "/" + text
    return text.lower()


def path_sensitive_read(path: str) -> bool:
    for form in variants(path):
        lowered = form.replace("\\", "/").lower()
        if any(marker in _norm_slashes(lowered) or marker in lowered for marker in _READ_DIR_MARKERS):
            return True
        base = lowered.rsplit("/", 1)[-1]
        if base in _READ_NAMES or base == ".env" or base.startswith(".env."):
            return True
        if base.endswith(".pem") or base == "authorized_keys":
            return True
    return False


def path_sensitive_write(path: str) -> bool:
    for form in variants(path):
        lowered = "/" + form.replace("\\", "/").lstrip("/").lower()
        if any(marker in lowered for marker in _WRITE_MARKERS):
            return True
        if path_sensitive_read(form):
            return True
    return False


def extract_path(args: dict | None) -> str:
    if not args:
        return ""
    for key in ("path", "file", "filepath", "target", "dest", "destination"):
        value = args.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""
