"""把一次工具调用变成策略引擎可以比对的特征。"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

from aegis.intent import deviation, is_consequential
from aegis.models import Intent
from aegis.paths import extract_path, path_sensitive_read, path_sensitive_write, variants
from aegis.policy import domain_trusted
from aegis.redact import contains_secret, secret_needles
from aegis.shell import command_classes, extract_command
from aegis.taint import contains_taint, credential_values, redact_taint

_URL = re.compile(r"https?://[^\s\"'<>)\]]+", re.IGNORECASE)
_PATH = re.compile(
    r"(?:~|/Users/[A-Za-z0-9._-]+|/home/[A-Za-z0-9._-]+)?/(?:\.ssh|\.aws|\.gnupg|\.kube)/[A-Za-z0-9._/-]+"
    r"|/etc/cron[^\s\"']*"
)


@dataclass
class IOC:
    kind: str
    value: str
    source_id: str
    span_id: str


@dataclass
class SecretRecord:
    source: str
    kind: str
    needles: list[str] = field(default_factory=list)
    path: str = ""


def dumps_args(args: dict | None) -> str:
    return json.dumps(args or {}, ensure_ascii=False, sort_keys=True)


def hosts_of(text: str) -> list[str]:
    found: list[str] = []
    for match in _URL.findall(text or ""):
        host = urlparse(match).hostname or ""
        host = host.lower()
        if host and host not in found:
            found.append(host)
    return found


def extract_iocs(text: str, findings, source_id: str, span_id: str, trusted: list[str]) -> list[IOC]:
    if not findings:
        return []
    windows: list[str] = []
    for finding in findings:
        if finding.severity < 0.7:
            continue
        if finding.start is None or finding.end is None:
            windows.append(finding.quote)
            continue
        windows.append(text[max(0, finding.start - 80) : finding.end + 260])
    iocs: list[IOC] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, value: str) -> None:
        key = (kind, value.lower())
        if not value or key in seen:
            return
        seen.add(key)
        iocs.append(IOC(kind=kind, value=value, source_id=source_id, span_id=span_id))

    for window in windows:
        for url in _URL.findall(window):
            host = (urlparse(url).hostname or "").lower()
            if host and not domain_trusted(host, trusted):
                add("url", url.rstrip(").,;"))
                add("host", host)
        for path in _PATH.findall(window):
            add("path", path.rstrip(").,;"))
    return iocs


def ioc_hit(iocs: list[IOC], tool: str, args: dict | None, text: str) -> bool:
    blob = text.lower()
    path = extract_path(args).replace("\\", "/").lower()
    for item in iocs:
        value = item.value.lower()
        if item.kind in {"host", "url"} and value and value in blob:
            return True
        if item.kind == "path" and value:
            if value in blob or value in path or path.endswith(value.split("/")[-1]) and "/.ssh/" in value and "/.ssh/" in path:
                return True
            if _same_sensitive_path(value, path):
                return True
    return False


def _same_sensitive_path(ioc_path: str, call_path: str) -> bool:
    if not call_path:
        return False
    ioc_path = ioc_path.replace("\\", "/")
    call_path = call_path.replace("\\", "/")
    for marker in ("/.ssh/", "/.aws/", "/.gnupg/", "/.kube/"):
        if marker in ioc_path and marker in ("/" + call_path.lstrip("~")):
            tail = ioc_path.split(marker, 1)[-1]
            return tail in call_path
    return False


def carries_secret(records: list[SecretRecord], text: str) -> bool:
    if not text or not records:
        return False
    for record in records:
        if contains_taint(text, record.needles):
            return True
        if record.path and record.path in text:
            return True
    return False


def harvest_secret(source: str, text: str, path: str) -> SecretRecord | None:
    """按来源保留完整敏感文件和凭据值，原文仅留在会话内存。"""
    needles = [needle for _, needle in secret_needles(text)]
    sensitive = bool(path) and (path_sensitive_read(path) or path_sensitive_write(path))
    if sensitive:
        if text.strip():
            needles.append(text)
        needles.extend(credential_values(text))
    if not needles and not sensitive:
        return None
    return SecretRecord(source=source, kind="observed", needles=list(dict.fromkeys(needles)), path=path)


def redact_session(value, records: list[SecretRecord]):
    """将原文与编码后的会话秘密从任意嵌套审计数据中替换掉。"""
    return redact_taint(value, [needle for record in records for needle in record.needles])


def build_features(
    *,
    tool: str,
    args: dict | None,
    intent: Intent,
    injection_active: bool,
    iocs: list[IOC],
    secrets: list[SecretRecord],
    trusted_domains: list[str],
) -> dict:
    serialized = dumps_args(args)
    path = extract_path(args)
    command = extract_command(args) if tool == "exec" or tool.startswith("exec.") else ""
    host_list = hosts_of(serialized)
    untrusted = bool(host_list) and any(not domain_trusted(host, trusted_domains) for host in host_list)
    return {
        "tool": tool,
        "intent": intent.value,
        "intent_deviation": deviation(intent, tool),
        "paths": variants(path),
        "path_sensitive_read": path_sensitive_read(path) if tool in {"fs.read", "fs.write"} else False,
        "domain_not_trusted": untrusted,
        "carries_session_secret": carries_secret(secrets, serialized),
        "args_contain_secret": contains_secret(serialized),
        "ioc_match": ioc_hit(iocs, tool, args, serialized),
        "injection_active": injection_active,
        "command_classes": command_classes(command),
        "tool_consequential": is_consequential(tool),
        "hosts": host_list,
        "path": path,
        "command": command,
        "serialized": serialized,
    }
