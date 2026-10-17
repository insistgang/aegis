"""策略 DSL 解释器。组织策略可以加严，不能拿掉赛题基线。"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import os

import yaml

from aegis.models import Decision
from aegis.paths import any_glob, glob_match

KNOWN_CONDITIONS = {
    "path_any",
    "path_sensitive_read",
    "intent_in",
    "injection_active",
    "domain_not_trusted",
    "carries_session_secret",
    "args_contain_secret",
    "ioc_match",
    "command_class_any",
    "tool_consequential",
    "intent_deviation_gte",
    "all",
    "any",
}


class PolicyError(ValueError):
    pass


@dataclass
class Rule:
    id: str
    tool: str
    decision: Decision
    risk: str
    when: dict
    description: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "tool": self.tool,
            "decision": self.decision.value,
            "risk": self.risk,
            "description": self.description,
        }


@dataclass
class PolicySet:
    rules: list[Rule] = field(default_factory=list)
    trusted_domains: list[str] = field(default_factory=list)
    path: str = ""

    def evaluate(self, features: dict) -> list[Rule]:
        hits: list[Rule] = []
        for rule in self.rules:
            if not tool_matches(rule.tool, features["tool"]):
                continue
            if match_when(rule.when, features):
                hits.append(rule)
        return hits


def tool_matches(pattern: str, tool: str) -> bool:
    if pattern == "*" or pattern == tool:
        return True
    if pattern.endswith(".*"):
        return tool.startswith(pattern[:-1])
    return glob_match(pattern, tool)


def match_when(when: dict | None, features: dict) -> bool:
    if not when:
        return True
    if "all" in when:
        return all(match_when(item, features) for item in when["all"])
    if "any" in when:
        return any(match_when(item, features) for item in when["any"])
    for key, expected in when.items():
        if not _match_condition(key, expected, features):
            return False
    return True


def _match_condition(key: str, expected, features: dict) -> bool:
    if key == "intent_deviation_gte":
        return float(features["intent_deviation"]) >= float(expected)
    if key == "intent_in":
        return features["intent"] in set(expected)
    if key == "path_any":
        return any_glob(list(expected), list(features["paths"]))
    if key == "command_class_any":
        return bool(set(features["command_classes"]) & set(expected))
    if key not in features:
        raise PolicyError(f"运行时缺少条件字段 {key}")
    return features[key] == expected


def default_policy_path() -> Path:
    return Path(__file__).resolve().parent / "data" / "default.yaml"


def load_policy(path: str | Path | None = None) -> PolicySet:
    chosen = path or os.environ.get("AEGIS_POLICY") or default_policy_path()
    policy_path = Path(chosen)
    try:
        raw = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise PolicyError(f"找不到策略文件 {policy_path}") from exc
    if not isinstance(raw, dict):
        raise PolicyError("策略文件顶层必须是映射")
    rules = [_parse_rule(item) for item in raw.get("rules") or []]
    trusted = [str(item).lower() for item in raw.get("trusted_domains") or []]
    validate_floor(rules)
    return PolicySet(rules=rules, trusted_domains=trusted, path=str(policy_path))


def _parse_rule(item: dict) -> Rule:
    if not isinstance(item, dict):
        raise PolicyError("规则必须是映射")
    missing = [key for key in ("id", "tool", "decision") if key not in item]
    if missing:
        raise PolicyError(f"规则缺少字段 {missing}")
    try:
        decision = Decision(str(item["decision"]))
    except ValueError as exc:
        raise PolicyError(f"规则 {item.get('id')} 的 decision 必须是 allow、ask 或 block") from exc
    when = item.get("when") or {}
    if not isinstance(when, dict):
        raise PolicyError(f"规则 {item['id']} 的 when 必须是映射")
    _validate_when(when, item["id"])
    risk = str(item.get("risk") or "medium")
    if risk not in {"low", "medium", "high", "critical"}:
        raise PolicyError(f"规则 {item['id']} 的 risk 不合法")
    return Rule(
        id=str(item["id"]),
        tool=str(item["tool"]),
        decision=decision,
        risk=risk,
        when=when,
        description=str(item.get("description") or ""),
    )


def _validate_when(when: dict, rule_id: str) -> None:
    unknown = [key for key in when if key not in KNOWN_CONDITIONS]
    if unknown:
        raise PolicyError(f"规则 {rule_id} 含未知条件 {unknown}")
    for key in ("all", "any"):
        if key in when:
            if not isinstance(when[key], list):
                raise PolicyError(f"规则 {rule_id} 的 {key} 必须是列表")
            for child in when[key]:
                if not isinstance(child, dict):
                    raise PolicyError(f"规则 {rule_id} 的嵌套条件必须是映射")
                _validate_when(child, rule_id)


def iter_conditions(when: dict):
    if not when:
        return
    if "all" in when:
        for child in when["all"]:
            yield from iter_conditions(child)
        return
    if "any" in when:
        for child in when["any"]:
            yield from iter_conditions(child)
        return
    yield from when.items()


def validate_floor(rules: list[Rule]) -> None:
    """赛题五条基线必须存在，且决策不能弱于阻断。"""
    problems: list[str] = []

    def blocked(tool: str) -> list[Rule]:
        return [rule for rule in rules if rule.decision == Decision.BLOCK and tool_matches(rule.tool, tool)]

    write_globs: list[str] = []
    for rule in blocked("fs.write"):
        for key, value in iter_conditions(rule.when):
            if key == "path_any":
                write_globs.extend(str(item) for item in value)
    blob = " ".join(write_globs)
    for needle in (".ssh", "cron", "LaunchAgents"):
        if needle not in blob:
            problems.append(f"fs.write 阻断规则缺少路径 {needle}")

    def has(tool: str, predicate) -> bool:
        return any(predicate(rule) for rule in blocked(tool))

    if not has(
        "net.fetch",
        lambda rule: _has(rule, "carries_session_secret", True) and _has(rule, "domain_not_trusted", True),
    ):
        problems.append("缺少非信任域名外发会话密钥的阻断规则")
    if not has(
        "exec",
        lambda rule: _has_any(rule, "command_class_any", {"download_pipe", "decode_exec"}),
    ):
        problems.append("缺少下载管道或解码执行的阻断规则")
    if not has("git.push", lambda rule: _has_value(rule, "intent_in", "code_review")):
        problems.append("缺少代码检视时禁止 git.push 的规则")
    if not has(
        "agent.spawn",
        lambda rule: _has(rule, "carries_session_secret", True) or _has(rule, "args_contain_secret", True),
    ):
        problems.append("缺少子 Agent 传递密钥的阻断规则")
    if problems:
        raise PolicyError("策略低于赛题基线：" + "；".join(problems))


def _has(rule: Rule, key: str, expected) -> bool:
    return any(item_key == key and item_value == expected for item_key, item_value in iter_conditions(rule.when))


def _has_value(rule: Rule, key: str, expected: str) -> bool:
    for item_key, item_value in iter_conditions(rule.when):
        if item_key == key and expected in set(item_value):
            return True
    return False


def _has_any(rule: Rule, key: str, expected: set[str]) -> bool:
    for item_key, item_value in iter_conditions(rule.when):
        if item_key == key and set(item_value) >= expected:
            return True
    return False


def domain_trusted(host: str, trusted: list[str]) -> bool:
    host = (host or "").lower().rstrip(".")
    if not host:
        return False
    for item in trusted:
        if host == item or host.endswith("." + item):
            return True
    return False
