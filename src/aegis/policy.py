"""策略 DSL 解释器。组织策略可以加严，不能拿掉赛题基线。"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import os

import yaml

from aegis.models import Decision
from aegis.paths import any_glob, glob_match, path_sensitive_write

# 仅保留不可变原始值；Rule/when 在每次求值时重新创建，不能通过修改命中结果降级。
_FLOOR_WRITE_PATHS = (
    "**/.ssh/**", "**/.aws/**", "**/.gnupg/**", "**/.kube/**", "**/authorized_keys",
    "**/.env", "**/.env.*", "**/credentials", "**/credentials.json", "/etc/cron*",
    "/etc/cron*/**", "/etc/crontab", "**/cron.d/**", "**/LaunchAgents/**",
    "**/LaunchDaemons/**", "**/systemd/system/**", "**/systemd/user/**",
)
_FLOOR_EXEC_CLASSES = ("download_pipe", "decode_exec", "command_subst_download", "download_exec_chain")
_FLOOR_REVIEW_INTENTS = ("code_review", "read_doc", "data_query")

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
        hits = _runtime_floor(features)
        floor_ids = {rule.id for rule in hits}
        for rule in self.rules:
            if not tool_matches(rule.tool, features["tool"]):
                continue
            if match_when(rule.when, features):
                if rule.id in floor_ids and rule.decision == Decision.BLOCK:
                    continue
                hits.append(rule)
        return hits


def _floor_rules() -> list[Rule]:
    """每次返回新的强制基线，不依赖 YAML、PolicySet.rules 或可变单例。"""
    return [
        Rule("fs-write-sensitive", "fs.write", Decision.BLOCK, "critical",
             {"path_any": list(_FLOOR_WRITE_PATHS)}, "禁止写入敏感凭据、cron 与系统自启动位置"),
        Rule("net-exfil-secret", "net.fetch", Decision.BLOCK, "critical",
             {"domain_not_trusted": True, "carries_session_secret": True}, "禁止向非信任域名外发会话秘密"),
        Rule("net-exfil-secret-pattern", "net.fetch", Decision.BLOCK, "critical",
             {"domain_not_trusted": True, "args_contain_secret": True}, "禁止向非信任域名外发密钥材料"),
        Rule("exec-malicious", "exec", Decision.BLOCK, "critical",
             {"command_class_any": list(_FLOOR_EXEC_CLASSES)}, "禁止下载或解码后执行命令"),
        Rule("exec-destructive", "exec", Decision.BLOCK, "critical",
             {"command_class_any": ["destructive"]}, "禁止破坏根文件系统的命令"),
        Rule("git-push-off-review", "git.push", Decision.BLOCK, "high",
             {"intent_in": list(_FLOOR_REVIEW_INTENTS)}, "检视或阅读任务禁止推送"),
        Rule("subagent-secret", "agent.*", Decision.BLOCK, "critical",
             {"any": [{"carries_session_secret": True}, {"args_contain_secret": True}]},
             "禁止向子 Agent 传递秘密"),
    ]


def _runtime_floor(features: dict) -> list[Rule]:
    hits = []
    for rule in _floor_rules():
        if not tool_matches(rule.tool, features["tool"]):
            continue
        # 路径函数也覆盖大小写、规范化变体及凭据后缀；不会读取文件系统。
        sensitive_write = rule.id == "fs-write-sensitive" and any(
            path_sensitive_write(path) for path in features.get("paths", [])
        )
        if sensitive_write or match_when(rule.when, features):
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
    for key, expected in when.items():
        if key == "all":
            matched = all(match_when(item, features) for item in expected)
        elif key == "any":
            matched = any(match_when(item, features) for item in expected)
        else:
            matched = _match_condition(key, expected, features)
        if not matched:
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
    when = item.get("when")
    if when is None:
        when = {}
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
    for key, value in when.items():
        if key in {"all", "any"}:
            continue
        if key in {"path_any", "intent_in", "command_class_any"}:
            if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
                raise PolicyError(f"规则 {rule_id} 的 {key} 必须是字符串列表")
        elif key == "intent_deviation_gte":
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value <= 1:
                raise PolicyError(f"规则 {rule_id} 的 {key} 必须在 0 到 1 之间")
        elif not isinstance(value, bool):
            raise PolicyError(f"规则 {rule_id} 的 {key} 必须是布尔值")


def iter_conditions(when: dict):
    for key, value in when.items():
        if key in {"all", "any"}:
            for child in value:
                yield from iter_conditions(child)
        else:
            yield key, value


def validate_floor(rules: list[Rule]) -> None:
    """用结构蕴含证明基线覆盖，不把有限运行样例或条件出现当作证明。

    每个默认路径模式、危险类别和受保护意图均单独证明。all 必须逐项
    蕴含，any 必须至少有完整覆盖分支；不能证明的额外限制不算基线。
    路径证明保守接受相同模式、全局 ** 或确定覆盖的目录前缀，避免用
    几个路径样例声称两个任意 glob 等价。可添加任意加严规则，或改成
    无条件/更宽的 block 规则。
    """
    problems: list[str] = []
    for rule in rules:
        _validate_when(rule.when, rule.id)

    def require(tool: str, premise: dict, label: str) -> None:
        if not any(
            rule.decision == Decision.BLOCK and tool_matches(rule.tool, tool) and _when_covers(rule.when, premise)
            for rule in rules
        ):
            problems.append(label)

    for pattern in _FLOOR_WRITE_PATHS:
        require("fs.write", {"path_any": pattern}, f"fs.write 缺少完整路径阻断 {pattern}")
    for secret_field in ("carries_session_secret", "args_contain_secret"):
        require("net.fetch", {"domain_not_trusted": True, secret_field: True}, f"缺少非信任域名 {secret_field} 外发阻断")
        require("agent.spawn", {secret_field: True}, f"缺少子 Agent {secret_field} 传递阻断")
    for command_class in (*_FLOOR_EXEC_CLASSES, "destructive"):
        require("exec", {"command_class_any": command_class}, f"缺少危险命令 {command_class} 阻断")
    for intent in _FLOOR_REVIEW_INTENTS:
        require("git.push", {"intent_in": intent}, f"缺少 {intent} 任务的推送阻断")
    if problems:
        raise PolicyError("策略低于赛题基线：" + "；".join(problems))


def _when_covers(when: dict, premise: dict) -> bool:
    for key, expected in when.items():
        if key == "all":
            covered = all(_when_covers(child, premise) for child in expected)
        elif key == "any":
            covered = any(_when_covers(child, premise) for child in expected)
        elif key not in premise:
            covered = False
        elif key == "path_any":
            covered = any(_glob_covers(pattern, premise[key]) for pattern in expected)
        elif key in {"intent_in", "command_class_any"}:
            covered = premise[key] in expected
        else:
            covered = expected == premise[key]
        if not covered:
            return False
    return True


def _glob_covers(pattern: str, required: str) -> bool:
    if pattern in {required, "**"}:
        return True
    # 没有通配符的目录前缀加 **，其所有后缀确定包含被保护模式。
    prefix = pattern[:-2] if pattern.endswith("/**") else ""
    return bool(prefix and "*" not in prefix and required.startswith(prefix))


def domain_trusted(host: str, trusted: list[str]) -> bool:
    host = (host or "").lower().rstrip(".")
    if not host:
        return False
    for item in trusted:
        if host == item or host.endswith("." + item):
            return True
    return False
