"""锁定用户任务意图。带注入的输入不能改写已经锁定的任务。"""

from __future__ import annotations

import re

from aegis.models import Intent
from aegis.normalize import normalize

_SHIP = re.compile(r"(推送到远程|发布上线|git push\b)|^\s*(?:please\s+)?push\b")
_NO_PUSH = re.compile(r"(?:不要|禁止|不得|别|勿).{0,6}(?:提交|推送)|\b(?:do not|don't|must not|never|no)\s+(?:git\s+)?push\b")
_REVIEW = re.compile(r"(代码检视|code review|审查|检视|不要改代码|只看\s*diff|\breview\b)")
_EDIT = re.compile(r"(实现|修改代码|重构|\bfix\b|refactor|implement|写到|写入)")
_OPS = re.compile(r"(部署|deploy|运行.{0,12}测试|run the tests|排查)")
_READ = re.compile(r"(readme|文档|总结用法|读一下)")
_QUERY = re.compile(r"(查询|查找资料|lookup)")
_ISSUE = re.compile(r"(\bissue\b|\bpull request\b|\bpr\b)")
_EXPLICIT_EDIT = re.compile(r"^\s*(?:please\s+)?(?:write|save|create|update)\b", re.I)
_EXPLICIT_CHECK = re.compile(r"^\s*(?:please\s+)?run\b.{0,100}(?:scripts/[^\s`]+|local check|tests?)", re.I)
_EXPLICIT_HEALTH = re.compile(r"^\s*(?:please\s+)?(?:check|fetch|query|request)\b.{0,100}\bhealth\b", re.I)
_EXPLICIT_CONFIG = re.compile(r"^\s*(?:please\s+)?(?:check|verify|inspect|diagnose)\b.{0,100}(?:configuration|credentials?|\.env\b)", re.I)


def classify(text: str) -> Intent:
    folded = normalize(text or "").folded
    if _SHIP.search(folded) and not _NO_PUSH.search(folded):
        return Intent.SHIP
    review = _REVIEW.search(folded) is not None
    edit = _EDIT.search(folded) is not None or _EXPLICIT_EDIT.search(folded) is not None
    if review and not edit:
        return Intent.CODE_REVIEW
    if edit:
        return Intent.CODE_EDIT
    if _OPS.search(folded) or _EXPLICIT_CHECK.search(folded) or _EXPLICIT_CONFIG.search(folded):
        return Intent.OPS
    if _READ.search(folded):
        return Intent.READ_DOC
    if _QUERY.search(folded) or _EXPLICIT_HEALTH.search(folded):
        return Intent.DATA_QUERY
    if _ISSUE.search(folded):
        return Intent.CODE_REVIEW
    return Intent.UNKNOWN


# 工具不在允许集时视为偏离。读文档允许拉取受控网页，检视不允许提交。
_ALLOWED: dict[Intent, set[str]] = {
    Intent.READ_DOC: {"fs.read", "fs.list", "net.fetch"},
    Intent.CODE_REVIEW: {"fs.read", "fs.list", "git.diff", "git.log", "git.show", "net.fetch"},
    Intent.CODE_EDIT: {"fs.read", "fs.list", "fs.write", "git.diff", "git.log", "git.show", "git.commit"},
    Intent.SHIP: {"fs.read", "fs.list", "fs.write", "git.diff", "git.commit", "git.push", "exec", "net.fetch"},
    Intent.OPS: {"fs.read", "fs.list", "fs.write", "exec", "net.fetch", "git.status"},
    Intent.DATA_QUERY: {"fs.read", "fs.list", "net.fetch", "db.query"},
    Intent.UNKNOWN: {"fs.read", "fs.list"},
}

CONSEQUENTIAL = {
    "exec",
    "fs.write",
    "net.fetch",
    "git.push",
    "git.commit",
    "agent.spawn",
    "agent.dispatch",
    "agent.send",
}


def is_consequential(tool: str) -> bool:
    return tool in CONSEQUENTIAL or tool.startswith("agent.")


def deviation(intent: Intent, tool: str) -> float:
    allowed = _ALLOWED.get(intent, set())
    if tool in allowed:
        return 0.0
    if is_consequential(tool):
        return 0.85
    return 0.4


def evaluate_alignment(
    intent: Intent,
    task_messages: list[str],
    tool: str,
    args: dict,
    history: list[dict],
    plan: list[dict],
    **kwargs,
) -> dict:
    """在既有工具意图分数之外检查合法任务约束、计划及调用序列。"""
    from aegis.alignment import evaluate_alignment as evaluate

    return evaluate(intent, task_messages, tool, args, history, plan, **kwargs)
