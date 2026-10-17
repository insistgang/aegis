"""把一次判定写成可落地的中文结论。"""

from __future__ import annotations

import re

from aegis.models import DECISION_ZH, INTENT_ZH, Decision, Intent, Verdict
from aegis.paths import extract_path
from aegis.redact import redact

_CAUSE = {
    "resource": "间接提示注入引发的工具滥用行为",
    "tool_result": "间接提示注入引发的工具滥用行为",
    "memory": "记忆污染引发的工具滥用行为",
    "tool_desc": "MCP 工具链投毒引发的工具滥用行为",
    "user": "直接提示注入引发的工具滥用行为",
}


def host_of(url: str) -> str:
    match = re.search(r"https?://([^/\s:]+)", url or "", re.IGNORECASE)
    return match.group(1).lower() if match else ""


def describe_action(tool: str, args: dict | None) -> str:
    args = args or {}
    path = extract_path(args)
    if tool == "fs.read":
        if ".ssh" in path:
            return "调用 fs.read 读取本地 SSH 私钥文件"
        if ".aws" in path:
            return "调用 fs.read 读取本地 AWS 凭证文件"
        if path_name_sensitive(path):
            return f"调用 fs.read 读取凭据文件 {path}"
        return f"调用 fs.read 读取 {path or '文件'}"
    if tool == "fs.write":
        return f"调用 fs.write 向 {path or '目标路径'} 写入文件"
    if tool == "net.fetch":
        host = host_of(str(args.get("url") or args.get("endpoint") or ""))
        target = host or "未知目标"
        return f"通过 net.fetch 向外部未知域名 {target} 发起数据传输"
    if tool == "exec":
        command = str(args.get("command") or args.get("cmd") or "")
        short = command if len(command) <= 72 else command[:69] + "..."
        return f"调用 exec 执行命令“{short}”"
    if tool == "git.push":
        repo = args.get("repo") or args.get("remote") or "当前仓库"
        return f"调用 git.push 推送 {repo}"
    if tool == "git.commit":
        return "调用 git.commit 创建提交"
    if tool.startswith("agent."):
        child = args.get("child") or "worker"
        return f"向子 Agent {child} 传递当前会话中的敏感信息"
    return f"调用 {tool}"


def path_name_sensitive(path: str) -> bool:
    base = path.replace("\\", "/").rsplit("/", 1)[-1]
    return base in {".env", "credentials", "credentials.json", "id_rsa", "id_ed25519"} or base.startswith(".env.")


def step_explanation(verdict_bits: dict) -> str:
    decision = DECISION_ZH[Decision(verdict_bits["decision"])]
    parts = [f"判定为{decision}"]
    if verdict_bits.get("action"):
        parts.append(verdict_bits["action"])
    if verdict_bits.get("policies"):
        names = "、".join(item["id"] for item in verdict_bits["policies"])
        parts.append(f"命中策略 {names}")
    if verdict_bits.get("families"):
        parts.append("识别到 " + "、".join(verdict_bits["families"]))
    if verdict_bits.get("deviation", 0) >= 0.65:
        parts.append("执行计划偏离用户原始任务")
    if verdict_bits.get("confirmed") and verdict_bits["decision"] == Decision.ALLOW.value:
        parts.append("本次询问已由用户确认")
    if verdict_bits.get("confirmed") and verdict_bits["decision"] == Decision.BLOCK.value:
        parts.append("用户确认不能覆盖强制阻断")
    return "。".join(parts) + "。"


def narrative(session_view: dict, blocked_actions: list[str]) -> str:
    cause = _CAUSE.get(session_view.get("cause_channel", ""), "")
    phrase = session_view.get("task_phrase") or INTENT_ZH[Intent(session_view.get("intent", "unknown"))]
    source = session_view.get("cause_source") or ""
    source_bit = f"触发源：{source}。" if source else ""
    if session_view.get("hostile_open") and not blocked_actions:
        return f"用户输入本身为直接提示注入，系统已阻断，未把该输入当作可执行任务。{source_bit}"
    if not blocked_actions:
        if cause:
            return f"用户原始请求为{phrase}。系统在输入链路中识别到{cause.replace('引发的工具滥用行为', '')}，已隔离对应内容。{source_bit}"
        return f"用户原始请求为{phrase}。已观察的工具调用与该意图一致，予以放行。"
    actions = _join_actions(blocked_actions)
    if not cause:
        cause = "意图与执行计划偏离引发的策略阻断"
    head = "用户输入为直接提示注入" if session_view.get("hostile_open") else f"用户原始请求为{phrase}"
    return redact(f"{head}，Agent 却{actions}，判定为{cause}。{source_bit}")


def _join_actions(actions: list[str]) -> str:
    read_ssh = next((item for item in actions if item.startswith("调用 fs.read 读取本地 SSH")), "")
    fetch = next((item for item in actions if item.startswith("通过 net.fetch")), "")
    if read_ssh and fetch and len(actions) == 2:
        return f"{read_ssh}，并{fetch}"
    if len(actions) == 1:
        return actions[0]
    return "，并".join(actions)


def risk_level(decision: Decision, score: float) -> str:
    if decision == Decision.BLOCK:
        return "critical" if score >= 0.9 else "high"
    if decision == Decision.ASK:
        return "medium"
    return "low"


def public_verdict(verdict: Verdict) -> dict:
    data = verdict.to_dict()
    data["explanation"] = redact(data["explanation"])
    return data
