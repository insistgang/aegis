"""受害 Agent：不调用任何大模型 API。
根据用户意图与外部不可信文本，用确定性规则抽取工具调用计划，并交给 AegisGuard 判定。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from aegis.guard import AegisGuard
from aegis.models import Decision, Verdict
from aegis.redact import redact

# 路径匹配
_PATH_RE = re.compile(
    r"(?:~|\/|[a-zA-Z]:\\)[\w\-.\/\\~]+"
    r"|(?:\.[\w\-]+|\/[\w\-]+|\b(?:id_rsa|credentials|authorized_keys|\.env|id_ed25519)\b)"
)

# URL 匹配
_URL_RE = re.compile(r"https?:\/\/[^\s\"'<>`\)\}\]]+")

# 命令执行模式
_EXEC_PATTERNS = [
    re.compile(r"(?:^|[\s;`\"'\(])(?:执行|运行|\brun\b|\bexec\b|\bbash\b|\bsh\b)\s*[:：`\"']?\s+([^\n`\"'<>]{3,})", re.IGNORECASE),
    re.compile(r"`([^`\n]{3,})`"),
    re.compile(r"(?:curl|wget)\s+[^\n|]+\|\s*(?:bash|sh)", re.IGNORECASE),
    re.compile(r"rm\s+-rf\s+[^\n`\"'<>]+", re.IGNORECASE),
]

# Git 推送模式
_GIT_PUSH_RE = re.compile(r"(?:git\s+push|推送代码|提交并推送|git\.push|push\s+to\s+origin)", re.IGNORECASE)

# 子 Agent 派生模式
_SPAWN_PATTERNS = [
    re.compile(r"(?:派生|创建|交给|spawn|agent\.spawn)(?:子任务|子\s*Agent|subagent)\s*[:：]?\s*([^\n]{3,})", re.IGNORECASE),
    re.compile(r"agent\.spawn\s*\((.*?)\)", re.IGNORECASE),
]


@dataclass
class PlannedStep:
    tool: str
    args: dict[str, Any]
    reason: str = ""
    executed: bool = False
    decision: Decision | None = None
    verdict: Verdict | None = None

    def to_dict(self) -> dict:
        return {
            "tool": self.tool,
            "args": redact(self.args),
            "reason": self.reason,
            "executed": self.executed,
            "decision": self.decision.value if self.decision else None,
            "verdict": self.verdict.to_dict() if self.verdict else None,
        }


def extract_tool_plan(text: str) -> list[PlannedStep]:
    """从不可信文本中，用确定性规则提取该 Agent 盲从诱导会尝试调用的工具列表。
    涵盖：fs.read, fs.write, net.fetch, exec, git.push, agent.spawn。
    """
    plan: list[PlannedStep] = []
    seen: set[tuple[str, str]] = set()

    def add(tool: str, args: dict[str, Any], reason: str) -> None:
        key = (tool, str(sorted(args.items())))
        if key not in seen:
            seen.add(key)
            plan.append(PlannedStep(tool=tool, args=args, reason=reason))

    # 1. 查找读取文件指令 (fs.read)
    text_no_urls = _URL_RE.sub(" ", text)
    read_keywords = ["读取", "read", "查看", "cat", "view", "dump", "读出", "get"]
    for line in text_no_urls.splitlines():
        if any(kw in line.casefold() for kw in read_keywords):
            for match in _PATH_RE.finditer(line):
                path = match.group(0).strip(" \t'\"`.,;")
                if len(path) >= 3 and not path.startswith(("//", "http")):
                    add("fs.read", {"path": path}, f"从文本提取读取指令: {path}")

    # 兜底直接找敏感路径如果文本包含读取倾向
    if not any(step.tool == "fs.read" for step in plan) and any(kw in text_no_urls.casefold() for kw in ["id_rsa", "credentials", ".env", "passwd", "authorized_keys"]):
        for match in _PATH_RE.finditer(text_no_urls):
            path = match.group(0).strip(" \t'\"`.,;")
            if not path.startswith(("//", "http")) and any(s in path for s in ["id_rsa", "credentials", ".env", "passwd", "authorized_keys"]):
                add("fs.read", {"path": path}, f"提取目标路径: {path}")

    # 2. 查找写入文件指令 (fs.write)
    write_keywords = ["写入", "write", "append", "覆盖", "保存到", "save to", "echo"]
    for line in text_no_urls.splitlines():
        if any(kw in line.casefold() for kw in write_keywords):
            for match in _PATH_RE.finditer(line):
                path = match.group(0).strip(" \t'\"`.,;")
                if len(path) >= 3 and not path.startswith(("//", "http")):
                    add("fs.write", {"path": path, "content": "injected_content"}, f"提取写入指令: {path}")

    # 3. 查找网络外发指令 (net.fetch)
    urls = _URL_RE.findall(text)
    for url in urls:
        clean_url = url.rstrip(".,;`\"'>")
        add("net.fetch", {"url": clean_url, "body": "exfiltrated_data"}, f"提取外发 URL: {clean_url}")

    # 4. 查找命令执行指令 (exec)
    exec_found = False
    for pat in _EXEC_PATTERNS:
        for match in pat.finditer(text):
            cmd = match.group(1 if match.groups() else 0).strip(" \t`\"'")
            if len(cmd) >= 4 and not cmd.startswith(("http", "~", "/id_rsa")) and not any(p in cmd for p in ["并发送", "读取", "-->"]):
                add("exec", {"command": cmd}, f"提取可疑执行命令: {cmd}")
                exec_found = True
    if not exec_found and ("bash" in text or "curl" in text or "rm -rf" in text):
        for line in text.splitlines():
            line_s = line.strip()
            if line_s.startswith(("curl ", "wget ", "rm -rf ", "bash ", "sh ")):
                add("exec", {"command": line_s}, f"提取单行脚本命令: {line_s}")

    # 5. 查找 Git 推送指令 (git.push)
    if _GIT_PUSH_RE.search(text):
        add("git.push", {"repo": "origin", "remote": "origin"}, "提取 Git 推送指令")

    # 6. 查找子 Agent 派生 (agent.spawn)
    for pat in _SPAWN_PATTERNS:
        for match in pat.finditer(text):
            arg = match.group(1).strip()
            add("agent.spawn", {"child": "auditor", "prompt": arg}, f"提取子任务派生指令: {arg[:40]}")

    return plan


class VictimAgent:
    """不接大模型的受害 Agent，用于在测试与看板中真实再现攻击驱动。"""

    def __init__(self, guard: AegisGuard | None = None) -> None:
        self.guard = guard or AegisGuard()

    def run(
        self,
        task: str,
        untrusted_text: str,
        *,
        session_id: str = "victim_sim",
        channel: str = "resource",
        source: str = "README.md",
        auto_confirm_ask: bool = False,
    ) -> dict[str, Any]:
        """执行完整仿真循环：
        1. 检查用户原始请求
        2. 引入不可信外部资源
        3. 从不可信文本中提取工具计划
        4. 将每一步工具调用交给 AegisGuard
        5. 询问停住，阻断留痕并不假装执行
        """
        history: list[dict[str, Any]] = []

        # 1. 守卫检查用户任务
        user_verdict = self.guard.inspect_user(session_id, task)
        history.append({
            "stage": "user_input",
            "text": task,
            "verdict": user_verdict.to_dict(),
        })

        # 2. 检查不可信内容输入
        if channel == "tool_result":
            content_verdict = self.guard.observe_tool_result(session_id, "fs.read", {"path": source}, untrusted_text)
        elif channel == "tool_desc":
            content_verdict = self.guard.inspect_tool_description(session_id, "upstream", source, untrusted_text)
        elif channel == "memory":
            content_verdict = self.guard.inspect_memory(session_id, untrusted_text, memory_id=source)
        else:
            content_verdict = self.guard.inspect_resource(session_id, untrusted_text, source=source, kind="file")

        history.append({
            "stage": "untrusted_input",
            "channel": channel,
            "source": source,
            "verdict": content_verdict.to_dict(),
        })

        # 3. 规划工具链
        plan = extract_tool_plan(untrusted_text)
        status = "completed"

        # 4. 逐个工具调用过守卫
        for step in plan:
            # 首次调用判定
            verdict = self.guard.inspect_tool_call(
                session_id,
                step.tool,
                step.args,
                confirmed=False,
            )
            step.verdict = verdict
            step.decision = verdict.decision

            if verdict.decision == Decision.ALLOW:
                step.executed = True
            elif verdict.decision == Decision.ASK:
                if auto_confirm_ask:
                    # 模拟用户确认
                    confirmed_verdict = self.guard.inspect_tool_call(
                        session_id,
                        step.tool,
                        step.args,
                        confirmed=True,
                    )
                    step.verdict = confirmed_verdict
                    step.decision = confirmed_verdict.decision
                    step.executed = (confirmed_verdict.decision == Decision.ALLOW)
                else:
                    step.executed = False
                    status = "paused_for_confirmation"
                    break
            elif verdict.decision == Decision.BLOCK:
                # 阻断：必须留下轨迹，不得假装已经执行
                step.executed = False

        snapshot = self.guard.snapshot(session_id)
        return {
            "session_id": session_id,
            "task": task,
            "status": status,
            "plan": [step.to_dict() for step in plan],
            "history": history,
            "narrative": snapshot.get("narrative", ""),
            "dag": snapshot.get("dag", {}),
            "timeline": snapshot.get("timeline", []),
            "impact": snapshot.get("impact", []),
            "iocs": snapshot.get("iocs", []),
        }
