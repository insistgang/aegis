"""MCP 中间代理的判定与多上游路由。传输循环在 proxy.py，这里只改写 JSON-RPC。"""

from __future__ import annotations

import json
import threading
from typing import Any

from aegis.guard import AegisGuard
from aegis.models import Decision, Verdict


class McpGate:
    def __init__(self, guard: AegisGuard | None = None, *, session_id: str = "mcp", server_name: str = "upstream") -> None:
        self.guard = guard or AegisGuard()
        self.session_id = session_id
        self.server_name = server_name
        self.pending: dict[object, dict] = {}
        # A later description refresh cannot silently release a known poisoned tool.
        self._quarantined_tools: dict[str, Verdict] = {}
        self._lock = threading.Lock()

    def on_client(self, message: dict) -> tuple[str, dict]:
        if message.get("method") != "tools/call":
            return "forward", message
        params = message.get("params") or {}
        name = str(params.get("name") or "")
        quarantined = self.quarantined_verdict(name)
        if quarantined is not None:
            return "respond", _deny(message.get("id"), quarantined)
        args = params.get("arguments") or {}
        if not isinstance(args, dict):
            args = {"value": args}
        meta = params.get("_meta") or {}
        confirmed = bool(meta.get("aegisConfirm"))
        verdict = self.guard.inspect_tool_call(
            self.session_id,
            name,
            args,
            confirmed=confirmed,
            mcp=self.server_name,
        )
        if verdict.decision == Decision.ALLOW:
            with self._lock:
                self.pending[message.get("id")] = {"name": name, "args": args}
            return "forward", message
        return "respond", _deny(message.get("id"), verdict)

    def on_upstream(self, message: dict) -> dict:
        result = message.get("result")
        if isinstance(result, dict) and "tools" in result:
            return self._filter_tools(message)
        call_id = message.get("id")
        with self._lock:
            call = self.pending.pop(call_id, None)
        if call and isinstance(result, dict):
            verdict = self.guard.observe_tool_result(
                self.session_id,
                call["name"],
                call["args"],
                _result_text(result),
            )
            if verdict.decision == Decision.BLOCK:
                rewritten = dict(message)
                rewritten["result"] = {
                    "content": [
                        {
                            "type": "text",
                            "text": "[AEGIS] 工具结果已隔离，未把外部注入转发进模型上下文。" + verdict.explanation,
                        }
                    ],
                    "isError": False,
                    "_meta": {"aegisDecision": "block"},
                }
                return rewritten
        return message

    def quarantined_verdict(self, name: str) -> Verdict | None:
        with self._lock:
            return self._quarantined_tools.get(name)

    def _filter_tools(self, message: dict) -> dict:
        kept = []
        for tool in message["result"].get("tools") or []:
            name = str(tool.get("name") or "")
            description = str(tool.get("description") or "")
            verdict = self.guard.inspect_tool_description(self.session_id, self.server_name, name, description)
            if verdict.decision == Decision.BLOCK:
                with self._lock:
                    self._quarantined_tools[name] = verdict
                continue
            if self.quarantined_verdict(name) is not None:
                continue
            tool = dict(tool)
            tool["source"] = self.server_name
            tool["server"] = self.server_name
            if verdict.decision == Decision.ASK:
                tool["description"] = description[:120] + "\n[AEGIS] 工具描述发生变化，调用前需要重新确认。"
            kept.append(tool)
        rewritten = json.loads(json.dumps(message))
        rewritten["result"]["tools"] = kept
        return rewritten


class MultiMcpGate:
    """管理多个命名上游 stdio MCP server 的统一安全门禁与路由。"""

    def __init__(
        self,
        guard: AegisGuard | None = None,
        *,
        session_id: str = "mcp",
        servers: list[str] | None = None,
    ) -> None:
        self.guard = guard or AegisGuard()
        self.session_id = session_id
        self.servers = list(servers or [])
        self.gates: dict[str, McpGate] = {
            s: McpGate(self.guard, session_id=session_id, server_name=s)
            for s in self.servers
        }
        self.tool_routes: dict[str, str] = {}
        self.pending_calls: dict[object, tuple[str, str, dict]] = {}  # id -> (server_name, raw_name, args)
        self._lock = threading.Lock()

    def get_gate(self, server_name: str) -> McpGate:
        with self._lock:
            if server_name not in self.gates:
                self.gates[server_name] = McpGate(self.guard, session_id=self.session_id, server_name=server_name)
                if server_name not in self.servers:
                    self.servers.append(server_name)
            return self.gates[server_name]

    def register_tools(self, server_name: str, tools: list[dict]) -> None:
        with self._lock:
            for tool in tools:
                name = str(tool.get("name") or "")
                self.tool_routes[name] = server_name
                self.tool_routes[f"{server_name}.{name}"] = server_name

    def filter_server_tools(self, server_name: str, message: dict) -> dict:
        gate = self.get_gate(server_name)
        filtered = gate._filter_tools(message)
        self.register_tools(server_name, filtered["result"].get("tools") or [])
        return filtered

    def on_client(self, message: dict) -> tuple[str, str | None, dict]:
        """返回 (action, target_server, message_to_send)
        action:
        - "respond": 代理直接响应给客户端
        - "broadcast": 需要向全部上游广播（如 tools/list）
        - "forward": 转发给 target_server
        """
        method = message.get("method")
        msg_id = message.get("id")

        if method == "initialize":
            return "respond", None, {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "aegis-mcp-multi-proxy", "version": "1.0"},
                },
            }

        if method == "tools/list":
            return "broadcast", None, message

        if method != "tools/call":
            target = self.servers[0] if self.servers else "upstream"
            return "forward", target, message

        params = message.get("params") or {}
        raw_name = str(params.get("name") or "")
        args = params.get("arguments") or {}
        if not isinstance(args, dict):
            args = {"value": args}
        meta = params.get("_meta") or {}
        confirmed = bool(meta.get("aegisConfirm"))

        # 解析路由目标
        target_server = None
        target_tool = raw_name

        if "." in raw_name:
            prefix, suffix = raw_name.split(".", 1)
            if prefix in self.servers or prefix in self.gates:
                target_server = prefix
                target_tool = suffix

        if not target_server and meta.get("server"):
            target_server = str(meta["server"])

        if not target_server and params.get("server"):
            target_server = str(params["server"])

        if not target_server:
            with self._lock:
                target_server = self.tool_routes.get(raw_name)

        if not target_server:
            target_server = self.servers[0] if self.servers else "upstream"

        quarantined = self.get_gate(target_server).quarantined_verdict(target_tool)
        if quarantined is not None:
            return "respond", None, _deny(msg_id, quarantined)

        # 安全判定：传 target_tool 或 raw_name
        verdict = self.guard.inspect_tool_call(
            self.session_id,
            target_tool,
            args,
            confirmed=confirmed,
            mcp=target_server,
        )

        if verdict.decision == Decision.ALLOW:
            with self._lock:
                self.pending_calls[msg_id] = (target_server, target_tool, args)
            forwarded = dict(message)
            f_params = dict(params)
            f_params["name"] = target_tool
            forwarded["params"] = f_params
            return "forward", target_server, forwarded

        # 阻断或等待确认：截断并直接回包，绝不发送给任何上游
        return "respond", None, _deny(msg_id, verdict)

    def on_upstream_result(self, server_name: str, message: dict) -> dict:
        call_id = message.get("id")
        with self._lock:
            call = self.pending_calls.pop(call_id, None)

        result = message.get("result")
        if call and isinstance(result, dict):
            _, target_tool, args = call
            verdict = self.guard.observe_tool_result(
                self.session_id,
                target_tool,
                args,
                _result_text(result),
            )
            if verdict.decision == Decision.BLOCK:
                rewritten = dict(message)
                rewritten["result"] = {
                    "content": [
                        {
                            "type": "text",
                            "text": f"[AEGIS] 工具结果已隔离，未把外部注入转发进模型上下文。{verdict.explanation}",
                        }
                    ],
                    "isError": False,
                    "_meta": {"aegisDecision": "block"},
                }
                return rewritten
        return message


def _deny(message_id, verdict) -> dict:
    label = "AEGIS_BLOCK" if verdict.decision == Decision.BLOCK else "AEGIS_ASK"
    return {
        "jsonrpc": "2.0",
        "id": message_id,
        "result": {
            "content": [{"type": "text", "text": f"{label}: {verdict.explanation}"}],
            "isError": True,
            "_meta": {"aegisDecision": verdict.decision.value},
        },
    }


def _result_text(result: dict) -> str:
    chunks = []
    for item in result.get("content") or []:
        if isinstance(item, dict) and item.get("type") == "text":
            chunks.append(str(item.get("text") or ""))
        elif isinstance(item, str):
            chunks.append(item)
    if chunks:
        return "\n".join(chunks)
    return json.dumps(result, ensure_ascii=False)
