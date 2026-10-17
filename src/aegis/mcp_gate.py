"""MCP 中间代理的判定。传输循环在 proxy.py，这里只改写 JSON-RPC。"""

from __future__ import annotations

import json
import threading

from aegis.guard import AegisGuard
from aegis.models import Decision


class McpGate:
    def __init__(self, guard: AegisGuard | None = None, *, session_id: str = "mcp", server_name: str = "upstream") -> None:
        self.guard = guard or AegisGuard()
        self.session_id = session_id
        self.server_name = server_name
        self.pending: dict[object, dict] = {}
        self._lock = threading.Lock()

    def on_client(self, message: dict) -> tuple[str, dict]:
        if message.get("method") != "tools/call":
            return "forward", message
        params = message.get("params") or {}
        name = str(params.get("name") or "")
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

    def _filter_tools(self, message: dict) -> dict:
        kept = []
        for tool in message["result"].get("tools") or []:
            name = str(tool.get("name") or "")
            description = str(tool.get("description") or "")
            verdict = self.guard.inspect_tool_description(self.session_id, self.server_name, name, description)
            if verdict.decision == Decision.BLOCK:
                continue
            if verdict.decision == Decision.ASK:
                tool = dict(tool)
                tool["description"] = description[:120] + "\n[AEGIS] 工具描述发生变化，调用前需要重新确认。"
            kept.append(tool)
        rewritten = json.loads(json.dumps(message))
        rewritten["result"]["tools"] = kept
        return rewritten


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
