"""本地研判看板。默认只听 127.0.0.1。"""

from __future__ import annotations

import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from aegis.guard import AegisGuard
from aegis.model import model_card
from aegis.models import Decision
from aegis.policy import default_policy_path, load_policy
from aegis.runner import run_all, run_scenario, summary
from aegis.scenarios import SCENARIOS

_WEB = Path(__file__).resolve().parent / "web" / "index.html"
_MAX_BODY = 1_000_000


def _local_origin(value: str, port: int) -> tuple[str, int] | None:
    """只接受当前端口上的回环 HTTP 源，拒绝 URL 解析器可能宽松处理的请求头。"""
    if not value or any(char.isspace() for char in value) or any(char in value for char in "\\?#"):
        return None
    try:
        parsed = urlparse(value)
        if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
            return None
        if parsed.username is not None or parsed.password is not None or parsed.path or parsed.netloc.endswith(":"):
            return None
        origin_port = parsed.port if parsed.port is not None else 80
        return (parsed.hostname, origin_port) if origin_port == port else None
    except ValueError:
        return None


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path == "/api/health":
            self._json({"ok": True, "service": "aegis"})
            return
        if path == "/api/llm":
            from aegis.agent import AgentConfigError, llm_status

            try:
                self._json(llm_status())
            except AgentConfigError as exc:
                self._json({"configured": False, "error": str(exc)}, status=400)
            return
        if path == "/api/scenarios":
            self._json(
                {
                    "scenarios": [
                        {
                            "id": item.id,
                            "title": item.title,
                            "summary": item.summary,
                            "capabilities": list(item.capabilities),
                            "steps": len(item.steps),
                        }
                        for item in SCENARIOS
                    ]
                }
            )
            return
        if path == "/api/policy":
            policy = load_policy()
            self._json(
                {
                    "path": str(default_policy_path()),
                    "trusted_domains": policy.trusted_domains,
                    "rules": [rule.to_dict() | {"description": rule.description} for rule in policy.rules],
                }
            )
            return
        if path in {"/", "/index.html"}:
            data = _WEB.read_bytes()
            self._bytes(data, "text/html; charset=utf-8")
            return
        self._json({"error": "not found"}, status=404)

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path == "/api/agent/run":
            # 即使看板监听 0.0.0.0，模型入口也仅支持回环 Host，不接受局域网或公网域名。
            hosts = self.headers.get_all("Host", [])
            origins = self.headers.get_all("Origin", [])
            port = self.server.server_address[1]
            host_origin = _local_origin(f"http://{hosts[0]}", port) if len(hosts) == 1 else None
            if host_origin is None:
                self._json({"error": "模型调用只接受当前端口的 localhost、127.0.0.1 或 [::1] Host"}, status=403)
                return
            if origins and (len(origins) != 1 or _local_origin(origins[0], port) != host_origin):
                self._json({"error": "模型调用只接受同源浏览器请求"}, status=403)
                return
            if self.headers.get_content_type() != "application/json":
                self._json({"error": "模型调用请求必须使用 application/json"}, status=415)
                return
        try:
            payload = self._body()
        except ValueError as exc:
            self._json({"error": str(exc)}, status=400)
            return
        try:
            if path == "/api/run":
                name = str(payload.get("name") or "")
                self._json(run_scenario(name))
                return
            if path == "/api/run-all":
                reports = run_all()
                self._json({"summary": summary(reports), "reports": reports})
                return
            if path == "/api/scan":
                self._json(_scan(payload))
                return
            if path == "/api/agent/run":
                from aegis.agent import (
                    AgentConfigError,
                    ScriptedChat,
                    live_backend_from_env,
                    llm_settings,
                    readme_exfil_turns,
                    run_tool_agent,
                )

                task = str(payload.get("task") or "读取项目 README 并总结用法")
                text = str(payload.get("text") or "")
                source = str(payload.get("source") or "README.md")
                backend_name = str(payload.get("backend") or "scripted")
                try:
                    backend = live_backend_from_env() if backend_name == "live" else ScriptedChat(readme_exfil_turns())
                except AgentConfigError as exc:
                    self._json(
                        {
                            "error": str(exc),
                            "configured": False,
                        },
                        status=400,
                    )
                    return
                result = run_tool_agent(task, text, backend, source=source)
                try:
                    settings = llm_settings()
                    result["configured_live"] = bool(settings["api_key"] and settings["model"])
                except AgentConfigError as exc:
                    result["configured_live"] = False
                    result["configuration_error"] = str(exc)
                self._json(result)
                return
            if path == "/api/victim/run":
                from aegis.victim import VictimAgent

                task = str(payload.get("task") or "读取项目 README 并总结用法")
                text = str(payload.get("text") or "")
                channel = str(payload.get("channel") or "resource")
                source = str(payload.get("source") or "README.md")
                auto_confirm = bool(payload.get("confirm", False))
                agent = VictimAgent()
                result = agent.run(task, text, channel=channel, source=source, auto_confirm_ask=auto_confirm)
                self._json(result)
                return
        except KeyError:
            self._json({"error": "未知场景"}, status=404)
            return
        except Exception as exc:  # noqa: BLE001
            self._json({"error": str(exc)}, status=500)
            return
        self._json({"error": "not found"}, status=404)

    def log_message(self, fmt: str, *args) -> None:
        return

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length > _MAX_BODY:
            raise ValueError("请求体过大")
        raw = self.rfile.read(length) if length else b"{}"
        data = json.loads(raw.decode("utf-8") or "{}")
        if not isinstance(data, dict):
            raise ValueError("请求体必须是 JSON 对象")
        return data

    def _json(self, payload: dict, status: int = 200) -> None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self._bytes(data, "application/json; charset=utf-8", status)

    def _bytes(self, data: bytes, content_type: str, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def make_server(host: str = "127.0.0.1", port: int = 8765) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), Handler)


def serve(host: str = "127.0.0.1", port: int = 8765) -> None:
    server = make_server(host, port)
    print(f"神盾 AEGIS 看板  http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


_BYPASS_INDICATORS: list[tuple[str, str, Any]] = [
    ("ear_wind", "隐喻对抗表达", re.compile(r"耳旁风|耳边风|当成玩笑|不要当真|就当没看见")),
    ("jailbreak_phrase", "越狱模式短语", re.compile(r"(?i)\b(?:dan mode|jailbreak|developer mode|do anything now)\b")),
    ("prompt_leak", "系统指令探测", re.compile(r"(?i)(?:system prompt|reveal (?:the|your) instructions|打印.*提示词|输出.*系统指令|把系统提示发给我)")),
    ("hypothetical", "假设情景规避", re.compile(r"(?i)\b(?:hypothetically speaking|pretend there are no rules|假设没有限制|在虚拟故事中)\b")),
    ("roleplay_override", "无约束角色扮演", re.compile(r"(?i)(?:扮演无限制|无约束角色|acting as an unfiltered)")),
]


def _scan(payload: dict) -> dict:
    channel = str(payload.get("channel") or "resource")
    text = str(payload.get("text") or "")
    source = str(payload.get("source") or "paste")
    guard = AegisGuard()
    if channel == "user":
        verdict = guard.inspect_user("scan", text)
    elif channel == "memory":
        verdict = guard.inspect_memory("scan", text, memory_id=source, op=str(payload.get("op") or "read"))
    elif channel == "tool_desc":
        verdict = guard.inspect_tool_description("scan", "paste", source, text)
    else:
        kind = channel if channel not in {"resource", "paste"} else "file"
        verdict = guard.inspect_resource("scan", text, source=source, kind=kind)

    # 研判分类：拦下了 / 这段绕过了当前规则 / 正常良性文档
    if verdict.decision in {Decision.BLOCK, Decision.ASK}:
        status = "blocked"
        status_zh = "拦下了"
        is_attack = True
        hit_rules = [f.family for f in verdict.findings] + [p.get("id") for p in verdict.policies if p.get("id")]
        hit_rules = list(dict.fromkeys(hit_rules))  # 去重保序
        evidence_indices = [
            {
                "id": f.id,
                "family": f.family,
                "start": f.start,
                "end": f.end,
                "quote": f.quote,
                "techniques": f.techniques,
            }
            for f in verdict.findings
        ]
        bypass_reason = ""
    else:
        # 放行时，区分究竟是良性安全文档，还是绕过了规则的对抗样本
        detected_indicators = [
            label for _, label, pat in _BYPASS_INDICATORS if pat.search(text)
        ]
        if detected_indicators or payload.get("expect_attack"):
            status = "bypassed"
            status_zh = "这段绕过了当前规则"
            is_attack = True
            hit_rules = []
            evidence_indices = []
            reasons = [f"触发诱导特征: {', '.join(detected_indicators)}" if detected_indicators else "用户标记为对抗样本"]
            reasons.append("当前确定性引擎规则库尚未覆盖此特定变形正则，未达拦截置信度阈值 (0.75)")
            bypass_reason = "；".join(reasons)
        else:
            status = "benign"
            status_zh = "正常放行（良性文档）"
            is_attack = False
            hit_rules = []
            evidence_indices = []
            bypass_reason = ""

    return {
        "status": status,
        "status_zh": status_zh,
        "is_attack": is_attack,
        "hit_rules": hit_rules,
        "evidence_indices": evidence_indices,
        "bypass_reason": bypass_reason,
        "verdict": verdict.to_dict(),
        "narrative": guard.narrative("scan"),
        "model_threshold": model_card().get("threshold", 0.5),
    }
