"""本地研判看板。默认只听 127.0.0.1。"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from aegis.guard import AegisGuard
from aegis.policy import default_policy_path, load_policy
from aegis.runner import run_all, run_scenario, summary
from aegis.scenarios import SCENARIOS

_WEB = Path(__file__).resolve().parent / "web" / "index.html"
_MAX_BODY = 1_000_000


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path == "/api/health":
            self._json({"ok": True, "service": "aegis"})
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
    return {"verdict": verdict.to_dict(), "narrative": guard.narrative("scan")}
