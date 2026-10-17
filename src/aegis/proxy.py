"""把 AEGIS 放在 MCP 客户端和上游 server 之间。"""

from __future__ import annotations

import subprocess
import sys
import threading

from aegis.framing import encode_message, read_message
from aegis.mcp_gate import McpGate


def serve_stdio(upstream: list[str], server_name: str = "upstream") -> int:
    if not upstream:
        print("用法: aegis proxy --name files -- <上游命令>", file=sys.stderr)
        return 2
    process = subprocess.Popen(upstream, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    gate = McpGate(server_name=server_name)
    write_lock = threading.Lock()

    def emit(payload: dict | None) -> None:
        if payload is None:
            return
        data = encode_message(payload)
        with write_lock:
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()

    def upstream_loop() -> None:
        assert process.stdout is not None
        while True:
            message = read_message(process.stdout)
            if message is None:
                break
            try:
                emit(gate.on_upstream(message))
            except Exception as exc:  # noqa: BLE001 - 代理不能把上游异常变成静默丢包
                print(f"aegis proxy upstream error: {exc}", file=sys.stderr)

    worker = threading.Thread(target=upstream_loop, daemon=True)
    worker.start()
    assert process.stdin is not None
    try:
        while True:
            message = read_message(sys.stdin.buffer)
            if message is None:
                break
            action, payload = gate.on_client(message)
            if action == "respond":
                emit(payload)
            else:
                process.stdin.write(encode_message(payload))
                process.stdin.flush()
    finally:
        process.stdin.close()
        process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
    return 0
