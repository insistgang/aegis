"""把 AEGIS 放在 MCP 客户端和上游 server 之间，支持单上游与多上游 stdio 中间代理。"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
from pathlib import Path

from aegis.framing import encode_message, read_message
from aegis.mcp_gate import McpGate, MultiMcpGate


def load_proxy_config(path: str | Path) -> dict[str, list[str]]:
    """加载多上游配置，支持 JSON 与 YAML。格式兼容 mcpServers / mcp_servers / servers。"""
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    if p.suffix in {".yaml", ".yml"}:
        import yaml

        data = yaml.safe_load(text) or {}
    else:
        data = json.loads(text) or {}

    raw_servers = data.get("mcpServers") or data.get("mcp_servers") or data.get("servers") or {}
    upstreams: dict[str, list[str]] = {}
    for name, spec in raw_servers.items():
        if isinstance(spec, list):
            upstreams[name] = [str(x) for x in spec]
        elif isinstance(spec, dict):
            cmd = spec.get("command")
            args = spec.get("args") or []
            if cmd:
                upstreams[name] = [str(cmd)] + [str(a) for a in args]
    return upstreams


def serve_stdio(
    upstream: list[str] | dict[str, list[str]] | None = None,
    server_name: str = "upstream",
    config_path: str | Path | None = None,
) -> int:
    upstreams: dict[str, list[str]] = {}
    if config_path:
        upstreams = load_proxy_config(config_path)
    elif isinstance(upstream, dict):
        upstreams = dict(upstream)
    elif upstream:
        upstreams = {server_name: list(upstream)}

    if not upstreams:
        print("用法: aegis proxy [--config CONFIG] [--name NAME] [-- <上游命令>]", file=sys.stderr)
        return 2

    is_single = len(upstreams) == 1
    multi_gate = MultiMcpGate(servers=list(upstreams.keys()))

    processes: dict[str, subprocess.Popen] = {}
    write_locks: dict[str, threading.Lock] = {}
    for name, cmd in upstreams.items():
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        processes[name] = proc
        write_locks[name] = threading.Lock()

    client_write_lock = threading.Lock()

    def emit_client(payload: dict | None) -> None:
        if payload is None:
            return
        data = encode_message(payload)
        with client_write_lock:
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()

    def send_upstream(s_name: str, payload: dict) -> None:
        proc = processes.get(s_name)
        if proc and proc.stdin:
            data = encode_message(payload)
            with write_locks[s_name]:
                proc.stdin.write(data)
                proc.stdin.flush()

    # 聚合 tools/list
    pending_list_queries: dict[str, dict[str, Any]] = {}
    list_lock = threading.Lock()

    def upstream_loop(s_name: str, proc: subprocess.Popen) -> None:
        assert proc.stdout is not None
        while True:
            message = read_message(proc.stdout)
            if message is None:
                break
            try:
                msg_id = str(message.get("id")) if message.get("id") is not None else None
                # 判断是否是聚合 tools/list 响应
                handled = False
                if msg_id and msg_id.startswith("list_"):
                    parts = msg_id.split("_", 2)
                    if len(parts) >= 3:
                        orig_cid_str, s_target = parts[1], parts[2]
                        if s_target == s_name:
                            filtered = multi_gate.filter_server_tools(s_name, message)
                            tools = filtered["result"].get("tools") or []
                            with list_lock:
                                if orig_cid_str in pending_list_queries:
                                    entry = pending_list_queries[orig_cid_str]
                                    entry["results"][s_name] = tools
                                    if len(entry["results"]) >= len(upstreams):
                                        # 全部上游已返回
                                        all_tools = []
                                        for s_k in upstreams:
                                            all_tools.extend(entry["results"].get(s_k, []))
                                        combined_resp = {
                                            "jsonrpc": "2.0",
                                            "id": entry["orig_id"],
                                            "result": {"tools": all_tools},
                                        }
                                        pending_list_queries.pop(orig_cid_str, None)
                                        emit_client(combined_resp)
                                    handled = True
                if not handled:
                    # 单上游 tools/list 或 普通 tools/call 响应
                    result = message.get("result")
                    if isinstance(result, dict) and "tools" in result:
                        filtered = multi_gate.filter_server_tools(s_name, message)
                        emit_client(filtered)
                    else:
                        rewritten = multi_gate.on_upstream_result(s_name, message)
                        emit_client(rewritten)
            except Exception as exc:  # noqa: BLE001
                print(f"aegis proxy upstream [{s_name}] error: {exc}", file=sys.stderr)

    threads = []
    for s_name, proc in processes.items():
        t = threading.Thread(target=upstream_loop, args=(s_name, proc), daemon=True)
        t.start()
        threads.append(t)

    try:
        while True:
            client_msg = read_message(sys.stdin.buffer)
            if client_msg is None:
                break
            method = client_msg.get("method")
            cid = client_msg.get("id")

            # 处理单上游向下兼容：如果是单上游并且是 initialize，直接转给该上游
            if is_single and method == "initialize":
                single_name = next(iter(upstreams))
                send_upstream(single_name, client_msg)
                continue

            if method == "tools/list":
                if is_single:
                    single_name = next(iter(upstreams))
                    send_upstream(single_name, client_msg)
                else:
                    cid_str = str(cid)
                    with list_lock:
                        pending_list_queries[cid_str] = {
                            "orig_id": cid,
                            "results": {},
                        }
                    for s_k in upstreams:
                        send_upstream(s_k, {
                            "jsonrpc": "2.0",
                            "id": f"list_{cid_str}_{s_k}",
                            "method": "tools/list",
                            "params": client_msg.get("params") or {},
                        })
                continue

            # tools/call 或其他消息
            action, target_server, payload = multi_gate.on_client(client_msg)
            if action == "respond":
                emit_client(payload)
            elif action == "forward":
                if target_server and target_server in processes:
                    send_upstream(target_server, payload)
                else:
                    # 默认发送给第一个上游
                    default_s = next(iter(upstreams))
                    send_upstream(default_s, payload)
            elif action == "broadcast":
                for s_k in upstreams:
                    send_upstream(s_k, payload)
    finally:
        for proc in processes.values():
            if proc.stdin:
                try:
                    proc.stdin.close()
                except Exception:
                    pass
            proc.terminate()
        for proc in processes.values():
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
    return 0
