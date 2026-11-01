"""确定性的工具语义映射，不把任意名称或自然语言伪装成已理解的操作。

已知名称按命名空间后缀匹配。原生 git.*、agent.* 及已知的同类别名保留
自身操作，参数中的路径、URL、命令是上下文数据，仍接受完整参数秘密检查。
其余名称按保守优先级解析：危险命令、path + 写入内容、git push 命令、
HTTP(S) URL、普通命令；随后保留已知名称或把单独 path 视作读取。
因此 read_file 不能掩盖写入，未知 URL/path 也不能绕过网络/读取策略。
普通 echo(message) 和没有上述形状的未知调用保留原名。仅检查明确字段和
常见一层请求封装；不声称理解任意代码、加密参数或非标准隐式编码。
"""

from __future__ import annotations

from copy import deepcopy
import re
from urllib.parse import urlparse

from aegis.paths import path_sensitive_write
from aegis.shell import command_classes, normalize_shell


_ALIASES = {
    "fs.read": (
        "read", "fs_read", "filesystem_read", "read_file", "read_text_file", "readfile", "file_read",
        "read_file_content", "read_file_contents", "get_file_contents", "read_document",
    ),
    "fs.write": (
        "write", "edit", "fs_write", "filesystem_write", "write_file", "write_text_file", "writefile", "file_write",
        "save_file", "create_file", "append_file", "append_to_file", "edit_file", "update_file", "replace_file",
    ),
    "exec": (
        "exec", "exec_command", "execute_command", "run_command", "shell_command", "run_shell_command",
        "execute_shell", "shell_exec", "shell_run", "shell_execute", "terminal_run", "terminal_exec", "bash", "powershell",
    ),
    "net.fetch": (
        "net_fetch", "fetch", "fetch_url", "http_request", "http_get", "http_post", "http_put",
        "requests_get", "requests_post", "requests_put", "web_request", "web_fetch", "http_fetch",
    ),
    "git.push": ("git_push", "push_files", "push_to_remote", "push_changes"),
    "git.commit": ("git_commit", "create_commit"),
    "agent.spawn": (
        "agent_spawn", "spawn_agent", "spawn_subagent", "create_agent", "create_subagent",
        "agent_delegate", "agents_delegate", "delegate", "task", "delegate_task", "run_subagent", "agent_run",
    ),
}
_PATH_KEYS = ("path", "file", "filepath", "file_path", "filename", "file_name", "target", "dest", "destination")
_CONTENT_KEYS = ("content", "contents", "text", "data", "new_content", "file_content", "replacement", "new_string", "new_text")
_URL_KEYS = ("url", "uri", "endpoint", "href", "request_url")
_BODY_KEYS = ("body", "payload", "data", "json", "content")
_COMMAND_KEYS = ("command", "cmd", "script", "cmdline", "shell_command", "command_line")


def _operation_name(tool: str) -> str:
    if tool in {"git.push", "git.commit", "git.diff", "git.log", "git.show", "git.status", "agent.spawn", "agent.dispatch", "agent.send", "agent.update"}:
        return tool
    name = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", tool)
    name = re.sub(r"[^a-z0-9]+", "_", name.casefold()).strip("_")
    for operation, aliases in _ALIASES.items():
        if any(name == alias or name.endswith("_" + alias) for alias in aliases):
            return operation
    return ""


def _first(mappings: list[dict], keys: tuple[str, ...], *, text: bool = False):
    for mapping in mappings:
        for key in keys:
            if key not in mapping or mapping[key] is None:
                continue
            value = mapping[key]
            if not text or isinstance(value, str) and value.strip():
                return value
    return None


def _command(mappings: list[dict]) -> str:
    commands = [
        mapping[key] for mapping in mappings for key in _COMMAND_KEYS
        if isinstance(mapping.get(key), str) and mapping[key].strip()
    ]
    for mapping in mappings:
        for key in ("argv", "command_args", "command"):
            argv = mapping.get(key)
            if isinstance(argv, list) and argv:
                commands.append(" ".join(str(item) for item in argv))
    # 一个良性的 command 不能遮住另一个危险 cmd 或嵌套请求里的命令。
    return next((command for command in commands if command_classes(command)),
                next((command for command in commands if _is_git_push(command)), commands[0] if commands else ""))


def _is_http_url(url: str | None) -> bool:
    if not url:
        return False
    try:
        parsed = urlparse(url)
        return parsed.scheme.casefold() in {"http", "https"} and bool(parsed.hostname)
    except ValueError:
        return False


def _is_git_push(command: str) -> bool:
    # 支持普通 git push、git -C/-c、--git-dir= 等形状；不运行 shell。
    return bool(re.search(
        r"(?:^|[\s;&|()])git\s+(?:(?:-C|-c|--git-dir|--work-tree)\s+\S+\s+|--[\w-]+=\S+\s+)*push(?:\s|$)",
        normalize_shell(command), re.IGNORECASE,
    ))


def resolve_tool(tool: str, args: dict) -> tuple[str, dict]:
    """返回规范操作及独立参数副本；保留原键，规范键供统一门禁使用。"""
    normalized = deepcopy(args)
    # 常见一层请求封装也属于可明确识别的协议形状，不递归猜测任意数据。
    mappings = [normalized] + [
        normalized[key] for key in ("arguments", "parameters", "input", "request")
        if isinstance(normalized.get(key), dict)
    ]
    paths = [
        mapping[key] for mapping in mappings for key in _PATH_KEYS
        if isinstance(mapping.get(key), str) and mapping[key].strip()
    ]
    # 冲突的路径别名不能用一个良性 path 遮住敏感 file_path/destination。
    path = next((value for value in paths if path_sensitive_write(value)), paths[0] if paths else None)
    content = _first(mappings, _CONTENT_KEYS)
    has_content = any(key in mapping for mapping in mappings for key in _CONTENT_KEYS)
    url = _first(mappings, _URL_KEYS, text=True)
    command = _command(mappings)
    operation = _operation_name(tool)
    if not operation.startswith(("git.", "agent.")):
        if command and command_classes(command):
            operation = "exec"
        elif path and has_content:
            operation = "fs.write"
        elif command and _is_git_push(command):
            operation = "git.push"
        elif _is_http_url(url):
            operation = "net.fetch"
        elif command:
            operation = "exec"
        elif not operation and path:
            operation = "fs.read"
    if not operation:
        return tool, normalized
    if operation in {"fs.read", "fs.write"}:
        if path is not None:
            normalized["path"] = path.strip()
        if operation == "fs.write" and has_content:
            normalized["content"] = content
    elif operation == "net.fetch":
        if url is not None:
            normalized["url"] = url
        body = _first(mappings, _BODY_KEYS)
        if body is not None:
            normalized["body"] = body
    elif operation == "exec" or operation == "git.push" and command:
        if command:
            normalized["command"] = command
    elif operation == "agent.spawn":
        child = _first(mappings, ("child", "agent_id", "name", "agent"), text=True)
        prompt = _first(mappings, ("prompt", "message", "task", "instructions"))
        if child is not None:
            normalized["child"] = child
        if prompt is not None:
            normalized["prompt"] = prompt
    return operation, normalized
