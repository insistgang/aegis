"""不调用模型的任务对齐；仅解释明确约束，不推断任意自然语言授权。"""

from __future__ import annotations

from dataclasses import dataclass, field
import posixpath
import re
import shlex
import unicodedata

from aegis.models import Intent
from aegis.shell import extract_command, normalize_shell

_UPDATE = re.compile(r"^\s*(?:(?:更新|修改|更改|重设)任务|任务更新|(?:update|change|revise|replace)\s+(?:the\s+)?task)\s*[:：]", re.I)
_ONLY_READ = re.compile(r"(?:只能|仅(?:可|允许)?|只(?:能|可|允许)?|只准)\s*(?:读取|阅读|读|查看)|\bonly\s+(?:read|view|inspect)\b|\b(?:read|view|inspect)\s+only\b|\b(?:read|view|inspect)\b(?=[^;；。！？\n]{0,200}\bonly\b)", re.I)
_ONLY_PATH = re.compile(r"(?:只能|仅(?:可|允许)?|只(?:能|可|允许)?|限于)\s*(?:访问|操作|修改|写入|处理)|\bonly\s+(?:access|modify|write|edit|use)\b", re.I)
_PATH = re.compile(r"(?<![\w:/])(?:[a-zA-Z]:[\\/]|/|\.{1,2}/|~/)[^\s`'\"<>，。；;：:,!?！？\[\](){}]+|(?<![\w./])([\w.-]+\.[a-zA-Z0-9]{1,12})(?![\w.])")
_PATH_KEYS = {"path", "paths", "file", "files", "filepath", "target", "dest", "destination", "directory", "cwd", "source_path", "output_path", "root"}
_NEG = r"(?:不要|禁止|不得|不允许|不能|不准|勿|别|不)"
_NO_WRITE = re.compile(_NEG + r".{0,8}(?:写入|写文件|写\s|修改|改动|删除|创建)|只读|\bread[- ]only\b|\b(?:do not|don't|must not|never|no)\s+(?:write|modify|edit|delete|create|change)\b", re.I)
_NO_NETWORK = re.compile(_NEG + r".{0,8}(?:联网|网络|外网)|离线|\b(?:no|without)\s+(?:network|internet)\b|\boffline\b|\b(?:do not|don't|must not|never)\s+(?:access|use|connect to)\s+(?:the\s+)?(?:network|internet)\b", re.I)
_NO_PUSH = re.compile(_NEG + r".{0,8}推送|\b(?:do not|don't|must not|never|no)\s+(?:git\s+)?push\b", re.I)
_NO_DELEGATE = re.compile(_NEG + r".{0,8}(?:委派|委托|子代理|子智能体)|\bno\s+(?:delegation|subagents?)\b|\b(?:do not|don't|must not|never)\s+(?:delegate|spawn|dispatch)\b", re.I)
_SHELL_WRITE = re.compile(r"(?:^|[;&|\s])(?:rm|mv|cp|touch|mkdir|rmdir|tee|truncate|install|chmod|chown)\b|(?<![<>=])>{1,2}(?![=])|\b(?:sed\s+-i|git\s+(?:commit|reset|checkout|clean|apply)|write_text|write_bytes)\b|\.(?:write|writelines)\s*\(|\b(?:unlink|rmtree|rename|remove)\s*\(")
_SHELL_NETWORK = re.compile(r"\b(?:curl|wget|fetch|ssh|scp|sftp|nc|ncat|netcat|invoke-webrequest|urlopen|requests\.(?:get|post))\b|\bgit\b[^;&|\n]*\b(?:push|pull|fetch|clone)\b|\b(?:pip3?|npm|yarn)\s+install\b")
_SHELL_PUSH = re.compile(r"\bgit\b[^;&|\n]*\bpush\b")


def _path(value: str) -> str:
    """只消除词法上的 . 和 ..；不把符号链接解析伪装成沙箱。"""
    value = unicodedata.normalize("NFKC", value).strip().strip("\"'`").replace("\\", "/")
    return posixpath.normpath(value)


def _text_paths(text: str) -> list[str]:
    text = re.sub(r"https?://\S+", "", text)
    return [match.group(0).rstrip(".") for match in _PATH.finditer(text)]


def _arg_paths(args: dict) -> list[str]:
    found: list[str] = []
    for key, value in args.items():
        if key in _PATH_KEYS:
            values = value if isinstance(value, list) else [value]
            found.extend(item for item in values if isinstance(item, str) and item.strip())
        elif isinstance(value, dict):
            found.extend(_arg_paths(value))
    return found


@dataclass
class _Constraints:
    # 每条规则内部是并集；消息间的规则取交集，普通后续文本不能扩权。
    scopes: list[tuple[str, list[tuple[str, bool]]]] = field(default_factory=list)
    read_only_scope: bool = False
    no_write: bool = False
    no_network: bool = False
    no_push: bool = False
    no_delegate: bool = False


def _constraints(messages: list[str]) -> _Constraints:
    result = _Constraints()
    for message in messages:
        text = unicodedata.normalize("NFKC", str(message))
        if _UPDATE.match(text):
            result = _Constraints()
        result.no_write |= bool(_NO_WRITE.search(text))
        result.no_network |= bool(_NO_NETWORK.search(text))
        result.no_push |= bool(_NO_PUSH.search(text))
        result.no_delegate |= bool(_NO_DELEGATE.search(text))
        for clause in re.split(r"[;；。！？\n]|\.\s+", text):
            read_match = _ONLY_READ.search(clause)
            marker = read_match or _ONLY_PATH.search(clause)
            if marker is None:
                continue
            # 否定或转折后提到的文件不是 allowlist 的新成员。
            scope_text = re.split(r"\b(?:but|except|excluding|do not|don't)\b|但是|但|不要|禁止|不得|不包括|除外", clause[marker.end():], maxsplit=1, flags=re.I)[0]
            paths = _text_paths(scope_text)
            if paths:
                directory = re.search(r"\b(?:under|within|directory|folder)\b|目录|文件夹", scope_text, re.I)
                operation = "write" if not read_match and re.search(r"modify|write|edit|修改|写入", marker.group(0), re.I) else "all"
                result.scopes.append((operation, [(_path(path), bool(directory) or path.endswith(("/", "\\"))) for path in paths]))
                result.read_only_scope |= read_match is not None
    return result


def _violations(constraints: _Constraints, tool: str, args: dict) -> list[str]:
    reasons: list[str] = []
    command = normalize_shell(extract_command(args)) if tool == "exec" else ""
    if constraints.read_only_scope and tool not in {"fs.read", "fs.list"}:
        reasons.append(f"explicit read-only scope disallows tool {tool}")
    if constraints.no_write and (tool in {"fs.write", "git.commit", "git.push"} or _SHELL_WRITE.search(command)):
        reasons.append("explicit no-write constraint forbids this operation")
    if constraints.no_network and (tool == "net.fetch" or tool == "git.push" or _SHELL_NETWORK.search(command)):
        reasons.append("explicit no-network constraint forbids this operation")
    if constraints.no_push and (tool == "git.push" or _SHELL_PUSH.search(command)):
        reasons.append("explicit no-push constraint forbids this operation")
    if constraints.no_delegate and tool.startswith("agent."):
        reasons.append("explicit no-delegation constraint forbids this operation")
    scopes = [scope for operation, scope in constraints.scopes if operation == "all" or tool == "fs.write" or (tool == "exec" and _SHELL_WRITE.search(command))]
    if scopes:
        paths = _arg_paths(args)
        if tool == "exec":
            paths.extend(_text_paths(extract_command(args)))
        if tool.startswith("fs.") and not paths:
            reasons.append("explicit path scope cannot be verified without a path")
        for path in paths:
            normalized = _path(path)
            if any(not any(normalized == allowed or (directory and normalized.startswith(allowed.rstrip("/") + "/")) for allowed, directory in scope) for scope in scopes):
                reasons.append(f"path outside explicit task scope: {normalized}")
    return reasons


def _comparable_args(args: dict, *, metadata: bool = True) -> dict:
    """所有参数都参与比较；只规范化路径和不改变数据的确认元数据。"""
    result = {}
    for key, value in args.items():
        if metadata and key == "confirmed":
            continue
        if key in _PATH_KEYS:
            if isinstance(value, str):
                value = _path(value)
            elif isinstance(value, list):
                value = [_path(item) if isinstance(item, str) else item for item in value]
        elif isinstance(value, dict):
            value = _comparable_args(value, metadata=False)
        result[key] = value
    return result


def _same_call(left: dict, right: dict) -> bool:
    return left["tool"] == right["tool"] and _comparable_args(left.get("args", {})) == _comparable_args(right.get("args", {}))


def _observed(history: list[dict]) -> list[dict]:
    """被拒绝或尚待确认的尝试不代表已经执行；call_id 防止重放计数。"""
    result = []
    seen = set()
    for entry in history:
        if not isinstance(entry, dict) or not isinstance(entry.get("tool"), str) or not isinstance(entry.get("args", {}), dict):
            continue
        decision = entry.get("decision", "allow")
        if getattr(decision, "value", decision) != "allow":
            continue
        call_id = entry.get("call_id")
        if call_id and str(call_id) in seen:
            continue
        if call_id:
            seen.add(str(call_id))
        result.append(entry)
    return result


def _plan_deviation(tool: str, args: dict, observed: list[dict], plan: list[dict]) -> tuple[float, bool, list[str]]:
    from aegis.intent import is_consequential

    if not plan:
        return 0.0, False, []
    current = {"tool": tool, "args": args}
    next_step = 0
    for previous in observed:
        if next_step < len(plan) and _same_call(previous, plan[next_step]):
            next_step += 1
    if next_step < len(plan) and _same_call(current, plan[next_step]):
        return 0.0, False, []
    if any(_same_call(current, entry) for entry in plan[next_step + 1:]):
        return 0.85, True, [f"plan order deviation: step {next_step + 1} has not been observed"]
    if next_step < len(plan) and tool == plan[next_step]["tool"]:
        return 0.85, True, [f"plan arguments differ from expected step {next_step + 1}"]
    consequential = is_consequential(tool)
    return (0.85 if consequential else 0.45), consequential, ["tool call is outside the remaining submitted plan"]


def _executed_paths(command: str, cwd: str = "", *, depth: int = 0) -> set[str]:
    """识别直接脚本调用和常见解释器，不把 cat/echo 的参数当成执行。"""
    if depth > 3:
        return set()
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|\n")
        lexer.whitespace = " \t\r"
        lexer.whitespace_split = True
        lexer.commenters = ""
        tokens = list(lexer)
    except ValueError:
        return set()
    segments: list[list[str]] = [[]]
    for token in tokens:
        if token and set(token) <= set(";&|\n"):
            segments.append([])
        else:
            segments[-1].append(token)
    paths = set()
    shells = {"sh", "bash", "zsh", "dash", "ksh"}
    for segment in segments:
        while segment and (segment[0] in {"env", "command", "exec", "nohup"} or re.match(r"^[A-Za-z_]\w*=", segment[0])):
            segment = segment[1:]
        if not segment:
            continue
        head = posixpath.basename(segment[0])
        script = ""
        if head in shells or re.fullmatch(r"python(?:\d+(?:\.\d+)?)?|node|perl|ruby|powershell|pwsh", head):
            for index, value in enumerate(segment[1:], 1):
                if value in {"-c", "--command", "-Command"}:
                    if head in shells and index + 1 < len(segment):
                        paths.update(_executed_paths(segment[index + 1], cwd, depth=depth + 1))
                    break
                if value == "-m":
                    break
                if not value.startswith("-"):
                    script = value
                    break
        elif head in {"source", "."} and len(segment) > 1:
            script = segment[1]
        elif "/" in segment[0] or "\\" in segment[0] or "." in head:
            script = segment[0]
        if script:
            if cwd and not script.startswith(("/", "~")) and not re.match(r"^[A-Za-z]:", script):
                script = posixpath.join(cwd, script)
            paths.add(_path(script))
    return paths


def _sequence_reasons(tool: str, args: dict, observed: list[dict]) -> list[str]:
    if tool != "exec":
        return []
    executed = _executed_paths(extract_command(args), str(args.get("cwd", "")))
    if not executed:
        return []
    remote_seen = False
    for previous in observed:
        if previous["tool"] == "net.fetch":
            remote_seen = True
            if executed.intersection(_path(path) for path in _arg_paths(previous.get("args", {}))):
                return ["suspicious tool sequence: executing a previously downloaded artifact"]
        elif remote_seen and previous["tool"] == "fs.write":
            if executed.intersection(_path(path) for path in _arg_paths(previous.get("args", {}))):
                return ["suspicious tool sequence: remote fetch, artifact write, then execution of that path"]
    return []


def evaluate_alignment(
    intent: Intent,
    task_messages: list[str],
    tool: str,
    args: dict,
    history: list[dict],
    plan: list[dict],
    *,
    plan_history_start: int = 0,
) -> dict:
    """输入须是干净用户任务、规范工具名及实际计划；计划本身不授予权限。

    支持中英文明确禁令、文件/目录 allowlist 和带冒号的任务更新标记。
    词法路径匹配无法识别符号链接；shell 检查不声称理解任意程序行为。
    调用序列仅依据已放行记录，下载后写入同一路径再执行属于可疑进展。
    """
    from aegis.intent import deviation

    constraints = _constraints(task_messages)
    reasons = _violations(constraints, tool, args)
    valid_plan = []
    for index, entry in enumerate(plan):
        if not isinstance(entry, dict) or not isinstance(entry.get("tool"), str) or not isinstance(entry.get("args", {}), dict):
            reasons.append(f"invalid plan step {index + 1}: expected tool and args")
            continue
        valid_plan.append(entry)
        reasons.extend(f"plan step {index + 1}: {reason}" for reason in _violations(constraints, entry["tool"], entry.get("args", {})))
    hard_block = bool(reasons)
    observed = _observed(history)
    plan_observed = _observed(history[plan_history_start:])
    plan_score, plan_block, plan_reasons = _plan_deviation(tool, args, plan_observed, valid_plan)
    sequence_reasons = _sequence_reasons(tool, args, observed)
    baseline = deviation(intent, tool)
    if baseline:
        reasons.append(f"tool {tool} is outside the broad intent allowance for {intent.value}")
    score = max(baseline, 0.95 if hard_block else 0.0, plan_score, 0.9 if sequence_reasons else 0.0)
    return {"deviation": score, "block": hard_block or plan_block or bool(sequence_reasons), "reasons": list(dict.fromkeys(reasons + plan_reasons + sequence_reasons))}
