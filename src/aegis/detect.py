"""多通道注入检测。规则跑在规范化之后的文本上，证据指回原文下标。"""

from __future__ import annotations

import re
from dataclasses import dataclass

from aegis.models import Finding
from aegis.normalize import join_quoted_with_map, normalize, span_from_map

_PATTERNS: list[tuple[str, float, re.Pattern[str]]] = [
    (
        "override",
        0.9,
        re.compile(
            r"ignore (?:all |any |the )?(?:previous|prior|above|earlier) "
            r"(?:system )?(?:instructions|prompts|directives|prompt)\b"
        ),
    ),
    (
        "override",
        0.9,
        re.compile(
            r"disregard (?:all |any )?(?:previous|prior|above|earlier) "
            r"(?:instructions|prompts|directives)\b"
        ),
    ),
    (
        "override",
        0.88,
        re.compile(r"忽略(?:掉)?(?:以上|之前|以前|上文|前面|所有|全部).{0,16}(?:指令|提示词|系统提示|提示|规则|约束)"),
    ),
    ("override", 0.88, re.compile(r"以前の指示を(?:すべて)?無視")),
    ("override", 0.88, re.compile(r"これまでの(?:指示|命令)を無視")),
    ("override", 0.88, re.compile(r"игнорир\w{0,8}\s+предыдущ\w+\s+инструкц\w+")),
    ("override", 0.86, re.compile(r"забудь(?:те)?\s+системн\w+\s+промпт")),
    (
        "role_hijack",
        0.84,
        re.compile(r"you are now (?:a |an )?(?:unrestricted|jailbroken) (?:admin|root|assistant)\b"),
    ),
    ("role_hijack", 0.84, re.compile(r"你现在是(?:无限制|越狱)?管理员")),
    ("conceal", 0.7, re.compile(r"do not (?:tell|inform|notify|alert) the user")),
    ("conceal", 0.7, re.compile(r"(?:不要|别|勿)(?:告诉|提示|通知|告知)(?:用户|操作者|主人)")),
    (
        "secret_exfil",
        0.93,
        re.compile(
            r"(?:~/?\.ssh/|/~?\.ssh/|id_rsa|id_ed25519|\.aws/credentials|(?:^|[^\w])\.env\b|私钥|凭证文件)"
            r".{0,80}(?:发送|外发|同步|上传|传出|post\b|send\b|upload\b|exfil)"
        ),
    ),
    (
        "secret_exfil",
        0.93,
        re.compile(
            r"(?:send|upload|post|exfiltrate|transmit).{0,80}"
            r"(?:id_rsa|\.ssh/|\.aws/credentials|private key|secret key|私钥)"
        ),
    ),
    (
        "remote_exec",
        0.92,
        re.compile(r"\b(?:curl|wget)\b[^|]{0,180}\|\s*(?:ba)?sh\b"),
    ),
    (
        "sensitive_write",
        0.9,
        re.compile(r"(?<!不要)(?<!别)(?<!请勿)(?:写入|写进|追加到).{0,48}(?:authorized_keys|/etc/cron)"),
    ),
    (
        "review_push",
        0.9,
        re.compile(r"(?<!不要)(?<!别)(?<!勿)(?:执行|运行).{0,16}git push\b"),
    ),
    (
        "review_push",
        0.9,
        re.compile(r"(?<!not )(?<!don't )git push\b.{0,32}(?:origin|head)"),
    ),
    ("memory_trigger", 0.82, re.compile(r"(?:会话|对话)(?:开始|启动)(?:时|后).{0,24}(?:必须|务必|自动|立即)")),
    ("memory_trigger", 0.86, re.compile(r"(?:每次|下一次).{0,8}(?:会话|对话).{0,40}(?:读取|发送|忽略|外发)")),
    (
        "memory_trigger",
        0.84,
        re.compile(
            r"when (?:the )?(?:session|conversation) (?:starts|begins).{0,80}"
            r"(?:send|read|ignore|exfil|curl|always)"
        ),
    ),
]

_NEEDLES: list[tuple[str, float, str]] = [
    ("override", 0.9, "ignorepreviousinstructions"),
    ("override", 0.9, "ignoreallpreviousinstructions"),
    ("override", 0.9, "disregardpreviousinstructions"),
    ("override", 0.88, "忽略上文所有指令"),
    ("override", 0.88, "忽略之前的指令"),
    ("override", 0.88, "以前の指示を無視"),
    ("override", 0.88, "игнорируйпредыдущиеинструкции"),
]

_TOOL_MARKERS: list[tuple[str, float, re.Pattern[str]]] = [
    ("tool_poison", 0.92, re.compile(r"<important>")),
    ("tool_poison", 0.9, re.compile(r"before using this tool")),
    ("tool_poison", 0.9, re.compile(r"调用本工具之前")),
    ("tool_poison", 0.88, re.compile(r"instead of calling")),
]


@dataclass
class Analysis:
    findings: list[Finding]
    techniques: list[str]
    folded: str
    source_ref: str = ""


def analyze(text: str, channel: str, source_id: str) -> Analysis:
    norm = normalize(text or "")
    findings: list[Finding] = []
    _scan_both(norm, channel, source_id, findings, _PATTERNS)
    directed = []
    _scan_directed(norm.plain, channel, source_id, directed)
    for item in directed:
        item.start, item.end = span_from_map(norm.fold_map, item.start, item.end)
        _add(findings, item)
    for start, end, body in norm.comments:
        inner = normalize(body)
        before = len(findings)
        _scan_both(inner, channel, source_id, findings, _PATTERNS)
        for item in findings[before:]:
            # 注释内的命中归属整段注释，避免下标落在折叠后的副本上。
            item.start = start
            item.end = end
            if "comment_embed" not in item.techniques:
                item.techniques.append("comment_embed")
    _scan_needles(norm, channel, source_id, findings)
    joined, joined_map = join_quoted_with_map(text or "")
    if joined != (text or ""):
        inner = normalize(joined)
        before = len(findings)
        _scan_both(inner, channel, source_id, findings, _PATTERNS)
        for item in findings[before:]:
            if item.start is not None and item.end is not None:
                item.start, item.end = span_from_map(joined_map, item.start, item.end)
            item.techniques.append("string_concat")
            item.detail = item.detail or "joined"
    for start, end, decoded in norm.decoded:
        inner = normalize(decoded)
        before = len(findings)
        _scan_both(inner, channel, source_id, findings, _PATTERNS)
        for item in findings[before:]:
            item.start = start
            item.end = end
            item.quote = "decoded: " + decoded[:180]
            item.techniques.append("encoded_payload")
    if channel == "tool_desc":
        _scan_both(norm, channel, source_id, findings, _TOOL_MARKERS)
    for item in findings:
        item.techniques = sorted(set(item.techniques + norm.techniques))
    return Analysis(findings=findings, techniques=list(norm.techniques), folded=norm.folded)


_NEGATION = ("不要", "别把", "请勿", "禁止", "不能", "not ", "don't", "do not", "never ")
_CLAUSE_BREAK = re.compile(r"[;；,，!?。！？\r\n]|\.(?=\s|$)")


def _negated(view: str, start: int) -> bool:
    window = view[max(0, start - 16) : start].casefold()
    # A prohibition in an earlier clause does not negate this action.
    window = _CLAUSE_BREAK.split(window)[-1]
    return any(token in window for token in _NEGATION)


def _scan_view(
    view: str,
    mapping: list[int],
    channel: str,
    source_id: str,
    findings: list[Finding],
    patterns: list[tuple[str, float, re.Pattern[str]]],
) -> None:
    for family, severity, pattern in patterns:
        cursor = 0
        while match := pattern.search(view, cursor):
            cursor = match.end()
            if family == "secret_exfil" and _negated(view, match.start()):
                # A greedy negated match may also contain a later positive action.
                boundary = _CLAUSE_BREAK.search(view, match.start(), match.end())
                if boundary is not None:
                    cursor = boundary.end()
                continue
            start, end = span_from_map(mapping, match.start(), match.end())
            _add(
                findings,
                Finding(
                    family=family,
                    severity=severity,
                    quote=match.group(0)[:180],
                    channel=channel,
                    source_id=source_id,
                    start=start,
                    end=end,
                ),
            )


_DIRECTED: list[tuple[str, float, re.Pattern[str]]] = [
    (
        "secret_exfil",
        0.9,
        re.compile(
            r"发送到|贴到|转交到|送到|发往|send it to|deliver it to|forward |paste |hand it|"
            r"送って|貼って|転送して|渡して|届け|отправьте|вставьте|перешлите|передайте|доставить",
            re.IGNORECASE,
        ),
    ),
    (
        "sensitive_write",
        0.9,
        re.compile(
            r"写入|写进|追加计划|落进|落地位置|write a startup|append a scheduled|persistent entry|"
            r"autostart|belongs in|landing path|書いて|追加して|置いて|書き込み先|"
            r"запишите|добавьте задание|автозапуска|путь записи",
            re.IGNORECASE,
        ),
    ),
    (
        "subagent_secret",
        0.9,
        re.compile(r"子代理|sub-agent|サブエージェント|субагент", re.IGNORECASE),
    ),
]
_DIRECTED_PATH = re.compile(
    r"(?i)(?:~/?\.ssh/|~/?\.aws/|authorized_keys|id_rsa|id_ed25519|/etc/cron|密钥|secret|秘密)"
)
_DIRECTED_NEG = re.compile(
    r"不要|别把|请勿|禁止|不能|do not|don't|never|送らない|не отправ|не переда",
    re.IGNORECASE,
)


def _scan_directed(text: str, channel: str, source_id: str, findings: list[Finding]) -> None:
    """敏感路径和动作词同句出现时记为攻击。否定词在动作之前则跳过。"""
    for family, severity, pattern in _DIRECTED:
        for match in pattern.finditer(text):
            sentence_start = 0
            for mark in ("。", "\n", "!", "?"):
                sentence_start = max(sentence_start, text.rfind(mark, 0, match.start()) + 1)
            spaced_period = text.rfind(". ", 0, match.start())
            if spaced_period >= 0:
                sentence_start = max(sentence_start, spaced_period + 2)
            before = text[sentence_start:match.start()]
            if _DIRECTED_NEG.search(before):
                continue
            window = text[max(0, match.start() - 160) : match.end() + 160]
            if not _DIRECTED_PATH.search(window):
                continue
            _add(
                findings,
                Finding(
                    family=family,
                    severity=severity,
                    quote=match.group(0)[:180],
                    channel=channel,
                    source_id=source_id,
                    start=match.start(),
                    end=match.end(),
                ),
            )


def _scan_both(norm, channel: str, source_id: str, findings: list[Finding], patterns) -> None:
    _scan_view(norm.plain, norm.fold_map, channel, source_id, findings, patterns)
    if norm.folded != norm.plain:
        _scan_view(norm.folded, norm.fold_map, channel, source_id, findings, patterns)


def _scan_needles(norm, channel: str, source_id: str, findings: list[Finding]) -> None:
    if any(item.family == "override" for item in findings):
        return
    views = [(norm.despaced, norm.despace_map), (norm.plain_despaced, norm.plain_despace_map)]
    for view, mapping in views:
        if _scan_needle_view(norm, view, mapping, channel, source_id, findings):
            return


def _scan_needle_view(norm, view: str, mapping: list[int], channel: str, source_id: str, findings: list[Finding]) -> bool:
    for family, severity, needle in _NEEDLES:
        index = view.find(needle)
        if index < 0:
            continue
        start, end = span_from_map(mapping, index, index + len(needle))
        quote = needle
        if start is not None and end is not None:
            quote = norm.original[start:end][:180]
        _add(
            findings,
            Finding(
                family=family,
                severity=severity,
                quote=quote,
                channel=channel,
                source_id=source_id,
                start=start,
                end=end,
                detail="despaced",
            ),
        )
        return True
    return False


def _add(findings: list[Finding], candidate: Finding) -> None:
    for index, current in enumerate(findings):
        if current.family != candidate.family:
            continue
        if current.start is None or candidate.start is None:
            if current.quote == candidate.quote:
                if candidate.severity > current.severity:
                    findings[index] = candidate
                return
            continue
        if abs(current.start - candidate.start) < 24:
            if candidate.severity > current.severity:
                findings[index] = candidate
            return
    findings.append(candidate)
