"""统一执法点：内容进会话前检查，工具出去前再检查。"""

from __future__ import annotations

import hashlib
import json
import threading
from pathlib import Path

from aegis.detect import analyze
from aegis.explain import describe_action, host_of, narrative, risk_level, step_explanation
from aegis.features import SecretRecord, build_features, extract_iocs
from aegis.intent import classify
from aegis.models import (
    DECISION_ZH,
    FAMILY_ZH,
    RISK_SCORE,
    Channel,
    Decision,
    Finding,
    Intent,
    Verdict,
)
from aegis.paths import extract_path, path_sensitive_read, path_sensitive_write
from aegis.policy import PolicySet, load_policy
from aegis.redact import contains_secret, redact, secret_needles
from aegis.session import Session

_INJECTION_FAMILIES = {
    "override",
    "role_hijack",
    "secret_exfil",
    "remote_exec",
    "memory_trigger",
    "tool_poison",
    "rug_pull",
}

_KIND_ZH = {
    "issue": "Issue 正文",
    "file": "外部文件",
    "email": "邮件正文",
    "pdf": "PDF 文本",
    "web": "网页内容",
    "knowledge": "知识库条目",
    "tool_result": "工具返回",
    "memory": "长期记忆",
    "tool_desc": "MCP 工具描述",
    "user": "用户输入",
    "code": "源码文本",
}


class AegisGuard:
    def __init__(self, policy_path: str | Path | None = None, policy: PolicySet | None = None) -> None:
        self.policy = policy or load_policy(policy_path)
        self.sessions: dict[str, Session] = {}
        self.pins: dict[tuple[str, str], str] = {}
        self._lock = threading.Lock()

    def session(self, sid: str) -> Session:
        if sid not in self.sessions:
            self.sessions[sid] = Session(sid)
        return self.sessions[sid]

    def inspect_user(self, sid: str, text: str) -> Verdict:
        with self._lock:
            session = self.session(sid)
            findings = self._bind(session, self._analyze(session, text, Channel.USER.value, "user"))
            decision = _content_decision(findings, channel=Channel.USER, op="read")
            self._lock_intent(session, text, decision)
            span = self._add_span(
                session,
                kind="user",
                name="user",
                summary=_clip(text),
                decision=decision,
                findings=findings,
                parent=None,
            )
            session.user_span_id = span.id
            self._ensure_agent(session)
            self._note_injection(session, findings, decision, Channel.USER.value, "用户输入", span.id, text)
            return self._verdict(
                session,
                decision=decision,
                findings=findings,
                policies=[],
                span_id=span.id,
                channel=Channel.USER.value,
                source_id="user",
                action="",
                deviation=0.0,
            )

    def inspect_resource(self, sid: str, text: str, *, source: str, kind: str = "file") -> Verdict:
        with self._lock:
            return self._inspect_untrusted(
                sid,
                text,
                channel=Channel.RESOURCE,
                source_id=source,
                kind=kind,
                span_kind="resource",
                span_name=f"{kind}:{source}",
            )

    def inspect_memory(self, sid: str, text: str, *, memory_id: str, op: str = "read") -> Verdict:
        with self._lock:
            session = self.session(sid)
            self._ensure_agent(session)
            findings = self._bind(session, self._analyze(session, text, Channel.MEMORY.value, memory_id))
            decision = _content_decision(findings, channel=Channel.MEMORY, op=op)
            label = f"长期记忆 {memory_id}（{op}）"
            span = self._add_span(
                session,
                kind="memory",
                name=memory_id,
                summary=label + " " + _clip(text),
                decision=decision,
                findings=findings,
                parent=session.agent_span_id,
                detail={"op": op},
            )
            self._note_injection(session, findings, decision, Channel.MEMORY.value, label, span.id, text)
            return self._verdict(
                session,
                decision=decision,
                findings=findings,
                policies=[],
                span_id=span.id,
                channel=Channel.MEMORY.value,
                source_id=memory_id,
                action="",
                deviation=0.0,
            )

    def inspect_tool_description(self, sid: str, server: str, tool: str, description: str) -> Verdict:
        with self._lock:
            session = self.session(sid)
            self._ensure_agent(session)
            source = f"{server}.{tool}"
            findings = self._bind(session, self._analyze(session, description, Channel.TOOL_DESC.value, source))
            digest = hashlib.sha256(description.encode("utf-8")).hexdigest()
            previous = self.pins.get((server, tool))
            if previous is not None and previous != digest:
                findings.append(
                    Finding(
                        id=session.next_finding_id(),
                        family="rug_pull",
                        severity=0.9 if findings else 0.74,
                        quote="tool description hash changed",
                        channel=Channel.TOOL_DESC.value,
                        source_id=source,
                        detail=f"prev={previous[:12]} now={digest[:12]}",
                        techniques=["rug_pull"],
                    )
                )
            self.pins[(server, tool)] = digest
            decision = _content_decision(findings, channel=Channel.TOOL_DESC, op="read")
            if any(item.family == "rug_pull" for item in findings) and decision == Decision.ALLOW:
                decision = Decision.ASK
            label = f"MCP 工具描述 {source}"
            span = self._add_span(
                session,
                kind="tool_desc",
                name=source,
                summary=label,
                decision=decision,
                findings=findings,
                parent=session.agent_span_id,
                detail={"server": server, "tool": tool},
            )
            self._note_injection(session, findings, decision, Channel.TOOL_DESC.value, label, span.id, description)
            return self._verdict(
                session,
                decision=decision,
                findings=findings,
                policies=[],
                span_id=span.id,
                channel=Channel.TOOL_DESC.value,
                source_id=source,
                action="",
                deviation=0.0,
            )

    def inspect_tool_call(
        self,
        sid: str,
        tool: str,
        args: dict | None = None,
        *,
        confirmed: bool = False,
        agent: str = "main",
        mcp: str | None = None,
    ) -> Verdict:
        with self._lock:
            session = self.session(sid)
            args = dict(args or {})
            features = build_features(
                tool=tool,
                args=args,
                intent=session.intent,
                injection_active=session.injection_active,
                iocs=session.iocs,
                secrets=session.secrets,
                trusted_domains=self.policy.trusted_domains,
            )
            arg_text = features["command"] or features["serialized"]
            findings = self._bind(session, analyze(arg_text, Channel.TOOL_CALL.value, tool))
            hits = self.policy.evaluate(features)
            max_sev = max((item.severity for item in findings), default=0.0)
            block_hit = any(item.decision == Decision.BLOCK for item in hits)
            ask_hit = any(item.decision == Decision.ASK for item in hits)
            if block_hit or (max_sev >= 0.85 and features["tool_consequential"]):
                decision = Decision.BLOCK
            elif ask_hit or (features["intent_deviation"] >= 0.65 and features["tool_consequential"]):
                decision = Decision.ASK
            else:
                decision = Decision.ALLOW
            if decision == Decision.ASK and confirmed:
                decision = Decision.ALLOW
            parent = self._parent(session, agent if agent != "main" else "main", mcp if not tool.startswith("agent.") else None)
            if tool.startswith("agent."):
                parent = self._parent(session, "main", mcp)
            action = describe_action(tool, args)
            caused = list(session.injection_spans) if decision != Decision.ALLOW else []
            span = self._add_span(
                session,
                kind="tool",
                name=tool,
                summary=action,
                decision=decision,
                findings=findings,
                parent=parent,
                caused_by=caused,
                detail={"tool": tool, "args": args, "mcp": mcp, "agent": agent},
            )
            if tool.startswith("agent."):
                child = str(args.get("child") or "worker")
                self._add_span(
                    session,
                    kind="subagent",
                    name=child,
                    summary=f"子 Agent {child}",
                    decision=decision,
                    findings=[],
                    parent=span.id,
                    detail={"tool": tool},
                )
            impacts = _impacts(tool, args, features, decision)
            session.impacts.extend(impacts)
            if decision == Decision.BLOCK:
                session.blocked_actions.append(action)
            return self._verdict(
                session,
                decision=decision,
                findings=findings,
                policies=[item.to_dict() for item in hits],
                span_id=span.id,
                channel=Channel.TOOL_CALL.value,
                source_id=tool,
                tool=tool,
                action=action,
                deviation=features["intent_deviation"],
                confirmed=confirmed,
            )

    def observe_tool_result(self, sid: str, tool: str, args: dict | None, result) -> Verdict:
        with self._lock:
            session = self.session(sid)
            self._ensure_agent(session)
            text = result if isinstance(result, str) else json.dumps(result, ensure_ascii=False)
            text = _bounded(text)
            path = extract_path(args)
            source = path or tool
            findings = self._bind(session, self._analyze(session, text, Channel.TOOL_RESULT.value, source))
            decision = _content_decision(findings, channel=Channel.TOOL_RESULT, op="read")
            self._harvest(session, path or tool, text, path)
            label = f"工具返回 {tool}"
            if path:
                label += f"（{path}）"
            span = self._add_span(
                session,
                kind="tool_result",
                name=tool,
                summary=label,
                decision=decision,
                findings=findings,
                parent=session.agent_span_id,
                detail={"tool": tool, "path": path, "preview": text[:240]},
            )
            self._note_injection(session, findings, decision, Channel.TOOL_RESULT.value, label, span.id, text)
            return self._verdict(
                session,
                decision=decision,
                findings=findings,
                policies=[],
                span_id=span.id,
                channel=Channel.TOOL_RESULT.value,
                source_id=source,
                tool=tool,
                action="",
                deviation=0.0,
            )

    def narrative(self, sid: str) -> str:
        session = self.session(sid)
        return narrative(
            {
                "cause_channel": session.cause_channel,
                "cause_source": session.cause_source,
                "task_phrase": session.task_phrase,
                "intent": session.intent.value,
                "hostile_open": session.hostile_open,
            },
            list(getattr(session, "blocked_actions", [])),
        )

    def snapshot(self, sid: str) -> dict:
        session = self.session(sid)
        return {
            "session_id": sid,
            "intent": session.intent.value,
            "intent_zh": session.task_phrase,
            "injection_active": session.injection_active,
            "narrative": self.narrative(sid),
            "impact": redact(session.impacts),
            "dag": session.trace.dag(),
            "timeline": session.trace.timeline(),
            "mermaid": session.trace.mermaid(),
            "iocs": [
                {"kind": item.kind, "value": item.value, "source_id": item.source_id, "span_id": item.span_id}
                for item in session.iocs
            ],
        }

    def _inspect_untrusted(self, sid, text, *, channel, source_id, kind, span_kind, span_name) -> Verdict:
        session = self.session(sid)
        self._ensure_agent(session)
        findings = self._bind(session, self._analyze(session, text, channel.value, source_id))
        decision = _content_decision(findings, channel=channel, op="read")
        label = f"{_KIND_ZH.get(kind, kind)}（{source_id}）"
        span = self._add_span(
            session,
            kind=span_kind,
            name=span_name,
            summary=label,
            decision=decision,
            findings=findings,
            parent=session.agent_span_id,
            detail={"kind": kind, "source": source_id},
        )
        self._note_injection(session, findings, decision, channel.value, label, span.id, text)
        return self._verdict(
            session,
            decision=decision,
            findings=findings,
            policies=[],
            span_id=span.id,
            channel=channel.value,
            source_id=source_id,
            action="",
            deviation=0.0,
        )

    def _analyze(self, session: Session, text: str, channel: str, source_id: str):
        prefix = session.untrusted_tail
        combined = f"{prefix}\n{text}" if prefix else text
        analysis = analyze(_bounded(combined), channel, source_id)
        if prefix:
            offset = len(prefix) + 1
            kept = []
            for finding in analysis.findings:
                if finding.start is None or finding.end is None:
                    kept.append(finding)
                    continue
                if finding.end <= offset:
                    continue
                if finding.start < offset:
                    finding.start = 0
                    finding.techniques = sorted(set(finding.techniques + ["turn_split"]))
                else:
                    finding.start -= offset
                finding.end -= offset
                kept.append(finding)
            analysis.findings = kept
        session.untrusted_tail = text[-180:]
        return analysis

    def _bind(self, session: Session, analysis) -> list[Finding]:
        for item in analysis.findings:
            item.id = session.next_finding_id()
        return list(analysis.findings)

    def _lock_intent(self, session: Session, text: str, decision: Decision) -> None:
        clean = decision != Decision.BLOCK
        new_intent = classify(text) if clean else Intent.UNKNOWN
        if clean:
            if (not session.intent_locked) or (new_intent != Intent.UNKNOWN and new_intent != session.intent):
                session.intent = new_intent
                session.intent_locked = True
                session.user_text = text
                session.task_phrase = _task_phrase(text, new_intent)
                session.hostile_open = False
            return
        if not session.intent_locked:
            session.intent = Intent.UNKNOWN
            session.intent_locked = True
            session.user_text = text
            session.task_phrase = "一段越权指令"
            session.hostile_open = True

    def _note_injection(self, session, findings, decision, channel, label, span_id, text) -> None:
        serious = decision == Decision.BLOCK or any(
            item.family in _INJECTION_FAMILIES and item.severity >= 0.85 for item in findings
        )
        if not serious:
            return
        session.injection_active = True
        session.injection_spans.append(span_id)
        if not session.cause_channel:
            session.cause_channel = channel
            session.cause_source = label
        session.iocs.extend(
            extract_iocs(text, findings, label, span_id, self.policy.trusted_domains)
        )

    def _harvest(self, session: Session, source: str, text: str, path: str) -> None:
        needles = [needle for _, needle in secret_needles(text)]
        sensitive = bool(path) and (path_sensitive_read(path) or path_sensitive_write(path))
        if not needles and not sensitive:
            return
        session.secrets.append(SecretRecord(source=source, kind="observed", needles=needles, path=path))

    def _ensure_agent(self, session: Session) -> None:
        if session.agent_span_id:
            return
        span = session.trace.add(
            kind="agent",
            name="main",
            summary="主 Agent",
            parent_id=session.user_span_id,
        )
        session.agent_span_id = span.id
        if not hasattr(session, "blocked_actions"):
            session.blocked_actions = []

    def _parent(self, session: Session, agent: str, mcp: str | None) -> str:
        self._ensure_agent(session)
        parent = session.agent_span_id or ""
        if agent and agent != "main":
            if agent not in session.subagents:
                span = session.trace.add(
                    kind="subagent",
                    name=agent,
                    summary=f"子 Agent {agent}",
                    parent_id=parent,
                )
                session.subagents[agent] = span.id
            parent = session.subagents[agent]
        if mcp:
            key = (parent, mcp)
            if key not in session.mcp_nodes:
                span = session.trace.add(
                    kind="mcp",
                    name=mcp,
                    summary=f"MCP 代理 {mcp}",
                    parent_id=parent,
                )
                session.mcp_nodes[key] = span.id
            parent = session.mcp_nodes[key]
        return parent

    def _add_span(self, session, *, kind, name, summary, decision, findings, parent, caused_by=None, detail=None):
        if not hasattr(session, "blocked_actions"):
            session.blocked_actions = []
        return session.trace.add(
            kind=kind,
            name=name,
            summary=summary,
            parent_id=parent,
            decision=decision.value,
            detail=detail or {},
            caused_by=caused_by,
            finding_ids=[item.id for item in findings if item.id],
        )

    def _verdict(self, session, *, decision, findings, policies, span_id, channel, source_id, action, deviation, tool="", confirmed=False) -> Verdict:
        families = []
        for item in findings:
            label = FAMILY_ZH.get(item.family, item.family)
            if label not in families:
                families.append(label)
        score = 0.08
        if findings:
            score = max(score, max(item.severity for item in findings))
        for item in policies:
            score = max(score, RISK_SCORE.get(item.get("risk", "medium"), 0.55))
        score = max(score, deviation * 0.55)
        if decision == Decision.BLOCK:
            score = max(score, 0.86)
        elif decision == Decision.ASK:
            score = max(score, 0.48)
        else:
            score = min(score, 0.32)
        explanation = step_explanation(
            {
                "decision": decision.value,
                "action": action,
                "policies": policies,
                "families": families,
                "deviation": deviation,
                "confirmed": confirmed,
            }
        )
        return Verdict(
            decision=decision,
            risk=score,
            risk_level=risk_level(decision, score),
            explanation=redact(explanation),
            intent=session.intent,
            findings=findings,
            policies=policies,
            span_id=span_id,
            tool=tool,
            channel=channel,
            source_id=source_id,
            confirmed=confirmed,
            deviation=deviation,
        )


def _content_decision(findings: list[Finding], *, channel: Channel, op: str) -> Decision:
    severity = max((item.severity for item in findings), default=0.0)
    if channel == Channel.MEMORY and op == "write" and severity >= 0.6:
        return Decision.BLOCK
    if severity >= 0.75:
        return Decision.BLOCK
    if severity >= 0.45:
        return Decision.ASK
    return Decision.ALLOW


def _task_phrase(text: str, intent: Intent) -> str:
    from aegis.models import INTENT_ZH

    if "readme" in text.casefold():
        return "读取项目 README 文档"
    if intent == Intent.CODE_REVIEW and "issue" in text.casefold():
        return "阅读并总结 Issue"
    return INTENT_ZH[intent]


def _impacts(tool: str, args: dict, features: dict, decision: Decision) -> list[dict]:
    rows = []
    path = features.get("path") or ""
    if path:
        kind = "credential" if features.get("path_sensitive_read") or path_sensitive_write(path) else "file"
        rows.append({"type": kind, "value": path, "action": tool, "decision": decision.value})
    for host in features.get("hosts") or []:
        rows.append({"type": "domain", "value": host, "action": tool, "decision": decision.value})
    if tool.startswith("git."):
        repo = args.get("repo") or args.get("remote")
        if repo:
            rows.append({"type": "repo", "value": str(repo), "action": tool, "decision": decision.value})
    if tool.startswith("agent."):
        rows.append(
            {
                "type": "agent",
                "value": str(args.get("child") or "worker"),
                "action": tool,
                "decision": decision.value,
            }
        )
    if tool == "net.fetch":
        url = str(args.get("url") or "")
        if host_of(url) and not any(row["type"] == "domain" for row in rows):
            rows.append({"type": "domain", "value": host_of(url), "action": tool, "decision": decision.value})
    return rows


def _clip(text: str, limit: int = 160) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _bounded(text: str, limit: int = 400_000) -> str:
    if len(text) <= limit:
        return text
    return text[:20_000] + "\n" + text[-20_000:]


# 让 DECISION_ZH 被引用，避免三态文案和实现分叉后无人检查。
assert set(DECISION_ZH) == set(Decision)
assert not contains_secret("")
