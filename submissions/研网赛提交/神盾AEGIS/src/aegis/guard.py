"""统一执法点：内容进会话前检查，工具出去前再检查。"""

from __future__ import annotations

import hashlib
import json
import threading
from copy import deepcopy
from pathlib import Path
from typing import Any

from aegis.detect import Analysis, analyze
from aegis.explain import describe_action, host_of, narrative, risk_level, step_explanation
from aegis.features import build_features, extract_iocs, harvest_secret, redact_session
from aegis.intent import classify, evaluate_alignment
from aegis.model import score as model_score
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
from aegis.paths import extract_path, path_sensitive_write
from aegis.policy import PolicySet, load_policy
from aegis.redact import contains_secret, redact
from aegis.session import Session
from aegis.tool_semantics import resolve_tool

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
    def __init__(
        self,
        policy_path: str | Path | None = None,
        policy: PolicySet | None = None,
        audit_db: str | Path | None = None,
        audit: Any | None = None,
        tokenizer=None,
    ) -> None:
        from aegis.audit import AuditStore

        self.policy = policy or load_policy(policy_path)
        self.sessions: dict[str, Session] = {}
        self.pins: dict[tuple[str, str], str] = {}
        self._lock = threading.Lock()
        self.tokenizer = tokenizer
        if audit is not None:
            self.audit = audit
        elif audit_db is not None:
            self.audit = AuditStore(audit_db)
        else:
            self.audit = None

    def session(self, sid: str) -> Session:
        if sid not in self.sessions:
            self.sessions[sid] = Session(sid, tokenizer=self.tokenizer)
        return self.sessions[sid]

    def inspect_user(self, sid: str, text: str) -> Verdict:
        with self._lock:
            session = self.session(sid)
            findings = self._bind(session, self._analyze(session, text, Channel.USER.value, "user"))
            decision = _content_decision(findings, channel=Channel.USER, op="read")
            self._lock_intent(session, text, decision)
            if decision == Decision.ALLOW:
                session.user_messages.append(text)
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
                scored_text=text,
            )

    def inspect_resource(self, sid: str, text: str, *, source: str, kind: str = "file", agent: str = "main", mcp: str | None = None) -> Verdict:
        with self._lock:
            return self._inspect_untrusted(
                sid,
                text,
                channel=Channel.RESOURCE,
                source_id=source,
                kind=kind,
                span_kind="resource",
                span_name=f"{kind}:{source}",
                agent=agent, mcp=mcp,
            )

    def inspect_memory(self, sid: str, text: str, *, memory_id: str, op: str = "read", agent: str = "main") -> Verdict:
        with self._lock:
            session = self.session(sid)
            parent = self._parent(session, agent, None)
            findings = self._bind(session, self._analyze(session, text, Channel.MEMORY.value, memory_id, agent=agent))
            decision = _content_decision(findings, channel=Channel.MEMORY, op=op)
            label = f"长期记忆 {memory_id}（{op}）"
            span = self._add_span(
                session,
                kind="memory",
                name=memory_id,
                summary=label + " " + _clip(text),
                decision=decision,
                findings=findings,
                parent=parent,
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
                scored_text=text,
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
                scored_text=description,
            )

    def inspect_plan(self, sid: str, plan: list[dict], *, agent: str = "main") -> dict:
        """记录模型实际提出的整组计划，在任何工具执行前检查任务约束。"""
        with self._lock:
            session = self.session(sid)
            parent = self._parent(session, agent, None)
            normalized = []
            for step in plan:
                if not isinstance(step, dict) or not isinstance(step.get("tool"), str) or not isinstance(step.get("args", {}), dict):
                    raise ValueError("计划必须是含 tool 和 args 的步骤列表")
                tool, args = resolve_tool(step["tool"], step.get("args", {}))
                normalized.append({"tool": tool, "args": args})
            session.agent_plans[agent] = normalized
            session.plan_history_starts[agent] = sum(h["agent"] == agent for h in session.tool_history)
            if agent == "main":
                session.plan = normalized
            checks = [evaluate_alignment(session.intent, session.user_messages, s["tool"], s["args"], normalized[:index], normalized)
                      for index, s in enumerate(normalized)]
            blocked = any(c["block"] for c in checks)
            text = json.dumps(normalized, ensure_ascii=False)
            findings = self._bind(session, self._analyze(session, text, "plan", agent, remember=False, agent=agent))
            span = self._add_span(session, kind="plan", name=agent, summary="模型提出的完整工具计划", decision=Decision.BLOCK if blocked else Decision.ALLOW,
                                  findings=findings, parent=parent, detail={"steps": normalized, "alignment": checks})
            return {"span_id": span.id, "decision": "block" if blocked else "allow", "steps": checks}

    def inspect_tool_call(
        self,
        sid: str,
        tool: str,
        args: dict | None = None,
        *,
        confirmed: bool = False,
        agent: str = "main",
        mcp: str | None = None,
        call_id: str | int | None = None,
    ) -> Verdict:
        with self._lock:
            session = self.session(sid)
            raw_tool, raw_args = tool, deepcopy(args or {})
            tool, args = resolve_tool(tool, raw_args)
            parent = self._parent(session, agent, mcp)
            if call_id is None:
                call_id = f"auto-{len(session.calls) + 1}"
            if isinstance(call_id, bool) or not isinstance(call_id, (str, int)):
                raise ValueError("call_id 必须是字符串或整数")
            call_key = (agent, mcp, type(call_id).__name__, call_id)
            previous = session.call_keys.get(call_key)
            if previous and session.calls[previous]["decision"] == "allow" and not session.calls[previous]["returned"]:
                raise ValueError("同一代理与 MCP 的活动 call_id 不能重复")
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
            alignment = evaluate_alignment(session.intent, session.user_messages, tool, args,
                                           [h for h in session.tool_history if h["agent"] == agent],
                                           session.agent_plans.get(agent, []),
                                           plan_history_start=session.plan_history_starts.get(agent, 0))
            features["intent_deviation"] = max(features["intent_deviation"], alignment["deviation"])
            findings = self._bind(session, self._analyze(session, arg_text, Channel.TOOL_CALL.value, raw_tool, remember=False, agent=agent))
            hits = self.policy.evaluate(features)
            max_sev = max((item.severity for item in findings), default=0.0)
            block_hit = any(item.decision == Decision.BLOCK for item in hits)
            ask_hit = any(item.decision == Decision.ASK for item in hits)
            if alignment["block"] or block_hit or (max_sev >= 0.85 and features["tool_consequential"]):
                decision = Decision.BLOCK
            elif ask_hit or (features["intent_deviation"] >= 0.65 and features["tool_consequential"]):
                decision = Decision.ASK
            else:
                decision = Decision.ALLOW
            if decision == Decision.ASK and confirmed:
                decision = Decision.ALLOW
            action = describe_action(tool, args)
            caused = list(session.injection_spans) if decision != Decision.ALLOW else []
            span = self._add_span(
                session,
                kind="tool",
                name=raw_tool,
                summary=action,
                decision=decision,
                findings=findings,
                parent=parent,
                caused_by=caused,
                detail={"tool": raw_tool, "canonical_tool": tool, "args": raw_args, "normalized_args": args,
                        "mcp": mcp, "agent": agent, "call_id": call_id, "alignment": alignment},
            )
            session.calls[span.id] = {"tool": raw_tool, "canonical_tool": tool, "args": raw_args,
                                      "normalized_args": args, "agent": agent, "mcp": mcp,
                                      "call_id": call_id, "returned": False, "decision": decision.value}
            session.call_keys[call_key] = span.id
            if tool == "agent.spawn" and decision == Decision.ALLOW:
                child = str(args.get("child") or "worker")
                self._register_agent(session, child, parent_agent=agent, parent_span=span.id)
            impacts = _impacts(tool, args, features, decision)
            session.impacts.extend(impacts)
            if decision == Decision.BLOCK:
                session.blocked_actions.append(action)
            return self._verdict(
                session,
                decision=decision,
                findings=findings,
                policies=[item.to_dict() for item in hits] + ([{"id": "task-constraint", "decision": "block", "risk": "high", "description": "；".join(alignment["reasons"])}] if alignment["block"] else []),
                span_id=span.id,
                channel=Channel.TOOL_CALL.value,
                source_id=tool,
                tool=tool,
                action=action,
                detail=span.detail,
                deviation=features["intent_deviation"],
                confirmed=confirmed,
                scored_text=arg_text,
            )

    def observe_tool_result(self, sid: str, tool: str, args: dict | None, result, *,
                            call_span_id: str | None = None, call_id: str | int | None = None,
                            agent: str = "main", mcp: str | None = None) -> Verdict:
        with self._lock:
            session = self.session(sid)
            self._ensure_agent(session)
            canonical, normalized_args = resolve_tool(tool, args or {})
            call_ref = self._resolve_call(session, tool, normalized_args, call_span_id=call_span_id,
                                          call_id=call_id, agent=agent, mcp=mcp)
            call = session.calls.get(call_ref) if call_ref else None
            if call:
                agent, mcp = call["agent"], call["mcp"]
                normalized_args = call["normalized_args"]
            text = result if isinstance(result, str) else json.dumps(result, ensure_ascii=False)
            path = extract_path(normalized_args)
            source = path or tool
            findings = self._bind(session, self._analyze(session, text, Channel.TOOL_RESULT.value, source, agent=agent))
            decision = _content_decision(findings, channel=Channel.TOOL_RESULT, op="read")
            self._harvest(session, path or tool, text, path)
            if isinstance(result, dict):
                for item in result.get("content") or []:
                    if isinstance(item, dict) and isinstance(item.get("text"), str):
                        self._harvest(session, path or tool, item["text"], path)
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
                parent=call_ref or self._parent(session, agent, mcp),
                detail={"tool": tool, "canonical_tool": canonical, "path": path,
                        "result": result, "preview": text[:240], "call_id": call["call_id"] if call else call_id,
                        "call_span_id": call_ref, "agent": agent, "mcp": mcp, "unmatched_result": call is None},
            )
            if call:
                call["returned"] = True
                session.tool_history.append({"tool": call["canonical_tool"], "args": call["normalized_args"],
                                             "call_id": call["call_id"], "decision": call["decision"], "agent": agent})
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
                detail=span.detail,
                scored_text=text,
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
        if getattr(self, "audit", None) is not None:
            self.audit.sync_session(session, narrative=self.narrative(sid))
        return self._clean(session, {
            "session_id": sid,
            "intent": session.intent.value,
            "intent_zh": session.task_phrase,
            "injection_active": session.injection_active,
            "narrative": self.narrative(sid),
            "impact": redact(session.impacts),
            "dag": session.trace.dag(),
            "timeline": session.trace.timeline(),
            "mermaid": session.trace.mermaid(),
            "sources": redact(session.trace.sources.export()),
            "iocs": [
                {"kind": item.kind, "value": item.value, "source_id": item.source_id, "span_id": item.span_id}
                for item in session.iocs
            ],
        })

    def sanitize(self, sid: str, value):
        """在宿主导出或返回调试报告前，擦除该会话已观察到的秘密及变体。"""
        with self._lock:
            return self._clean(self.session(sid), value)

    def _inspect_untrusted(self, sid, text, *, channel, source_id, kind, span_kind, span_name, agent="main", mcp=None) -> Verdict:
        session = self.session(sid)
        parent = self._parent(session, agent, mcp)
        findings = self._bind(session, self._analyze(session, text, channel.value, source_id, agent=agent))
        decision = _content_decision(findings, channel=channel, op="read")
        label = f"{_KIND_ZH.get(kind, kind)}（{source_id}）"
        span = self._add_span(
            session,
            kind=span_kind,
            name=span_name,
            summary=label,
            decision=decision,
            findings=findings,
            parent=parent,
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
            scored_text=text,
        )

    def _analyze(self, session: Session, text: str, channel: str, source_id: str, *, remember: bool = True, agent: str = "main"):
        source_ref = session.trace.sources.register(text, source_id=source_id, channel=channel)
        session.trace.sources.records[source_ref]["agent"] = agent
        prefix, tail_ref, tail_offset = session.source_tails.get(agent, ("", "", 0)) if remember else ("", "", 0)
        offset = len(prefix) + 1 if prefix else 0
        combined = f"{prefix}\n{text}" if prefix else text
        analysis = analyze(combined, channel, source_id)
        findings = []
        # A single lossless normalization also catches fragments separated by arbitrarily long whitespace.
        for item in analysis.findings:
            if item.start is None or item.end is None:
                findings.append(item)
                continue
            start, end = item.start, item.end
            if end <= offset:
                continue
            spans = []
            if start < len(prefix) and tail_ref:
                spans.append(session.trace.sources.interval(
                    tail_ref,
                    tail_offset + start,
                    tail_offset + min(end, len(prefix)),
                ))
                item.techniques = sorted(set(item.techniques + ["turn_split"]))
            local_start, local_end = max(0, start - offset), min(len(text), end - offset)
            if local_end > local_start:
                spans.append(session.trace.sources.interval(source_ref, local_start, local_end))
            item.start, item.end = local_start, local_end
            item.source_spans = spans
            findings.append(item)
        if remember:
            session.source_tails[agent] = (text[-180:], source_ref, max(0, len(text) - 180))
        return Analysis(findings=findings, techniques=analysis.techniques, folded="", source_ref=source_ref)

    def _bind(self, session: Session, analysis) -> list[Finding]:
        session.last_source_ref = analysis.source_ref or None
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
        record = harvest_secret(source, text, path)
        if record and not any(r.path == record.path and r.needles == record.needles for r in session.secrets):
            session.secrets.append(record)

    @staticmethod
    def _clean(session: Session, value):
        return redact(redact_session(value, session.secrets))

    def register_agent(self, sid: str, agent_id: str, *, parent_agent: str = "main") -> str:
        """由可信宿主登记已启动的子代理身份，不接受未知父级或重新挂接。"""
        with self._lock:
            return self._register_agent(self.session(sid), agent_id, parent_agent=parent_agent)

    def _register_agent(self, session: Session, agent_id: str, *, parent_agent: str, parent_span: str | None = None) -> str:
        self._ensure_agent(session)
        if not isinstance(agent_id, str) or not agent_id or agent_id == "main":
            raise ValueError("子代理必须有非 main 的唯一 agent_id")
        if parent_agent != "main" and parent_agent not in session.subagents:
            raise ValueError("子代理的父身份尚未登记")
        if agent_id == parent_agent:
            raise ValueError("代理不能成为自己的父级")
        if agent_id in session.subagents:
            if session.agent_parents[agent_id] != parent_agent or parent_span is not None:
                raise ValueError("agent_id 不能重复启动或重新挂接")
            for span in session.trace.spans:
                if span.id == session.subagents[agent_id]:
                    span.detail["status"] = "registered"
            return session.subagents[agent_id]
        parent = parent_span or (session.agent_span_id if parent_agent == "main" else session.subagents[parent_agent])
        span = session.trace.add(kind="subagent", name=agent_id, summary=f"子 Agent {agent_id}", parent_id=parent,
                                 detail={"agent_id": agent_id, "parent_agent": parent_agent, "status": "declared" if parent_span else "registered"})
        session.subagents[agent_id] = span.id
        session.agent_parents[agent_id] = parent_agent
        return span.id

    def _resolve_call(self, session, tool, args, *, call_span_id, call_id, agent, mcp):
        if call_span_id is not None:
            candidates = [call_span_id]
        elif call_id is not None:
            key = (agent, mcp, type(call_id).__name__, call_id)
            candidates = [session.call_keys.get(key)]
        else:
            canonical, _ = resolve_tool(tool, args)
            candidates = [ref for ref, call in session.calls.items()
                          if not call["returned"] and call["canonical_tool"] == canonical
                          and call["normalized_args"] == args and call["agent"] == agent
                          and (mcp is None or call["mcp"] == mcp)]
            allowed = [ref for ref in candidates if session.calls[ref]["decision"] == "allow"]
            if allowed:
                candidates = allowed
            if not candidates:
                # Passive SDK observation is explicitly marked unmatched, never invented as a correlated call.
                return None
        open_calls = [item for item in candidates if item in session.calls and not session.calls[item]["returned"]]
        if len(open_calls) != 1:
            raise ValueError("返回无法唯一关联到已登记调用")
        candidates = open_calls
        ref = candidates[0]
        call = session.calls[ref]
        canonical, _ = resolve_tool(tool, args)
        if call["returned"] or call["canonical_tool"] != canonical or call["normalized_args"] != args:
            raise ValueError("返回调用不匹配或已完成")
        return ref

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
                raise ValueError("未知 agent_id，请由宿主先调用 register_agent")
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
        span = session.trace.add(
            kind=kind,
            name=self._clean(session, name),
            summary=self._clean(session, summary),
            parent_id=parent,
            decision=decision.value,
            detail=self._clean(session, detail or {}),
            caused_by=caused_by,
            finding_ids=[item.id for item in findings if item.id],
        )
        if session.last_source_ref and kind in {"user", "resource", "memory", "tool_desc", "tool_result", "tool", "plan"}:
            source = session.trace.sources.records[session.last_source_ref]
            source["span_id"] = span.id
            span.detail["source"] = self._clean(session, source)
        return span

    def _verdict(
        self,
        session,
        *,
        decision,
        findings,
        policies,
        span_id,
        channel,
        source_id,
        action,
        deviation,
        tool="",
        detail=None,
        confirmed=False,
        scored_text="",
    ) -> Verdict:
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
        for item in findings:
            item.quote = self._clean(session, item.quote)
            item.detail = self._clean(session, item.detail)
            item.source_id = self._clean(session, item.source_id)
            item.source_spans = self._clean(session, item.source_spans)
        verdict = Verdict(
            decision=decision,
            risk=score,
            risk_level=risk_level(decision, score),
            explanation=self._clean(session, explanation),
            intent=session.intent,
            findings=findings,
            policies=self._clean(session, policies),
            span_id=span_id,
            tool=tool,
            channel=channel,
            source_id=self._clean(session, source_id),
            action=self._clean(session, action),
            confirmed=confirmed,
            deviation=deviation,
            model_score=model_score(scored_text) if scored_text else None,
        )
        if getattr(self, "audit", None) is not None:
            if detail is None:
                detail = next((span.detail for span in session.trace.spans if span.id == span_id), None)
            self.audit.record_verdict(session, verdict, action=action, detail=detail)
        return verdict


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


# 让 DECISION_ZH 被引用，避免三态文案和实现分叉后无人检查。
assert set(DECISION_ZH) == set(Decision)
assert not contains_secret("")
