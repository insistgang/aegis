"""SQLite 审计落盘与 JSON 导出。所有敏感材料在写入前必须抹掉。"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any

from aegis.models import Verdict
from aegis.redact import redact
from aegis.session import Session


def _safe(session: Session, value):
    from aegis.features import redact_session

    return redact(redact_session(value, getattr(session, "secrets", [])))


class AuditStore:
    def __init__(self, db_path: str | Path) -> None:
        self.db_path = str(db_path)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode = WAL;")
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    intent TEXT,
                    intent_zh TEXT,
                    injection_active INTEGER,
                    narrative TEXT,
                    user_text TEXT,
                    task_phrase TEXT,
                    cause_channel TEXT,
                    cause_source TEXT,
                    dag_json TEXT,
                    created_at REAL,
                    updated_at REAL
                );

                CREATE TABLE IF NOT EXISTS audit_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    span_id TEXT,
                    channel TEXT,
                    source_id TEXT,
                    tool TEXT,
                    action TEXT,
                    decision TEXT NOT NULL,
                    risk REAL,
                    risk_level TEXT,
                    explanation TEXT,
                    deviation REAL,
                    policy_ids TEXT,
                    evidence_indices TEXT,
                    findings TEXT,
                    policies TEXT,
                    detail TEXT,
                    confirmed INTEGER DEFAULT 0,
                    created_at REAL,
                    FOREIGN KEY (session_id) REFERENCES sessions(id)
                );

                CREATE TABLE IF NOT EXISTS spans (
                    id TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    kind TEXT,
                    name TEXT,
                    parent_id TEXT,
                    summary TEXT,
                    decision TEXT,
                    detail TEXT,
                    caused_by TEXT,
                    finding_ids TEXT,
                    ts REAL,
                    PRIMARY KEY (session_id, id),
                    FOREIGN KEY (session_id) REFERENCES sessions(id)
                );

                CREATE TABLE IF NOT EXISTS impacts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    type TEXT,
                    value TEXT,
                    action TEXT,
                    decision TEXT,
                    FOREIGN KEY (session_id) REFERENCES sessions(id)
                );

                CREATE INDEX IF NOT EXISTS idx_records_session ON audit_records(session_id);
                CREATE INDEX IF NOT EXISTS idx_spans_session ON spans(session_id);
                CREATE INDEX IF NOT EXISTS idx_impacts_session ON impacts(session_id);
                """
            )

    def record_verdict(
        self,
        session: Session,
        verdict: Verdict,
        *,
        action: str = "",
        detail: dict | None = None,
    ) -> None:
        # 写入前必须先用 redact 脱敏
        session_id = _safe(session, session.id)
        span_id = _safe(session, verdict.span_id)
        channel = _safe(session, verdict.channel)
        source_id = _safe(session, verdict.source_id)
        tool = _safe(session, verdict.tool)
        action_clean = _safe(session, action or getattr(verdict, "action", "") or tool)
        decision = verdict.decision.value
        risk = verdict.risk
        risk_level = verdict.risk_level
        explanation = _safe(session, verdict.explanation)
        deviation = verdict.deviation
        policy_ids = [_safe(session, p.get("id", "")) for p in verdict.policies if p.get("id")]
        
        evidence_indices = []
        for finding in verdict.findings:
            evidence_indices.append(
                {
                    "id": _safe(session, finding.id),
                    "family": _safe(session, finding.family),
                    "start": finding.start,
                    "end": finding.end,
                    "quote": _safe(session, finding.quote),
                    "techniques": _safe(session, finding.techniques),
                    "severity": finding.severity,
                    "source_spans": _safe(session, finding.source_spans),
                }
            )

        findings_clean = [finding.to_dict() for finding in verdict.findings]
        policies_clean = _safe(session, verdict.policies)
        detail_clean = _safe(session, detail or {})
        now = time.time()

        with self._connect() as conn:
            # 确保 session 存在或更新
            dag = session.trace.dag() if hasattr(session, "trace") else {}
            narrative = getattr(session, "narrative", "") or ""
            conn.execute(
                """
                INSERT INTO sessions (id, intent, intent_zh, injection_active, narrative, user_text, task_phrase, cause_channel, cause_source, dag_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    intent = excluded.intent,
                    intent_zh = excluded.intent_zh,
                    injection_active = excluded.injection_active,
                    narrative = excluded.narrative,
                    user_text = excluded.user_text,
                    task_phrase = excluded.task_phrase,
                    cause_channel = excluded.cause_channel,
                    cause_source = excluded.cause_source,
                    dag_json = excluded.dag_json,
                    updated_at = excluded.updated_at
                """,
                (
                    session_id,
                    getattr(session.intent, "value", str(session.intent)),
                    getattr(session, "task_phrase", ""),
                    1 if getattr(session, "injection_active", False) else 0,
                    _safe(session, narrative),
                    _safe(session, getattr(session, "user_text", "")),
                    _safe(session, getattr(session, "task_phrase", "")),
                    _safe(session, getattr(session, "cause_channel", "")),
                    _safe(session, getattr(session, "cause_source", "")),
                    json.dumps(_safe(session, dag), ensure_ascii=False),
                    now,
                    now,
                ),
            )

            # 插入审计记录
            conn.execute(
                """
                INSERT INTO audit_records (
                    session_id, span_id, channel, source_id, tool, action, decision,
                    risk, risk_level, explanation, deviation, policy_ids, evidence_indices,
                    findings, policies, detail, confirmed, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    span_id,
                    channel,
                    source_id,
                    tool,
                    action_clean,
                    decision,
                    risk,
                    risk_level,
                    explanation,
                    deviation,
                    json.dumps(policy_ids, ensure_ascii=False),
                    json.dumps(evidence_indices, ensure_ascii=False),
                    json.dumps(findings_clean, ensure_ascii=False),
                    json.dumps(policies_clean, ensure_ascii=False),
                    json.dumps(detail_clean, ensure_ascii=False),
                    1 if verdict.confirmed else 0,
                    now,
                ),
            )

            # 同步 spans
            if hasattr(session, "trace") and session.trace.spans:
                for span in session.trace.spans:
                    conn.execute(
                        """
                        INSERT INTO spans (id, session_id, kind, name, parent_id, summary, decision, detail, caused_by, finding_ids, ts)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(session_id, id) DO UPDATE SET
                            decision = excluded.decision,
                            summary = excluded.summary,
                            detail = excluded.detail,
                            caused_by = excluded.caused_by,
                            finding_ids = excluded.finding_ids
                        """,
                        (
                            span.id,
                            session_id,
                            span.kind,
                            _safe(session, span.name),
                            span.parent_id,
                            _safe(session, span.summary),
                            span.decision,
                            json.dumps(_safe(session, span.detail), ensure_ascii=False),
                            json.dumps(list(span.caused_by), ensure_ascii=False),
                            json.dumps(list(span.finding_ids), ensure_ascii=False),
                            span.ts or now,
                        ),
                    )

            # 同步 impacts
            if hasattr(session, "impacts") and session.impacts:
                # 清除旧 impacts 并全量重写以防重复
                conn.execute("DELETE FROM impacts WHERE session_id = ?", (session_id,))
                for impact in session.impacts:
                    conn.execute(
                        """
                        INSERT INTO impacts (session_id, type, value, action, decision)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            session_id,
                            _safe(session, impact.get("type", "")),
                            _safe(session, impact.get("value", "")),
                            _safe(session, impact.get("action", "")),
                            _safe(session, impact.get("decision", "")),
                        ),
                    )

    def sync_session(self, session: Session, narrative: str = "") -> None:
        """显式同步会话元信息、DAG 与影响面。"""
        session_id = _safe(session, session.id)
        now = time.time()
        dag = session.trace.dag() if hasattr(session, "trace") else {}
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO sessions (id, intent, intent_zh, injection_active, narrative, user_text, task_phrase, cause_channel, cause_source, dag_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    intent = excluded.intent,
                    intent_zh = excluded.intent_zh,
                    injection_active = excluded.injection_active,
                    narrative = excluded.narrative,
                    user_text = excluded.user_text,
                    task_phrase = excluded.task_phrase,
                    cause_channel = excluded.cause_channel,
                    cause_source = excluded.cause_source,
                    dag_json = excluded.dag_json,
                    updated_at = excluded.updated_at
                """,
                (
                    session_id,
                    getattr(session.intent, "value", str(session.intent)),
                    getattr(session, "task_phrase", ""),
                    1 if getattr(session, "injection_active", False) else 0,
                    _safe(session, narrative),
                    _safe(session, getattr(session, "user_text", "")),
                    _safe(session, getattr(session, "task_phrase", "")),
                    _safe(session, getattr(session, "cause_channel", "")),
                    _safe(session, getattr(session, "cause_source", "")),
                    json.dumps(_safe(session, dag), ensure_ascii=False),
                    now,
                    now,
                ),
            )
            # 同步 spans
            if hasattr(session, "trace") and session.trace.spans:
                for span in session.trace.spans:
                    conn.execute(
                        """
                        INSERT INTO spans (id, session_id, kind, name, parent_id, summary, decision, detail, caused_by, finding_ids, ts)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(session_id, id) DO UPDATE SET
                            decision = excluded.decision,
                            summary = excluded.summary,
                            detail = excluded.detail,
                            caused_by = excluded.caused_by,
                            finding_ids = excluded.finding_ids
                        """,
                        (
                            span.id,
                            session_id,
                            span.kind,
                            _safe(session, span.name),
                            span.parent_id,
                            _safe(session, span.summary),
                            span.decision,
                            json.dumps(_safe(session, span.detail), ensure_ascii=False),
                            json.dumps(list(span.caused_by), ensure_ascii=False),
                            json.dumps(list(span.finding_ids), ensure_ascii=False),
                            span.ts or now,
                        ),
                    )
            # 同步 impacts
            if hasattr(session, "impacts") and session.impacts:
                conn.execute("DELETE FROM impacts WHERE session_id = ?", (session_id,))
                for impact in session.impacts:
                    conn.execute(
                        """
                        INSERT INTO impacts (session_id, type, value, action, decision)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            session_id,
                            _safe(session, impact.get("type", "")),
                            _safe(session, impact.get("value", "")),
                            _safe(session, impact.get("action", "")),
                            _safe(session, impact.get("decision", "")),
                        ),
                    )

    def export_dict(self, session_id: str | None = None) -> dict[str, Any]:
        with self._connect() as conn:
            if session_id:
                session_rows = conn.execute("SELECT * FROM sessions WHERE id = ?", (session_id,)).fetchall()
            else:
                session_rows = conn.execute("SELECT * FROM sessions ORDER BY created_at ASC").fetchall()

            sessions_out = []
            for srow in session_rows:
                sid = srow["id"]
                dag = json.loads(srow["dag_json"] or "{}")

                # 读取 records
                rec_rows = conn.execute(
                    "SELECT * FROM audit_records WHERE session_id = ? ORDER BY id ASC", (sid,)
                ).fetchall()
                records_out = []
                for rrow in rec_rows:
                    records_out.append(
                        {
                            "id": rrow["id"],
                            "span_id": rrow["span_id"],
                            "channel": rrow["channel"],
                            "source_id": rrow["source_id"],
                            "tool": rrow["tool"],
                            "action": rrow["action"],
                            "decision": rrow["decision"],
                            "risk": rrow["risk"],
                            "risk_level": rrow["risk_level"],
                            "explanation": rrow["explanation"],
                            "deviation": rrow["deviation"],
                            "policy_ids": json.loads(rrow["policy_ids"] or "[]"),
                            "evidence_indices": json.loads(rrow["evidence_indices"] or "[]"),
                            "findings": json.loads(rrow["findings"] or "[]"),
                            "policies": json.loads(rrow["policies"] or "[]"),
                            "detail": json.loads(rrow["detail"] or "{}"),
                            "confirmed": bool(rrow["confirmed"]),
                            "created_at": rrow["created_at"],
                        }
                    )

                # 读取 impacts
                imp_rows = conn.execute(
                    "SELECT * FROM impacts WHERE session_id = ? ORDER BY id ASC", (sid,)
                ).fetchall()
                impacts_out = [
                    {
                        "type": irow["type"],
                        "value": irow["value"],
                        "action": irow["action"],
                        "decision": irow["decision"],
                    }
                    for irow in imp_rows
                ]

                # 读取 spans
                span_rows = conn.execute(
                    "SELECT * FROM spans WHERE session_id = ? ORDER BY ts ASC", (sid,)
                ).fetchall()
                spans_out = [
                    {
                        "id": sprow["id"],
                        "kind": sprow["kind"],
                        "name": sprow["name"],
                        "parent_id": sprow["parent_id"],
                        "summary": sprow["summary"],
                        "decision": sprow["decision"],
                        "detail": json.loads(sprow["detail"] or "{}"),
                        "caused_by": json.loads(sprow["caused_by"] or "[]"),
                        "finding_ids": json.loads(sprow["finding_ids"] or "[]"),
                        "ts": sprow["ts"],
                    }
                    for sprow in span_rows
                ]

                sessions_out.append(
                    {
                        "session_id": sid,
                        "intent": srow["intent"],
                        "intent_zh": srow["intent_zh"],
                        "injection_active": bool(srow["injection_active"]),
                        "narrative": srow["narrative"],
                        "user_text": srow["user_text"],
                        "task_phrase": srow["task_phrase"],
                        "cause_channel": srow["cause_channel"],
                        "cause_source": srow["cause_source"],
                        "dag": dag,
                        "spans": spans_out,
                        "impact": impacts_out,
                        "records": records_out,
                    }
                )

            result = {"sessions": sessions_out}
            # 导出前做二次 redact 保底
            return redact(result)

    def export_json(self, session_id: str | None = None, output_path: str | Path | None = None) -> str:
        data = self.export_dict(session_id=session_id)
        encoded = json.dumps(data, ensure_ascii=False, indent=2)
        if output_path:
            Path(output_path).write_text(encoded, encoding="utf-8")
        return encoded
