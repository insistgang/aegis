"""一次 Agent 会话的意图、污点、IOC 与轨迹。"""

from __future__ import annotations

from aegis.features import IOC, SecretRecord
from aegis.models import Intent
from aegis.trace import Trace


class Session:
    def __init__(self, sid: str) -> None:
        self.id = sid
        self.intent = Intent.UNKNOWN
        self.intent_locked = False
        self.user_text = ""
        self.task_phrase = ""
        self.hostile_open = False
        self.injection_active = False
        self.cause_channel = ""
        self.cause_source = ""
        self.iocs: list[IOC] = []
        self.secrets: list[SecretRecord] = []
        self.trace = Trace()
        self.impacts: list[dict] = []
        self.blocked_actions: list[str] = []
        self.untrusted_tail = ""
        self.user_span_id: str | None = None
        self.agent_span_id: str | None = None
        self.subagents: dict[str, str] = {}
        self.mcp_nodes: dict[tuple[str, str], str] = {}
        self.injection_spans: list[str] = []
        self._finding_seq = 0

    def next_finding_id(self) -> str:
        self._finding_seq += 1
        return f"f{self._finding_seq}"
