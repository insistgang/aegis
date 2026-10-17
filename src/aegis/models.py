"""共享类型。决策只有放行、询问、阻断三态。"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from aegis.redact import redact


class Decision(str, Enum):
    ALLOW = "allow"
    ASK = "ask"
    BLOCK = "block"


class Intent(str, Enum):
    READ_DOC = "read_doc"
    CODE_REVIEW = "code_review"
    CODE_EDIT = "code_edit"
    OPS = "ops"
    DATA_QUERY = "data_query"
    SHIP = "ship"
    UNKNOWN = "unknown"


class Channel(str, Enum):
    USER = "user"
    RESOURCE = "resource"
    MEMORY = "memory"
    TOOL_DESC = "tool_desc"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    SUBAGENT = "subagent"


DECISION_RANK = {Decision.ALLOW: 0, Decision.ASK: 1, Decision.BLOCK: 2}

DECISION_ZH = {
    Decision.ALLOW: "放行",
    Decision.ASK: "询问用户确认",
    Decision.BLOCK: "阻断",
}

INTENT_ZH = {
    Intent.READ_DOC: "读取项目 README 文档",
    Intent.CODE_REVIEW: "代码检视",
    Intent.CODE_EDIT: "修改代码",
    Intent.OPS: "运维排查或执行测试",
    Intent.DATA_QUERY: "查询外部资料",
    Intent.SHIP: "发布并推送代码",
    Intent.UNKNOWN: "未明确的对话任务",
}

FAMILY_ZH = {
    "override": "越权指令 / 上下文劫持",
    "role_hijack": "角色伪装",
    "conceal": "隐蔽执行",
    "secret_exfil": "窃密外发指令",
    "remote_exec": "远程下载执行指令",
    "memory_trigger": "跨会话记忆触发器",
    "tool_poison": "MCP 工具描述投毒",
    "rug_pull": "MCP 工具描述掉包",
}

RISK_SCORE = {"low": 0.2, "medium": 0.55, "high": 0.82, "critical": 0.96}


def strictest(decisions: list[Decision]) -> Decision:
    if not decisions:
        return Decision.ALLOW
    return max(decisions, key=lambda item: DECISION_RANK[item])


@dataclass
class Finding:
    family: str
    severity: float
    quote: str
    channel: str
    source_id: str
    start: int | None = None
    end: int | None = None
    techniques: list[str] = field(default_factory=list)
    detail: str = ""
    id: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "family": self.family,
            "family_zh": FAMILY_ZH.get(self.family, self.family),
            "severity": round(self.severity, 3),
            "quote": redact(self.quote[:240]),
            "channel": self.channel,
            "source_id": self.source_id,
            "start": self.start,
            "end": self.end,
            "techniques": list(self.techniques),
            "detail": self.detail,
        }


@dataclass
class Verdict:
    decision: Decision
    risk: float
    risk_level: str
    explanation: str
    intent: Intent
    findings: list[Finding] = field(default_factory=list)
    policies: list[dict] = field(default_factory=list)
    span_id: str = ""
    tool: str = ""
    channel: str = ""
    source_id: str = ""
    confirmed: bool = False
    deviation: float = 0.0

    def to_dict(self) -> dict:
        return {
            "decision": self.decision.value,
            "decision_zh": DECISION_ZH[self.decision],
            "risk": round(self.risk, 3),
            "risk_level": self.risk_level,
            "explanation": self.explanation,
            "intent": self.intent.value,
            "intent_zh": INTENT_ZH[self.intent],
            "deviation": round(self.deviation, 3),
            "findings": [item.to_dict() for item in self.findings],
            "policies": self.policies,
            "span_id": self.span_id,
            "tool": self.tool,
            "channel": self.channel,
            "source_id": self.source_id,
            "confirmed": self.confirmed,
        }
