"""调用链与攻击路径。结构边表示谁调用了谁，影响边表示哪段不可信文本驱动了工具。"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from aegis.redact import redact


@dataclass
class Span:
    id: str
    kind: str
    name: str
    parent_id: str | None
    summary: str
    decision: str | None = None
    detail: dict = field(default_factory=dict)
    caused_by: list[str] = field(default_factory=list)
    finding_ids: list[str] = field(default_factory=list)
    ts: float = 0.0

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "kind": self.kind,
            "name": self.name,
            "parent_id": self.parent_id,
            "summary": redact(self.summary),
            "decision": self.decision,
            "detail": redact(self.detail),
            "caused_by": list(self.caused_by),
            "finding_ids": list(self.finding_ids),
            "ts": self.ts,
        }


class Trace:
    def __init__(self) -> None:
        self.spans: list[Span] = []

    def add(
        self,
        *,
        kind: str,
        name: str,
        summary: str,
        parent_id: str | None = None,
        decision: str | None = None,
        detail: dict | None = None,
        caused_by: list[str] | None = None,
        finding_ids: list[str] | None = None,
    ) -> Span:
        span = Span(
            id=f"s{len(self.spans) + 1}",
            kind=kind,
            name=name,
            parent_id=parent_id,
            summary=summary,
            decision=decision,
            detail=detail or {},
            caused_by=list(caused_by or []),
            finding_ids=list(finding_ids or []),
            ts=time.time(),
        )
        self.spans.append(span)
        return span

    def dag(self) -> dict:
        nodes = []
        edges = []
        seen = set()
        for span in self.spans:
            if span.parent_id:
                key = (span.parent_id, span.id, "calls")
                if key not in seen:
                    edges.append({"src": span.parent_id, "dst": span.id, "label": "calls"})
                    seen.add(key)
            for source in span.caused_by:
                if source == span.parent_id:
                    continue
                key = (source, span.id, "influenced")
                if key not in seen:
                    edges.append({"src": source, "dst": span.id, "label": "influenced"})
                    seen.add(key)
        ranks = _layers(self.spans, edges)
        buckets: dict[int, list[Span]] = {}
        for span in self.spans:
            buckets.setdefault(ranks.get(span.id, 0), []).append(span)
        for rank, group in buckets.items():
            for offset, span in enumerate(group):
                nodes.append(
                    {
                        "id": span.id,
                        "label": _label(span),
                        "kind": span.kind,
                        "decision": span.decision,
                        "x": 80 + rank * 210,
                        "y": 36 + offset * 78,
                    }
                )
        width = 160 + (max(ranks.values(), default=0) + 1) * 210
        height = 80 + max((len(group) for group in buckets.values()), default=1) * 78
        return {"nodes": nodes, "edges": edges, "width": width, "height": height}

    def timeline(self) -> list[dict]:
        return [
            {
                "id": span.id,
                "kind": span.kind,
                "name": span.name,
                "decision": span.decision,
                "summary": redact(span.summary),
                "ts": span.ts,
            }
            for span in self.spans
        ]

    def mermaid(self) -> str:
        lines = ["flowchart LR"]
        for span in self.spans:
            safe = _label(span).replace('"', "'")
            lines.append(f'  {span.id}["{safe}"]')
        for span in self.spans:
            if span.parent_id:
                lines.append(f"  {span.parent_id} --> {span.id}")
            for source in span.caused_by:
                if source != span.parent_id:
                    lines.append(f"  {source} -.->|influenced| {span.id}")
        return "\n".join(lines)


def _layers(spans: list[Span], edges: list[dict]) -> dict[str, int]:
    children: dict[str, list[str]] = {span.id: [] for span in spans}
    indeg = {span.id: 0 for span in spans}
    for edge in edges:
        if edge["dst"] not in indeg or edge["src"] not in indeg:
            continue
        children[edge["src"]].append(edge["dst"])
        indeg[edge["dst"]] += 1
    ranks = {span.id: 0 for span in spans if indeg[span.id] == 0}
    queue = [span.id for span in spans if indeg[span.id] == 0]
    while queue:
        current = queue.pop(0)
        for child in children[current]:
            ranks[child] = max(ranks.get(child, 0), ranks[current] + 1)
            indeg[child] -= 1
            if indeg[child] == 0:
                queue.append(child)
    for span in spans:
        ranks.setdefault(span.id, 0)
    return ranks


def _label(span: Span) -> str:
    decision = f" {span.decision}" if span.decision else ""
    name = span.name if len(span.name) <= 42 else span.name[:39] + "..."
    return f"{span.kind}:{name}{decision}"
