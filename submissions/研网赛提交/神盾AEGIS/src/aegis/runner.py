"""按场景回放守卫，供测试、命令行和看板使用。"""

from __future__ import annotations

from aegis.guard import AegisGuard
from aegis.model import model_card
from aegis.scenarios import BY_ID, SCENARIOS, Scenario, Step


def run_scenario(spec: Scenario | str, policy_path: str | None = None) -> dict:
    if isinstance(spec, str):
        spec = BY_ID[spec]
    guard = AegisGuard(policy_path)
    steps = []
    for step in spec.steps:
        verdict = _dispatch(guard, spec.id, step)
        got = verdict.decision.value
        steps.append(
            {
                "op": step.op,
                "tool": step.tool,
                "source": step.source,
                "expect": step.expect,
                "got": got,
                "ok": got == step.expect,
                "verdict": verdict.to_dict(),
            }
        )
    snapshot = guard.snapshot(spec.id)
    return {
        "id": spec.id,
        "title": spec.title,
        "summary": spec.summary,
        "capabilities": list(spec.capabilities),
        "passed": all(item["ok"] for item in steps),
        "steps": steps,
        "model_threshold": model_card().get("threshold", 0.5),
        **snapshot,
    }


def run_all(policy_path: str | None = None) -> list[dict]:
    return [run_scenario(spec, policy_path) for spec in SCENARIOS]


def summary(reports: list[dict]) -> dict:
    steps = [step for report in reports for step in report["steps"]]
    return {
        "scenarios": len(reports),
        "passed_scenarios": sum(1 for report in reports if report["passed"]),
        "steps": len(steps),
        "passed_steps": sum(1 for step in steps if step["ok"]),
    }


def _dispatch(guard: AegisGuard, sid: str, step: Step):
    if step.op == "user":
        return guard.inspect_user(sid, step.text)
    if step.op == "resource":
        return guard.inspect_resource(sid, step.text, source=step.source, kind=step.kind)
    if step.op == "memory":
        return guard.inspect_memory(sid, step.text, memory_id=step.source, op=step.mem_op)
    if step.op == "tool_desc":
        return guard.inspect_tool_description(sid, step.server, step.tool, step.text)
    if step.op == "tool":
        return guard.inspect_tool_call(
            sid,
            step.tool,
            step.args,
            confirmed=step.confirmed,
            agent=step.agent,
            mcp=step.mcp,
        )
    if step.op == "result":
        return guard.observe_tool_result(sid, step.tool, step.args, step.text)
    raise ValueError(f"未知步骤 {step.op}")
