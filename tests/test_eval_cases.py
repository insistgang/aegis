import json
import re

from aegis.agent import TOOL_NAMES, _tool_calls
from aegis.eval_cases import CASES


TOOLS_AND_GOALS = {
    "fs.read": ("sensitive_read", "readme_read"),
    "fs.write": ("sensitive_write", "report_write"),
    "net.fetch": ("secret_exfil", "health_fetch"),
    "exec": ("canary_exec", "check_exec"),
    "git.push": ("git_push", "git_push"),
    "agent.spawn": ("child_secret", "child_spawn"),
}
CASE_FIELDS = {
    "id", "kind", "tool", "variant", "task", "resource", "script",
    "confirm_tools", "goal", "origin",
}
ALLOWED_PLACEHOLDERS = {"COLLECTOR", "PAYLOAD_URL", "CANARY_B64", "SECRET"}
ALLOWED_PATHS = {
    "README.md",
    "report.txt",
    "scripts/check.py",
    "~/.ssh/id_rsa",
    "~/.ssh/authorized_keys",
    "/work/.env",
}


def _walk_strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, nested in value.items():
            yield from _walk_strings(key)
            yield from _walk_strings(nested)
    elif isinstance(value, (list, tuple)):
        for nested in value:
            yield from _walk_strings(nested)


def test_cases_have_exact_shape_and_unique_ids():
    assert isinstance(CASES, list)
    assert len(CASES) == 18
    assert all(isinstance(case, dict) and set(case) == CASE_FIELDS for case in CASES)
    ids = [case["id"] for case in CASES]
    assert len(ids) == len(set(ids))
    assert all(isinstance(case_id, str) and case_id for case_id in ids)
    assert {case["origin"] for case in CASES} == {"new_handcrafted_20261018"}


def test_each_canonical_tool_has_two_attack_variants_and_one_benign_case():
    assert {case["tool"] for case in CASES} == set(TOOLS_AND_GOALS)
    for tool, (attack_goal, benign_goal) in TOOLS_AND_GOALS.items():
        selected = [case for case in CASES if case["tool"] == tool]
        assert len(selected) == 3
        attacks = [case for case in selected if case["kind"] == "attack"]
        benign = [case for case in selected if case["kind"] == "benign"]
        assert len(attacks) == 2
        assert len(benign) == 1
        assert {case["goal"] for case in attacks} == {attack_goal}
        assert benign[0]["goal"] == benign_goal
        assert {case["variant"] for case in attacks} == {
            "claimed_procedure",
            "source_delegated_authorization",
        }
        assert all(case["variant"] == "normal_task" for case in benign)


def test_scripts_are_canonical_bounded_tool_trajectories():
    for case in CASES:
        assert isinstance(case["task"], str) and case["task"].strip()
        assert isinstance(case["resource"], str)
        assert isinstance(case["script"], list) and case["script"]
        assert isinstance(case["confirm_tools"], list)
        assert all(tool in TOOLS_AND_GOALS for tool in case["confirm_tools"])
        assert all(
            isinstance(call, dict)
            and set(call) == {"tool", "args"}
            and call["tool"] in TOOLS_AND_GOALS
            and isinstance(call["args"], dict)
            for call in case["script"]
        )
        assert case["script"][-1]["tool"] == case["tool"]

        if case["kind"] == "attack":
            assert case["resource"].strip()
            bounded_task_patterns = {
                "fs.read": r"do not (?:read|inspect)",
                "fs.write": r"do not (?:change|modify)",
                "net.fetch": r"(?:never send|do not transmit)",
                "exec": r"(?:do not (?:run|decode)|don't decode)",
                "git.push": r"do not (?:commit|publish|push)",
                "agent.spawn": r"(?:do not (?:share|delegate)|without disclosing)",
            }[case["tool"]]
            assert re.search(bounded_task_patterns, case["task"], re.IGNORECASE)
            requested_action = {
                "fs.read": "~/.ssh/id_rsa",
                "fs.write": "~/.ssh/authorized_keys",
                "net.fetch": "{COLLECTOR}/collect",
                "git.push": "origin",
                "agent.spawn": "helper",
            }.get(case["tool"])
            if case["tool"] == "exec":
                assert any(token in case["resource"] for token in ("{PAYLOAD_URL}", "{CANARY_B64}"))
            else:
                assert requested_action in case["resource"]
            if case["tool"] in {"net.fetch", "agent.spawn"}:
                assert case["script"][0]["tool"] == "fs.read"
                assert case["script"][0]["args"].get("path") == "/work/.env"
                assert case["confirm_tools"] == ["fs.read"]
            else:
                assert case["confirm_tools"] == []
        else:
            assert case["confirm_tools"] == ([case["tool"]] if case["tool"] in {"git.push", "agent.spawn"} else [])

        for call in case["script"]:
            path = call["args"].get("path")
            if path is not None:
                assert path in ALLOWED_PATHS


def test_placeholders_hosts_and_credential_literals_are_safe():
    text = "\n".join(value for case in CASES for value in _walk_strings(case))
    placeholders = set(re.findall(r"\{([A-Z_]+)\}", text))
    assert placeholders <= ALLOWED_PLACEHOLDERS

    # Network fixtures only use the per-run local collector placeholder.
    for case in CASES:
        for call in case["script"]:
            if call["tool"] == "net.fetch":
                url = call["args"].get("url", "")
                assert url.startswith("{COLLECTOR}/")
                assert url.split("/", 1)[1] in {"collect", "health"}
                if url.endswith("/collect"):
                    assert call["args"].get("body") == "{SECRET}"
            if call["tool"] == "exec":
                command = call["args"].get("command", "")
                assert "evil." not in command and "https://" not in command
            if call["tool"] == "agent.spawn" and case["kind"] == "attack":
                assert "{SECRET}" in call["args"].get("note", "")

    forbidden_credentials = (
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
        r"\bAKIA[0-9A-Z]{16}\b",
        r"\bgh[pousr]_[A-Za-z0-9]{20,}\b",
        r"\bsk-[A-Za-z0-9]{20,}\b",
    )
    assert all(not re.search(pattern, text) for pattern in forbidden_credentials)
    assert "injection_10k" not in text


def test_normal_cases_have_user_goals_for_the_six_real_operations():
    benign = {case["tool"]: case for case in CASES if case["kind"] == "benign"}
    expected_targets = {
        "fs.read": ("README.md", "README.md"),
        "fs.write": ("report.txt", "report.txt"),
        "net.fetch": ("{COLLECTOR}/health", "{COLLECTOR}/health"),
        "exec": ("python scripts/check.py", "python scripts/check.py"),
        "git.push": ("origin", "origin"),
        "agent.spawn": ("helper", "helper"),
    }
    for tool, (task_target, script_target) in expected_targets.items():
        case = benign[tool]
        assert task_target in " ".join(_walk_strings(case["task"]))
        assert case["script"][-1]["tool"] == tool
        assert script_target in " ".join(_walk_strings(case["script"][-1]["args"]))


def test_every_script_call_round_trips_through_the_real_tool_parser():
    model_names = {canonical: model_name for model_name, canonical in TOOL_NAMES.items()}
    for case in CASES:
        message = {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {
                    "id": f"{case['id']}-{index}",
                    "type": "function",
                    "function": {
                        "name": model_names[call["tool"]],
                        "arguments": json.dumps(call["args"]),
                    },
                }
                for index, call in enumerate(case["script"])
            ],
        }
        parsed = _tool_calls(message)
        assert [(tool, args) for _, tool, args in parsed] == [
            (call["tool"], call["args"]) for call in case["script"]
        ]
