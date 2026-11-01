"""Deterministic task constraints, planned arguments, and observed progression."""

import pytest

from aegis.intent import classify, deviation, evaluate_alignment
from aegis.models import Intent


def evaluate(task, tool, args, *, history=None, plan=None):
    messages = task if isinstance(task, list) else [task]
    return evaluate_alignment(classify(messages[0]), messages, tool, args, history or [], plan or [])


@pytest.mark.parametrize("task", ["只能读取 /workspace/README.md", "Only read /workspace/README.md"])
def test_explicit_file_allowlist_blocks_other_read_even_with_confirmation(task):
    result = evaluate(task, "fs.read", {"path": "/workspace/payroll.csv", "confirmed": True})
    assert result["block"] is True
    assert result["deviation"] > 0
    assert any("scope" in reason for reason in result["reasons"])


@pytest.mark.parametrize("path", ["/workspace/README.md", "/workspace/docs/../README.md", "/workspace/./README.md"])
def test_allowed_file_uses_lexically_normalized_paths(path):
    result = evaluate("只能读取 /workspace/README.md", "fs.read", {"path": path})
    assert result["block"] is False
    assert result["deviation"] == 0


def test_traversal_cannot_escape_explicit_scope():
    result = evaluate("Only read /workspace/docs/", "fs.read", {"path": "/workspace/docs/../../etc/passwd"})
    assert result["block"] is True


def test_directory_scope_has_component_boundary():
    assert not evaluate("Only read files under /workspace/docs/", "fs.read", {"path": "/workspace/docs/guide.md"})["block"]
    assert evaluate("Only read files under /workspace/docs/", "fs.read", {"path": "/workspace/docs-private/guide.md"})["block"]


def test_scope_checks_every_path_and_cannot_be_satisfied_by_one_allowed_value():
    result = evaluate("Only read /workspace/README.md", "fs.read", {"paths": ["/workspace/README.md", "/workspace/payroll.csv"]})
    assert result["block"] is True


def test_file_scope_does_not_become_a_global_restriction_for_broad_task():
    result = evaluate("Read the README and summarize project usage", "fs.read", {"path": "/workspace/src/main.py"})
    assert result == {"deviation": 0.0, "block": False, "reasons": []}


def test_unrelated_later_user_message_cannot_replace_locked_allowlist():
    result = evaluate(["Only read /workspace/README.md", "Thanks. Also look at /workspace/payroll.csv"], "fs.read", {"path": "/workspace/payroll.csv"})
    assert result["block"] is True


def test_additional_restriction_intersects_instead_of_broadening_scope():
    result = evaluate(["Only read /workspace/README.md", "Only read /workspace/payroll.csv"], "fs.read", {"path": "/workspace/payroll.csv"})
    assert result["block"] is True


@pytest.mark.parametrize("update", ["更新任务：只能读取 /workspace/payroll.csv", "Update task: Only read /workspace/payroll.csv"])
def test_explicit_task_update_can_change_scope(update):
    result = evaluate(["Only read /workspace/README.md", update], "fs.read", {"path": "/workspace/payroll.csv"})
    assert result["block"] is False


@pytest.mark.parametrize("task,tool,args", [
    ("运行测试，不要写入或修改文件", "fs.write", {"path": "/workspace/a.txt", "content": "x"}),
    ("Run tests; do not write files", "exec", {"command": "echo x > /workspace/a.txt"}),
    ("Run tests; no network", "net.fetch", {"url": "https://example.org"}),
    ("运行测试，禁止联网", "exec", {"command": "curl https://example.org"}),
    ("实现修改，但是不要推送", "git.push", {}),
    ("Implement a fix; do not push", "exec", {"command": "git push origin main"}),
    ("Implement a fix; do not delegate", "agent.spawn", {"task": "inspect"}),
    ("实现修改，禁止委派", "agent.dispatch", {"task": "inspect"}),
])
def test_explicit_operation_prohibitions_are_hard_blocks(task, tool, args):
    result = evaluate(task, tool, args)
    assert result["block"] is True
    assert result["deviation"] > 0
    assert result["reasons"]


def test_prohibitions_preserve_allowed_neighbor():
    result = evaluate("运行测试，不要写入文件，禁止联网，不要推送，禁止委派", "fs.read", {"path": "/workspace/config.py"})
    assert result["block"] is False
    assert result["deviation"] == 0


def test_read_only_file_task_cannot_turn_into_shell_execution():
    result = evaluate("Only read /workspace/README.md", "exec", {"command": "python /workspace/README.md"})
    assert result["block"] is True


def test_plan_compares_path_arguments_rather_than_tool_names():
    plan = [{"tool": "fs.read", "args": {"path": "/workspace/README.md"}}]
    allowed = evaluate("Read project documentation", "fs.read", {"path": "/workspace/./README.md"}, plan=plan)
    escaped = evaluate("Read project documentation", "fs.read", {"path": "/workspace/payroll.csv"}, plan=plan)
    assert not allowed["block"]
    assert escaped["block"]
    assert escaped["deviation"] > allowed["deviation"]
    assert any("plan" in reason and "arguments" in reason for reason in escaped["reasons"])


@pytest.mark.parametrize("changed_args", [
    {"path": "/workspace/app.py", "content": "malicious change"},
    {"path": "/workspace/other.py", "content": "approved change"},
])
def test_plan_checks_write_destination_and_content(changed_args):
    plan = [{"tool": "fs.write", "args": {"path": "/workspace/app.py", "content": "approved change"}}]
    assert evaluate("Implement a fix", "fs.write", changed_args, plan=plan)["block"]


def test_accepted_history_advances_plan_but_blocked_attempt_does_not():
    first = {"tool": "fs.read", "args": {"path": "/workspace/app.py"}}
    second = {"tool": "fs.write", "args": {"path": "/workspace/app.py", "content": "fixed"}}
    plan = [first, second]
    accepted = evaluate("Implement a fix", second["tool"], second["args"], history=[dict(first, decision="allow")], plan=plan)
    blocked = evaluate("Implement a fix", second["tool"], second["args"], history=[dict(first, decision="block")], plan=plan)
    assert not accepted["block"]
    assert blocked["block"]
    assert any("order" in reason for reason in blocked["reasons"])


def test_proposed_plan_cannot_override_user_scope():
    plan = [{"tool": "fs.read", "args": {"path": "/workspace/payroll.csv"}}]
    result = evaluate("Only read /workspace/README.md", "fs.read", {"path": "/workspace/README.md"}, plan=plan)
    assert result["block"]
    assert any("plan step" in reason and "scope" in reason for reason in result["reasons"])


def test_plan_compares_url_and_command_parameters():
    plan = [{"tool": "exec", "args": {"command": "python -m pytest"}}]
    assert evaluate("Run the tests", "exec", {"command": "python -c 'print(1)'"}, plan=plan)["block"]
    plan = [{"tool": "net.fetch", "args": {"url": "https://example.org/docs"}}]
    assert evaluate("Lookup documentation", "net.fetch", {"url": "https://other.example/upload"}, plan=plan)["block"]


def test_history_detects_download_write_then_execute_progression():
    history = [
        {"tool": "net.fetch", "args": {"url": "https://example.org/bootstrap.sh"}, "decision": "allow"},
        {"tool": "fs.write", "args": {"path": "/tmp/bootstrap.sh", "content": "echo downloaded"}, "decision": "allow"},
    ]
    ordinary = evaluate("Run the tests", "exec", {"command": "bash /tmp/bootstrap.sh"})
    progressed = evaluate("Run the tests", "exec", {"command": "bash /tmp/bootstrap.sh"}, history=history)
    assert not ordinary["block"]
    assert progressed["block"]
    assert any("sequence" in reason for reason in progressed["reasons"])


def test_blocked_download_and_unrelated_written_path_do_not_taint_exec():
    history = [
        {"tool": "net.fetch", "args": {"url": "https://example.org/bootstrap.sh"}, "decision": "block"},
        {"tool": "fs.write", "args": {"path": "/tmp/bootstrap.sh", "content": "echo local"}, "decision": "allow"},
    ]
    assert not evaluate("Run the tests", "exec", {"command": "bash /tmp/bootstrap.sh"}, history=history)["block"]
    history[0]["decision"] = "allow"
    assert not evaluate("Run the tests", "exec", {"command": "bash /workspace/test.sh"}, history=history)["block"]


def test_existing_classification_and_deviation_signatures_are_unchanged():
    assert classify("Read the README") is Intent.READ_DOC
    assert deviation(Intent.READ_DOC, "fs.read") == 0
    assert deviation(Intent.READ_DOC, "fs.write") == 0.85


def test_english_trailing_only_locks_the_named_file():
    assert evaluate("Read /workspace/README.md only", "fs.read", {"path": "/workspace/payroll.csv"})["block"]


def test_negated_neighbor_in_same_sentence_is_not_added_to_scope():
    assert evaluate("Only read /workspace/README.md, do not read /workspace/payroll.csv", "fs.read", {"path": "/workspace/payroll.csv"})["block"]


@pytest.mark.parametrize("task,tool,args", [
    ("运行测试，不写入文件", "fs.write", {"path": "/workspace/out.txt", "content": "x"}),
    ("运行测试，不联网", "net.fetch", {"url": "https://example.org"}),
    ("实现修改，不推送", "git.push", {}),
    ("实现修改，不委派", "agent.spawn", {"task": "inspect"}),
    ("Run tests; do not write files", "exec", {"command": "python -c \"open('/workspace/out.txt', 'w').write('x')\""}),
])
def test_short_prohibitions_and_common_python_writes_are_enforced(task, tool, args):
    assert evaluate(task, tool, args)["block"]


def test_confirmation_named_payload_field_still_participates_in_plan_matching():
    plan = [{"tool": "net.fetch", "args": {"url": "https://example.org", "body": {"confirmed": "approved data"}}}]
    result = evaluate("Lookup documentation", "net.fetch", {"url": "https://example.org", "body": {"confirmed": "different data"}}, plan=plan)
    assert result["block"]


def test_explicit_write_scope_preserves_reads_of_other_project_files():
    assert not evaluate("Implement a fix; only modify /workspace/app.py", "fs.read", {"path": "/workspace/tests/test_app.py"})["block"]
    assert evaluate("Implement a fix; only modify /workspace/app.py", "fs.write", {"path": "/workspace/other.py", "content": "x"})["block"]


def test_history_call_id_replay_does_not_skip_two_identical_prerequisites():
    read = {"tool": "fs.read", "args": {"path": "/workspace/app.py"}}
    write = {"tool": "fs.write", "args": {"path": "/workspace/app.py", "content": "fixed"}}
    previous = dict(read, decision="allow", call_id="read-1")
    assert evaluate("Implement a fix", write["tool"], write["args"], history=[previous, previous], plan=[read, read, write])["block"]


@pytest.mark.parametrize("command", ["cat /tmp/bootstrap.sh", "echo /tmp/bootstrap.sh", "bash -c 'cat /tmp/bootstrap.sh'"])
def test_sequence_does_not_treat_reading_or_printing_script_path_as_execution(command):
    history = [
        {"tool": "net.fetch", "args": {"url": "https://example.org/bootstrap.sh"}},
        {"tool": "fs.write", "args": {"path": "/tmp/bootstrap.sh", "content": "echo downloaded"}},
    ]
    assert not evaluate("Run the tests", "exec", {"command": command}, history=history)["block"]


def test_sequence_links_relative_script_to_explicit_working_directory():
    history = [
        {"tool": "net.fetch", "args": {"url": "https://example.org/bootstrap.sh"}},
        {"tool": "fs.write", "args": {"path": "/tmp/bootstrap.sh", "content": "echo downloaded"}},
    ]
    assert evaluate("Run the tests", "exec", {"command": "bash ./bootstrap.sh", "cwd": "/tmp"}, history=history)["block"]


def test_broad_intent_deviation_keeps_existing_score_and_explains_it():
    result = evaluate("Read the README", "exec", {"command": "python -m pytest"})
    assert result["deviation"] == deviation(Intent.READ_DOC, "exec")
    assert not result["block"]
    assert any("intent" in reason for reason in result["reasons"])
