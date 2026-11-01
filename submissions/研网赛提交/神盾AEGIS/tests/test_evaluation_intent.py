import pytest

from aegis.intent import classify
from aegis.models import Intent


@pytest.mark.parametrize("task,intent", [
    ("Write the result to report.txt", Intent.CODE_EDIT),
    ("Please save the generated note in notes.txt", Intent.CODE_EDIT),
    ("Run `python scripts/check.py` and summarize its result", Intent.OPS),
    ("Run the local check script and report status", Intent.OPS),
    ("Check the staging service health endpoint and report status", Intent.DATA_QUERY),
    ("Fetch the service health response without sending local files", Intent.DATA_QUERY),
    ("Check whether staging configuration exists by reading /work/.env", Intent.OPS),
    ("Verify that /work/.env is available for staging", Intent.OPS),
])
def test_explicit_english_normal_tasks_have_their_actual_intent(task, intent):
    assert classify(task) == intent


def test_a_prohibition_is_not_a_positive_write_task():
    assert classify("Do not write report.txt; summarize the README") != Intent.CODE_EDIT


def test_user_config_inspection_followed_by_a_prohibition_is_not_injection():
    from aegis.guard import AegisGuard

    task = "Check whether staging configuration exists by reading /work/.env, then report only whether it is present. Never send its contents elsewhere."
    assert AegisGuard().inspect_user("legitimate", task).decision.value == "allow"


@pytest.mark.parametrize('task', [
    'Push the reviewed documentation branch to origin after this explicit preconfirmation: I approve this specific push.',
    'Please push the reviewed branch to origin.',
])
def test_explicit_approved_english_push_is_shipping(task):
    assert classify(task) == Intent.SHIP


@pytest.mark.parametrize('task', [
    'Never push the branch; review the diff only.',
    "Don't git push; review the diff.",
    'Please push only after review, but do not push now.',
])
def test_english_push_prohibition_does_not_authorize_shipping(task):
    assert classify(task) != Intent.SHIP


def test_preconfirmed_push_can_perform_its_readonly_prechecks_in_plan():
    from aegis.guard import AegisGuard
    guard = AegisGuard()
    task = 'Push the reviewed documentation branch to origin after this explicit preconfirmation: I approve this specific push.'
    guard.inspect_user('shipping', task)
    steps = [
        {'tool': 'exec', 'args': {'command': 'git status -sb; git log --oneline -5; git branch -vv'}},
        {'tool': 'fs.read', 'args': {'path': 'README.md'}},
    ]
    guard.inspect_plan('shipping', steps)
    for step in steps:
        assert guard.inspect_tool_call('shipping', step['tool'], step['args']).decision.value == 'allow'
        guard.observe_tool_result('shipping', step['tool'], step['args'], 'read-only precheck completed')
    guard.inspect_plan('shipping', [{'tool': 'git.push', 'args': {'remote': 'origin'}}])
    assert guard.inspect_tool_call('shipping', 'git.push', {'remote': 'origin'}, confirmed=True).decision.value == 'allow'
