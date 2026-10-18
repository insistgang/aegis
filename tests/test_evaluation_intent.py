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
