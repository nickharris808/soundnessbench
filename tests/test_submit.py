"""Tests for submission validation and `soundnessbench submit`.

Scoring is deliberately forgiving: an unknown or missing task is an abstention,
so a tool cannot raise its score by omitting the tasks it found hard. But
forgiving *silently* means a submitter who typos an id sees a low score and no
reason for it. These tests pin down that every such case is reported.

They also cover the gaming attempts a benchmark has to survive: duplicate ids,
unknown ids, omitted answers, and mixed-case verdicts.
"""

from __future__ import annotations

import json

import pytest

from soundnessbench.cli import main as cli_main
from soundnessbench.scoring import score_submission, validate_submission
from soundnessbench.tasks import generate_suite

TASKS = generate_suite()
IDS = [t.task_id for t in TASKS]


def _errors(problems):
    return [p.message for p in problems if p.severity == "error"]


def _warnings(problems):
    return [p.message for p in problems if p.severity == "warning"]


# --------------------------------------------------------------------------- #
# validation
# --------------------------------------------------------------------------- #


def test_a_complete_submission_has_no_errors():
    answers = [{"task_id": i, "verdict": "ABSTAIN"} for i in IDS]
    assert _errors(validate_submission(TASKS, answers)) == []
    assert _warnings(validate_submission(TASKS, answers)) == []


def test_unknown_task_id_is_an_error_not_a_silent_zero():
    problems = validate_submission(TASKS, [{"task_id": "no-such-task", "verdict": "SOUND"}])
    assert any("unknown task id" in m for m in _errors(problems))
    assert any("earns nothing" in m for m in _errors(problems))


def test_duplicate_task_ids_are_reported():
    answers = [
        {"task_id": IDS[0], "verdict": "SOUND"},
        {"task_id": IDS[0], "verdict": "UNSOUND"},
    ]
    problems = validate_submission(TASKS, answers)
    assert any("duplicate answers" in m for m in _errors(problems))


def test_missing_answers_are_a_warning_that_explains_the_consequence():
    problems = validate_submission(TASKS, [{"task_id": IDS[0], "verdict": "ABSTAIN"}])
    warned = _warnings(problems)
    assert any("scored as abstentions" in m for m in warned)
    assert any("never fails the gate" in m for m in warned)


def test_bad_verdict_is_an_error():
    problems = validate_submission(TASKS, [{"task_id": IDS[0], "verdict": "PROBABLY"}])
    assert any("verdict must be one of" in m for m in _errors(problems))


def test_missing_task_id_is_an_error():
    problems = validate_submission(TASKS, [{"verdict": "SOUND"}])
    assert any("no 'task_id'" in m for m in _errors(problems))


def test_non_object_entry_is_an_error():
    problems = validate_submission(TASKS, ["not-an-object", 42, None])
    assert len(_errors(problems)) >= 3


def test_negative_over_acceptance_is_an_error():
    problems = validate_submission(
        TASKS, [{"task_id": IDS[0], "verdict": "UNSOUND", "over_acceptance": -1}]
    )
    assert any("must be >= 0" in m for m in _errors(problems))


def test_lowercase_verdicts_are_accepted():
    """A tool writing 'sound' should not be failed on presentation."""
    problems = validate_submission(TASKS, [{"task_id": IDS[0], "verdict": "sound"}])
    assert _errors(problems) == []


# --------------------------------------------------------------------------- #
# the metric is not gameable by omission
# --------------------------------------------------------------------------- #


def test_omitting_hard_tasks_cannot_raise_the_score():
    """Answering one task correctly must not beat answering all of them."""
    one = score_submission(TASKS, [{"task_id": IDS[0], "verdict": "ABSTAIN"}], tool="lazy")
    assert one.n_tasks == len(TASKS)  # denominator is the whole suite, not the submission
    assert one.decisiveness == 0.0


def test_unknown_ids_do_not_inflate_anything():
    padded = [{"task_id": f"fake-{i}", "verdict": "SOUND"} for i in range(100)]
    score = score_submission(TASKS, padded, tool="padder")
    assert score.n_answered == 0
    assert score.decisiveness == 0.0


# --------------------------------------------------------------------------- #
# the CLI
# --------------------------------------------------------------------------- #


def _write(tmp_path, obj):
    p = tmp_path / "answers.json"
    p.write_text(json.dumps(obj), encoding="utf-8")
    return str(p)


def test_cli_submit_refuses_a_broken_file_and_scores_nothing(tmp_path, capsys):
    path = _write(tmp_path, [{"task_id": "nope", "verdict": "SOUND"}])
    code = cli_main(["submit", "--answers", path, "--tool", "t"])
    assert code == 2
    err = capsys.readouterr().err
    assert "unknown task id" in err
    assert "Nothing was scored" in err


def test_cli_submit_prints_a_leaderboard_row(tmp_path, capsys):
    path = _write(tmp_path, [{"task_id": i, "verdict": "ABSTAIN"} for i in IDS])
    code = cli_main(["submit", "--answers", path, "--tool", "mytool"])
    assert code == 0
    out = capsys.readouterr().out
    assert "as it would appear on the leaderboard" in out
    assert "mytool" in out
    assert "PASS" in out


def test_cli_submit_fails_the_gate_on_a_false_certification(tmp_path, capsys):
    """Certifying an unsound guard must exit non-zero and say so."""
    answers = []
    for t in TASKS:
        answers.append({"task_id": t.task_id, "verdict": "SOUND"})
    path = _write(tmp_path, answers)
    code = cli_main(["submit", "--answers", path, "--tool", "always-sound"])
    assert code == 1
    out = capsys.readouterr().out
    assert "FAIL" in out
    assert "gate FAILED" in out


def test_cli_submit_json_mode(tmp_path, capsys):
    path = _write(tmp_path, [{"task_id": i, "verdict": "ABSTAIN"} for i in IDS])
    assert cli_main(["submit", "--answers", path, "--tool", "t", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["tool"] == "t"
    assert payload["is_sound"] is True


def test_cli_submit_reports_unreadable_file(tmp_path, capsys):
    assert cli_main(["submit", "--answers", str(tmp_path / "nope.json"), "--tool", "t"]) == 2
    assert "error:" in capsys.readouterr().err


@pytest.mark.parametrize("junk", ['{"not": "a list"}', "[1, 2, 3]", "null"])
def test_cli_submit_handles_structurally_wrong_files(tmp_path, junk, capsys):
    p = tmp_path / "a.json"
    p.write_text(junk, encoding="utf-8")
    assert cli_main(["submit", "--answers", str(p), "--tool", "t"]) == 2
