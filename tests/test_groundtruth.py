"""Ground-truth cache integrity (stress-test item S4).

The suite's answers are precomputed and committed so the CLI does not spend 2.8
seconds brute-forcing them on every invocation. The danger that buys is a stale
file: relations change, the committed answer does not, and the benchmark grades
against a number nobody checked.

Two properties make that safe, and both are tested here:

1. Entries are keyed by a **content hash of the task's relations**, so editing a
   task changes its key, misses the cache, and recomputes. A stale entry is
   unreachable rather than merely detectable.
2. `verify-ground-truth` recomputes everything and compares, so a hand-edited or
   truncated file is caught in CI.

The overarching property: the file is a cache. Deleting it changes speed, never
answers.
"""

from __future__ import annotations

import json

import pytest

from soundnessbench.cli import main as cli_main
from soundnessbench.groundtruth import (
    GROUND_TRUTH_PATH,
    SCHEMA,
    build_ground_truth,
    load_ground_truth,
    task_key,
)
from soundnessbench.tasks import brute_force_over_acceptance, generate_suite

TASKS = generate_suite()


# --------------------------------------------------------------------------- #
# the file agrees with a fresh enumeration
# --------------------------------------------------------------------------- #


def test_every_committed_answer_matches_a_fresh_enumeration():
    """The load-bearing test. If this fails, the benchmark is grading on fiction."""
    committed = json.loads(GROUND_TRUTH_PATH.read_text(encoding="utf-8"))["entries"]
    for t in TASKS:
        count, _ = brute_force_over_acceptance(t.domain, t.guard, t.safety, t.box)
        key = task_key(t.domain, t.guard, t.safety, t.box)
        assert key in committed, f"{t.task_id} has no committed answer"
        assert committed[key]["over_acceptance"] == count, t.task_id


def test_committed_file_covers_every_task_and_nothing_else():
    """One file serves both splits -- entries are keyed by a hash of the
    relations, not by split -- so the comparison is against their union. The
    'nothing else' half is the important one: a leftover entry is an answer to a
    question nobody asks any more."""
    from soundnessbench.hard import generate_hard_suite

    committed = json.loads(GROUND_TRUTH_PATH.read_text(encoding="utf-8"))["entries"]
    every = list(TASKS) + generate_hard_suite()
    keys = {task_key(t.domain, t.guard, t.safety, t.box) for t in every}
    assert set(committed) == keys


def test_cli_verify_ground_truth_passes():
    assert cli_main(["verify-ground-truth"]) == 0


# --------------------------------------------------------------------------- #
# the cache cannot serve a stale answer
# --------------------------------------------------------------------------- #


def test_editing_a_relation_changes_the_key():
    """This is what makes staleness impossible rather than merely detectable."""
    t = TASKS[0]
    original = task_key(t.domain, t.guard, t.safety, t.box)
    bumped_guard = [dict(a) for a in t.guard]
    bumped_guard[0] = dict(bumped_guard[0], const=bumped_guard[0]["const"] + 1)
    assert task_key(t.domain, bumped_guard, t.safety, t.box) != original
    widened = dict(t.box)
    k = next(iter(widened))
    widened[k] = [widened[k][0], widened[k][1] + 1]
    assert task_key(t.domain, t.guard, t.safety, widened) != original


def test_key_ignores_labels_but_not_content():
    """Family and note are labels; they must not affect the answer's identity."""
    t = TASKS[0]
    a = task_key(t.domain, t.guard, t.safety, t.box)
    b = task_key(list(t.domain), list(t.guard), list(t.safety), dict(t.box))
    assert a == b


# --------------------------------------------------------------------------- #
# a broken file degrades to slow, never to wrong
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "content",
    [
        "",  # empty
        "not json",
        "{}",  # no schema
        '{"schema": "wrong/v1", "entries": {}}',
        '{"schema": "soundnessbench/groundtruth/v1"}',  # no entries
        '{"schema": "soundnessbench/groundtruth/v1", "entries": "nope"}',
        '{"schema": "soundnessbench/groundtruth/v1", "entries": {"k": "not-a-dict"}}',
    ],
)
def test_a_broken_file_is_ignored_not_trusted(tmp_path, content):
    p = tmp_path / "gt.json"
    p.write_text(content, encoding="utf-8")
    assert load_ground_truth(p) == {}


def test_a_missing_file_is_ignored(tmp_path):
    assert load_ground_truth(tmp_path / "absent.json") == {}


def test_entries_with_non_integer_counts_are_dropped(tmp_path):
    p = tmp_path / "gt.json"
    p.write_text(
        json.dumps(
            {
                "schema": SCHEMA,
                "entries": {
                    "good": {"over_acceptance": 3},
                    "bad": {"over_acceptance": "many"},
                    "worse": {"over_acceptance": None},
                },
            }
        ),
        encoding="utf-8",
    )
    loaded = load_ground_truth(p)
    assert set(loaded) == {"good"}


def test_corrupted_counts_are_caught_by_the_verifier(tmp_path, monkeypatch, capsys):
    """A tampered answer must fail loudly, never silently grade against it."""
    doc = build_ground_truth(TASKS)
    key = next(iter(doc["entries"]))
    doc["entries"][key]["over_acceptance"] += 1  # one wrong number
    p = tmp_path / "gt.json"
    p.write_text(json.dumps(doc), encoding="utf-8")

    import soundnessbench.cli as cli_mod

    monkeypatch.setattr(cli_mod, "GROUND_TRUTH_PATH", p)
    assert cli_main(["verify-ground-truth"]) == 1
    err = capsys.readouterr().err
    assert "MISMATCH" in err
    assert "but enumeration says" in err


def test_a_stale_extra_entry_is_reported(tmp_path, monkeypatch, capsys):
    doc = build_ground_truth(TASKS)
    doc["entries"]["deadbeef" * 8] = {"task_id": "ghost", "over_acceptance": 0, "witness": None}
    p = tmp_path / "gt.json"
    p.write_text(json.dumps(doc), encoding="utf-8")

    import soundnessbench.cli as cli_mod

    monkeypatch.setattr(cli_mod, "GROUND_TRUTH_PATH", p)
    assert cli_main(["verify-ground-truth"]) == 1
    assert "stale entry" in capsys.readouterr().err


def test_unreadable_file_is_a_usage_error_not_a_pass(tmp_path, monkeypatch, capsys):
    import soundnessbench.cli as cli_mod

    monkeypatch.setattr(cli_mod, "GROUND_TRUTH_PATH", tmp_path / "nope.json")
    assert cli_main(["verify-ground-truth"]) == 2
    assert "cannot read" in capsys.readouterr().err


# --------------------------------------------------------------------------- #
# the memoised suite is still a fresh list
# --------------------------------------------------------------------------- #


def test_generate_suite_returns_an_independent_list():
    """Callers must not be able to corrupt the cache by mutating a result."""
    a = generate_suite()
    n = len(a)
    a.pop()
    assert len(generate_suite()) == n


def test_generate_suite_is_deterministic_across_calls():
    a, b = generate_suite(), generate_suite()
    assert [t.to_dict() for t in a] == [t.to_dict() for t in b]
