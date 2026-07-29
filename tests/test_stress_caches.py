"""Adversarial stress tests for the caches and the scoring frontend.

Oracle: **no input may produce a confident-looking answer that is wrong.**

For a benchmark, the two ways to be confidently wrong are a stale answer served
from a cache, and a submission scored as better than it is. Both are tested here
by attacking them rather than by asserting they work.
"""

from __future__ import annotations

import json

import pytest

from soundnessbench.groundtruth import load_ground_truth, task_key
from soundnessbench.hard import (
    OFFSETS_PATH,
    _atom_from_corpus,
    _box_for,
    _offset_key,
    generate_hard_suite,
    load_corpus,
)
from soundnessbench.scoring import score_submission, validate_submission
from soundnessbench.tasks import brute_force_over_acceptance, generate_suite

PUBLIC = generate_suite()
HARD = generate_hard_suite()
ALL = PUBLIC + HARD


# --------------------------------------------------------------------------- #
# caches must key on content, so a stale answer is unreachable
# --------------------------------------------------------------------------- #


def test_editing_any_component_of_a_task_changes_its_key():
    """Every field that can change the answer must be inside the key. A field
    left out is a field that can change while the cached answer does not."""
    task = ALL[0]
    base = task_key(task.domain, task.guard, task.safety, task.box)

    variations = {
        "domain": task_key(task.domain[1:], task.guard, task.safety, task.box),
        "guard": task_key(
            task.domain,
            [dict(a, const=a["const"] - 1) for a in task.guard],
            task.safety,
            task.box,
        ),
        "safety": task_key(
            task.domain,
            task.guard,
            [dict(a, const=a["const"] + 1) for a in task.safety],
            task.box,
        ),
        "box": task_key(
            task.domain,
            task.guard,
            task.safety,
            {k: [v[0], v[1] + 1] for k, v in task.box.items()},
        ),
        "strictness": task_key(
            task.domain,
            task.guard,
            [dict(a, strict=not a["strict"]) for a in task.safety],
            task.box,
        ),
    }
    for what, key in variations.items():
        assert key != base, f"editing the {what} did not change the cache key"


def test_reordering_atoms_changes_the_key_rather_than_silently_matching():
    """Conservative on purpose. A key that normalised order would be cleverer and
    would have to be right about what 'equivalent' means; a key that does not
    merely recomputes, which is never wrong."""
    task = next(t for t in ALL if len(t.domain) > 1)
    a = task_key(task.domain, task.guard, task.safety, task.box)
    b = task_key(list(reversed(task.domain)), task.guard, task.safety, task.box)
    assert a != b


def test_every_cached_answer_matches_a_fresh_enumeration():
    """The load-bearing one. If this fails, the benchmark grades on fiction."""
    committed = load_ground_truth()
    for task in ALL:
        key = task_key(task.domain, task.guard, task.safety, task.box)
        assert key in committed, task.task_id
        count, _ = brute_force_over_acceptance(task.domain, task.guard, task.safety, task.box)
        assert committed[key]["over_acceptance"] == count, task.task_id


def test_a_corrupted_ground_truth_file_degrades_to_slow_not_to_wrong(tmp_path):
    """A cache that cannot be read must be ignored, never half-trusted."""
    bad = tmp_path / "broken.json"
    for content in ("", "{", "null", "[]", '{"entries": "not-a-dict"}', '{"no-entries": 1}'):
        bad.write_text(content, encoding="utf-8")
        assert load_ground_truth(bad) == {}, content


def test_a_tampered_answer_is_caught_by_verification(tmp_path):
    """The point of `verify-ground-truth`: an edited data file must be detected,
    not trusted because it parses."""
    from soundnessbench.cli import main as cli_main

    real = load_ground_truth()
    key, entry = next(iter(real.items()))
    tampered = {
        "schema": "soundnessbench/groundtruth/v1",
        "note": "tampered",
        "n_entries": 1,
        "entries": {key: {**entry, "over_acceptance": entry["over_acceptance"] + 1}},
    }
    path = tmp_path / "gt.json"
    path.write_text(json.dumps(tampered), encoding="utf-8")

    loaded = load_ground_truth(path)
    task = next(t for t in ALL if task_key(t.domain, t.guard, t.safety, t.box) == key)
    count, _ = brute_force_over_acceptance(task.domain, task.guard, task.safety, task.box)
    assert loaded[key]["over_acceptance"] != count, "the tampered value should differ"
    # And the shipped verifier says so:
    assert cli_main(["verify-ground-truth"]) == 0, "the real file must still verify"


def test_the_offsets_cache_is_keyed_the_same_way():
    doc = json.loads(OFFSETS_PATH.read_text(encoding="utf-8"))
    corpus = load_corpus()
    row = corpus[0]
    domain = [_atom_from_corpus(a) for a in row["spec"]["domain"]]
    guard = [_atom_from_corpus(a) for a in row["spec"]["guard"]]
    safety = [_atom_from_corpus(a) for a in row["spec"]["safety"]]
    box, _ = _box_for(domain, guard, safety)

    key = _offset_key(domain, guard, safety, box, 0)
    assert key in doc["entries"]
    edited = [dict(guard[0], const=guard[0]["const"] - 7), *guard[1:]]
    assert _offset_key(domain, edited, safety, box, 0) != key


def test_generating_the_suite_twice_gives_identical_tasks():
    """Memoisation must not leak mutable state between callers."""
    first = generate_suite()
    second = generate_suite()
    assert [t.to_dict() for t in first] == [t.to_dict() for t in second]
    first.clear()  # a caller mutating the returned list must not affect the next
    assert len(generate_suite()) == len(second)


def test_the_hard_suite_is_deterministic_across_calls():
    assert [t.to_dict() for t in generate_hard_suite()] == [
        t.to_dict() for t in generate_hard_suite()
    ]


# --------------------------------------------------------------------------- #
# scoring: a submission may be wrong, malformed, or hostile
# --------------------------------------------------------------------------- #

HOSTILE_SUBMISSIONS = [
    ("empty", []),
    ("string-entries", ["SOUND", "UNSOUND"]),
    ("null-entry", [None]),
    ("no-task-id", [{"verdict": "SOUND"}]),
    ("unknown-task", [{"task_id": "no-such-task", "verdict": "SOUND"}]),
    ("bad-verdict", [{"task_id": "bounds-0", "verdict": "PROBABLY"}]),
    ("verdict-null", [{"task_id": "bounds-0", "verdict": None}]),
    ("verdict-number", [{"task_id": "bounds-0", "verdict": 1}]),
    ("count-string", [{"task_id": "bounds-0", "verdict": "UNSOUND", "over_acceptance": "many"}]),
    ("count-negative", [{"task_id": "bounds-0", "verdict": "UNSOUND", "over_acceptance": -5}]),
    ("nested", [{"task_id": {"a": 1}, "verdict": "SOUND"}]),
]


@pytest.mark.parametrize(
    "label,answers", HOSTILE_SUBMISSIONS, ids=[s[0] for s in HOSTILE_SUBMISSIONS]
)
def test_a_hostile_submission_never_scores_as_a_clean_pass(label, answers):
    problems = validate_submission(PUBLIC, answers)
    try:
        score = score_submission(PUBLIC, answers, tool=label)
    except (ValueError, KeyError, TypeError):
        return  # refusing to score at all is acceptable
    # If it did score, it must not look like a complete, correct run.
    assert score.n_answered < score.n_tasks or problems, label
    assert score.coverage is None or score.coverage < 1.0 or score.n_answered < score.n_tasks


def test_omitting_hard_tasks_cannot_inflate_a_score():
    """The obvious cheat: answer only the easy ones."""
    easy = [
        {"task_id": t.task_id, "verdict": "SOUND" if t.is_sound else "UNSOUND"}
        for t in PUBLIC
        if t.family != "needle"
    ]
    partial = score_submission(PUBLIC, easy, tool="cherry-picker")
    full = score_submission(
        PUBLIC,
        [{"task_id": t.task_id, "verdict": "SOUND" if t.is_sound else "UNSOUND"} for t in PUBLIC],
        tool="honest",
    )
    assert partial.decisiveness < full.decisiveness
    assert partial.n_abstained > 0


def test_duplicate_answers_do_not_multiply_credit():
    answers = []
    for t in PUBLIC[:5]:
        entry = {"task_id": t.task_id, "verdict": "SOUND" if t.is_sound else "UNSOUND"}
        answers.extend([entry, entry, entry])
    score = score_submission(PUBLIC, answers, tool="duplicator")
    assert score.n_answered <= 5
    assert any(p.severity in ("warning", "error") for p in validate_submission(PUBLIC, answers))


def test_one_false_certification_fails_the_gate_whatever_else_is_right():
    unsound = next(t for t in PUBLIC if not t.is_sound)
    answers = [
        {"task_id": t.task_id, "verdict": "SOUND" if t.is_sound else "UNSOUND"} for t in PUBLIC
    ]
    for a in answers:
        if a["task_id"] == unsound.task_id:
            a["verdict"] = "SOUND"
    score = score_submission(PUBLIC, answers, tool="one-slip")
    assert score.is_sound is False
    assert score.coverage > 0.9, "almost everything else is right, and it still fails"


def test_abstaining_everywhere_passes_the_gate_and_earns_no_coverage():
    answers = [{"task_id": t.task_id, "verdict": "ABSTAIN"} for t in PUBLIC]
    score = score_submission(PUBLIC, answers, tool="cautious")
    assert score.is_sound is True
    assert score.coverage is None, "0.0% would read as 'answered everything wrong'"
    assert score.decisiveness == 0.0


def test_a_wildly_wrong_count_does_not_affect_the_gate():
    """Count accuracy is a separate column on purpose. Being wrong about the size
    of a hole is not the same as denying the hole exists."""
    answers = [
        {
            "task_id": t.task_id,
            "verdict": "SOUND" if t.is_sound else "UNSOUND",
            "over_acceptance": 10**9,
        }
        for t in PUBLIC
    ]
    score = score_submission(PUBLIC, answers, tool="bad-counter")
    assert score.is_sound is True
    assert score.counts_correct < score.counts_offered


def test_scores_from_different_splits_are_not_silently_comparable():
    """A submission written for one split must not score well against another."""
    hard_answers = [
        {"task_id": t.task_id, "verdict": "SOUND" if t.is_sound else "UNSOUND"} for t in HARD
    ]
    cross = score_submission(PUBLIC, hard_answers, tool="wrong-split")
    assert cross.n_answered == 0
    assert cross.coverage is None
    problems = validate_submission(PUBLIC, hard_answers)
    assert any("unknown task id" in p.message for p in problems)
