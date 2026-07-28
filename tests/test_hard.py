"""The hard split, derived from real CVE relations.

The point of this split is to answer the strongest objection to the benchmark:
that seven synthetic families can be tuned for. So the tests here are mostly
about whether the split is *a measurement* -- balanced, exhaustively grounded,
and not beatable by a constant answer -- rather than about whether the code runs.
"""

from __future__ import annotations

import json

import pytest

from soundnessbench.baselines import BASELINES, run_baseline
from soundnessbench.hard import (
    MAX_ENUMERATED_POINTS,
    break_offset,
    generate_hard_suite,
    load_corpus,
    minimal_break,
)
from soundnessbench.scoring import score_submission
from soundnessbench.tasks import brute_force_over_acceptance

TASKS = generate_hard_suite()


def test_the_split_is_not_empty_and_comes_from_the_corpus():
    corpus = load_corpus()
    assert corpus, "the CVE corpus must ship inside the package"
    assert TASKS
    ids = {row["id"] for row in corpus}
    for task in TASKS:
        assert any(task.task_id.startswith(f"hard-{i}") for i in ids), task.task_id


def test_a_constant_answer_cannot_score_well():
    """The failure of the first design: fixed weakenings left almost everything
    sound, so 'always sound' scored 16/21. Both answers must now be wrong often."""
    sound = sum(t.is_sound for t in TASKS)
    unsound = len(TASKS) - sound
    assert sound >= 3 and unsound >= 3, f"{sound} sound / {unsound} unsound is too lopsided"
    assert max(sound, unsound) / len(TASKS) <= 0.75


def test_every_answer_is_reproducible_by_enumeration():
    """The ground truth is a cache, not a claim -- including here."""
    for task in TASKS:
        count, _ = brute_force_over_acceptance(task.domain, task.guard, task.safety, task.box)
        assert count == task.over_acceptance, task.task_id
        assert task.is_sound == (count == 0)


def test_boxes_stay_inside_the_enumeration_budget():
    for task in TASKS:
        assert task.box_volume <= MAX_ENUMERATED_POINTS * 2, task.task_id


def test_a_narrowed_box_says_so_in_the_note():
    """Narrowing changes the question, so it is never done silently."""
    narrowed = [t for t in TASKS if "narrowed" in t.note]
    assert narrowed, "expected at least one task whose box was narrowed"
    for task in narrowed:
        assert "real bound" in task.note


def test_constructed_variants_are_labelled_as_constructed():
    """Responsible-disclosure discipline: the weakenings are synthetic, and the
    task must not read as a statement about any shipped code."""
    for task in TASKS:
        if task.family == "cve-fixed" and task.task_id.endswith("-fixed"):
            assert "unmodified" in task.note
        else:
            assert "not shipped code" in task.note, task.task_id


def test_every_task_carries_its_provenance():
    for task in TASKS:
        assert "relation from CVE-" in task.note, task.task_id


def test_the_fixed_relations_are_all_sound():
    """If a corpus relation were unsound over its own box, either the corpus or
    the box is wrong, and the split would be grading a broken question."""
    for task in TASKS:
        if task.task_id.endswith("-fixed"):
            assert task.is_sound, f"{task.task_id} is not sound as fixed"


def test_the_edge_pairs_really_differ_by_one_step():
    pairs = {}
    for task in TASKS:
        if task.family in ("cve-edge-sound", "cve-edge-unsound"):
            base = task.task_id.rsplit("-edge-", 1)[0]
            pairs.setdefault(base, {})[task.family] = task
    for base, pair in pairs.items():
        if len(pair) == 2:
            assert pair["cve-edge-sound"].is_sound, base
            assert not pair["cve-edge-unsound"].is_sound, base


def test_minimal_break_finds_the_boundary_not_merely_a_break():
    """k must break the guard and k-1 must not; otherwise it is not minimal."""
    corpus = load_corpus()
    row = next(r for r in corpus if r["id"] == "openssl_heartbeat")
    from soundnessbench.hard import _atom_from_corpus, _box_for, _relaxed

    domain = [_atom_from_corpus(a) for a in row["spec"]["domain"]]
    guard = [_atom_from_corpus(a) for a in row["spec"]["guard"]]
    safety = [_atom_from_corpus(a) for a in row["spec"]["safety"]]
    box, _ = _box_for(domain, guard, safety)

    found = break_offset(domain, guard, safety, box)
    assert found is not None
    index, k = found
    assert k >= 1
    broken, _ = brute_force_over_acceptance(domain, _relaxed(guard, index, k), safety, box)
    assert broken > 0, "k must break the guard"
    if k > 1:
        intact, _ = brute_force_over_acceptance(domain, _relaxed(guard, index, k - 1), safety, box)
        assert intact == 0, "k-1 must not break it, or k is not minimal"


def test_minimal_break_returns_none_rather_than_guessing():
    """A guard nothing in the budget breaks reports None, and the suite says that
    is a fact about the box -- not that the guard cannot be broken."""
    domain = [{"coeff": {"x": -1}, "const": 0, "strict": False}]
    guard = [{"coeff": {"x": 1}, "const": -5, "strict": False}]
    safety = [{"coeff": {"x": 0}, "const": -1, "strict": False}]  # always true
    box = {"x": (0, 10)}
    assert minimal_break(domain, guard, safety, box, 0, limit=16) is None

    unbreakable = [t for t in TASKS if t.task_id.endswith("-wide")]
    for task in unbreakable:
        assert "fact about the box" in task.note


def test_the_offsets_cache_is_keyed_by_content_so_it_cannot_go_stale():
    from soundnessbench.hard import OFFSETS_PATH, _offset_key

    doc = json.loads(OFFSETS_PATH.read_text(encoding="utf-8"))
    assert doc["schema"] == "soundnessbench/hard-offsets/v1"
    corpus = load_corpus()
    from soundnessbench.hard import _atom_from_corpus, _box_for

    row = corpus[0]
    domain = [_atom_from_corpus(a) for a in row["spec"]["domain"]]
    guard = [_atom_from_corpus(a) for a in row["spec"]["guard"]]
    safety = [_atom_from_corpus(a) for a in row["spec"]["safety"]]
    box, _ = _box_for(domain, guard, safety)
    key = _offset_key(domain, guard, safety, box, 0)
    assert key in doc["entries"]

    # Edit one relation: the key must change, so the edited task misses the cache.
    edited = [dict(guard[0], const=guard[0]["const"] - 3), *guard[1:]]
    assert _offset_key(domain, edited, safety, box, 0) != key


@pytest.mark.parametrize("name", sorted(BASELINES))
def test_every_baseline_runs_on_the_hard_split(name):
    answers = run_baseline(name, TASKS)
    assert len(answers) == len(TASKS)
    score = score_submission(TASKS, answers, tool=name)
    assert score.n_tasks == len(TASKS)


def test_the_split_separates_sampling_from_proving():
    """The reason the benchmark exists. A sampler must not gate-pass here."""
    sampler = score_submission(TASKS, run_baseline("sampler-1k", TASKS), tool="sampler-1k")
    exact = score_submission(TASKS, run_baseline("certkit-stack", TASKS), tool="certkit-stack")
    assert not sampler.is_sound, "a 1k sampler should miss at least one needle"
    assert exact.is_sound, "an exact tool should pass the gate"


def test_an_empty_corpus_yields_an_empty_split_rather_than_invented_tasks():
    assert generate_hard_suite(corpus=[]) == []
