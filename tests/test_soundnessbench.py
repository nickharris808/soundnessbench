"""Benchmark tests.

Two things must be true for this benchmark to mean anything, and both are tested
here rather than asserted in the README:

1. The ground truth is right. Checked by re-deriving it a second way.
2. The metric is not gameable. Checked by running degenerate strategies and
   confirming they lose.
"""

import itertools
import json

import pytest

from soundnessbench import (
    SOUND,
    UNSOUND,
    brute_force_over_acceptance,
    generate_suite,
    run_baseline,
    score_submission,
)
from soundnessbench.tasks import satisfies


@pytest.fixture(scope="module")
def tasks():
    return generate_suite()


# --------------------------------------------------------------------------- #
# suite shape
# --------------------------------------------------------------------------- #


def test_suite_is_deterministic():
    a = [t.to_dict() for t in generate_suite()]
    b = [t.to_dict() for t in generate_suite()]
    assert a == b


def test_suite_has_both_answers_represented(tasks):
    """A suite that is all-sound or all-unsound is trivially gameable."""
    sound = sum(1 for t in tasks if t.is_sound)
    unsound = len(tasks) - sound
    assert sound >= 10 and unsound >= 10
    # Neither class may dominate: guessing the majority must not be a strategy.
    assert 0.3 < sound / len(tasks) < 0.7


def test_task_ids_are_unique(tasks):
    ids = [t.task_id for t in tasks]
    assert len(ids) == len(set(ids))


def test_every_family_is_present(tasks):
    from soundnessbench.tasks import FAMILIES

    present = {t.family for t in tasks}
    assert present == set(FAMILIES)


def test_public_tasks_carry_no_answers(tasks):
    """A leaked answer key makes the benchmark worthless."""
    for t in tasks:
        pub = t.public_dict()
        assert "over_acceptance" not in pub
        assert "is_sound" not in pub
        assert "witness" not in pub
        # And the answer must not be recoverable from the serialised form.
        assert "is_sound" not in json.dumps(pub)


# --------------------------------------------------------------------------- #
# ground truth correctness
# --------------------------------------------------------------------------- #


def test_ground_truth_matches_an_independent_enumeration(tasks):
    """Re-derive every answer a second, differently-written way."""
    for t in tasks:
        names = sorted(t.box)
        ranges = [range(t.box[n][0], t.box[n][1] + 1) for n in names]
        count = 0
        for point in itertools.product(*ranges):
            assign = dict(zip(names, point))
            ok_dom = all(satisfies(a, assign) for a in t.domain)
            ok_guard = all(satisfies(a, assign) for a in t.guard)
            ok_safe = all(satisfies(a, assign) for a in t.safety)
            if ok_dom and ok_guard and not ok_safe:
                count += 1
        assert count == t.over_acceptance, t.task_id
        assert (count == 0) == t.is_sound, t.task_id


def test_witness_really_violates(tasks):
    """A witness that does not actually break the property is a bug."""
    for t in tasks:
        if t.is_sound:
            assert t.witness is None, t.task_id
            continue
        w = t.witness
        assert w is not None, t.task_id
        assert all(satisfies(a, w) for a in t.domain), t.task_id
        assert all(satisfies(a, w) for a in t.guard), t.task_id
        assert not all(satisfies(a, w) for a in t.safety), t.task_id


def test_needle_gaps_really_are_rare(tasks):
    """The needle family must be rare enough that sampling genuinely fails."""
    needles = [t for t in tasks if t.family == "needle"]
    assert needles
    for t in needles:
        assert not t.is_sound
        rate = t.over_acceptance / t.box_volume
        assert rate < 1e-4, f"{t.task_id} gap is not rare ({rate:.2e})"


def test_brute_force_helper_agrees_with_stored_answers(tasks):
    for t in tasks[:8]:
        count, _ = brute_force_over_acceptance(
            t.domain, t.guard, t.safety, {k: tuple(v) for k, v in t.box.items()}
        )
        assert count == t.over_acceptance


# --------------------------------------------------------------------------- #
# the metric is not gameable
# --------------------------------------------------------------------------- #


def test_always_sound_fails_the_gate(tasks):
    """The headline test. Answering SOUND to everything must not pass."""
    answers = run_baseline("always-sound", tasks)
    score = score_submission(tasks, answers, tool="always-sound")
    assert not score.is_sound
    assert score.false_certifications > 0
    # It has perfect decisiveness and non-trivial accuracy, and still loses.
    assert score.decisiveness == 1.0
    assert score.coverage > 0.4


def test_always_abstain_passes_the_gate_but_is_useless(tasks):
    """Abstaining is honest, so it must not fail the gate -- and must not win."""
    answers = run_baseline("always-abstain", tasks)
    score = score_submission(tasks, answers, tool="always-abstain")
    assert score.is_sound
    assert score.decisiveness == 0.0
    assert score.coverage is None


def test_sampler_false_certifies_the_rare_gaps(tasks):
    """The benchmark's reason to exist: testing misses needles.

    If this ever stops being true the needle family has become too easy and the
    benchmark no longer distinguishes testing from proving.
    """
    answers = run_baseline("sampler-1k", tasks)
    score = score_submission(tasks, answers, tool="sampler-1k")
    assert not score.is_sound, "sampling should miss at least one rare gap"
    missed = set(score.false_certification_ids)
    assert any(tid.startswith("needle-") for tid in missed)


def test_exhaustive_baseline_is_perfect(tasks):
    answers = run_baseline("exhaustive", tasks)
    score = score_submission(tasks, answers, tool="exhaustive")
    assert score.is_sound
    assert score.coverage == 1.0
    assert score.count_accuracy == 1.0


def test_omitted_answers_score_as_abstention_not_as_credit(tasks):
    """Dropping the hard tasks must not improve coverage."""
    answers = [
        {"task_id": t.task_id, "verdict": SOUND if t.is_sound else UNSOUND}
        for t in tasks
        if t.is_sound
    ]
    score = score_submission(tasks, answers, tool="cherry-picker")
    assert score.n_missing == sum(1 for t in tasks if not t.is_sound)
    assert score.decisiveness < 1.0
    assert score.is_sound  # it never certified anything false...
    # ...but it is transparently incomplete, which the decisiveness column shows.


# --------------------------------------------------------------------------- #
# scoring mechanics
# --------------------------------------------------------------------------- #


def test_wrong_count_does_not_affect_the_verdict(tasks):
    t = next(t for t in tasks if not t.is_sound)
    answers = [{"task_id": t.task_id, "verdict": UNSOUND, "over_acceptance": 999999}]
    score = score_submission([t], answers)
    assert score.correct == 1
    assert score.counts_offered == 1
    assert score.counts_correct == 0


def test_invalid_verdict_is_rejected(tasks):
    with pytest.raises(ValueError):
        score_submission(tasks, [{"task_id": tasks[0].task_id, "verdict": "MAYBE"}])


def test_negative_count_is_rejected(tasks):
    with pytest.raises(ValueError):
        score_submission(
            tasks, [{"task_id": tasks[0].task_id, "verdict": UNSOUND, "over_acceptance": -1}]
        )


def test_per_family_breakdown_sums_to_the_total(tasks):
    answers = run_baseline("exhaustive", tasks)
    score = score_submission(tasks, answers)
    assert sum(f["n"] for f in score.per_family.values()) == len(tasks)
    assert sum(f["correct"] for f in score.per_family.values()) == score.correct


def test_summary_renders(tasks):
    answers = run_baseline("always-sound", tasks)
    text = score_submission(tasks, answers, tool="always-sound").summary()
    assert "UNSOUND" in text
    assert "false certification" in text


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def test_cli_leaderboard_runs(capsys):
    from soundnessbench.cli import main

    assert main(["leaderboard"]) == 0
    out = capsys.readouterr().out
    assert "always-sound" in out
    assert "FAIL" in out


def test_cli_tasks_export_strips_answers(capsys):
    from soundnessbench.cli import main

    assert main(["tasks"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload and all("is_sound" not in t for t in payload)


def test_cli_score_exit_code_reflects_the_gate(tmp_path, capsys):
    from soundnessbench.cli import main

    ts = generate_suite()
    good = tmp_path / "good.json"
    good.write_text(json.dumps(run_baseline("exhaustive", ts)))
    assert main(["score", "--answers", str(good)]) == 0

    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(run_baseline("always-sound", ts)))
    assert main(["score", "--answers", str(bad)]) == 1


def test_cli_rejects_malformed_submission(tmp_path):
    from soundnessbench.cli import main

    f = tmp_path / "bad.json"
    f.write_text(json.dumps({"not": "a list"}))
    assert main(["score", "--answers", str(f)]) == 2


def test_sampler_baseline_is_reproducible_across_processes(tasks):
    """The sampler must not depend on Python's per-process string hashing.

    Seeding with hash() would make published scores vary between runs, which
    would quietly destroy the benchmark's reproducibility claim.
    """
    import subprocess
    import sys

    code = (
        "from soundnessbench import generate_suite, run_baseline, score_submission;"
        "t=generate_suite();"
        "s=score_submission(t, run_baseline('sampler-1k', t));"
        "print(s.false_certifications)"
    )
    # Inherit the real environment and override only the hash seed. A hand-built
    # env broke on Windows: stripping SystemRoot leaves Python unable to
    # initialise hash randomisation at all.
    import os

    env = dict(os.environ)
    env["PYTHONHASHSEED"] = "random"

    runs = set()
    for _ in range(3):
        out = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            check=True,
            env=env,
        )
        runs.add(out.stdout.strip())
    assert len(runs) == 1, f"sampler score varies across processes: {runs}"
