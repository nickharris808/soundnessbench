"""Scoring.

The design problem with any "is this guard safe?" benchmark is that plain
accuracy rewards the wrong behaviour. Roughly half these tasks are sound, so a
tool that answers SOUND unconditionally scores ~50% and looks like it is doing
something. Worse, in security the two error directions are not equally bad:

    false certification -- saying SOUND when the guard is UNSOUND.
        This is the one that ships a vulnerability. It is unbounded harm.

    false alarm -- saying UNSOUND when the guard is SOUND.
        Wastes an engineer's afternoon. Bounded harm.

    abstention -- saying "I cannot decide".
        Honest and useful, provided it is not the answer to everything.

So the headline number is **not** accuracy. It is:

    SOUNDNESS  -- false-certification count. Must be zero. A tool with any
                  false certification is reported as UNSOUND regardless of how
                  well it scores elsewhere, and no other number can redeem it.

    COVERAGE   -- of the tasks it did not abstain on, how many did it get right.

    DECISIVENESS -- what fraction it was willing to answer at all.

Reporting all three is what stops the metric being gameable. Answer everything
and you risk a false certification. Abstain on everything and coverage is
undefined while decisiveness is zero. Neither degenerate strategy wins.

Exact-count accuracy is scored separately and only over the tasks where a tool
volunteered a count, because a tool that correctly says UNSOUND without
quantifying is still useful.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, field
from typing import Any

__all__ = [
    "Answer",
    "Score",
    "score_submission",
    "validate_submission",
    "SubmissionProblem",
    "SOUND",
    "UNSOUND",
    "ABSTAIN",
]

SOUND = "SOUND"
UNSOUND = "UNSOUND"
ABSTAIN = "ABSTAIN"

VALID_VERDICTS = (SOUND, UNSOUND, ABSTAIN)


@dataclass
class Answer:
    """One tool's answer to one task."""

    task_id: str
    verdict: str
    over_acceptance: int | None = None

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> Answer:
        verdict = str(d.get("verdict", "")).upper()
        if verdict not in VALID_VERDICTS:
            raise ValueError(
                f"task {d.get('task_id')!r}: verdict must be one of "
                f"{VALID_VERDICTS}, got {d.get('verdict')!r}"
            )
        count = d.get("over_acceptance")
        if count is not None:
            count = int(count)
            if count < 0:
                raise ValueError(f"task {d.get('task_id')!r}: over_acceptance must be >= 0")
        return cls(task_id=str(d["task_id"]), verdict=verdict, over_acceptance=count)


@dataclass
class Score:
    tool: str
    n_tasks: int
    n_answered: int
    n_abstained: int
    n_missing: int

    false_certifications: int
    false_alarms: int
    correct: int

    counts_offered: int
    counts_correct: int

    per_family: dict[str, dict[str, int]] = field(default_factory=dict)
    false_certification_ids: list[str] = field(default_factory=list)

    @property
    def is_sound(self) -> bool:
        """The gate. One false certification and the tool is unsound, full stop."""
        return self.false_certifications == 0

    @property
    def coverage(self) -> float | None:
        """Accuracy over answered tasks. ``None`` when the tool answered nothing."""
        if self.n_answered == 0:
            return None
        return self.correct / self.n_answered

    @property
    def decisiveness(self) -> float:
        if self.n_tasks == 0:
            return 0.0
        return self.n_answered / self.n_tasks

    @property
    def count_accuracy(self) -> float | None:
        if self.counts_offered == 0:
            return None
        return self.counts_correct / self.counts_offered

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d.update(
            is_sound=self.is_sound,
            coverage=self.coverage,
            decisiveness=self.decisiveness,
            count_accuracy=self.count_accuracy,
        )
        return d

    def summary(self) -> str:
        gate = "SOUND" if self.is_sound else "UNSOUND"
        cov = "n/a" if self.coverage is None else f"{self.coverage:6.1%}"
        cnt = "n/a" if self.count_accuracy is None else f"{self.count_accuracy:6.1%}"
        lines = [
            f"{self.tool}",
            f"  soundness gate    : {gate}"
            + ("" if self.is_sound else f"  ({self.false_certifications} false certification(s))"),
            f"  coverage          : {cov}   ({self.correct}/{self.n_answered} answered correctly)",
            f"  decisiveness      : {self.decisiveness:6.1%}   ({self.n_answered}/{self.n_tasks} answered)",
            f"  exact-count acc.  : {cnt}   ({self.counts_correct}/{self.counts_offered} counts offered)",
            f"  false alarms      : {self.false_alarms}",
        ]
        if self.n_missing:
            lines.append(f"  missing answers   : {self.n_missing} (scored as abstention)")
        if self.false_certification_ids:
            shown = ", ".join(self.false_certification_ids[:5])
            more = "" if len(self.false_certification_ids) <= 5 else " ..."
            lines.append(f"  FALSE CERTIFIED   : {shown}{more}")
        return "\n".join(lines)


@dataclass
class SubmissionProblem:
    """Something wrong with a submission file, and what to do about it."""

    severity: str  # "error" (will not be scored) or "warning" (scored, but read this)
    message: str

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"{self.severity}: {self.message}"


def validate_submission(
    tasks: Sequence[Any],
    answers: Sequence[Mapping[str, Any]],
) -> list[SubmissionProblem]:
    """Report everything wrong with a submission before it is scored.

    Scoring is deliberately forgiving -- an unknown or missing task is treated as
    an abstention so that omitting hard tasks cannot inflate a score. But
    forgiving silently is its own trap: a submitter who typos a task id sees a
    low score with no indication why, and concludes the benchmark is broken.

    So this says out loud what scoring will quietly do. Nothing here changes a
    verdict; it explains one.
    """
    problems: list[SubmissionProblem] = []
    known = {t.task_id for t in tasks}

    if not isinstance(answers, Sequence) or isinstance(answers, (str, bytes)):
        return [SubmissionProblem("error", "the submission must be a JSON list of answers")]

    seen: dict[str, int] = {}
    for i, raw in enumerate(answers):
        if not isinstance(raw, Mapping):
            problems.append(
                SubmissionProblem("error", f"entry {i} is {type(raw).__name__}, not an object")
            )
            continue
        if "task_id" not in raw:
            problems.append(SubmissionProblem("error", f"entry {i} has no 'task_id'"))
            continue
        tid = str(raw["task_id"])
        try:
            Answer.from_dict(raw)
        except (ValueError, KeyError, TypeError) as exc:
            problems.append(SubmissionProblem("error", str(exc)))
            continue
        if tid not in known:
            problems.append(
                SubmissionProblem(
                    "error",
                    f"unknown task id {tid!r}. It will be ignored, so this answer earns "
                    f"nothing. Run 'soundnessbench tasks' for the current ids.",
                )
            )
        seen[tid] = seen.get(tid, 0) + 1

    duplicates = sorted(t for t, n in seen.items() if n > 1)
    if duplicates:
        shown = ", ".join(duplicates[:5])
        more = "" if len(duplicates) <= 5 else f" (+{len(duplicates) - 5} more)"
        problems.append(
            SubmissionProblem(
                "error",
                f"duplicate answers for {shown}{more}. Only the last is scored, so the "
                f"others are silently discarded -- submit one answer per task.",
            )
        )

    missing = sorted(known - set(seen))
    if missing:
        shown = ", ".join(missing[:5])
        more = "" if len(missing) <= 5 else f" (+{len(missing) - 5} more)"
        problems.append(
            SubmissionProblem(
                "warning",
                f"{len(missing)} task(s) have no answer and are scored as abstentions: "
                f"{shown}{more}. Abstaining is allowed and never fails the gate; it "
                f"lowers decisiveness only.",
            )
        )
    return problems


def score_submission(
    tasks: Sequence[Any],
    answers: Sequence[Mapping[str, Any]],
    tool: str = "unnamed",
) -> Score:
    """Grade a submission against ground truth.

    A task with no answer is scored as an abstention, not as a free pass and not
    as an error -- otherwise a tool could improve its coverage by omitting the
    tasks it was unsure about.
    """
    parsed: dict[str, Answer] = {}
    for raw in answers:
        a = Answer.from_dict(raw)
        parsed[a.task_id] = a

    truth = {t.task_id: t for t in tasks}

    n_answered = n_abstained = n_missing = 0
    false_cert = false_alarm = correct = 0
    counts_offered = counts_correct = 0
    per_family: dict[str, dict[str, int]] = {}
    false_cert_ids: list[str] = []

    for task_id, task in truth.items():
        fam = per_family.setdefault(
            task.family,
            {"n": 0, "answered": 0, "correct": 0, "false_certifications": 0},
        )
        fam["n"] += 1

        answer = parsed.get(task_id)
        if answer is None:
            n_missing += 1
            n_abstained += 1
            continue

        if answer.verdict == ABSTAIN:
            n_abstained += 1
            continue

        n_answered += 1
        fam["answered"] += 1
        said_sound = answer.verdict == SOUND

        if said_sound and not task.is_sound:
            false_cert += 1
            fam["false_certifications"] += 1
            false_cert_ids.append(task_id)
        elif not said_sound and task.is_sound:
            false_alarm += 1
        else:
            correct += 1
            fam["correct"] += 1

        if answer.over_acceptance is not None:
            counts_offered += 1
            if answer.over_acceptance == task.over_acceptance:
                counts_correct += 1

    return Score(
        tool=tool,
        n_tasks=len(truth),
        n_answered=n_answered,
        n_abstained=n_abstained,
        n_missing=n_missing,
        false_certifications=false_cert,
        false_alarms=false_alarm,
        correct=correct,
        counts_offered=counts_offered,
        counts_correct=counts_correct,
        per_family=per_family,
        false_certification_ids=false_cert_ids,
    )
