"""Reference solvers, including deliberately degenerate ones.

The degenerate baselines are not filler. A benchmark that does not publish what
a trivial strategy scores is impossible to interpret -- if `always-sound` scored
90%, then 92% would be a meaningless result. Publishing them is how a reader
calibrates.

Four baselines ship:

    always-sound   answers SOUND to everything. Maximum decisiveness, and it
                   false-certifies, so the soundness gate fails it. This is the
                   baseline that proves the headline metric is not accuracy.

    always-abstain answers ABSTAIN to everything. Passes the soundness gate
                   trivially -- and has zero decisiveness, which is why the gate
                   alone is not the whole score either.

    sampler        draws random points and answers UNSOUND if it happens to hit
                   a violating one, SOUND otherwise. This is what testing does.
                   It false-certifies on rare gaps, which is the entire thesis
                   of the estate expressed as a baseline.

    exhaustive     enumerates the box. Sound and complete for these task sizes;
                   the ceiling any tool should be measured against.
"""

from __future__ import annotations

import random
import zlib
from collections.abc import Sequence
from typing import Any

from .scoring import ABSTAIN, SOUND, UNSOUND
from .tasks import Task, satisfies

__all__ = ["run_baseline", "BASELINES"]


def _always_sound(tasks: Sequence[Task], **kw: Any) -> list[dict[str, Any]]:
    return [{"task_id": t.task_id, "verdict": SOUND} for t in tasks]


def _always_abstain(tasks: Sequence[Task], **kw: Any) -> list[dict[str, Any]]:
    return [{"task_id": t.task_id, "verdict": ABSTAIN} for t in tasks]


def _sampler(tasks: Sequence[Task], n_samples: int = 1000, seed: int = 0, **kw: Any):
    """Random testing: the strategy this whole field is trying to improve on."""
    out: list[dict[str, Any]] = []
    for t in tasks:
        # zlib.crc32, not hash(): Python randomises string hashing per process,
        # so hash() here would make the baseline's score vary between runs. A
        # benchmark figure that changes when you rerun it is not a figure.
        rng = random.Random(seed + zlib.crc32(t.task_id.encode()))
        names = sorted(t.box)
        found = False
        for _ in range(n_samples):
            assign = {n: rng.randint(t.box[n][0], t.box[n][1]) for n in names}
            if not all(satisfies(a, assign) for a in t.domain):
                continue
            if not all(satisfies(a, assign) for a in t.guard):
                continue
            if all(satisfies(a, assign) for a in t.safety):
                continue
            found = True
            break
        # Never having seen a violation is treated as SOUND -- which is exactly
        # the unsound inference that makes testing insufficient.
        out.append({"task_id": t.task_id, "verdict": UNSOUND if found else SOUND})
    return out


def _exhaustive(tasks: Sequence[Task], **kw: Any) -> list[dict[str, Any]]:
    """Enumerate every point. Independent re-derivation of the ground truth."""
    import itertools

    out: list[dict[str, Any]] = []
    for t in tasks:
        names = sorted(t.box)
        ranges = [range(t.box[n][0], t.box[n][1] + 1) for n in names]
        count = 0
        for point in itertools.product(*ranges):
            assign = dict(zip(names, point))
            if not all(satisfies(a, assign) for a in t.domain):
                continue
            if not all(satisfies(a, assign) for a in t.guard):
                continue
            if all(satisfies(a, assign) for a in t.safety):
                continue
            count += 1
        out.append(
            {
                "task_id": t.task_id,
                "verdict": SOUND if count == 0 else UNSOUND,
                "over_acceptance": count,
            }
        )
    return out


def _certkit_stack(tasks: Sequence[Task], **kw: Any) -> list[dict[str, Any]]:
    """The certkit + exploit-counter stack, if installed.

    Abstains on any task the counting engine declines, which is the behaviour
    the packages are designed for and what the benchmark should reward.
    """
    try:
        from certkit import atom as ck_atom
        from exploit_counter import over_acceptance as ec_over
    except ImportError:
        # Not installed. Abstain on every task, explicitly, rather than returning
        # an empty list: an empty submission is scored as abstaining on
        # everything anyway, but it reports as a row with no tasks, which reads
        # like the baseline was not run rather than like it could not run. The
        # note travels with each answer so a leaderboard can say why.
        return [
            {
                "task_id": t.task_id,
                "verdict": ABSTAIN,
                "note": "certkit / exploit-counter not installed: pip install "
                "'soundnessbench[stack]'",
            }
            for t in tasks
        ]

    out: list[dict[str, Any]] = []
    for t in tasks:

        def conv(atoms):
            return [ck_atom(a["coeff"], a["const"], a["strict"]) for a in atoms]

        box = {k: (v[0], v[1]) for k, v in t.box.items()}
        try:
            res = ec_over(conv(t.domain), conv(t.guard), conv(t.safety), box)
        except Exception:
            out.append({"task_id": t.task_id, "verdict": ABSTAIN})
            continue

        if res.exact is None:
            out.append({"task_id": t.task_id, "verdict": ABSTAIN})
            continue
        out.append(
            {
                "task_id": t.task_id,
                "verdict": SOUND if res.exact == 0 else UNSOUND,
                "over_acceptance": res.exact,
            }
        )
    return out


BASELINES = {
    "always-sound": _always_sound,
    "always-abstain": _always_abstain,
    "sampler-1k": _sampler,
    "exhaustive": _exhaustive,
    "certkit-stack": _certkit_stack,
}


def run_baseline(name: str, tasks: Sequence[Task], **kw: Any) -> list[dict[str, Any]]:
    if name not in BASELINES:
        raise KeyError(f"unknown baseline {name!r}; have {sorted(BASELINES)}")
    return BASELINES[name](tasks, **kw)
