"""Task generation with brute-force ground truth.

The benchmark's credibility rests entirely on the ground truth being computed by
a method that shares no code with the tools being graded. So every task's answer
comes from **exhaustive point-by-point enumeration** of the declared box -- the
dumbest possible algorithm, chosen precisely because it is too simple to be
wrong in an interesting way.

That constrains task size: boxes must stay small enough to enumerate completely.
A benchmark whose answers you cannot independently confirm is a leaderboard, not
a measurement, so we take the size limit rather than the reach.

Task families are drawn from real vulnerability shapes rather than random linear
systems, because the interesting failure mode is not "can a tool do arithmetic"
but "does a tool get *this* shape right":

    bounds       offset + length <= capacity          (CWE-787 / CWE-125)
    heartbleed   overhead + payload <= record_len     (CVE-2014-0160)
    index        index < count, scaled access         (CWE-129)
    offbyone     the classic <= vs < confusion
    twovar       two coupled constraints
    wrap         addition that can overflow its declared range
    needle       a gap of a handful of states in a box of a quarter million

The `needle` family is the one that matters most. Its guards are wrong on only a
few states out of hundreds of thousands, so random testing almost never finds
them -- a sampler that draws a thousand points misses a one-state gap in a
262,144-point box about 99.6% of the time. Any benchmark whose gaps are all
easily sampled cannot distinguish testing from proving, which is the distinction
this benchmark exists to measure.
"""

from __future__ import annotations

import itertools
import random
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from typing import Any

from .groundtruth import load_ground_truth, task_key

__all__ = ["Task", "generate_suite", "brute_force_over_acceptance", "FAMILIES"]

FAMILIES = ("bounds", "heartbleed", "index", "offbyone", "twovar", "wrap", "needle")


# --------------------------------------------------------------------------- #
# a self-contained atom representation
#
# soundnessbench deliberately does NOT import certkit. The benchmark must be able to
# grade certkit, so sharing its atom type would make the ground truth depend on
# the thing under test.
# --------------------------------------------------------------------------- #


def atom(coeff: dict[str, int], const: int = 0, strict: bool = False) -> dict[str, Any]:
    """``sum(coeff*var) + const <= 0`` (or ``< 0`` when strict)."""
    return {"coeff": dict(coeff), "const": int(const), "strict": bool(strict)}


def satisfies(a: dict[str, Any], assign: dict[str, int]) -> bool:
    s = a["const"]
    for v, c in a["coeff"].items():
        s += c * assign[v]
    return (s < 0) if a["strict"] else (s <= 0)


def negate(a: dict[str, Any]) -> dict[str, Any]:
    return {
        "coeff": {v: -c for v, c in a["coeff"].items()},
        "const": -a["const"],
        "strict": not a["strict"],
    }


@dataclass
class Task:
    """One benchmark task, with its answer."""

    task_id: str
    family: str
    difficulty: str
    domain: list[dict[str, Any]]
    guard: list[dict[str, Any]]
    safety: list[dict[str, Any]]
    box: dict[str, list[int]]
    # --- ground truth, by exhaustive enumeration ---
    over_acceptance: int
    is_sound: bool
    witness: dict[str, int] | None
    box_volume: int
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def public_dict(self) -> dict[str, Any]:
        """The task as a solver sees it -- answers stripped."""
        d = self.to_dict()
        for key in ("over_acceptance", "is_sound", "witness"):
            d.pop(key)
        return d


# --------------------------------------------------------------------------- #
# ground truth
# --------------------------------------------------------------------------- #


def brute_force_over_acceptance(
    domain: Sequence[dict[str, Any]],
    guard: Sequence[dict[str, Any]],
    safety: Sequence[dict[str, Any]],
    box: dict[str, Sequence[int]],
) -> tuple[int, dict[str, int] | None]:
    """Count, point by point, the states the guard admits but safety forbids.

    Returns ``(count, first_witness)``. This is the reference answer: no
    intervals, no closed forms, no shared code with any tool under test.
    """
    names = sorted(box)
    ranges = [range(box[n][0], box[n][1] + 1) for n in names]
    count = 0
    witness: dict[str, int] | None = None

    for point in itertools.product(*ranges):
        assign = dict(zip(names, point))
        if not all(satisfies(a, assign) for a in domain):
            continue
        if not all(satisfies(a, assign) for a in guard):
            continue
        if all(satisfies(a, assign) for a in safety):
            continue
        count += 1
        if witness is None:
            witness = dict(assign)

    return count, witness


def _volume(box: dict[str, Sequence[int]]) -> int:
    v = 1
    for lo, hi in box.values():
        v *= max(0, hi - lo + 1)
    return v


def _finalise(
    task_id: str,
    family: str,
    difficulty: str,
    domain: list[dict[str, Any]],
    guard: list[dict[str, Any]],
    safety: list[dict[str, Any]],
    box: dict[str, tuple[int, int]],
    note: str = "",
) -> Task:
    # Reuse the committed answer only when the task's relations hash to the same
    # key. Any edit to domain/guard/safety/box changes the key, misses, and is
    # recomputed -- so a stale entry cannot be served. See groundtruth.py.
    box_json = {k: [v[0], v[1]] for k, v in box.items()}
    cached = load_ground_truth().get(task_key(domain, guard, safety, box_json))
    if cached is not None:
        count = cached["over_acceptance"]
        witness = cached.get("witness")
    else:
        count, witness = brute_force_over_acceptance(domain, guard, safety, box)
    return Task(
        task_id=task_id,
        family=family,
        difficulty=difficulty,
        domain=domain,
        guard=guard,
        safety=safety,
        box={k: [v[0], v[1]] for k, v in box.items()},
        over_acceptance=count,
        is_sound=(count == 0),
        witness=witness,
        box_volume=_volume(box),
        note=note,
    )


# --------------------------------------------------------------------------- #
# families
# --------------------------------------------------------------------------- #


def _bounds(idx: int, cap: int, slack: int) -> Task:
    """`off + len <= cap`, guard may be short by `slack`."""
    domain = [atom({"off": -1}), atom({"off": 1}, -cap), atom({"len": -1}), atom({"len": 1}, -cap)]
    guard = [atom({"off": 1, "len": 1}, -(cap + slack))]
    safety = [atom({"off": 1, "len": 1}, -cap)]
    box = {"off": (0, cap), "len": (0, cap)}
    note = "sound when slack <= 0" if slack <= 0 else f"guard is {slack} too permissive"
    return _finalise(
        f"bounds-{idx:03d}", "bounds", _difficulty(box), domain, guard, safety, box, note
    )


def _heartbleed(idx: int, pmax: int, overhead: int, guard_overhead: int) -> Task:
    """`overhead + payload <= record_len`; guard uses its own overhead."""
    domain = [
        atom({"payload": -1}),
        atom({"payload": 1}, -pmax),
        atom({"record_len": -1}),
        atom({"record_len": 1}, -pmax),
    ]
    guard = [atom({"payload": 1, "record_len": -1}, guard_overhead)]
    safety = [atom({"payload": 1, "record_len": -1}, overhead)]
    box = {"payload": (0, pmax), "record_len": (0, pmax)}
    note = (
        "guard overhead meets or exceeds the requirement"
        if guard_overhead >= overhead
        else "guard overhead is too small"
    )
    return _finalise(
        f"heartbleed-{idx:03d}", "heartbleed", _difficulty(box), domain, guard, safety, box, note
    )


def _index(idx: int, count_max: int, scale: int, guard_strict: bool) -> Task:
    """`scale*i < n` style access; strictness is the trap."""
    domain = [
        atom({"i": -1}),
        atom({"i": 1}, -count_max),
        atom({"n": -1}),
        atom({"n": 1}, -count_max),
    ]
    guard = [atom({"i": scale, "n": -1}, 0, strict=guard_strict)]
    safety = [atom({"i": scale, "n": -1}, 0, strict=True)]
    box = {"i": (0, count_max), "n": (0, count_max)}
    note = (
        "guard is strict, matching safety"
        if guard_strict
        else "guard is non-strict; safety is strict"
    )
    return _finalise(
        f"index-{idx:03d}", "index", _difficulty(box), domain, guard, safety, box, note
    )


def _offbyone(idx: int, cap: int, delta: int) -> Task:
    """`x <= cap - 1` vs `x < cap`, perturbed by delta."""
    domain = [atom({"x": -1}), atom({"x": 1}, -cap)]
    guard = [atom({"x": 1}, -(cap - 1 + delta))]
    safety = [atom({"x": 1}, -(cap - 1))]
    box = {"x": (0, cap)}
    note = f"guard bound offset by {delta}"
    return _finalise(
        f"offbyone-{idx:03d}", "offbyone", _difficulty(box), domain, guard, safety, box, note
    )


def _twovar(idx: int, lim: int, a1: int, a2: int, slack: int) -> Task:
    """Two coupled constraints; the guard must imply both."""
    domain = [atom({"u": -1}), atom({"u": 1}, -lim), atom({"v": -1}), atom({"v": 1}, -lim)]
    guard = [atom({"u": a1, "v": a2}, -(lim + slack))]
    safety = [atom({"u": a1, "v": a2}, -lim), atom({"u": 1}, -lim)]
    box = {"u": (0, lim), "v": (0, lim)}
    note = "two safety conjuncts; both must hold"
    return _finalise(
        f"twovar-{idx:03d}", "twovar", _difficulty(box), domain, guard, safety, box, note
    )


def _wrap(idx: int, lim: int, guard_bound: int) -> Task:
    """Sum must stay inside the declared range."""
    domain = [atom({"a": -1}), atom({"a": 1}, -lim), atom({"b": -1}), atom({"b": 1}, -lim)]
    guard = [atom({"a": 1}, -guard_bound), atom({"b": 1}, -guard_bound)]
    safety = [atom({"a": 1, "b": 1}, -lim)]
    box = {"a": (0, lim), "b": (0, lim)}
    note = (
        "per-operand bounds compose to the sum bound"
        if 2 * guard_bound <= lim
        else "per-operand bounds do NOT compose"
    )
    return _finalise(f"wrap-{idx:03d}", "wrap", _difficulty(box), domain, guard, safety, box, note)


def _needle(idx: int, lim: int, k: int) -> Task:
    """A gap of exactly `k*(k+1)/2` states in a `(lim+1)^2` box.

    Domain is the square `[0, lim]^2`. The guard permits the whole square (its
    bound is the maximum attainable sum), while safety requires the sum to stay
    `k` below that maximum. The violating region is the top `k` anti-diagonals:
    `k = 1` gives exactly one state, `k = 2` gives three, `k = 3` gives six.
    """
    top = 2 * lim
    domain = [atom({"x": -1}), atom({"x": 1}, -lim), atom({"y": -1}), atom({"y": 1}, -lim)]
    guard = [atom({"x": 1, "y": 1}, -top)]
    safety = [atom({"x": 1, "y": 1}, -(top - k))]
    box = {"x": (0, lim), "y": (0, lim)}
    expected = k * (k + 1) // 2
    note = (
        f"gap is {expected} state(s) in {(lim + 1) ** 2}; "
        "a uniform sampler will almost never find it"
    )
    return _finalise(
        f"needle-{idx:03d}", "needle", _difficulty(box), domain, guard, safety, box, note
    )


def _difficulty(box: dict[str, tuple[int, int]]) -> str:
    v = _volume(box)
    if v <= 4_096:
        return "easy"
    if v <= 262_144:
        return "medium"
    return "hard"


# --------------------------------------------------------------------------- #
# suite
# --------------------------------------------------------------------------- #


_SUITE_CACHE: dict[int, list[Task]] = {}


def generate_suite(seed: int = 20260728) -> list[Task]:
    """Build the full task suite.

    Deterministic: the same seed yields byte-identical tasks, so a published
    score is reproducible. Roughly half the tasks are sound by construction, so
    a tool cannot score well by always answering one way.
    """
    cached = _SUITE_CACHE.get(seed)
    if cached is not None:
        return list(cached)

    random.Random(seed)
    tasks: list[Task] = []

    # bounds: slack <= 0 is sound, > 0 is not
    for i, (cap, slack) in enumerate(
        [(31, 0), (31, 1), (63, 0), (63, 2), (127, -1), (127, 3), (255, 0), (255, 1)]
    ):
        tasks.append(_bounds(i, cap, slack))

    # heartbleed: the real shape, sound and unsound variants
    for i, (pmax, need, have) in enumerate(
        [
            (255, 3, 19),
            (255, 3, 1),
            (255, 3, 3),
            (127, 5, 2),
            (127, 5, 8),
            (511, 3, 19),
            (511, 3, 0),
            (63, 4, 4),
        ]
    ):
        tasks.append(_heartbleed(i, pmax, need, have))

    # index: strictness traps
    for i, (cmax, scale, strict) in enumerate(
        [
            (63, 1, True),
            (63, 1, False),
            (127, 2, True),
            (127, 2, False),
            (255, 1, True),
            (255, 1, False),
        ]
    ):
        tasks.append(_index(i, cmax, scale, strict))

    # offbyone
    for i, (cap, delta) in enumerate([(63, 0), (63, 1), (127, 0), (127, 1), (255, 0), (255, 2)]):
        tasks.append(_offbyone(i, cap, delta))

    # twovar
    for i, (lim, a1, a2, slack) in enumerate(
        [(31, 1, 1, 0), (31, 1, 1, 4), (63, 2, 1, 0), (63, 2, 1, 3), (127, 1, 2, 0)]
    ):
        tasks.append(_twovar(i, lim, a1, a2, slack))

    # wrap: does a per-operand bound compose to a sum bound?
    for i, (lim, gb) in enumerate([(63, 31), (63, 40), (127, 63), (127, 80), (255, 127)]):
        tasks.append(_wrap(i, lim, gb))

    # needle: rare gaps that sampling misses. The point of the whole benchmark.
    for i, (lim, k) in enumerate([(511, 1), (511, 2), (511, 3), (255, 1), (255, 2), (383, 1)]):
        tasks.append(_needle(i, lim, k))

    # Memoised per seed: the suite is deterministic, so rebuilding it within a
    # process is pure waste. Callers get a fresh list each time so mutating the
    # result cannot corrupt the cache.
    _SUITE_CACHE[seed] = tasks
    return list(tasks)
