"""The **hard split**: tasks derived from real CVE relations, not synthetic families.

The public split is honest about being synthetic — `SCOPE.md` says so, and that
is the strongest objection to the benchmark: a tool could be tuned to seven
generated shapes. This split answers it. Every task here starts from a
specification in the published
[cve-proof-corpus](https://huggingface.co/datasets/nickh007/cve-proof-corpus):
the relation a real bounds check actually enforces, transcribed from a real
historical vulnerability class.

**What is real and what is not.** The *relations* come from the corpus. The
unsound variants are **synthetic weakenings** of them — an off-by-one, a dropped
conjunct, a relaxed constant. They are not what any project shipped, and nothing
here is a statement about any current version of any software. The sound variant
is the fixed relation; the weakened ones are the mistakes that shape invites, and
they are labelled as constructed.

**Why it is harder.** Real specs have more variables, more domain constraints,
and multiple safety conjuncts. A tool that handles one guard atom over two
variables can score well on the public split and fall over here.

**Ground truth is still exhaustive.** Same rule as the public split: every answer
comes from point-by-point enumeration, sharing no code with anything under test.
That forces the boxes to stay small, and where a corpus variable's real range is
too wide to enumerate, the box is narrowed and the narrowing is recorded in the
task's note. A benchmark whose answers you cannot confirm is a leaderboard, not a
measurement.

**What this split does not claim.** It is not a sample of "real-world guards" in
any statistical sense — six classes are six classes. It measures whether a tool
gets *these* real shapes right, which is more than the synthetic split measures
and much less than a survey.
"""

from __future__ import annotations

import json
from fractions import Fraction
from pathlib import Path
from typing import Any

from .groundtruth import task_key
from .tasks import Task, _finalise, brute_force_over_acceptance

__all__ = [
    "CORPUS_PATH",
    "HARD_FAMILIES",
    "load_corpus",
    "generate_hard_suite",
    "minimal_break",
    "break_offset",
    "build_offsets",
    "MAX_ENUMERATED_POINTS",
]

#: The corpus ships inside the package so the split is reproducible offline.
CORPUS_PATH = Path(__file__).resolve().parent / "data" / "cve-proof-corpus.jsonl"

#: Committed minimal-break offsets, keyed by a hash of the relations.
OFFSETS_PATH = Path(__file__).resolve().parent / "data" / "hard_offsets.json"

#: Enumeration budget per task. Chosen so the whole split brute-forces in a few
#: seconds; a wider box would be more faithful and less checkable, and
#: checkability is the property this benchmark trades everything else for.
MAX_ENUMERATED_POINTS = 200_000

HARD_FAMILIES = ("cve-fixed", "cve-edge-sound", "cve-edge-unsound", "cve-dropped")


def load_corpus(path: Path | None = None) -> list[dict[str, Any]]:
    """Read the bundled CVE corpus. Returns ``[]`` if it is missing.

    An empty list degrades to "no hard tasks", which a caller can see. The
    alternative -- inventing tasks when the data file is absent -- would make the
    split silently different from the published one.
    """
    target = path or CORPUS_PATH
    if not target.is_file():
        return []
    rows = []
    for line in target.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def _rational(pair: Any) -> Fraction:
    if isinstance(pair, (list, tuple)) and len(pair) == 2:
        return Fraction(int(pair[0]), int(pair[1]))
    return Fraction(int(pair))


def _atom_from_corpus(raw: dict[str, Any]) -> dict[str, Any] | None:
    """Convert a certkit JSON atom into the benchmark's integer atom form.

    Returns ``None`` for an atom whose coefficients are not integral. The
    benchmark's enumerator works over integers; silently rounding a 1/2 would
    change the relation being graded, which is the one thing a benchmark must
    never do to a task.
    """
    coeff: dict[str, int] = {}
    for var, value in raw.get("coeff", {}).items():
        c = _rational(value)
        if c.denominator != 1:
            return None
        if c != 0:
            coeff[var] = int(c)
    const = _rational(raw.get("const", [0, 1]))
    if const.denominator != 1:
        return None
    return {"coeff": coeff, "const": int(const), "strict": bool(raw.get("strict", False))}


def _box_for(
    domain: list[dict[str, Any]],
    guard: list[dict[str, Any]],
    safety: list[dict[str, Any]],
) -> tuple[dict[str, tuple[int, int]], str]:
    """A small integer box covering every variable, and a note describing it.

    Bounds from single-variable domain atoms are honoured where they fit; a
    variable whose real range is wider than the budget allows is narrowed, and
    the note says so. Narrowing is safe for the benchmark's purpose (the task is
    still a well-posed question with an exhaustively known answer) but it does
    change the question, so it is never done silently.
    """
    variables = sorted({v for atoms in (domain, guard, safety) for a in atoms for v in a["coeff"]})
    if not variables:
        return {}, ""

    upper: dict[str, int] = {}
    for a in domain:
        if len(a["coeff"]) != 1:
            continue
        ((var, c),) = a["coeff"].items()
        # c*var + k <= 0 with c > 0 gives var <= -k/c.
        if c > 0:
            bound = -a["const"] // c
            if bound >= 0:
                upper[var] = min(upper.get(var, bound), bound)

    # Start from the declared bounds, then shrink uniformly until the product
    # fits the enumeration budget.
    width = 1
    while True:
        span = max(1, int(round(MAX_ENUMERATED_POINTS ** (1.0 / len(variables))))) - 1
        width = max(1, span)
        break

    box: dict[str, tuple[int, int]] = {}
    narrowed: list[str] = []
    for var in variables:
        declared = upper.get(var)
        if declared is not None and declared <= width:
            box[var] = (0, int(declared))
        else:
            box[var] = (0, width)
            if declared is not None:
                narrowed.append(f"{var} (real bound {declared})")

    note = ""
    if narrowed:
        note = (
            "box narrowed to keep the answer exhaustively checkable: "
            + ", ".join(narrowed)
            + f"; enumerated to {width} instead"
        )
    return box, note


def _relaxed(guard: list[dict[str, Any]], index: int, k: int) -> list[dict[str, Any]]:
    """The guard with conjunct ``index`` relaxed by ``k``."""
    return [dict(a, const=a["const"] - k) if i == index else a for i, a in enumerate(guard)]


def minimal_break(
    domain: list[dict[str, Any]],
    guard: list[dict[str, Any]],
    safety: list[dict[str, Any]],
    box: dict[str, tuple[int, int]],
    index: int,
    *,
    limit: int = 1024,
) -> int | None:
    """The smallest relaxation of guard conjunct ``index`` that admits a forbidden state.

    Fixed weakenings (-1, -8) turned out to be the wrong design: on real specs
    with slack between the guard and the safety property, a relaxation of one or
    eight often changes nothing, so the "unsound" variants were still sound and a
    tool could score 16 out of 21 by answering "sound" every time. A benchmark
    that a constant answer beats is not measuring anything.

    So the split asks the sharper question instead: what is the smallest edit
    that breaks this guard? The task at ``k`` is unsound by exactly one step, and
    the task at ``k - 1`` is sound by exactly one step. A tool has to get the
    boundary right rather than the order of magnitude.

    Returns ``None`` when no relaxation up to ``limit`` breaks the guard --
    reported as "not found within the budget", never as "cannot be broken".
    """
    # Exponential search for an upper bound, then bisect. Each probe is a full
    # enumeration, so the number of probes is what costs.
    hi = 1
    while hi <= limit:
        count, _ = brute_force_over_acceptance(domain, _relaxed(guard, index, hi), safety, box)
        if count > 0:
            break
        hi *= 2
    else:
        return None

    lo = hi // 2  # known sound (or 0, which is the fixed guard)
    while lo + 1 < hi:
        mid = (lo + hi) // 2
        count, _ = brute_force_over_acceptance(domain, _relaxed(guard, index, mid), safety, box)
        if count > 0:
            hi = mid
        else:
            lo = mid
    return hi


def _offset_cache() -> dict[str, Any]:
    """Committed results of the minimal-break search, keyed by content hash.

    The search costs a dozen full enumerations per conjunct, which is too slow to
    repeat on every import. Keying by a hash of the relations means an edited
    corpus misses the cache and is recomputed -- a stale entry is unreachable
    rather than merely detectable, the same rule the ground-truth cache follows.
    """
    if not OFFSETS_PATH.is_file():
        return {}
    try:
        doc = json.loads(OFFSETS_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return doc.get("entries", {}) if isinstance(doc, dict) else {}


def _offset_key(
    domain: list[dict[str, Any]],
    guard: list[dict[str, Any]],
    safety: list[dict[str, Any]],
    box: dict[str, tuple[int, int]],
    index: int,
) -> str:
    box_json = {k: [v[0], v[1]] for k, v in box.items()}
    return f"{task_key(domain, guard, safety, box_json)}:{index}"


def break_offset(
    domain: list[dict[str, Any]],
    guard: list[dict[str, Any]],
    safety: list[dict[str, Any]],
    box: dict[str, tuple[int, int]],
) -> tuple[int, int] | None:
    """The first guard conjunct that can be broken, and the smallest edit that does it.

    Searching only conjunct 0 was not enough: on half the corpus, relaxing the
    first conjunct changes nothing over the task box, because a *different*
    conjunct is the one carrying the safety property. Those records produced no
    unsound task at all. So every conjunct is tried, in order, and the first that
    yields a breaking edit is used.

    Returns ``(index, k)``, or ``None`` when no single-conjunct relaxation within
    the budget admits a forbidden state over this box.
    """
    cache = _offset_cache()
    for index in range(len(guard)):
        key = _offset_key(domain, guard, safety, box, index)
        cached = cache.get(key)
        k = (
            cached.get("k")
            if cached is not None
            else minimal_break(domain, guard, safety, box, index)
        )
        if k is not None:
            return index, k
    return None


def generate_hard_suite(corpus: list[dict[str, Any]] | None = None) -> list[Task]:
    """Build the hard split from the CVE corpus.

    Per corpus record: the fixed relation, and a **pair** of tasks around the
    boundary of the first guard conjunct -- relaxed by k (unsound by one step) and
    by k-1 (sound by one step), where k is the smallest relaxation that breaks the
    guard. A tool cannot score on this split by answering the same way every time,
    and it cannot score by getting the order of magnitude right either.

    Every answer is computed by exhaustive enumeration, and a record whose
    relations cannot be represented in integer arithmetic is **skipped rather
    than approximated**.
    """
    rows = corpus if corpus is not None else load_corpus()
    tasks: list[Task] = []

    for row in sorted(rows, key=lambda r: r.get("id", "")):
        spec = row.get("spec") or {}
        domain = [_atom_from_corpus(a) for a in spec.get("domain", [])]
        guard = [_atom_from_corpus(a) for a in spec.get("guard", [])]
        safety = [_atom_from_corpus(a) for a in spec.get("safety", [])]
        if any(a is None for a in domain + guard + safety) or not guard or not safety:
            # Not representable as integer atoms, or nothing to grade. Skipping is
            # the honest option: a rounded coefficient is a different theorem.
            continue

        base = row.get("id", "unknown")
        box, box_note = _box_for(domain, guard, safety)
        if not box:
            continue

        provenance = (
            f"relation from {row.get('cve', '')} ({row.get('cwe', '')}); "
            f"{row.get('relation_in_words', '')}"
        ).strip()

        def note(*parts: str, _p: str = provenance, _b: str = box_note) -> str:
            # Defaults bind the loop variables at definition time; a closure over
            # them would silently attach the last record's provenance to every
            # task, which is exactly the kind of quiet mislabelling this split
            # cannot afford.
            return "; ".join(x for x in [_p, *parts, _b] if x)

        tasks.append(
            _finalise(
                f"hard-{base}-fixed",
                "cve-fixed",
                "hard",
                domain,
                guard,
                safety,
                box,
                note=note("the fixed relation, unmodified"),
            )
        )

        found = break_offset(domain, guard, safety, box)
        if found is None:
            # No relaxation within the search budget admits a forbidden state over
            # this box. Say so in the note; do not claim the guard is unbreakable.
            tasks.append(
                _finalise(
                    f"hard-{base}-wide",
                    "cve-fixed",
                    "hard",
                    domain,
                    _relaxed(guard, 0, 64),
                    safety,
                    box,
                    note=note(
                        "constructed: first guard conjunct relaxed by 64 (not shipped "
                        "code). No relaxation within the search budget broke this "
                        "guard over this box -- which is a fact about the box, not a "
                        "claim that the guard cannot be broken"
                    ),
                )
            )
            continue

        index, k = found
        tasks.append(
            _finalise(
                f"hard-{base}-edge-unsound",
                "cve-edge-unsound",
                "hard",
                domain,
                _relaxed(guard, index, k),
                safety,
                box,
                note=note(
                    f"constructed: guard conjunct {index} relaxed by {k}, the smallest "
                    "relaxation that admits a forbidden state over this box (not "
                    "shipped code)"
                ),
            )
        )
        if k > 1:
            tasks.append(
                _finalise(
                    f"hard-{base}-edge-sound",
                    "cve-edge-sound",
                    "hard",
                    domain,
                    _relaxed(guard, index, k - 1),
                    safety,
                    box,
                    note=note(
                        f"constructed: guard conjunct {index} relaxed by {k - 1} -- one "
                        "step short of breaking. Still sound, and the paired task "
                        "above differs by one (not shipped code)"
                    ),
                )
            )

        if len(guard) > 1:
            tasks.append(
                _finalise(
                    f"hard-{base}-dropped",
                    "cve-dropped",
                    "hard",
                    domain,
                    guard[1:],
                    safety,
                    box,
                    note=note(
                        "constructed: the first guard conjunct removed entirely, as a "
                        "refactor might (not shipped code)"
                    ),
                )
            )

    return tasks


def build_offsets(corpus: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Recompute every minimal-break offset from scratch, for the committed file.

    This is the slow, authoritative path -- a dozen full enumerations per record.
    `soundnessbench verify-ground-truth --write` regenerates it, and CI checks it.
    """
    rows = corpus if corpus is not None else load_corpus()
    entries: dict[str, Any] = {}
    for row in sorted(rows, key=lambda r: r.get("id", "")):
        spec = row.get("spec") or {}
        domain = [_atom_from_corpus(a) for a in spec.get("domain", [])]
        guard = [_atom_from_corpus(a) for a in spec.get("guard", [])]
        safety = [_atom_from_corpus(a) for a in spec.get("safety", [])]
        if any(a is None for a in domain + guard + safety) or not guard or not safety:
            continue
        box, _ = _box_for(domain, guard, safety)
        if not box:
            continue
        for index in range(len(guard)):
            k = minimal_break(domain, guard, safety, box, index)
            entries[_offset_key(domain, guard, safety, box, index)] = {
                "id": row.get("id"),
                "conjunct": index,
                "k": k,
            }
            if k is not None:
                # The suite uses the first breakable conjunct; the rest would be
                # search cost for an answer nothing reads.
                break
    return {
        "schema": "soundnessbench/hard-offsets/v1",
        "note": (
            "Smallest relaxation of each guard's first conjunct that admits a "
            "forbidden state over the task box, found by exhaustive enumeration. "
            "Keyed by a hash of the relations, so an edited corpus misses the "
            "cache and is recomputed rather than served stale."
        ),
        "n_entries": len(entries),
        "entries": entries,
    }
