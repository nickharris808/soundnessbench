# Architecture

## The one design constraint

**Ground truth is computed by exhaustive point-by-point enumeration, by code that shares nothing
with anything being graded.** Everything else in this package is downstream of that, including its
limitations. Task boxes are small because the answers must be confirmable; a benchmark whose answers
you cannot independently confirm is a leaderboard, not a measurement.

The package deliberately does **not** import `certkit`. It has to be able to grade `certkit`, and a
benchmark that shared its atom type with the tool under test would be measuring agreement.

## Module map

| Module | Role |
|---|---|
| `tasks.py` | The public split: seven synthetic families, its own atom representation, and the brute-force enumerator that produces every answer. |
| `hard.py` | The hard split, derived from real CVE relations, including the minimal-break search. |
| `groundtruth.py` | The committed answer cache, keyed by a content hash of each task's relations. |
| `scoring.py` | `Score`, the soundness gate, and `validate_submission`. |
| `baselines.py` | Five reference tools, including two that fail the gate on purpose. |
| `cli.py` | `tasks`, `score`, `submit`, `baseline`, `leaderboard`, `verify-ground-truth`, `dataset`, all with `--split`. |

## Why the metric is a gate

Accuracy averages reward a tool that is usually right. A soundness tool that is usually right is
not usable: one false certification is a merged vulnerability. So the headline is binary — any
false certification fails, whatever else the tool scores — and abstention costs decisiveness rather
than trust. That asymmetry is the benchmark's actual claim about the world.

## The caches, and why staleness is unreachable

Two files ship as committed data:

```
data/ground_truth.json    every task's answer, keyed by hash(domain, guard, safety, box)
data/hard_offsets.json    the minimal breaking edit per relation, keyed the same way
```

Editing a task changes the hash, misses the cache, and recomputes. Staleness is not *detected*, it
is unreachable — a stronger property than a validation step. `verify-ground-truth` recomputes
everything from scratch and compares, and it covers **both** splits because one file serves both:
verifying only one split would have let `--write` silently drop the other's answers.

## The hard split's minimal-break search

The first design used fixed weakenings (relax by 1, by 8). On real relations with slack between the
guard and the safety property those edits changed nothing, so 16 of 21 tasks came out sound and
"always answer SOUND" scored 76%. A benchmark a constant answer beats measures nothing.

The split now searches for the *smallest* relaxation `k` that admits a forbidden state — exponential
search then bisection, each probe a full enumeration — and ships the guard at `k` (unsound by one
step) and at `k − 1` (sound by one step). Searching only the first conjunct was also insufficient:
on half the corpus a different conjunct carries the safety property, so every conjunct is tried in
order.

## Honesty rules the code enforces

- A relation that cannot be represented in integer arithmetic is **skipped**, not rounded.
- A box narrowed to stay enumerable records the narrowing *and* the real bound in the task note.
- Constructed weakenings are labelled "not shipped code" in every note.
- A guard nothing in the search budget breaks reports `None`, and the note says that is a fact about
  the box rather than a claim that the guard cannot be broken.
- A baseline that cannot run abstains on every task **with the reason attached**, rather than
  returning an empty list that reports as a row with no tasks.
