# Contributing to soundnessbench

## Ground truth is sacred

Every answer is produced by exhaustive enumeration and nothing else. Do not "optimise" the ground
truth path with intervals, closed forms, or a solver — the whole benchmark rests on the answers being
computed by a method too simple to be subtly wrong, and independent of everything it grades.

`soundnessbench` must never import `certkit`, `exploit-counter`, or any other tool it scores. If you need
an atom type, use the one in `tasks.py`.

## New task families are welcome

A good family encodes a *real* mistake — a CWE shape, a strictness confusion, a composition failure —
rather than a random linear system. Include:

- both sound and unsound instances (a family that is all one answer teaches nothing);
- a `note` explaining the trap in plain English;
- a test asserting whatever property makes the family interesting.

If your family's gaps are rare, add an assertion on the rate like `test_needle_gaps_really_are_rare`
does. Rarity is a property we must not lose by accident.

## Keep the boxes enumerable

Every box must be small enough to enumerate exhaustively in the test suite. If a task is too big to
check, its answer is an assertion rather than a measurement, and it does not belong here.

## Do not weaken the gate

The soundness gate is binary and non-negotiable: one false certification fails a tool. Proposals to
soften it into a weighted score will be declined. The entire point is that this one error class is
not tradeable against the others.

## Tests

```bash
pip install -e ".[dev]"
pytest
```

The suite takes ~40s because it re-derives all ground truth. That is deliberate; do not skip it.

## License

Contributions are accepted under Apache-2.0.
