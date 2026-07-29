# Troubleshooting

## My tool scores 0% coverage

Coverage is accuracy over *answered* tasks, and it reads `n/a` when nothing was answered. If you see
`n/a`, your submission's `task_id`s probably do not match. Run:

```bash
soundnessbench --split hard submit --answers answers.json --tool my-tool
```

`submit` validates before it scores and names every unknown or missing id, rather than quietly
scoring them as abstentions and leaving you to guess.

## The gate says FAIL and I think my tool is right

`false_certification_ids` in the JSON output names the tasks. Each has a witness in the ground truth:
a concrete assignment that satisfies the domain and the guard and violates safety. Check it by hand —
that is the point of the witness being there. If the witness does not actually escape, the benchmark
is wrong and that is a security-grade bug (see `SECURITY.md`).

## `verify-ground-truth` says MISMATCH

The committed answers no longer match a fresh enumeration. That means a task's relations changed. If
the change was intended:

```bash
soundnessbench verify-ground-truth --write
```

Then read the diff before committing it. A changed verdict is a soundness question, not a formatting
one.

## The hard split is empty

```
error: the hard split is empty -- the bundled CVE corpus is missing.
```

The corpus ships inside the package, at `soundnessbench/data/cve-proof-corpus.jsonl`. If it is
absent, reinstall rather than scoring against no tasks — an empty suite would report a perfect result
for having answered nothing.

## `certkit-stack` shows `n/a` in the leaderboard

Its optional packages are not installed:

```bash
pip install "soundnessbench[stack]"
```

Without them the baseline abstains on every task and says so in each answer's `note`. It used to
return an empty list, which scored identically but reported as a row with no tasks — reading like
the baseline was never run rather than like it could not run.

## Generating the suite is slow

It should take milliseconds; the answers are precomputed and keyed by a content hash. If you are
waiting seconds, the cache is missing (a source checkout without the data file) or you edited a
task's relations, which changes its key and forces a recompute. That is the cache working correctly.

## Scores from different splits do not compare

They do not, and they are not meant to. `--split hard` is harder by construction, and a score is
only comparable to another score on the same split. The split is named in every output for that
reason.
