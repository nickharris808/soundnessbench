# Changelog

All notable changes to this package. Format follows [Keep a Changelog](https://keepachangelog.com/);
versioning is [semantic](https://semver.org/).

## [0.3.1]

### Fixed
- **`score_submission` raised `AttributeError`** on an answer entry that was not an object (a bare
  string, `null`, a number). `validate_submission` reported it properly and the scoring path did
  not, so a caller who scored without validating first got a traceback rather than a refusal.

### Added
- `ARCHITECTURE.md`, `TROUBLESHOOTING.md`, `CITATION.cff`, and a documentation-parity test.
- `tests/test_stress_caches.py` — adversarial tests over the caches and the scorer: every field that
  can change an answer must change the cache key, a corrupted ground-truth file must degrade to slow
  rather than to wrong, omitting hard tasks must not inflate a score, duplicate answers must not
  multiply credit, and one false certification must fail the gate even when everything else is right.

## [0.3.0]

### Added
- **The hard split** (`--split hard`): tasks whose relations are taken from real historical CVE
  classes in `cve-proof-corpus`, which ships inside the package. Unsound variants are built by
  searching for the **minimal edit that breaks each guard**, so a sound/unsound pair can differ by
  one. Constructed weakenings are labelled as constructed in every task's note; nothing in the split
  is a statement about any current version of any software.
- `--split {public,hard,all}` on every subcommand. A score is only comparable to another score on
  the same split, so the split is named in the output.
- `soundnessbench.hard.minimal_break()` and a committed `data/hard_offsets.json`, keyed by a content
  hash of the relations exactly like the ground truth — an edited corpus misses the cache and is
  recomputed rather than served stale.
- A **leaderboard Space**: <https://huggingface.co/spaces/nickh007/soundnessbench-leaderboard>.
  Scoring runs client-side under Pyodide; submissions are never uploaded, because there is no server
  to upload them to.

### Fixed
- `verify-ground-truth` now covers both splits. One file serves both (entries are keyed by relation
  hash), so verifying only one split would have let `--write` silently drop the other's answers.

## [0.2.0]

### Added
- **Precomputed ground truth**, shipped as `data/ground_truth.json`. Answers are keyed by a content
  hash of each task's relations, so editing a task changes its key, misses the cache, and recomputes
  — a stale entry is unreachable rather than merely detectable.
- `soundnessbench verify-ground-truth` recomputes every answer by enumeration and compares;
  `--write` regenerates. Run it in CI: it is what keeps the fast path honest.
- `soundnessbench submit` — validates a submission before scoring it. Unknown task ids, duplicates
  and malformed verdicts are errors that stop the run; missing answers are a warning, since
  abstaining is legitimate.
- `py.typed`.

### Changed
- `generate_suite()` is memoised per seed and reads the precomputed answers.
  Measured: **3,155 ms → 0.7 ms**; `soundnessbench tasks` **3,106 ms → 55 ms** (56x); the test suite
  **79 s → 30 s** while gaining 19 tests.
- No answer changed. The file is a cache: deleting it changes speed, never results.

## [0.1.0]
- First release: 44 tasks across 7 families, exhaustive ground truth, the soundness gate,
  five reference baselines.
