# Changelog

All notable changes to this package. Format follows [Keep a Changelog](https://keepachangelog.com/);
versioning is [semantic](https://semver.org/).

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
