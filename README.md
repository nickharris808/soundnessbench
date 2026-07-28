# soundnessbench

[![ci](https://github.com/nickharris808/soundnessbench/actions/workflows/ci.yml/badge.svg)](https://github.com/nickharris808/soundnessbench/actions/workflows/ci.yml)
[![tasks](https://img.shields.io/badge/tasks-44-informational.svg)](data/)
[![ground truth](https://img.shields.io/badge/ground%20truth-exhaustive-brightgreen.svg)](#ground-truth)
[![status](https://img.shields.io/badge/status-pre--release-orange.svg)](#install)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**A public benchmark for guard-soundness tools — where passing means never certifying a
vulnerability as safe.**

> **Try it now, no install:** [open the browser demo](https://huggingface.co/spaces/nickh007/certkit-demo) and press **Load a forgery** — the checker refuses it, client-side.

Ask a security tool "did you find any escapes?" and a clean answer tells you nothing. It is equally
consistent with *the guard is correct* and *you did not look hard enough*. SoundnessBench replaces that
with ground truth: for each task, exactly how many states the guard admits that the safety property
forbids — computed by exhaustive enumeration, sharing no code with any tool being graded.

<a id="install"></a>
```bash
pip install "soundnessbench@git+https://github.com/nickharris808/soundnessbench@main"
```

> **Pre-release.** The PyPI name is reserved and publication is imminent; until then the line above
> is the working install. It is tested in CI on Linux, macOS, and Windows.

## 30-second quickstart

```bash
soundnessbench leaderboard
```
```
soundnessbench leaderboard -- 44 tasks
  tool              gate  coverage  decisiveness  count acc  falseC  falseA
  ---------------- ------ -------- ------------- ---------- ------- -------
  certkit-stack     PASS    100.0%        100.0%     100.0%       0       0
  exhaustive        PASS    100.0%        100.0%     100.0%       0       0
  always-abstain    PASS       n/a          0.0%        n/a       0       0
  sampler-1k        FAIL     84.1%        100.0%        n/a       7       0
  always-sound      FAIL     47.7%        100.0%        n/a      23       0

  gate FAIL = the tool certified at least one unsound guard as SOUND.
  A failing gate is not redeemable by any other column.
```

That output is a real run, not an illustration.

## The result worth arguing about

**A 1,000-sample random tester scores 84.1% accuracy and still fails.** It false-certifies 7 unsound
guards — it looked, saw nothing, and reported SOUND.

That is not a strawman. It is what testing *does*. The `needle` family contains guards wrong on as
few as **1 state in 262,144**; a thousand random draws miss a gap that rare 99.6% of the time. Any
benchmark whose gaps are all easily sampled cannot tell testing apart from proving, which is the only
distinction here worth measuring.

## Why the headline metric is not accuracy

About 48% of tasks are sound. So `always-sound` — a tool that answers SOUND to everything and does no
work at all — scores 47.7% and looks like it is doing something. It also certifies all 23
vulnerabilities in the suite as safe.

In security the two error directions are not comparable:

| Error | Cost |
|---|---|
| **False certification** — SOUND on an unsound guard | ships a vulnerability. Unbounded. |
| **False alarm** — UNSOUND on a sound guard | wastes an afternoon. Bounded. |
| **Abstention** — "I cannot decide" | honest, and useful if not universal. |

So the gate is **false certifications must be zero**, and no other column can redeem a failure. Then:

- **coverage** — accuracy over what it answered
- **decisiveness** — how much it was willing to answer
- **count accuracy** — of the exact counts offered, how many were right

Neither degenerate strategy wins. Answer everything and you risk a false certification. Abstain on
everything and coverage is undefined while decisiveness is zero. `always-abstain` passes the gate and
is obviously useless — which is the point of publishing it.

## Submitting

```bash
soundnessbench tasks --out tasks.json        # answers stripped
# ... run your tool, emit [{"task_id": ..., "verdict": "SOUND"|"UNSOUND"|"ABSTAIN"}, ...]
soundnessbench score --answers answers.json --tool my-tool
```

Exit code is `0` if you pass the soundness gate and `1` if you false-certify anything, so this works
as a CI gate on your own tool.

Optionally include `"over_acceptance": <int>` to be scored on exact counts too. Getting the count
wrong does not change your verdict score — a tool that correctly says UNSOUND without quantifying is
still useful.

**Omitted answers count as abstentions**, so you cannot raise coverage by dropping the hard tasks.

## Task families

| Family | Shape | The trap |
|---|---|---|
| `bounds` | `off + len <= cap` | guard permits extra states (CWE-787 / CWE-125) |
| `heartbleed` | `overhead + payload <= record_len` | overhead too small (CVE-2014-0160) |
| `index` | `scale*i < n` | `<=` where `<` was required (CWE-129) |
| `offbyone` | `x <= cap-1` | the classic bound-by-one |
| `twovar` | two coupled constraints | both conjuncts must hold |
| `wrap` | per-operand bounds | do they compose to a sum bound? |
| `needle` | rare gap | **1–6 violating states in up to 262,144** |

## Ground truth

Every answer comes from point-by-point enumeration of the declared box — the dumbest available
algorithm, chosen because it is too simple to be wrong in an interesting way. `soundnessbench` does not
import `certkit`, because it has to be able to grade `certkit`.

The test suite re-derives all 44 answers a second, independently written way, and verifies that every
stored witness genuinely satisfies the guard while violating safety.

## Limitations

- **Quantifier-free linear integer arithmetic only.** No nonlinear terms, no heap, no aliasing, no
  floats. Doing well here does not make a tool a program verifier.
- **Small boxes by construction.** Ground truth must be enumerable, so the largest box is 262,144
  points. A tool that scales to 2^32 gets no credit for it here.
- **Synthetic instances with real shapes.** Modelled on real vulnerability classes; not extracted
  from production code.
- **44 tasks is small.** Family-level breakdowns are indicative, not statistically strong.
- **Over-acceptance is triggerability, not severity.** Not CVSS, not a weaponisability claim.

## Dataset

The suite is published as JSONL with a dataset card in [`data/`](data/), suitable for a dataset hub.
Both splits ship: one with ground truth, one with the answer key stripped.

```bash
soundnessbench dataset --out soundnessbench-v1.jsonl --with-answers
```

Generation is deterministic — same seed, byte-identical tasks — so a published score reproduces.

## Tests

```bash
pip install -e ".[dev]"
pytest
```

23 tests. The load-bearing ones are `test_always_sound_fails_the_gate` (the metric is not gameable)
and `test_sampler_false_certifies_the_rare_gaps` (the needles are genuinely rare). If the second ever
stops failing the sampler, the benchmark has lost its reason to exist.

## The rest of the toolkit

| | |
|---|---|
| **[certkit](https://github.com/nickharris808/certkit)** | the certificate format and the independent checker |
| **[exploit-counter](https://github.com/nickharris808/exploit-counter)** | if a guard is unsound, exactly how many states escape |
| **[crs-mcp](https://github.com/nickharris808/crs-mcp)** | the verdict surface AI coding agents call, over MCP |
| **[soundnessbench](https://github.com/nickharris808/soundnessbench)** | the benchmark that grades all of the above |
| **[certkit-action](https://github.com/nickharris808/certkit-action)** | run the check in your CI |
| **[pytest-mutation-verified](https://github.com/nickharris808/pytest-mutation-verified)** | prove your regression test can actually fail |
| **[cve-proof-corpus](https://huggingface.co/datasets/nickh007/cve-proof-corpus)** | six real CVEs with machine-checkable proofs |
| **[Try it in your browser](https://huggingface.co/spaces/nickh007/certkit-demo)** | no install; watch a forgery get refused |

---

## The closed core

These packages are the *checking* half. They deliberately contain no proof search, which is what keeps
them small enough to audit — and it means something upstream has to produce certificates.

For obligations over full machine-word domains, enumeration does not scale and a decision procedure
that does not enumerate is required: solver-free elimination emitting replayable certificates. That
engine, the repair synthesiser that derives a minimal guard from a refutation, and the evolutionary
search that drives them are **not** in this repository and are available commercially.

The split is deliberate and permanent. **The checker is free and always will be** — a certificate you
cannot independently verify is worth nothing, so charging for verification would defeat the format.
What costs money is *producing* certificates at scale.

## License

Apache-2.0. The benchmark and its data are meant to be copied, forked, and argued with.
