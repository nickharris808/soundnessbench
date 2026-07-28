---
license: apache-2.0
task_categories:
  - text-classification
tags:
  - formal-verification
  - program-analysis
  - security
  - benchmark
  - model-counting
pretty_name: SoundnessBench v1
size_categories:
  - n<1K
configs:
  - config_name: default
    data_files:
      - split: test
        path: soundnessbench-v1.jsonl
  - config_name: public
    data_files:
      - split: test
        path: soundnessbench-v1-public.jsonl
---

# SoundnessBench v1

A benchmark for tools that decide whether a **guard predicate** is sound: does the check a program
performs actually imply the safety property it is supposed to guarantee?

Every answer in this dataset was computed by **exhaustive point-by-point enumeration** of the
declared variable box. No solver, no closed form, no shared code with any tool the benchmark grades.

## Why this exists

Ask a security tool "did you find any escapes?" and a clean answer is unfalsifiable — equally
consistent with *the guard is correct* and *you did not look hard enough*. SoundnessBench replaces that
with a ground-truth integer: exactly how many states the guard admits that the safety property
forbids.

The benchmark's sharpest finding is built into its design. The `needle` family contains guards that
are wrong on as few as **1 state out of 262,144**. A random sampler drawing 1,000 points misses a gap
that rare about 99.6% of the time — and then reports SOUND. On this suite, a 1,000-sample tester
**false-certifies 7 of 23 unsound guards** while scoring 84.1% overall accuracy. That gap between
"high accuracy" and "certified a vulnerability as safe" is the thing the benchmark is built to
expose.

## Splits

| File | Rows | Contains |
|---|---|---|
| `soundnessbench-v1.jsonl` | 44 | tasks **with** ground truth (`over_acceptance`, `is_sound`, `witness`) |
| `soundnessbench-v1-public.jsonl` | 44 | tasks only — the answer key stripped, for honest self-evaluation |

## Fields

| Field | Type | Meaning |
|---|---|---|
| `task_id` | string | stable identifier, e.g. `needle-000` |
| `family` | string | one of `bounds`, `heartbleed`, `index`, `offbyone`, `twovar`, `wrap`, `needle` |
| `difficulty` | string | `easy` (box ≤ 4,096) or `medium` (≤ 262,144) |
| `domain` | list[atom] | constraints bounding the state space |
| `guard` | list[atom] | what the program checks |
| `safety` | list[atom] | what must actually hold |
| `box` | dict | integer bounds per variable |
| `box_volume` | int | total points in the box |
| `over_acceptance` | int | **answer**: states admitted by the guard but forbidden by safety |
| `is_sound` | bool | **answer**: `over_acceptance == 0` |
| `witness` | dict or null | **answer**: one concrete violating assignment |
| `note` | string | plain-English description of the trap |

An **atom** is a linear relation in canonical form:

```json
{"coeff": {"payload": 1, "record_len": -1}, "const": 19, "strict": false}
```

meaning `payload - record_len + 19 <= 0`, i.e. `19 + payload <= record_len`. When `strict` is true the
relation is `< 0`. All coefficients are integers.

## Task families

| Family | Shape | The trap |
|---|---|---|
| `bounds` | `off + len <= cap` | guard permits a few extra states (CWE-787 / CWE-125) |
| `heartbleed` | `overhead + payload <= record_len` | guard uses too small an overhead (CVE-2014-0160) |
| `index` | `scale*i < n` | `<=` where `<` was required (CWE-129) |
| `offbyone` | `x <= cap-1` | the classic bound-by-one error |
| `twovar` | two coupled constraints | both safety conjuncts must hold |
| `wrap` | per-operand bounds | do they compose to a bound on the sum? |
| `needle` | rare gap | **1–6 violating states in a box of up to 262,144** |

## How to use it

```python
import json

tasks = [json.loads(line) for line in open("soundnessbench-v1-public.jsonl")]

answers = []
for t in tasks:
    verdict = my_tool(t["domain"], t["guard"], t["safety"], t["box"])  # SOUND / UNSOUND / ABSTAIN
    answers.append({"task_id": t["task_id"], "verdict": verdict})

json.dump(answers, open("answers.json", "w"))
```

Then score:

```bash
pip install soundnessbench
soundnessbench score --answers answers.json --tool my-tool
```

## Scoring

The headline metric is **not** accuracy, because ~48% of tasks are sound and a tool that answers
SOUND unconditionally would score ~48% while certifying every vulnerability in the suite.

| Metric | Meaning |
|---|---|
| **soundness gate** | false-certification count. **Must be zero.** Any false certification fails the tool outright. |
| **coverage** | accuracy over the tasks it did not abstain on |
| **decisiveness** | fraction it was willing to answer at all |
| **count accuracy** | of the exact counts volunteered, how many were right |

`ABSTAIN` is a first-class answer and is never penalised as an error — but it drives decisiveness to
zero if overused. Neither degenerate strategy wins: answer everything and you risk a false
certification; abstain on everything and coverage is undefined.

Omitted answers are scored as abstentions, so a tool cannot raise its coverage by dropping the tasks
it found hard.

## Baselines

Run on the full 44-task suite:

| Tool | Gate | Coverage | Decisiveness | Count acc. | False certs |
|---|---|---|---|---|---|
| `certkit-stack` | **PASS** | 100.0% | 100.0% | 100.0% | 0 |
| `exhaustive` | **PASS** | 100.0% | 100.0% | 100.0% | 0 |
| `always-abstain` | **PASS** | n/a | 0.0% | n/a | 0 |
| `sampler-1k` | **FAIL** | 84.1% | 100.0% | n/a | **7** |
| `always-sound` | **FAIL** | 47.7% | 100.0% | n/a | **23** |

`always-sound` and `always-abstain` are published deliberately. A benchmark that does not tell you
what a trivial strategy scores cannot be interpreted.

## Limitations

- **Quantifier-free linear integer arithmetic only.** No nonlinear terms, no heap, no aliasing, no
  floating point. This measures one fragment, and a tool doing well here is not thereby a program
  verifier.
- **Small boxes by construction.** Ground truth must be exhaustively enumerable, so the largest box
  is 262,144 points. A tool that scales to 2^32 is not rewarded for it here.
- **Synthetic tasks with real shapes.** The families are modelled on real vulnerability classes, but
  these are constructed instances, not extracted from production code.
- **Over-acceptance is triggerability, not severity.** It counts reachable forbidden states under a
  uniform model. It is not CVSS and not a weaponisability claim.
- **44 tasks is small.** Treat family-level breakdowns as indicative, not statistically strong.

## Reproduction

```bash
pip install soundnessbench
soundnessbench dataset --out soundnessbench-v1.jsonl --with-answers
```

Generation is deterministic — the same seed produces byte-identical tasks, so a published score is
reproducible. The bundled test suite re-derives every answer by a second, independently written
enumeration.

## License

Apache-2.0.
