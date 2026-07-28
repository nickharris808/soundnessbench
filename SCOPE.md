# Honest scope

What `soundnessbench` measures, and what a score does not tell you.

## What it measures

44 tasks. Each asks one question: **does this guard admit a state this safety property forbids, over
this declared box?** Every answer comes from exhaustive enumeration, so the ground truth is a fact,
not a consensus.

| Family | Tasks | What it probes |
|---|---|---|
| `bounds` | 8 | plain bounds checks |
| `heartbleed` | 8 | the CVE-2014-0160 length relation shape |
| `index` | 6 | array index guards |
| `offbyone` | 6 | guards wrong by exactly one |
| `twovar` | 5 | two interacting variables |
| `wrap` | 5 | near-boundary arithmetic |
| `needle` | 6 | 1–6 escaping states hidden in up to 262,144 |

21 tasks are sound, 23 are unsound. A tool answers `SOUND`, `UNSOUND`, or `ABSTAIN` per task, and may
optionally supply an exact count.

## The one metric that matters

**The soundness gate: did the tool ever certify an unsound guard as `SOUND`?**

One false certification fails the gate, and no other column redeems it. Coverage, decisiveness, and
count accuracy are reported alongside, but they are descriptive. A tool that answers everything
correctly except for one guard it wrongly blessed has not "scored 97%" — it has failed.

This asymmetry is deliberate. In verification, a false negative costs you time; a false positive
costs you the property you thought you had.

**Abstaining never fails the gate.** `always-abstain` passes it with 0% decisiveness, which is
correct and is the point: a tool that knows it does not know is strictly better than one that
guesses. The `needle` family exists to make abstention the honest answer for samplers.

## What a passing gate does NOT tell you

### It is not a claim of general soundness

Passing means *this tool did not false-certify on these 44 tasks*. It is a floor, established by
counterexample, not a proof of anything. A tool can pass here and be unsound on a shape the suite
does not contain.

### The suite is small and synthetic

44 hand-constructed tasks in seven families, over small integer boxes. It is not a statistical sample
of real-world guards, and the families were chosen because they are shapes where soundness bugs are
known to hide — not because they are representative.

Nothing here involves the heap, aliasing, nonlinear arithmetic, concurrency, or control flow. A tool
is being graded on quantifier-free linear integer arithmetic over a box and nothing else.

### Coverage is not accuracy on tasks you skipped

`coverage` is correct answers as a fraction of answers *given*. `decisiveness` is answers given as a
fraction of the suite. Reading coverage alone rewards a tool for abstaining on everything hard, which
is why both are always printed together.

Omitting tasks cannot inflate a score: the denominator is the whole suite, and unanswered tasks are
scored as abstentions. `soundnessbench submit` reports unknown ids, duplicate ids, and missing
answers explicitly rather than silently absorbing them.

### The reference numbers are baselines, not competitors

`sampler-1k` scores 84.1% coverage and **still fails**, because it false-certifies 7 unsound guards.
`always-sound` fails with 23. Those exist to demonstrate what the gate catches — a plausible-looking
tester that reports SOUND because it looked and saw nothing.

`certkit-stack` passes at 100%, and you should discount that accordingly: the suite and that stack
come from the same authors. It is a demonstration that the metric is satisfiable, not evidence of
superiority. The benchmark deliberately **imports none of the tools it grades**, so it can grade them
without a shared dependency — but shared authorship is not something a code boundary can fix, and
you should weigh the number knowing that.

### Ground truth is exhaustive, so it is only as good as the box

Every task's answer is computed by enumerating its declared box. That makes the answer exact, and it
makes it a statement about that box. The boxes are small on purpose so this is affordable and
checkable.

## How to submit

```bash
soundnessbench tasks --out tasks.json          # answers stripped
# ... run your tool, write answers.json ...
soundnessbench submit --answers answers.json --tool your-tool-name
```

`submit` validates before it scores: unknown task ids, duplicates, malformed verdicts, and negative
counts are errors that stop the run, because a submission scored with a typo in it is a misleading
number rather than a low one. Missing answers are a warning — they are legal, and scored as
abstentions.

Exit 0 means the gate passed; exit 1 means it did not.

## The trusted computing base

1. **`tasks.py`**, which constructs the suite and computes ground truth by enumeration.
2. **`scoring.py`**, which is arithmetic on integers.
3. Python's standard library.

No dependency on any graded tool. `[stack]` is optional and only adds an entrant.

## When to use something else

| If you need | Use |
|---|---|
| To prove a specific guard | [certkit](https://github.com/nickharris808/certkit) |
| To count how badly a guard leaks | [exploit-counter](https://github.com/nickharris808/exploit-counter) |
| A benchmark over real-world C | SV-COMP, Test-Comp |
| A benchmark with a heap or nonlinear fragment | not this one |

## The one-sentence version

soundnessbench asks whether a tool ever calls an unsound guard sound, on 44 small tasks whose answers
are known by exhaustion — and a tool that never does has cleared a floor, not proved a ceiling.
