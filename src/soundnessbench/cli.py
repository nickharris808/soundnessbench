"""``soundnessbench`` command-line entry point.

    soundnessbench tasks   --out tasks.json     # export tasks (answers stripped)
    soundnessbench score   --answers mine.json  # grade a submission
    soundnessbench baseline --name exhaustive   # run and score a built-in baseline
    soundnessbench leaderboard                  # run every baseline, print the table

Exit codes:

    0  the submission passed the soundness gate
    1  the submission false-certified at least one task
    2  usage error
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .baselines import BASELINES, run_baseline
from .groundtruth import GROUND_TRUTH_PATH, build_ground_truth, task_key
from .hard import OFFSETS_PATH, build_offsets, generate_hard_suite
from .scoring import Score, score_submission, validate_submission
from .tasks import brute_force_over_acceptance, generate_suite


def _fmt_row(s: Score) -> str:
    gate = "PASS" if s.is_sound else "FAIL"
    cov = "   n/a" if s.coverage is None else f"{s.coverage:6.1%}"
    cnt = "   n/a" if s.count_accuracy is None else f"{s.count_accuracy:6.1%}"
    return (
        f"  {s.tool:<16} {gate:^6} {cov:>8} {s.decisiveness:>13.1%} "
        f"{cnt:>10} {s.false_certifications:>7} {s.false_alarms:>7}"
    )


def _header() -> str:
    return (
        f"  {'tool':<16} {'gate':^6} {'coverage':>8} {'decisiveness':>13} "
        f"{'count acc':>10} {'falseC':>7} {'falseA':>7}\n"
        f"  {'-' * 16} {'-' * 6} {'-' * 8} {'-' * 13} {'-' * 10} {'-' * 7} {'-' * 7}"
    )


def main(argv: Any = None) -> int:
    parser = argparse.ArgumentParser(
        prog="soundnessbench",
        description="A public benchmark for guard-soundness tools.",
    )
    parser.add_argument(
        "--split",
        choices=["public", "hard", "all"],
        default="public",
        help=(
            "which task suite to use. 'public' is the synthetic families; 'hard' is "
            "derived from real CVE relations in cve-proof-corpus; 'all' is both. A "
            "score is only comparable to another score on the same split."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_tasks = sub.add_parser("tasks", help="export the task suite without answers")
    p_tasks.add_argument("--out", type=Path, default=None)
    p_tasks.add_argument(
        "--with-answers",
        action="store_true",
        help="include ground truth (for local analysis, not submission)",
    )

    p_score = sub.add_parser("score", help="grade a submission file")
    p_score.add_argument("--answers", required=True, type=Path)
    p_score.add_argument("--tool", default="submission")
    p_score.add_argument("--json", action="store_true")

    p_submit = sub.add_parser(
        "submit",
        help="validate a submission file, then score it and print its leaderboard row",
    )
    p_submit.add_argument("--answers", required=True, type=Path)
    p_submit.add_argument("--tool", required=True, help="the name to show on the leaderboard")
    p_submit.add_argument("--json", action="store_true")

    p_base = sub.add_parser("baseline", help="run a built-in baseline and score it")
    p_base.add_argument("--name", required=True, choices=sorted(BASELINES))
    p_base.add_argument("--json", action="store_true")

    p_lb = sub.add_parser("leaderboard", help="run every baseline and print the table")
    p_lb.add_argument("--json", action="store_true")

    p_vgt = sub.add_parser(
        "verify-ground-truth",
        help="recompute every answer by enumeration and compare to the committed file",
    )
    p_vgt.add_argument(
        "--write",
        action="store_true",
        help="regenerate the file from a fresh enumeration instead of checking it",
    )

    p_ds = sub.add_parser("dataset", help="export the suite as JSONL for a dataset hub")
    p_ds.add_argument("--out", type=Path, required=True)
    p_ds.add_argument(
        "--with-answers", action="store_true", help="include ground truth (the public split does)"
    )

    args = parser.parse_args(argv)

    if args.split == "public":
        tasks = generate_suite()
    elif args.split == "hard":
        tasks = generate_hard_suite()
    else:
        tasks = generate_suite() + generate_hard_suite()

    if args.split in ("hard", "all") and not generate_hard_suite():
        # The hard split needs the bundled corpus. If it is missing the split is
        # empty, and scoring against an empty suite would report a perfect result
        # for having answered nothing.
        print(
            "error: the hard split is empty -- the bundled CVE corpus is missing. "
            "Reinstall the package rather than scoring against no tasks.",
            file=sys.stderr,
        )
        return 2

    if args.command == "tasks":
        payload = [t.to_dict() if args.with_answers else t.public_dict() for t in tasks]
        text = json.dumps(payload, indent=2)
        if args.out:
            args.out.write_text(text + "\n", encoding="utf-8")
            print(f"wrote {len(payload)} tasks to {args.out}")
        else:
            print(text)
        return 0

    if args.command == "dataset":
        args.out.parent.mkdir(parents=True, exist_ok=True)
        with args.out.open("w", encoding="utf-8") as fh:
            for t in tasks:
                row = t.to_dict() if args.with_answers else t.public_dict()
                fh.write(json.dumps(row, sort_keys=True) + "\n")
        print(f"wrote {len(tasks)} rows to {args.out}")
        return 0

    if args.command == "verify-ground-truth":
        # Recompute from scratch -- never consult the cache -- and compare. This
        # is the command that keeps the precomputed file honest; the fast path
        # exists only because this exists.
        import json as _json

        # Ground truth is one file across both splits (entries are keyed by a
        # hash of the relations), so verification always covers both -- otherwise
        # `--split public --write` would silently drop the hard split's answers.
        every_task = generate_suite() + generate_hard_suite()
        recomputed = {}
        for t_ in every_task:
            count, witness = brute_force_over_acceptance(t_.domain, t_.guard, t_.safety, t_.box)
            recomputed[task_key(t_.domain, t_.guard, t_.safety, t_.box)] = {
                "task_id": t_.task_id,
                "over_acceptance": count,
                "witness": witness,
            }

        if args.write:
            doc = {
                "schema": build_ground_truth(tasks)["schema"],
                "note": build_ground_truth(tasks)["note"],
                "n_entries": len(recomputed),
                "entries": recomputed,
            }
            GROUND_TRUTH_PATH.parent.mkdir(parents=True, exist_ok=True)
            GROUND_TRUTH_PATH.write_text(
                _json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            print(f"wrote {GROUND_TRUTH_PATH} ({len(recomputed)} entries)")

            offsets = build_offsets()
            OFFSETS_PATH.write_text(
                _json.dumps(offsets, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            print(f"wrote {OFFSETS_PATH} ({offsets['n_entries']} entries)")
            return 0

        try:
            committed = _json.loads(GROUND_TRUTH_PATH.read_text(encoding="utf-8"))["entries"]
        except (OSError, KeyError, ValueError) as exc:
            print(f"error: cannot read {GROUND_TRUTH_PATH}: {exc}", file=sys.stderr)
            return 2

        problems = []
        for key, truth in recomputed.items():
            have = committed.get(key)
            if have is None:
                problems.append(f"{truth['task_id']}: no committed answer for this task")
            elif have.get("over_acceptance") != truth["over_acceptance"]:
                problems.append(
                    f"{truth['task_id']}: committed {have.get('over_acceptance')} "
                    f"but enumeration says {truth['over_acceptance']}"
                )
        for key in set(committed) - set(recomputed):
            problems.append(f"stale entry {committed[key].get('task_id', key[:12])} (no such task)")

        for m in problems:
            print(f"MISMATCH {m}", file=sys.stderr)
        if problems:
            print(
                f"\n{len(problems)} problem(s). The committed answers do not match a fresh "
                f"enumeration. Regenerate with --write after confirming the task change was "
                f"intended.",
                file=sys.stderr,
            )
            return 1
        print(f"{len(recomputed)} of {len(recomputed)} answers match a fresh enumeration.")
        print("The precomputed ground truth is a cache, not a claim.")
        return 0

    if args.command == "score":
        try:
            answers = json.loads(args.answers.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        if not isinstance(answers, list):
            print("error: answers file must be a JSON list", file=sys.stderr)
            return 2
        try:
            score = score_submission(tasks, answers, tool=args.tool)
        except (ValueError, KeyError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        print(json.dumps(score.to_dict(), indent=2) if args.json else score.summary())
        return 0 if score.is_sound else 1

    if args.command == "submit":
        try:
            answers = json.loads(args.answers.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

        if not isinstance(answers, list):
            print(
                f"error: a submission is a JSON list of answers, got "
                f"{type(answers).__name__}. Each entry looks like "
                f'{{"task_id": "bounds-000", "verdict": "SOUND"}}.',
                file=sys.stderr,
            )
            return 2

        problems = validate_submission(tasks, answers)
        errors = [p for p in problems if p.severity == "error"]
        warnings = [p for p in problems if p.severity == "warning"]

        for p in errors:
            print(f"error: {p.message}", file=sys.stderr)
        for p in warnings:
            print(f"note: {p.message}", file=sys.stderr)
        if errors:
            print(
                f"\n{len(errors)} problem(s) must be fixed before this submission is "
                f"meaningful. Nothing was scored.",
                file=sys.stderr,
            )
            return 2

        try:
            score = score_submission(tasks, answers, tool=args.tool)
        except (ValueError, KeyError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

        if args.json:
            print(json.dumps(score.to_dict(), indent=2))
            return 0 if score.is_sound else 1

        print(score.summary())
        print()
        print("Your row, as it would appear on the leaderboard:")
        print()
        # Same formatter the leaderboard uses, so the row a submitter sees here
        # is character-for-character the row that would be published.
        print(_header())
        print(_fmt_row(score))
        print()
        if score.is_sound:
            print("The gate passed: nothing unsound was certified as sound.")
        else:
            print(
                "The gate FAILED. At least one unsound guard was certified as SOUND, and no\n"
                "other column redeems that. The ids are listed above -- start there."
            )
        return 0 if score.is_sound else 1

    if args.command == "baseline":
        answers = run_baseline(args.name, tasks)
        if not answers:
            print(
                f"baseline {args.name!r} produced no answers "
                f"(is the optional dependency installed?)",
                file=sys.stderr,
            )
            return 2
        score = score_submission(tasks, answers, tool=args.name)
        print(json.dumps(score.to_dict(), indent=2) if args.json else score.summary())
        return 0 if score.is_sound else 1

    if args.command == "leaderboard":
        scores: list[Score] = []
        for name in sorted(BASELINES):
            answers = run_baseline(name, tasks)
            if not answers:
                continue
            scores.append(score_submission(tasks, answers, tool=name))

        # Sound tools first, then by coverage, then by decisiveness.
        scores.sort(key=lambda s: (not s.is_sound, -(s.coverage or 0), -s.decisiveness))

        if args.json:
            print(json.dumps([s.to_dict() for s in scores], indent=2))
            return 0

        print(f"soundnessbench leaderboard -- {len(tasks)} tasks")
        print(_header())
        for s in scores:
            print(_fmt_row(s))
        print()
        print("  gate FAIL = the tool certified at least one unsound guard as SOUND.")
        print("  A failing gate is not redeemable by any other column.")
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
