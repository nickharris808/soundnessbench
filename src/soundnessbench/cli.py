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
from .scoring import Score, score_submission, validate_submission
from .tasks import generate_suite


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

    p_ds = sub.add_parser("dataset", help="export the suite as JSONL for a dataset hub")
    p_ds.add_argument("--out", type=Path, required=True)
    p_ds.add_argument(
        "--with-answers", action="store_true", help="include ground truth (the public split does)"
    )

    args = parser.parse_args(argv)
    tasks = generate_suite()

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
