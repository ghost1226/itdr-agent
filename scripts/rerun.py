"""One command for the post-fix re-runs (2026-10-23).

Joe's plan: ALERT_006 x3 and ALERT_004 x3 (the two model misses), then
ALERT_009 (thin data) and ALERT_010 (unknown user) once each — re-checked on
the fixed code. This script encodes that plan, groups the alerts by run count,
and drives the same ``scripts/evaluate.py`` harness, so the daily request
budget and the resume state are shared across the groups.

    python scripts/rerun.py --dry-run    # offline: scripted models, no key
    python scripts/rerun.py --live       # real free model; spends requests

The plan lives in ``eval/rerun/``. A run starts only if its worst case fits
the day's budget (``DEFAULT_DAILY_BUDGET``), so run the same command again
tomorrow to continue; it picks up where it stopped. ``--alerts`` and
``--runs`` override the plan for a one-off check.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from itdr_agent import config  # noqa: E402

import evaluate  # noqa: E402

# Windows: a redirected stdout may be cp1252; keep a non-ASCII verdict from
# crashing the command (same guard as ``itdr_agent/__main__.py``).
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

RERUN_PLAN: dict[str, int] = {
    "ALERT_006": 3,
    "ALERT_004": 3,
    "ALERT_009": 1,
    "ALERT_010": 1,
}


def group_plan(plan: dict[str, int]) -> dict[int, list[str]]:
    """``{alert_id: runs}`` -> ``{runs: [alert_id, ...]}`` (counts high first)."""
    groups: dict[int, list[str]] = {}
    for alert_id, count in plan.items():
        groups.setdefault(count, []).append(alert_id)
    return {
        count: sorted(ids) for count, ids in sorted(groups.items(), reverse=True)
    }


def build_plan(alerts: list[str] | None, runs: int | None) -> dict[str, int]:
    """The plan to run: explicit ``--alerts``/``--runs``, else ``RERUN_PLAN``."""
    ids = list(alerts) if alerts else list(RERUN_PLAN)
    if runs is not None:
        return {alert_id: runs for alert_id in ids}
    return {
        alert_id: RERUN_PLAN.get(alert_id, evaluate.RUNS_PER_ALERT)
        for alert_id in ids
    }


def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _report(run_dir: Path, ground_truth: dict, plan: dict[str, int], model: str) -> None:
    """Print each planned alert's per-run verdict against the ground truth."""
    by_alert: dict[str, list[dict]] = {}
    for record in _read_jsonl(run_dir / "raw.jsonl"):
        if record.get("model") == model:
            by_alert.setdefault(record["alert_id"], []).append(record)

    print()
    print("Re-run results (verdict per run vs ground truth):")
    all_green = True
    for alert_id in sorted(plan):
        expected = ground_truth[alert_id]["expected_verdict"]
        runs = sorted(by_alert.get(alert_id, []), key=lambda r: r["run"])
        if not runs:
            all_green = False
            print(f"  {alert_id}  expected {expected:<16} no runs yet")
            continue
        verdicts = [r.get("verdict") or f"error({r.get('error')})" for r in runs]
        matches = sum(1 for verdict in verdicts if verdict == expected)
        green = matches == len(verdicts)
        all_green = all_green and green
        flag = "" if green else "   <-- CHECK"
        print(
            f"  {alert_id}  expected {expected:<16} {matches}/{len(verdicts)} match  "
            + ", ".join(verdicts)
            + flag
        )
    planned = sum(plan.values())
    finished = sum(len(by_alert.get(alert_id, [])) for alert_id in plan)
    if all_green and finished == planned:
        print("All planned runs finished and every run matches the ground truth.")
    else:
        print(
            f"{finished} of {planned} planned runs finished. Run the same command "
            "again to continue (the daily budget resumes where it stopped)."
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="rerun", description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true",
                      help="offline: scripted models, no key, no network")
    mode.add_argument("--live", action="store_true",
                      help="real free model; spends daily requests")
    parser.add_argument("--alerts", nargs="+",
                        help="default: the plan's four alerts")
    parser.add_argument("--runs", type=int,
                        help="one run count for every chosen alert")
    parser.add_argument("--model",
                        default=os.getenv("EVAL_MODEL", evaluate.EVAL_DEFAULT_MODEL))
    parser.add_argument("--daily-budget", type=int,
                        default=evaluate.DEFAULT_DAILY_BUDGET)
    parser.add_argument("--eval-dir", default=None, help="default: eval/rerun/")
    args = parser.parse_args(argv)

    eval_dir = Path(args.eval_dir or PROJECT_ROOT / "eval" / "rerun")
    plan = build_plan(args.alerts, args.runs)

    alerts = evaluate.load_alerts(evaluate.FIXTURES / "alerts.jsonl")
    ground_truth = evaluate.load_ground_truth(evaluate.FIXTURES / "ground_truth.jsonl")
    unknown = sorted(set(plan) - {alert["id"] for alert in alerts})
    if unknown:
        print(f"Unknown alert ids: {unknown}")
        return 2

    if not (args.dry_run or args.live):
        print("Choose --dry-run (offline, no key) or --live (spends free requests).")
        return 2

    if args.dry_run:
        run_dir = eval_dir / "dry_run"
        if run_dir.exists():
            shutil.rmtree(run_dir)
        runner = evaluate.make_offline_runner(ground_truth, run_dir / "audit.jsonl")
        model, daily_budget, dry_run = "offline-dry-run", 10**9, True
        extra: dict = {"sleep": lambda _seconds: None}
    else:
        if not config.OPENROUTER_API_KEY:
            print("OPENROUTER_API_KEY is not set. Add it to .env (gitignored).")
            return 2
        run_dir = eval_dir
        timeout = min(config.TIMEOUT_SECONDS, 90)
        runner = evaluate.make_live_runner(
            config.OPENROUTER_API_KEY, args.model, timeout,
            run_dir / "audit.jsonl", total_timeout=config.TIMEOUT_SECONDS,
        )
        model, daily_budget, dry_run = args.model, args.daily_budget, False
        extra = {}

    print("Re-run plan: " + ", ".join(f"{a} x{c}" for a, c in plan.items()))
    print(f"Model: {model}   Budget: {daily_budget} requests/UTC day")

    completed = 0
    stopped: str | None = None
    for count, ids in sorted(group_plan(plan).items(), reverse=True):
        summary = evaluate.run_evaluation(
            alerts, ground_truth, runner,
            runs_per_alert=count, eval_dir=run_dir, model=model,
            daily_budget=daily_budget, dry_run=dry_run, only=set(ids),
            **extra,
        )
        completed += summary.completed_this_session
        if summary.stopped_reason:
            stopped = summary.stopped_reason
            break

    print(f"Runs finished this session: {completed}")
    if stopped:
        print(f"Stopped: {stopped}.")
    _report(run_dir, ground_truth, plan, model)
    print(f"Results: {run_dir / 'results.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
