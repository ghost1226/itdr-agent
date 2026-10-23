"""Build ``docs/test-cases.md``: one row per alert, expected vs observed.

Reads ``eval/final/raw.jsonl`` (3 runs per alert), ``eval/after-fix/raw.jsonl``
(1 run per alert) and ``data/fixtures/ground_truth.jsonl``. Offline: no key,
no network. Deterministic — the same inputs give a byte-identical file, and a
test proves the committed file is a fresh render.

    python scripts/test_cases_table.py
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Windows: a redirected stdout may be cp1252; keep output from crashing.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

FINAL_DEFAULT = PROJECT_ROOT / "eval" / "final" / "raw.jsonl"
AFTER_FIX_DEFAULT = PROJECT_ROOT / "eval" / "after-fix" / "raw.jsonl"
GROUND_TRUTH_DEFAULT = PROJECT_ROOT / "data" / "fixtures" / "ground_truth.jsonl"
OUT_DEFAULT = PROJECT_ROOT / "docs" / "test-cases.md"

# One line of context for a scenario whose misses need explaining (the
# 2026-10-23 evaluation), shown before the generated per-run notes.
CONTEXT = {
    "ALERT_004": "the Investigator did not pull the OAuth consent record",
    "ALERT_006": "only 3 sign-ins in the window, exactly the thin-evidence boundary, so the guard flipped final run 1",
    "ALERT_009": "too few sign-ins: missing evidence read as benign (the guard now returns INSUFFICIENT_DATA, see the after-fix run)",
    "ALERT_007": "MITRE recall only: the verdict stayed FALSE_POSITIVE",
}


def load_jsonl(path: str | Path) -> list[dict]:
    path = Path(path)
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _by_alert(records: list[dict]) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = {}
    for record in records:
        grouped.setdefault(record["alert_id"], []).append(record)
    for runs in grouped.values():
        runs.sort(key=lambda record: record["run"])
    return grouped


def _mitre_text(techniques: list[str]) -> str:
    return ", ".join(techniques) if techniques else "no MITRE"


def _mitre_cell(techniques: list[str]) -> str:
    return ", ".join(techniques) if techniques else "none"


def _confidence(record: dict) -> str:
    value = record.get("confidence")
    return f" ({value:.2f})" if isinstance(value, (int, float)) else ""


def _run_cell(runs: list[dict]) -> str:
    if not runs:
        return "no run"
    return "; ".join(
        f"{record['run']}: {record.get('verdict')}{_confidence(record)}"
        for record in runs
    )


def _observed_cell(runs: list[dict]) -> str:
    if not runs:
        return "none"
    return " / ".join(
        _mitre_cell(list(record.get("mitre_techniques_observed") or []))
        for record in runs
    )


def _notes(label: str, runs: list[dict], expected_verdict: str, expected_mitre: list[str]):
    """One line for every run whose verdict or MITRE set differs from truth."""
    notes: list[str] = []
    for record in runs:
        verdict = record.get("verdict")
        observed = list(record.get("mitre_techniques_observed") or [])
        if verdict != expected_verdict:
            notes.append(
                f"{label} run {record['run']} said {verdict}{_confidence(record)}, "
                f"expected {expected_verdict}"
            )
        if set(observed) != set(expected_mitre):
            notes.append(
                f"{label} run {record['run']} observed {_mitre_text(observed)}, "
                f"expected {_mitre_text(expected_mitre)}"
            )
    return notes


def build_rows(
    ground_truth: list[dict], final_records: list[dict], after_fix_records: list[dict]
) -> list[dict]:
    """One row per alert, alerts sorted by id, runs sorted by run number."""
    final_by = _by_alert(final_records)
    after_by = _by_alert(after_fix_records)
    rows: list[dict] = []
    for entry in sorted(ground_truth, key=lambda item: item["alert_id"]):
        alert_id = entry["alert_id"]
        expected_verdict = entry["expected_verdict"]
        expected_mitre = list(entry.get("expected_mitre") or [])
        final_runs = final_by.get(alert_id, [])
        after_runs = after_by.get(alert_id, [])
        notes = _notes("final", final_runs, expected_verdict, expected_mitre)
        notes += _notes("after-fix", after_runs, expected_verdict, expected_mitre)
        if notes and alert_id in CONTEXT:
            notes.insert(0, CONTEXT[alert_id])
        rows.append(
            {
                "alert_id": alert_id,
                "scenario": entry.get("scenario", ""),
                "expected_verdict": expected_verdict,
                "expected_mitre": expected_mitre,
                "final": final_runs,
                "after_fix": after_runs,
                "notes": notes,
            }
        )
    return rows


def render(rows: list[dict]) -> str:
    lines = [
        "# Test cases — expected vs observed",
        "",
        "Generated by `scripts/test_cases_table.py` from `eval/final/raw.jsonl`,",
        "`eval/after-fix/raw.jsonl` and `data/fixtures/ground_truth.jsonl`. Do not",
        "edit by hand: re-run the script after a new evaluation.",
        "",
        "`Final` is the locked 30-run evaluation; `After-fix` is the",
        "one-run-per-alert check that the thin-evidence guard landed. A note appears",
        "for every run whose verdict or MITRE set differs from the ground truth.",
        "",
        "| Alert | Scenario | Expected | Final runs | After-fix runs | MITRE expected | MITRE observed | Notes |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for row in rows:
        notes = "; ".join(row["notes"]) if row["notes"] else "—"
        observed = (
            f"final: {_observed_cell(row['final'])} / "
            f"after-fix: {_observed_cell(row['after_fix'])}"
        )
        lines.append(
            "| {alert} | {scenario} | {expected} | {final} | {after} | {exp} | {obs} | {notes} |".format(
                alert=row["alert_id"],
                scenario=row["scenario"],
                expected=row["expected_verdict"],
                final=_run_cell(row["final"]),
                after=_run_cell(row["after_fix"]),
                exp=_mitre_cell(row["expected_mitre"]),
                obs=observed,
                notes=notes,
            )
        )
    lines.append("")
    return "\n".join(lines)


def write_table(path: str | Path, text: str) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")
    return path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="test_cases_table")
    parser.add_argument("--ground-truth", default=str(GROUND_TRUTH_DEFAULT))
    parser.add_argument("--final", default=str(FINAL_DEFAULT))
    parser.add_argument("--after-fix", default=str(AFTER_FIX_DEFAULT))
    parser.add_argument("--out", default=str(OUT_DEFAULT))
    args = parser.parse_args(argv)
    rows = build_rows(
        load_jsonl(args.ground_truth),
        load_jsonl(args.final),
        load_jsonl(args.after_fix),
    )
    path = write_table(args.out, render(rows))
    print(f"Wrote {len(rows)} rows to {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
