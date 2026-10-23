"""Tests for the test-cases table (Task A, 2026-10-23). Offline, no network.

``scripts/test_cases_table.py`` turns the two raw run files plus the ground
truth into one deterministic row per alert. A small fake corpus checks the
rows, the per-run verdicts and confidence, the MITRE columns and the
one-line notes; a last test proves the committed ``docs/test-cases.md`` is
exactly what a fresh render produces.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

import test_cases_table as tct  # noqa: E402

GT = [
    {
        "alert_id": "ALERT_001",
        "scenario": "impossible_travel",
        "expected_verdict": "COMPROMISED",
        "expected_mitre": ["T1078.004"],
        "is_benign": False,
    },
    {
        "alert_id": "ALERT_002",
        "scenario": "benign_vpn",
        "expected_verdict": "FALSE_POSITIVE",
        "expected_mitre": [],
        "is_benign": True,
    },
]
FINAL = [
    {"alert_id": "ALERT_001", "run": 1, "verdict": "COMPROMISED",
     "confidence": 0.9, "mitre_techniques_observed": ["T1078.004"]},
    {"alert_id": "ALERT_001", "run": 2, "verdict": "SUSPICIOUS",
     "confidence": 0.6, "mitre_techniques_observed": []},
    {"alert_id": "ALERT_002", "run": 1, "verdict": "FALSE_POSITIVE",
     "confidence": 0.9, "mitre_techniques_observed": []},
    {"alert_id": "ALERT_002", "run": 2, "verdict": "FALSE_POSITIVE",
     "confidence": 0.8, "mitre_techniques_observed": ["T1098.003"]},
]
AFTER = [
    {"alert_id": "ALERT_001", "run": 1, "verdict": "COMPROMISED",
     "confidence": 0.95, "mitre_techniques_observed": ["T1078.004"]},
]


def _render(gt=None, final=None, after=None) -> str:
    rows = tct.build_rows(gt or GT, final or FINAL, after or AFTER)
    return tct.render(rows)


def _row(text: str, alert_id: str) -> str:
    for line in text.splitlines():
        if line.startswith(f"| {alert_id} "):
            return line
    raise AssertionError(f"no row for {alert_id}")


def _write_jsonl(path: Path, records: list[dict]) -> Path:
    path.write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")
    return path


# --- rows -------------------------------------------------------------------


def test_one_row_per_alert_in_alert_id_order():
    rows = tct.build_rows(GT, FINAL, AFTER)
    assert [row["alert_id"] for row in rows] == ["ALERT_001", "ALERT_002"]


def test_each_run_is_listed_with_its_verdict_and_confidence():
    text = _render()
    row = _row(text, "ALERT_001")
    assert "COMPROMISED (0.90)" in row  # final run 1
    assert "SUSPICIOUS (0.60)" in row   # final run 2
    assert "COMPROMISED (0.95)" in row  # after-fix run 1


def test_expected_and_observed_mitre_are_both_shown():
    text = _render()
    assert "T1078.004" in _row(text, "ALERT_001")
    row2 = _row(text, "ALERT_002")
    assert "none" in row2  # expected MITRE is empty
    assert "T1098.003" in row2  # observed on final run 2


# --- notes for every miss ---------------------------------------------------


def test_a_verdict_miss_gets_a_one_line_note():
    text = _render()
    row = _row(text, "ALERT_001")
    assert "final run 2 said SUSPICIOUS (0.60), expected COMPROMISED" in row


def test_a_mitre_miss_gets_a_one_line_note_even_when_the_verdict_is_right():
    text = _render()
    row = _row(text, "ALERT_002")
    assert "final run 2 observed T1098.003, expected no MITRE" in row


def test_an_alert_with_no_miss_has_no_note():
    only_good_final = [r for r in FINAL if r["alert_id"] == "ALERT_001" and r["run"] == 1]
    text = _render(final=only_good_final)
    assert "—" in _row(text, "ALERT_001")


# --- deterministic + the command --------------------------------------------


def test_render_is_deterministic():
    assert _render() == _render()


def test_render_sorts_runs_by_run_number():
    shuffled = [FINAL[1], FINAL[0], FINAL[3], FINAL[2]]
    assert _render(final=shuffled) == _render()


def test_main_writes_the_table_from_the_given_paths(tmp_path):
    gt = _write_jsonl(tmp_path / "gt.jsonl", GT)
    final = _write_jsonl(tmp_path / "final.jsonl", FINAL)
    after = _write_jsonl(tmp_path / "after.jsonl", AFTER)
    out = tmp_path / "test-cases.md"
    code = tct.main([
        "--ground-truth", str(gt), "--final", str(final),
        "--after-fix", str(after), "--out", str(out),
    ])
    assert code == 0
    text = out.read_text(encoding="utf-8")
    assert "| ALERT_001 " in text and "| ALERT_002 " in text
    assert text == _render()


def test_the_committed_table_is_a_fresh_render():
    gt = tct.load_jsonl(PROJECT_ROOT / "data" / "fixtures" / "ground_truth.jsonl")
    final = tct.load_jsonl(PROJECT_ROOT / "eval" / "final" / "raw.jsonl")
    after = tct.load_jsonl(PROJECT_ROOT / "eval" / "after-fix" / "raw.jsonl")
    fresh = tct.render(tct.build_rows(gt, final, after))
    committed = (PROJECT_ROOT / "docs" / "test-cases.md").read_text(encoding="utf-8")
    assert committed == fresh
