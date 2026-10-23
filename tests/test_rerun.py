"""One-command re-run of the four post-fix alerts (2026-10-23), offline.

``scripts/rerun.py`` encodes Joe's plan — ALERT_006 x3, ALERT_004 x3,
ALERT_009 and ALERT_010 once each — groups the alerts by run count, and drives
the same ``scripts/evaluate.py`` harness so the daily request budget and the
resume state are shared. These tests use ``--dry-run`` only: no key, no
network, no live tokens.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

import rerun  # noqa: E402
from itdr_agent import config  # noqa: E402

PLAN = {"ALERT_006": 3, "ALERT_004": 3, "ALERT_009": 1, "ALERT_010": 1}


def _records(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _counts(path: Path) -> dict[str, int]:
    counts: dict[str, int] = {}
    for record in _records(path):
        counts[record["alert_id"]] = counts.get(record["alert_id"], 0) + 1
    return counts


# --- the plan ---------------------------------------------------------------


def test_the_plan_is_joe_s_four_alert_recheck():
    assert rerun.RERUN_PLAN == PLAN
    assert sum(PLAN.values()) == 8


def test_group_plan_groups_alerts_by_run_count():
    assert rerun.group_plan(PLAN) == {
        3: ["ALERT_004", "ALERT_006"],
        1: ["ALERT_009", "ALERT_010"],
    }


def test_group_plan_sorts_and_is_stable():
    assert rerun.group_plan({"B": 1, "A": 1, "C": 2}) == {2: ["C"], 1: ["A", "B"]}


def test_build_plan_defaults_to_the_plan():
    assert rerun.build_plan(None, None) == PLAN


def test_build_plan_takes_explicit_alerts_and_runs():
    assert rerun.build_plan(["ALERT_001", "ALERT_002"], 2) == {
        "ALERT_001": 2,
        "ALERT_002": 2,
    }
    assert rerun.build_plan(["ALERT_009"], None) == {"ALERT_009": 1}
    assert rerun.build_plan(["ALERT_001"], None) == {"ALERT_001": 3}


# --- the command ------------------------------------------------------------


def test_dry_run_writes_exactly_the_planned_runs(tmp_path):
    code = rerun.main(["--dry-run", "--eval-dir", str(tmp_path)])
    assert code == 0
    assert _counts(tmp_path / "dry_run" / "raw.jsonl") == PLAN
    assert (tmp_path / "dry_run" / "results.md").exists()


def test_alerts_and_runs_override_the_plan(tmp_path):
    code = rerun.main(
        ["--dry-run", "--alerts", "ALERT_001", "--runs", "2", "--eval-dir", str(tmp_path)]
    )
    assert code == 0
    records = _records(tmp_path / "dry_run" / "raw.jsonl")
    assert len(records) == 2
    assert {record["alert_id"] for record in records} == {"ALERT_001"}


def test_rerun_needs_a_mode(tmp_path, capsys):
    assert rerun.main(["--eval-dir", str(tmp_path)]) == 2
    assert "--dry-run" in capsys.readouterr().out


def test_live_without_a_key_stops_before_any_request(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(config, "OPENROUTER_API_KEY", "")
    assert rerun.main(["--live", "--eval-dir", str(tmp_path)]) == 2
    assert "OPENROUTER_API_KEY" in capsys.readouterr().out
    assert not (tmp_path / "raw.jsonl").exists()


def test_unknown_alert_is_rejected(tmp_path, capsys):
    code = rerun.main(
        ["--dry-run", "--alerts", "ALERT_999", "--eval-dir", str(tmp_path)]
    )
    assert code == 2
    assert "ALERT_999" in capsys.readouterr().out
