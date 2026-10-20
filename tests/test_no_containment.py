"""Dream Run 1 item 4: no containment on benign or unknown verdicts (offline).

About 9-10 runs proposed containment on a FALSE_POSITIVE or INSUFFICIENT_DATA
verdict, e.g. a password reset plus MFA re-register for the benign traveler.
Containment is for COMPROMISED and SUSPICIOUS. On the other two verdicts code
moves each step into recommended actions (the analyst's call), so there is
nothing to approve.
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(Path(__file__).parent))

from itdr_agent import adjudicator as adj  # noqa: E402
from itdr_agent.human import ScriptedReviewer  # noqa: E402
from itdr_agent.schemas import AdjudicatorOutput, Verdict  # noqa: E402
from test_orchestrator import _audit, _dossier, _orchestrator, _report  # noqa: E402

RESET = {"step": "Reset the password", "rollback": "Issue a new temporary password"}


def _parsed(**overrides) -> AdjudicatorOutput:
    return AdjudicatorOutput.model_validate_json(_report(**overrides))


def test_false_positive_steps_move_to_recommended_actions():
    report = adj.apply_no_containment_guard(
        _parsed(verdict="FALSE_POSITIVE", containment_steps=[RESET])
    )
    assert report.containment_steps == []
    assert report.moved_containment_steps == 1
    assert report.recommended_actions[0] == "Contact the user"
    assert "Reset the password" in report.recommended_actions[1]
    assert "Issue a new temporary password" in report.recommended_actions[1]
    assert "No-containment guard" in report.audit_notes


def test_insufficient_data_steps_move_too():
    report = adj.apply_no_containment_guard(
        _parsed(verdict="INSUFFICIENT_DATA", containment_steps=[RESET])
    )
    assert report.containment_steps == []
    assert report.moved_containment_steps == 1


def test_compromised_and_suspicious_keep_their_steps():
    for verdict in ("COMPROMISED", "SUSPICIOUS"):
        report = adj.apply_no_containment_guard(
            _parsed(verdict=verdict, containment_steps=[RESET])
        )
        assert len(report.containment_steps) == 1
        assert report.moved_containment_steps == 0
        assert report.audit_notes == ""


def test_no_steps_means_no_note():
    report = adj.apply_no_containment_guard(
        _parsed(verdict="FALSE_POSITIVE", containment_steps=[])
    )
    assert report.moved_containment_steps == 0
    assert report.audit_notes == ""


def test_low_confidence_becomes_insufficient_data_then_loses_its_steps(tmp_path):
    # Confidence 0.5 is coerced to INSUFFICIENT_DATA first, so the steps move.
    reviewer = ScriptedReviewer()
    orch, _llm, audit = _orchestrator(
        tmp_path,
        _dossier(),
        [_report(verdict="SUSPICIOUS", confidence=0.5)],
        reviewer=reviewer,
    )
    result = orch.run({"id": "ALERT_001"}, run_id="r-low")
    assert result.report.verdict is Verdict.INSUFFICIENT_DATA
    assert result.report.containment_steps == []
    # Nothing was put in front of the analyst to approve.
    events = [e["event"] for e in _audit(audit)]
    assert "containment_decision" not in events
    moved = [e for e in _audit(audit) if e["event"] == "containment_moved"]
    assert moved and moved[0]["steps"] == 1
    assert moved[0]["verdict"] == "INSUFFICIENT_DATA"


def test_compromised_run_still_reviews_its_steps(tmp_path):
    orch, _llm, audit = _orchestrator(tmp_path, _dossier(), [_report()])
    result = orch.run({"id": "ALERT_001"}, run_id="r-comp")
    assert result.report.verdict is Verdict.COMPROMISED
    events = [e["event"] for e in _audit(audit)]
    assert "containment_decision" in events
    assert "containment_moved" not in events
