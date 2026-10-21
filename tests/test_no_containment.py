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


# --- Review 2026-10-21 finding 2: a moved step kept its unsafe undo ---------
# apply_no_containment_guard ran before the rollback guards, so a benign
# verdict's step landed in recommended actions as "(undo: Revert the password
# to its previous value)" with no flag. Now: known one-way steps get the
# standard rollback before the move, anything still unsafe is marked in the
# action text, recorded in moved_unsafe_rollbacks, and logged.

from itdr_agent.adjudicator import Adjudicator  # noqa: E402
from test_orchestrator import CompleteLLM  # noqa: E402

UNSAFE_UNKNOWN = {"step": "Lock the account",
                  "rollback": "Restore the old password"}
UNSAFE_RESET = {"step": "Reset the user's password",
                "rollback": "Revert the password to its previous value"}


def _benign_report(**overrides) -> str:
    return _report(verdict="FALSE_POSITIVE", confidence=0.9,
                   mitre_techniques_observed=[], **overrides)


def test_moved_step_with_an_unsafe_undo_is_flagged():
    report = adj.apply_no_containment_guard(
        _parsed(verdict="FALSE_POSITIVE", containment_steps=[UNSAFE_UNKNOWN])
    )
    (action,) = report.recommended_actions[1:]
    assert "Lock the account" in action
    assert "WARNING" in action and "credential" in action
    assert report.moved_unsafe_rollbacks == [0]
    assert "restore a credential" in report.audit_notes.lower()


def test_moved_safe_undo_is_not_flagged():
    report = adj.apply_no_containment_guard(
        _parsed(verdict="FALSE_POSITIVE", containment_steps=[RESET])
    )
    assert "WARNING" not in report.recommended_actions[1]
    assert report.moved_unsafe_rollbacks == []


def test_moved_one_way_step_gets_the_standard_rollback_first():
    llm = CompleteLLM([_benign_report(containment_steps=[UNSAFE_RESET])])
    report = Adjudicator(llm, baseline=None).adjudicate(
        _dossier(sign_in_history=[
            {"id": f"s{i}", "createdDateTime": f"2025-01-15T0{i}:00:00Z",
             "riskEventTypes_v2": []} for i in range(4)
        ])
    )
    assert report.verdict is Verdict.FALSE_POSITIVE
    assert report.containment_steps == []
    (action,) = report.recommended_actions[1:]
    assert adj.STANDARD_ROLLBACKS["password_reset"] in action
    assert "Revert the password" not in action
    assert report.moved_unsafe_rollbacks == []
    assert report.standard_rollbacks == [0]


def test_model_cannot_fill_moved_unsafe_rollbacks_itself():
    import json

    raw = json.loads(_benign_report())
    raw["moved_unsafe_rollbacks"] = [7]
    report = Adjudicator(CompleteLLM([json.dumps(raw)]), baseline=None).adjudicate(
        _dossier(sign_in_history=[
            {"id": f"s{i}", "createdDateTime": f"2025-01-15T0{i}:00:00Z",
             "riskEventTypes_v2": []} for i in range(4)
        ])
    )
    assert report.moved_unsafe_rollbacks == []


def test_moved_unsafe_undo_is_logged(tmp_path):
    orch, _llm, audit = _orchestrator(
        tmp_path, _dossier(), [_benign_report(containment_steps=[UNSAFE_UNKNOWN])]
    )
    result = orch.run({"id": "ALERT_006"}, run_id="r-moved-unsafe")
    assert result.report.containment_steps == []
    events = _audit(audit)
    assert "containment_decision" not in [e["event"] for e in events]
    (moved,) = [e for e in events if e["event"] == "containment_moved"]
    assert moved["steps"] == 1
    assert moved["unsafe_rollbacks"] == [0]
