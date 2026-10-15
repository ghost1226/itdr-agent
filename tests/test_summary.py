"""GUI batch 1, feature 2 — pure alert summaries (no model, no network).

``summary.py`` reads only fields in ``ALERT_FIELD_ALLOWLIST``. It must never
read ground truth (``scenario`` / ``expected_*`` / ``is_benign``) and must
never include the source IP address.
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

try:
    from itdr_agent.summary import (  # noqa: E402
        incident_note,
        severity,
        short_summary,
        stage,
        what,
    )
except ModuleNotFoundError:  # red phase: module not written yet
    pass

from itdr_agent.schemas import AdjudicatorOutput, ContainmentStep  # noqa: E402


def _alert(**overrides) -> dict:
    alert = {
        "id": "ALERT_001",
        "createdDateTime": "2025-01-15T09:00:00Z",
        "userPrincipalName": "alice.traveler@contoso.com",
        "appDisplayName": "Microsoft Teams",
        "ipAddress": "203.0.113.10",
        "location": {
            "city": "New York",
            "state": "NY",
            "countryOrRegion": "US",
            "geoCoordinates": {"latitude": 40.7128, "longitude": -74.006},
        },
        "riskLevelAggregated": "high",
        "riskState": "atRisk",
        "riskEventTypes_v2": ["unlikelyTravel"],
        "status": {"errorCode": 0, "failureReason": ""},
    }
    alert.update(overrides)
    return alert


def _result(
    verdict: str = "COMPROMISED",
    confidence: float = 0.9,
    narrative: str = "Evidence supports unlikely-travel sign-ins.",
    steps: list[dict] | None = None,
    recommended: list[str] | None = None,
    techniques: list[str] | None = None,
) -> SimpleNamespace:
    report = AdjudicatorOutput(
        verdict=verdict,
        confidence=confidence,
        narrative=narrative,
        containment_steps=[ContainmentStep(**s) for s in (steps or [])],
        recommended_actions=recommended or ["Contact the user"],
        mitre_techniques_observed=techniques or [],
        audit_notes="",
    )
    return SimpleNamespace(report=report)


class _TrackingDict(dict):
    """A dict that records which top-level keys were read."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.read: set[str] = set()

    def get(self, key, default=None):
        self.read.add(key)
        return super().get(key, default)

    def __getitem__(self, key):
        self.read.add(key)
        return super().__getitem__(key)


# --- what ------------------------------------------------------------------


def test_what_maps_each_risk_event():
    assert what(_alert(riskEventTypes_v2=["unlikelyTravel"])) == "Unlikely travel"
    assert (
        what(_alert(riskEventTypes_v2=["anonymizedIPAddress"]))
        == "Anonymous IP address"
    )
    assert (
        what(_alert(riskEventTypes_v2=["unfamiliarFeatures"]))
        == "Unfamiliar sign-in properties"
    )


def test_what_empty_is_neutral():
    assert what(_alert(riskEventTypes_v2=[])) == (
        "Sign-in flagged with no risk detection"
    )


def test_what_joins_several_with_plus():
    assert what(
        _alert(riskEventTypes_v2=["unlikelyTravel", "anonymizedIPAddress"])
    ) == "Unlikely travel + Anonymous IP address"


# --- stage -----------------------------------------------------------------


def test_stage_success():
    assert stage(_alert()) == "Successful (session created)"


def test_stage_mfa_denied():
    alert = _alert(
        status={
            "errorCode": 500121,
            "failureReason": "Authentication failed: MFA denied by user",
        }
    )
    assert stage(alert) == "Blocked (MFA denied)"


def test_stage_other_failure_uses_reason():
    alert = _alert(
        status={
            "errorCode": 50126,
            "failureReason": "Invalid username or password",
        }
    )
    assert stage(alert) == "Attempted (failed: Invalid username or password)"


def test_stage_never_says_compromised():
    for code in (0, 500121, 50126):
        alert = _alert(status={"errorCode": code, "failureReason": "x"})
        assert "compromised" not in stage(alert).lower()


# --- severity --------------------------------------------------------------


def test_severity_bars():
    assert severity(_alert(riskLevelAggregated="high")) == "■■■ High"
    assert severity(_alert(riskLevelAggregated="medium")) == "■■□ Medium"
    assert severity(_alert(riskLevelAggregated="low")) == "■□□ Low"
    assert severity(_alert(riskLevelAggregated="none")) == "□□□ None"


# --- short_summary ---------------------------------------------------------


def test_short_summary_is_one_line():
    summary = short_summary(_alert())
    assert "\n" not in summary
    assert "ALERT_001" in summary
    assert "alice.traveler@contoso.com" in summary
    assert "Unlikely travel" in summary
    assert "Successful (session created)" in summary


# --- no ground truth, no IP ------------------------------------------------


def test_summaries_never_read_ground_truth_or_ip():
    alert = _alert(
        scenario="SENTINEL_SCENARIO",
        expected_verdict="SENTINEL_VERDICT",
        expected_mitre=["SENTINEL_MITRE"],
        is_benign="SENTINEL_BENIGN",
    )
    blob = "\n".join(
        [
            what(alert),
            stage(alert),
            severity(alert),
            short_summary(alert),
            incident_note(alert, _result()),
        ]
    )
    for sentinel in (
        "SENTINEL_SCENARIO",
        "SENTINEL_VERDICT",
        "SENTINEL_MITRE",
        "SENTINEL_BENIGN",
    ):
        assert sentinel not in blob
    assert "203.0.113.10" not in blob


def test_summaries_read_only_allowlisted_fields():
    from itdr_agent.data_generator import ALERT_FIELD_ALLOWLIST

    tracking = _TrackingDict(_alert())
    what(tracking)
    stage(tracking)
    severity(tracking)
    short_summary(tracking)
    incident_note(tracking, _result())
    assert tracking.read <= set(ALERT_FIELD_ALLOWLIST)


# --- incident_note ---------------------------------------------------------


def test_incident_note_layout():
    alert = _alert()
    result = _result(
        verdict="COMPROMISED",
        narrative="Evidence supports unlikely-travel sign-ins.",
        steps=[
            {
                "step": "Disable the account pending analyst review",
                "rollback": "Re-enable if legitimate.",
            }
        ],
        recommended=["Confirm the activity with the user out-of-band"],
    )
    note = incident_note(alert, result)
    lines = note.splitlines()
    assert lines[0] == "Alert: ALERT_001"
    assert lines[1] == "What: Unlikely travel involving one user"
    assert lines[2] == "User: alice.traveler@contoso.com"
    assert lines[3].startswith(
        "Analysis: The affected user triggered Unlikely travel involving "
        "Microsoft Teams."
    )
    assert "The sign-in originated from New York, US." in note
    assert "IP reputation: not available in this dataset." in note
    assert "Authentication result: Successful (session created)." in note
    assert "Evidence supports unlikely-travel sign-ins." in note
    assert (
        "Conclusion: This appears to be likely account compromise. "
        "Stage: Successful (session created)."
    ) in note
    assert "Disable the account pending analyst review" in note
    assert "Confirm the activity with the user out-of-band" in note


def test_incident_note_false_positive_conclusion():
    note = incident_note(
        _alert(riskEventTypes_v2=[]),
        _result(verdict="FALSE_POSITIVE", steps=[], narrative="Benign."),
    )
    assert "Conclusion: This appears to be a false positive. Stage: " in note


def test_incident_note_insufficient_data_conclusion():
    note = incident_note(
        _alert(riskEventTypes_v2=[]),
        _result(
            verdict="INSUFFICIENT_DATA",
            confidence=0.4,
            steps=[],
            narrative="Not enough evidence.",
        ),
    )
    assert (
        "Conclusion: Not enough data to decide; escalate for manual review. "
        "Stage: "
    ) in note


def test_incident_note_no_action_required():
    note = incident_note(
        _alert(), _result(steps=[], recommended=["Continue monitoring"])
    )
    assert "No action required" in note
    assert "Continue monitoring" in note
