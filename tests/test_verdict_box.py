"""Verdict box in Joe's ticket format (offline, no model, no network).

Before the analyst decides, the GUI box shows: a one-sentence "What happened"
built by code from the evidence, the verdict and the model's narrative word
for word, then Alert / What / User / Analysis / Action. Never the source IP
(Joe, 2026-10-14), never the answer key.
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(Path(__file__).parent))

try:
    from itdr_agent.summary import found, ticket_lines, what_happened  # noqa: E402
except ImportError:  # red phase
    pass

from itdr_agent.schemas import (  # noqa: E402
    AdjudicatorOutput,
    ContainmentStep,
    InvestigatorOutput,
)
from itdr_agent.summary import incident_note  # noqa: E402

BOB = "bob.fatigue@contoso.com"
NARRATIVE = (
    "The user experienced a series of MFA push notification denials across "
    "multiple applications and devices, followed by a successful "
    "authentication."
)


def _alert(**overrides) -> dict:
    alert = {
        "id": "ALERT_002",
        "createdDateTime": "2025-01-15T09:00:00Z",
        "userPrincipalName": BOB,
        "appDisplayName": "Microsoft Teams",
        "ipAddress": "203.0.113.77",
        "location": {"city": "Seattle", "countryOrRegion": "US"},
        "riskLevelAggregated": "none",
        "riskEventTypes_v2": [],
        "status": {"errorCode": 500121,
                   "failureReason": "Authentication failed: MFA denied by user"},
    }
    alert.update(overrides)
    return alert


def _sign_in(i: int, denied: bool) -> dict:
    return {
        "id": f"s{i}",
        "createdDateTime": f"2025-01-15T09:0{i}:00Z",
        "ipAddress": "203.0.113.77",
        "riskEventTypes_v2": [],
        "status": {
            "errorCode": 500121 if denied else 0,
            "failureReason": "Authentication failed: MFA denied by user"
            if denied else "",
        },
    }


def _dossier(**overrides) -> InvestigatorOutput:
    base = dict(
        alert_id="ALERT_002",
        user_principal_name=BOB,
        user_profile={"userPrincipalName": BOB},
        sign_in_history=[_sign_in(i, i < 4) for i in range(9)],
        directory_audits=[],
        risk_indicators=["mfaFatigue"],
        mitre_attack_mapping=["T1621"],
        mitre_attack_evidence={"T1621": ["s0", "s1", "s2"]},
    )
    base.update(overrides)
    return InvestigatorOutput(**base)


def _report(**overrides) -> AdjudicatorOutput:
    base = dict(
        verdict="COMPROMISED",
        confidence=0.86,
        narrative=NARRATIVE,
        containment_steps=[
            ContainmentStep(step="Reset MFA and require re-registration",
                            rollback="Re-register after identity check"),
            ContainmentStep(step="Revoke all sessions",
                            rollback="User signs in again"),
        ],
        recommended_actions=["Contact the user"],
        mitre_techniques_observed=["T1621"],
    )
    base.update(overrides)
    return AdjudicatorOutput(**base)


def test_found_uses_the_evidence_not_just_the_alert():
    assert found(_alert(), _dossier()) == "MFA fatigue"
    # No dossier yet: falls back to the alert's own risk detections.
    assert found(_alert(), None) == "Sign-in flagged with no risk detection"
    travel = _alert(riskEventTypes_v2=["unlikelyTravel"])
    both = _dossier(mitre_attack_evidence={"T1078.004": ["s1"], "T1621": ["s0"]})
    assert found(travel, both) == "Unlikely travel + MFA fatigue"


def test_what_happened_sentence():
    text = what_happened(_alert(), _report(), _dossier())
    assert text.startswith(f"{BOB} had 9 sign-ins in the window: 5 succeeded, "
                           "4 failed with MFA denied.")
    assert "Alerted sign-in: Blocked (MFA denied) on Microsoft Teams from Seattle, US." in text
    assert "Found: MFA fatigue (T1621)." in text
    assert text.endswith("This appears to be likely account compromise.")


def test_what_happened_with_no_sign_ins():
    empty = _dossier(sign_in_history=[], mitre_attack_evidence={},
                     risk_indicators=[])
    text = what_happened(_alert(), _report(verdict="INSUFFICIENT_DATA",
                                           confidence=0.0), empty)
    assert text.startswith(f"{BOB} had 0 sign-ins in the window.")
    assert "Found:" not in text


def test_ticket_lines_in_joes_format():
    lines = ticket_lines(_alert(), _report(), _dossier())
    assert lines[0] == "Alert: ALERT_002"
    assert lines[1] == "What: MFA fatigue involving one user"
    assert lines[2] == f"User: {BOB}"
    assert lines[3].startswith(
        "Analysis: The user's account was flagged for MFA fatigue on "
        "Microsoft Teams from Seattle, US."
    )
    assert "9 sign-ins in the window, 4 failed with MFA denied" in lines[3]
    assert "IP reputation: not available in this dataset." in lines[3]
    assert lines[4] == (
        "Action: Proposed, each step needs your approval below: "
        "Reset MFA and require re-registration; Revoke all sessions"
    )


def test_ticket_action_with_no_steps():
    lines = ticket_lines(_alert(), _report(containment_steps=[],
                                           verdict="FALSE_POSITIVE"), _dossier())
    assert lines[4] == "Action: No containment proposed; monitor the user's account."


@pytest.mark.parametrize("fn", ["what_happened", "ticket_lines"])
def test_no_ip_and_no_answer_key(fn):
    import itdr_agent.summary as summary

    alert = _alert(scenario="SENTINEL_SCENARIO", expected_verdict="SENTINEL_V")
    out = getattr(summary, fn)(alert, _report(), _dossier())
    blob = out if isinstance(out, str) else "\n".join(out)
    assert "203.0.113.77" not in blob
    assert "SENTINEL" not in blob


def test_incident_note_uses_the_found_what_when_a_dossier_exists():
    result = SimpleNamespace(report=_report(), dossier=_dossier())
    note = incident_note(_alert(), result)
    assert "What: MFA fatigue involving one user" in note


def test_gui_box_shows_summary_narrative_and_ticket(tmp_path, monkeypatch):
    pytest.importorskip("streamlit")
    from test_app import _app, _page_text, _start

    monkeypatch.setenv("ITDR_GUI_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    at = _start(_app(), "ALERT_001")  # offline: waits on the first review step
    text = _page_text(at)
    assert "What happened:" in text
    assert "had " in text and "sign-ins in the window" in text
    assert "Alert: ALERT_001" in text
    assert "What: Unlikely travel involving one user" in text
    assert "Action: Proposed, each step needs your approval below:" in text


def _in_order(at) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []

    def walk(node):
        children = getattr(node, "children", None) or {}
        for key in sorted(children):
            child = children[key]
            value = getattr(child, "value", None)
            if isinstance(value, str):
                out.append((child.type, value))
            walk(child)

    walk(at.main)
    return out


def _index(items, needle: str) -> int:
    return next(i for i, (_t, v) in enumerate(items) if v.startswith(needle))


def test_what_happened_sits_right_below_the_alert_line(tmp_path, monkeypatch):
    """Joe, 2026-10-16: move it to the top, right below the alert line."""
    pytest.importorskip("streamlit")
    from test_app import _app, _start

    monkeypatch.setenv("ITDR_GUI_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    at = _start(_app(), "ALERT_001")
    items = _in_order(at)
    line = _index(items, "ALERT_001 · ")
    assert items[line + 1] == ("markdown", "**What happened:**")
    assert items[line + 2][1].startswith("alice.traveler@contoso.com had ")
    assert _index(items, "**Verdict:") > line + 2
    assert [v for _t, v in items].count("**What happened:**") == 1


def test_what_happened_stays_on_the_report(tmp_path, monkeypatch):
    pytest.importorskip("streamlit")
    from test_app import _app, _start

    monkeypatch.setenv("ITDR_GUI_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    at = _start(_app(), "ALERT_010")  # short-circuits straight to the report
    items = _in_order(at)
    line = _index(items, "ALERT_010 · ")
    assert items[line + 1] == ("markdown", "**What happened:**")
