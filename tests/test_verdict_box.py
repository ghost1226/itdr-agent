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
    assert 'class="cs-h1"' in text  # the code-built headline
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
    line = next(i for i, (_t, v) in enumerate(items) if 'class="cs-alert"' in v)
    assert "ALERT_001" in items[line][1]
    assert 'class="cs-h1"' in items[line + 1][1]
    assert "alice.traveler@contoso.com had " in items[line + 1][1]
    assert 'class="cs-cards"' in items[line + 2][1]
    narrative_panel = next(i for i, (_t, v) in enumerate(items) if "narrative, word for word" in v)
    assert narrative_panel > line + 2  # the verdict panel comes after the cards
    assert sum('class="cs-h1"' in v for _t, v in items) == 1


def test_what_happened_stays_on_the_report(tmp_path, monkeypatch):
    pytest.importorskip("streamlit")
    from test_app import _app, _start

    monkeypatch.setenv("ITDR_GUI_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    at = _start(_app(), "ALERT_010")  # short-circuits straight to the report
    items = _in_order(at)
    line = next(i for i, (_t, v) in enumerate(items) if 'class="cs-alert"' in v)
    assert "ALERT_010" in items[line][1]
    assert 'class="cs-h1"' in items[line + 1][1]


# --- GUI rebuild checkpoint 2: the four cards, code-built ---------------------


def test_technique_names_cover_every_mapped_technique():
    from itdr_agent.data_generator import SCENARIO_TECHNIQUES
    from itdr_agent.summary import TECHNIQUE_NAMES

    for technique in SCENARIO_TECHNIQUES.values():
        assert technique in TECHNIQUE_NAMES
    assert TECHNIQUE_NAMES["T1621"] == "MFA Request Generation"


def test_technique_card_names_the_technique_and_its_evidence_count():
    from itdr_agent.summary import technique_card

    assert technique_card(_report(), _dossier()) == (
        "T1621", "MFA Request Generation", "tied to 3 records")
    none = technique_card(_report(mitre_techniques_observed=[]), _dossier())
    assert none == ("None", "No technique proved", "no evidence-backed pattern")


def test_blast_radius_reads_the_audits_in_code():
    from itdr_agent.summary import blast_radius

    assert blast_radius(_dossier()) == ("Account", "No role, app or consent changes found")
    consent = {"id": "a1", "activityDisplayName": "Consent to application",
               "targetResources": [{"type": "Application", "displayName": "EvilSync"},
                                   {"type": "User", "userPrincipalName": BOB}]}
    assert blast_radius(_dossier(directory_audits=[consent])) == (
        "Apps", "1 app consent: EvilSync")
    role = {"id": "a2", "activityDisplayName": "Add member to role",
            "targetResources": [{"type": "Role", "displayName": "Global Administrator"},
                                {"type": "User", "userPrincipalName": BOB}]}
    assert blast_radius(_dossier(directory_audits=[consent, role])) == (
        "Roles", "1 role added: Global Administrator; 1 app consent: EvilSync")


def test_blast_radius_ignores_roles_the_user_only_granted():
    from itdr_agent.summary import blast_radius

    other = {"id": "a3", "activityDisplayName": "Add member to role",
             "initiatedBy": {"user": {"userPrincipalName": BOB}},
             "targetResources": [{"type": "Role", "displayName": "Helpdesk Administrator"},
                                 {"type": "User", "userPrincipalName": "other@contoso.com"}]}
    assert blast_radius(_dossier(directory_audits=[other]))[0] == "Account"


def test_alert_line_has_what_app_place_time_and_no_ip():
    from itdr_agent.summary import alert_line

    line = alert_line(_alert())
    assert line == "MFA denied · Microsoft Teams · Seattle, US · 2025-01-15 09:00Z"
    assert "203.0.113.77" not in line
    travel = _alert(riskEventTypes_v2=["unlikelyTravel"], status={"errorCode": 0, "failureReason": ""})
    assert alert_line(travel).startswith("Unlikely travel · ")


def test_run_page_shows_the_four_cards(tmp_path, monkeypatch):
    pytest.importorskip("streamlit")
    from test_app import _app, _page_text, _start

    monkeypatch.setenv("ITDR_GUI_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    at = _start(_app(), "ALERT_001")  # offline: COMPROMISED 0.9, T1078.004, 1 step
    text = _page_text(at)
    for label in ("VERDICT", "TECHNIQUE", "BLAST RADIUS", "STATUS"):
        assert label in text
    assert "COMPROMISED" in text and "0.90" in text and "0.70" in text
    assert "T1078.004" in text and "Valid Accounts: Cloud Accounts" in text
    assert "No role, app or consent changes found" in text
    assert "Waiting on you" in text and "1 step needs your countersign" in text
    assert "Risk: high" in text
    assert "203.0.113" not in text  # never an IP on screen


def test_run_page_cards_on_a_closed_run(tmp_path, monkeypatch):
    pytest.importorskip("streamlit")
    from test_app import _app, _page_text, _start

    monkeypatch.setenv("ITDR_GUI_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    at = _start(_app(), "ALERT_010")  # short-circuits: INSUFFICIENT_DATA, closed
    text = _page_text(at)
    assert "INSUFFICIENT_DATA" in text
    assert "Closed" in text
    assert "No technique proved" in text


# --- GUI rebuild checkpoint 7: evidence you can read, not GUIDs --------------


def test_evidence_detail_describes_sign_ins_and_audits():
    from itdr_agent.summary import evidence_detail

    sign_in = {"id": "s1", "createdDateTime": "2025-01-15T09:00:00Z",
               "appDisplayName": "Microsoft Teams",
               "location": {"city": "New York", "countryOrRegion": "US"},
               "deviceDetail": {"displayName": "LAPTOP-1", "operatingSystem": "iOS"},
               "ipAddress": "203.0.113.10"}
    audit = {"id": "a1", "activityDateTime": "2025-01-15T10:00:00Z",
             "activityDisplayName": "Add member to role",
             "targetResources": [{"type": "Role", "displayName": "Global Administrator"}]}
    dossier = _dossier(sign_in_history=[sign_in], directory_audits=[audit],
                       mitre_attack_evidence={"T1078.004": ["s1"], "T1098.003": ["a1"]})
    lines = evidence_detail(dossier, "T1078.004")
    assert lines == ["2025-01-15 09:00Z · Microsoft Teams · New York, US · LAPTOP-1 (iOS) · s1"]
    assert evidence_detail(dossier, "T1098.003") == [
        "2025-01-15 10:00Z · Add member to role · Global Administrator · a1"]
    assert evidence_detail(dossier, "T9999") == []
    assert "203.0.113.10" not in " ".join(lines)
