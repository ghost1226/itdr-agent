"""Dream Run 1 items 7-8: the analyst question by trigger + verdict display.

The question is built by code from the trigger, never by the LLM:
  * thin evidence (the guard flipped a FALSE_POSITIVE)
  * the alert's country is new for this user
  * otherwise, the model's verdict and confidence

Offline only: scripted LLMs, fixture dossiers, no network.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(Path(__file__).parent))

from itdr_agent.adjudicator import Adjudicator  # noqa: E402
from itdr_agent.human import ScriptedReviewer  # noqa: E402
from itdr_agent.orchestrator import Orchestrator  # noqa: E402
from itdr_agent.schemas import AdjudicatorOutput, InvestigatorOutput  # noqa: E402
from itdr_agent.summary import report_summary_lines  # noqa: E402
from test_orchestrator import CompleteLLM, FakeInvestigator, _report  # noqa: E402

ALERT_009 = {
    "id": "ALERT_009",
    "createdDateTime": "2025-01-15T08:00:00Z",
    "userPrincipalName": "user05@contoso.com",
    "appDisplayName": "OneDrive",
    "location": {"city": "New York", "state": "NY", "countryOrRegion": "US"},
}


def _dossier(**overrides):
    base = dict(
        alert_id="ALERT_009",
        user_principal_name="user05@contoso.com",
        user_profile={"userPrincipalName": "user05@contoso.com"},
        sign_in_history=[
            {
                "id": "s1",
                "createdDateTime": "2025-01-15T07:00:00Z",
                "location": {"countryOrRegion": "US"},
            }
        ],
        risk_indicators=[],
        mitre_attack_mapping=[],
        mitre_attack_evidence={},
    )
    base.update(overrides)
    return InvestigatorOutput(**base)


def _thin_report(**overrides):
    data = dict(
        verdict="INSUFFICIENT_DATA",
        confidence=0.0,
        narrative="thin evidence",
        containment_steps=[],
        recommended_actions=[],
        mitre_techniques_observed=[],
        audit_notes="",
        thin_evidence=True,
        model_verdict="FALSE_POSITIVE",
        model_confidence=0.92,
        baseline_sign_ins=2,
        baseline_directory_audits=0,
    )
    data.update(overrides)
    return AdjudicatorOutput(**data)


def _flip_alert(tmp_path):
    """Run the real thin-evidence guard on ALERT_009 and capture the question."""
    from itdr_agent.fixture_store import get_store

    alert = next(a for a in get_store().alerts if a["id"] == "ALERT_009")
    reviewer = ScriptedReviewer()
    llm = CompleteLLM(
        [
            _report(
                verdict="FALSE_POSITIVE",
                confidence=0.92,
                mitre_techniques_observed=[],
            )
        ]
    )
    orch = Orchestrator(
        FakeInvestigator(_dossier()),
        Adjudicator(llm),
        reviewer,
        audit_log=tmp_path / "audit.jsonl",
    )
    orch.run(alert)
    return alert, reviewer, orch


# --- one test per trigger ---------------------------------------------------


def test_thin_evidence_question_names_the_sign_ins_and_the_alert_sign_in():
    from itdr_agent.orchestrator import build_analyst_question

    trigger, question = build_analyst_question(
        ALERT_009, _dossier(), _thin_report()
    )
    assert trigger == "thin_evidence"
    assert "user05@contoso.com has only 2 sign-ins in the last 7 days" in question
    assert "New York, US" in question
    assert "2025-01-15" in question
    # Never the bare verdict/confidence: this question is about the evidence.
    assert "INSUFFICIENT_DATA" not in question
    assert "0.92" not in question


def test_new_country_question_when_the_alert_country_is_new():
    from itdr_agent.orchestrator import build_analyst_question

    alert = dict(ALERT_009, location={"city": "Lagos", "countryOrRegion": "NG"})
    report = AdjudicatorOutput(
        verdict="SUSPICIOUS", confidence=0.9, narrative="x"
    )
    trigger, question = build_analyst_question(alert, _dossier(), report)
    assert trigger == "new_country"
    assert question == (
        "Is user05@contoso.com traveling in NG, or expected to sign in from "
        "there?"
    )


def test_default_question_uses_the_verdict_and_confidence():
    from itdr_agent.orchestrator import build_analyst_question

    report = AdjudicatorOutput(
        verdict="SUSPICIOUS", confidence=0.65, narrative="x"
    )
    trigger, question = build_analyst_question(ALERT_009, _dossier(), report)
    assert trigger == "default"
    assert "SUSPICIOUS" in question and "0.65" in question
    assert "What context would help?" in question


# --- ALERT_009 gets the thin question, through the real guard --------------


def test_alert_009_gets_the_thin_question_through_the_guard(tmp_path):
    _alert, reviewer, _orch = _flip_alert(tmp_path)

    assert reviewer.asked, "the thin-evidence guard should ask one question"
    question = reviewer.asked[0]
    assert "has only 2 sign-ins in the last 7 days" in question
    assert "New York, US" in question


def test_ask_user_audit_line_records_the_trigger(tmp_path):
    _alert, _reviewer, _orch = _flip_alert(tmp_path)

    ask = next(
        e
        for e in map(
            json.loads,
            (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines(),
        )
        if e["event"] == "ask_user"
    )
    assert ask["trigger"] == "thin_evidence"


# --- verdict display --------------------------------------------------------


def test_flipped_verdict_shows_the_model_said_and_the_change():
    from itdr_agent.summary import verdict_line

    line = verdict_line(_thin_report())
    assert line == (
        "Model said FALSE_POSITIVE (0.92). Changed to INSUFFICIENT_DATA "
        "because only 2 sign-ins in the last 7 days."
    )
    assert "INSUFFICIENT_DATA 0.92" not in line
    assert report_summary_lines(_thin_report(), _dossier())[0] == line
