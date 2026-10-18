"""Problem #14: confidently wrong on thin data (offline, mocked).

ALERT_009 (a known user, 2 sign-ins, no audits) came back FALSE_POSITIVE at
0.90+ in all 3 evaluation runs. A FALSE_POSITIVE says the activity matches the
user's normal behavior, which thin evidence cannot show. Code turns such a
verdict into INSUFFICIENT_DATA (so the analyst is asked), unless an analyst
has already answered with context.
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(Path(__file__).parent))

from itdr_agent import adjudicator as adj  # noqa: E402
from itdr_agent.adjudicator import Adjudicator  # noqa: E402
from itdr_agent.human import AskUserResult, ScriptedReviewer  # noqa: E402
from itdr_agent.schemas import Verdict  # noqa: E402
from test_orchestrator import (  # noqa: E402
    CompleteLLM,
    _audit,
    _dossier,
    _orchestrator,
    _report,
)

# ALERT_009's user: 2 sign-ins and no audits in the fixtures over any window.
THIN_USER = "user05@contoso.com"
# ALERT_008's user: 6 sign-ins over 7 days, but only 2 in the default 24 hours.
VPN_USER = "gina.vpn@contoso.com"

BENIGN = dict(
    verdict="FALSE_POSITIVE",
    confidence=0.92,
    narrative="No risk signals; normal activity.",
    containment_steps=[],
    mitre_techniques_observed=[],
)


def _sign_ins(n: int) -> list[dict]:
    return [
        {"id": f"s{i}", "createdDateTime": f"2025-01-15T0{i}:00:00Z",
         "riskEventTypes_v2": []}
        for i in range(n)
    ]


def _thin(**overrides):
    base = dict(
        alert_id="ALERT_009",
        user_principal_name=THIN_USER,
        user_profile={"userPrincipalName": THIN_USER},
        sign_in_history=_sign_ins(2),
        directory_audits=[],
        risk_indicators=[],
        mitre_attack_mapping=[],
        mitre_attack_evidence={},
    )
    base.update(overrides)
    return _dossier(**base)


def test_thin_rule():
    assert adj.MIN_BASELINE_SIGN_INS == 3
    assert adj.is_thin_evidence(_thin())
    assert not adj.is_thin_evidence(_thin(sign_in_history=_sign_ins(3)))
    # An audit record is evidence too (ALERT_004: 2 sign-ins + a consent audit).
    assert not adj.is_thin_evidence(_thin(directory_audits=[{"id": "a1"}]))


def test_thin_false_positive_becomes_insufficient_data(tmp_path):
    orch, _llm, audit = _orchestrator(tmp_path, _thin(), [_report(**BENIGN)])
    result = orch.run({"id": "ALERT_009"}, run_id="r-thin")
    assert result.report.verdict is Verdict.INSUFFICIENT_DATA
    assert result.report.thin_evidence is True
    assert "Thin-evidence guard" in result.report.audit_notes
    events = [e["event"] for e in _audit(audit)]
    assert "thin_evidence" in events
    (line,) = [e for e in _audit(audit) if e["event"] == "thin_evidence"]
    assert line["sign_ins"] == 2 and line["directory_audits"] == 0
    assert line["model_verdict"] == "FALSE_POSITIVE"
    # INSUFFICIENT_DATA asks the analyst once (cancelled here: no re-run).
    assert "ask_user" in events


def test_enough_history_is_left_alone(tmp_path):
    orch, _llm, audit = _orchestrator(
        tmp_path, _thin(sign_in_history=_sign_ins(3)), [_report(**BENIGN)]
    )
    result = orch.run({"id": "ALERT_006"})
    assert result.report.verdict is Verdict.FALSE_POSITIVE
    assert result.report.thin_evidence is False
    assert "thin_evidence" not in [e["event"] for e in _audit(audit)]


def test_other_verdicts_on_thin_data_are_left_alone(tmp_path):
    orch, _llm, _audit_path = _orchestrator(
        tmp_path, _thin(), [_report(verdict="SUSPICIOUS", confidence=0.8,
                                    mitre_techniques_observed=[])]
    )
    result = orch.run({"id": "ALERT_009"})
    assert result.report.verdict is Verdict.SUSPICIOUS
    assert result.report.thin_evidence is False


def test_an_analyst_answer_is_respected(tmp_path):
    answered = AskUserResult(
        status="answered",
        answer="The activity is expected/benign",
        choice_index=0,
        free_text=False,
    )
    orch, llm, audit = _orchestrator(
        tmp_path, _thin(),
        [_report(**BENIGN), _report(**BENIGN)],
        reviewer=ScriptedReviewer(answers=[answered]),
    )
    result = orch.run({"id": "ALERT_009"})
    assert llm.calls == 2  # re-adjudicated with the analyst's context
    assert result.report.verdict is Verdict.FALSE_POSITIVE
    assert result.report.thin_evidence is False


def test_prompt_leaves_thin_data_to_the_code_guard():
    """Problem #33: with this rule in the prompt, the model answered
    INSUFFICIENT_DATA on ALERT_006 and ALERT_008 (real history, benign).
    The code guard alone catches the thin case (ALERT_009)."""
    assert "Missing evidence" not in adj.SYSTEM_PROMPT
    assert "too little history" not in adj.SYSTEM_PROMPT


# --- Problem #34: the guard counted the model's window, not the user's history.
# ALERT_008 (benign VPN) fetched 2 of 6 sign-ins (a short `hours` window); the
# model said FALSE_POSITIVE and the guard wrongly flipped it. The guard now
# looks up its own fixed baseline window in code.


def test_baseline_window_is_seven_days():
    assert adj.BASELINE_HOURS == 168
    assert adj.fetch_baseline(VPN_USER) == (6, 0)
    assert adj.fetch_baseline(THIN_USER) == (2, 0)
    assert adj.fetch_baseline("ghost.user@contoso.com") == (0, 0)


def test_short_window_with_real_history_is_not_thin(tmp_path):
    dossier = _thin(
        alert_id="ALERT_008",
        user_principal_name=VPN_USER,
        user_profile={"userPrincipalName": VPN_USER},
    )
    assert adj.is_thin_evidence(dossier, baseline=(6, 0)) is False
    orch, _llm, audit = _orchestrator(tmp_path, dossier, [_report(**BENIGN)])
    result = orch.run({"id": "ALERT_008"})
    assert result.report.verdict is Verdict.FALSE_POSITIVE
    assert result.report.thin_evidence is False
    assert result.report.baseline_sign_ins == 6
    assert "thin_evidence" not in [e["event"] for e in _audit(audit)]


def test_baseline_audit_counts_as_evidence():
    assert adj.is_thin_evidence(_thin(), baseline=(2, 1)) is False


def test_thin_audit_line_reports_the_baseline_counts(tmp_path):
    # Dossier holds 1 sign-in; the baseline lookup finds the user's 2.
    orch, _llm, audit = _orchestrator(
        tmp_path, _thin(sign_in_history=_sign_ins(1)), [_report(**BENIGN)]
    )
    result = orch.run({"id": "ALERT_009"})
    assert result.report.verdict is Verdict.INSUFFICIENT_DATA
    assert result.report.baseline_sign_ins == 2
    (line,) = [e for e in _audit(audit) if e["event"] == "thin_evidence"]
    assert line["sign_ins"] == 2 and line["directory_audits"] == 0


def test_baseline_can_be_turned_off():
    report = Adjudicator(CompleteLLM([_report(**BENIGN)]), baseline=None).adjudicate(
        _thin(user_principal_name=VPN_USER)
    )
    assert report.verdict is Verdict.INSUFFICIENT_DATA
    assert report.baseline_sign_ins is None


def test_model_cannot_set_the_baseline_counts():
    raw = _report(**BENIGN, baseline_sign_ins=99, baseline_directory_audits=5)
    report = Adjudicator(CompleteLLM([raw])).adjudicate(_thin())
    assert report.baseline_sign_ins == 2
    assert report.baseline_directory_audits == 0
    assert report.verdict is Verdict.INSUFFICIENT_DATA
