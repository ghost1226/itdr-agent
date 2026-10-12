"""Checkpoint 2 — Pydantic schema + structured I/O contract tests.

Red-green TDD: defines the evidence dossier and incident report contracts.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


# --- Helpers ---------------------------------------------------------------


def make_dossier(**overrides):
    from itdr_agent.schemas import InvestigatorOutput

    base = {
        "alert_id": "ALERT_001",
        "user_principal_name": "alice.traveler@contoso.com",
        "user_profile": {"displayName": "Alice Traveler", "department": "Engineering"},
        "sign_in_history": [{"id": "s1", "ipAddress": "203.0.113.10"}],
        "device_trust": {"deviceId": "d1", "isManaged": True},
        "directory_audits": [],
        "risk_indicators": ["impossibleTravel"],
        "mitre_attack_mapping": ["T1078.004"],
        "data_gaps": [],
    }
    base.update(overrides)
    return InvestigatorOutput(**base)


def make_report(**overrides):
    from itdr_agent.schemas import AdjudicatorOutput, Verdict

    base = {
        "verdict": Verdict.SUSPICIOUS,
        "confidence": 0.85,
        "narrative": "The account showed impossible travel and an MFA burst.",
        "containment_steps": [
            {"step": "Disable the account.", "rollback": "Re-enable after verification."}
        ],
        "recommended_actions": ["Force password reset."],
        "mitre_techniques_observed": ["T1078.004"],
        "audit_notes": "",
    }
    base.update(overrides)
    return AdjudicatorOutput(**base)


# --- InvestigatorOutput ----------------------------------------------------


def test_dossier_round_trips_through_json():
    dossier = make_dossier()
    dumped = dossier.model_dump_json()
    from itdr_agent.schemas import InvestigatorOutput

    restored = InvestigatorOutput.model_validate_json(dumped)
    assert restored == dossier


def test_dossier_requires_alert_id():
    from itdr_agent.schemas import InvestigatorOutput

    with pytest.raises(ValidationError):
        InvestigatorOutput(user_principal_name="a@b.com")


def test_mitre_mapping_is_a_list_of_strings():
    dossier = make_dossier(mitre_attack_mapping=["T1078.004", "T1621"])
    assert dossier.mitre_attack_mapping == ["T1078.004", "T1621"]


def test_critical_gap_when_user_profile_missing():
    wander = make_dossier(user_profile=None)
    assert wander.is_critical_gap is True


def test_critical_gap_when_signin_history_empty():
    wander = make_dossier(sign_in_history=[])
    assert wander.is_critical_gap is True


def test_not_critical_gap_when_only_directory_audits_missing():
    dossier = make_dossier(directory_audits=[])
    assert dossier.is_critical_gap is False


def test_critical_gap_flag_is_enforced_not_trusted():
    """A caller cannot claim is_critical_gap=False when data is missing."""
    from itdr_agent.schemas import InvestigatorOutput

    dossier = InvestigatorOutput(
        alert_id="ALERT_001",
        user_principal_name="ghost@contoso.com",
        user_profile=None,
        sign_in_history=[],
        is_critical_gap=False,
    )
    assert dossier.is_critical_gap is True


# --- AdjudicatorOutput -----------------------------------------------------


def test_report_round_trips_through_json():
    report = make_report()
    dumped = report.model_dump_json()
    from itdr_agent.schemas import AdjudicatorOutput

    restored = AdjudicatorOutput.model_validate_json(dumped)
    assert restored.verdict == report.verdict
    assert restored.confidence == report.confidence


def test_report_rejects_confidence_above_one():
    with pytest.raises(ValidationError):
        make_report(confidence=1.5)


def test_report_rejects_negative_confidence():
    with pytest.raises(ValidationError):
        make_report(confidence=-0.1)


def test_report_rejects_unknown_verdict():
    with pytest.raises(ValidationError):
        make_report(verdict="BANANA")


def test_containment_step_requires_rollback():
    with pytest.raises(ValidationError):
        make_report(containment_steps=[{"step": "Disable the account."}])


def test_valid_verdicts():
    from itdr_agent.schemas import Verdict

    assert {v.value for v in Verdict} == {
        "COMPROMISED",
        "SUSPICIOUS",
        "FALSE_POSITIVE",
        "INSUFFICIENT_DATA",
    }


# --- Confidence guardrail (code, not validator) ----------------------------


def test_confidence_coercion_low_confidence_changes_verdict():
    from itdr_agent.schemas import Verdict, apply_confidence_guardrail

    report = make_report(verdict=Verdict.FALSE_POSITIVE, confidence=0.6)
    guarded = apply_confidence_guardrail(report)
    assert guarded.verdict == Verdict.INSUFFICIENT_DATA
    assert "coerced" in guarded.audit_notes.lower()
    assert guarded.confidence == 0.6, "confidence itself is not falsified"


def test_confidence_coercion_is_noop_when_confident():
    from itdr_agent.schemas import Verdict, apply_confidence_guardrail

    report = make_report(verdict=Verdict.COMPROMISED, confidence=0.9)
    guarded = apply_confidence_guardrail(report)
    assert guarded.verdict == Verdict.COMPROMISED
    assert guarded.audit_notes == ""


def test_confidence_coercion_leaves_insufficient_data_alone():
    from itdr_agent.schemas import Verdict, apply_confidence_guardrail

    report = make_report(verdict=Verdict.INSUFFICIENT_DATA, confidence=0.4)
    guarded = apply_confidence_guardrail(report)
    assert guarded.verdict == Verdict.INSUFFICIENT_DATA
    assert "coerced" not in guarded.audit_notes.lower()


def test_confidence_coercion_preserves_existing_audit_notes():
    from itdr_agent.schemas import Verdict, apply_confidence_guardrail

    report = make_report(
        verdict=Verdict.SUSPICIOUS, confidence=0.5, audit_notes="Prior note."
    )
    guarded = apply_confidence_guardrail(report)
    assert guarded.verdict == Verdict.INSUFFICIENT_DATA
    assert "Prior note." in guarded.audit_notes
    assert "coerced" in guarded.audit_notes.lower()
