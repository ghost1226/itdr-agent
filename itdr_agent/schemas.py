"""Checkpoint 2 — Pydantic schemas and structured I/O contracts.

Two contracts:
  * InvestigatorOutput — the evidence dossier produced by the Investigator.
  * AdjudicatorOutput  — the incident report produced by the Adjudicator.

The confidence guardrail deliberately lives in a plain function, not a
Pydantic validator, so the orchestrator can apply policy transparently and
still let the LLM express honest uncertainty.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, model_validator


class Verdict(str, Enum):
    COMPROMISED = "COMPROMISED"
    SUSPICIOUS = "SUSPICIOUS"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"


class AnalystAnswer(BaseModel):
    """A single analyst answer to one targeted question."""

    question: str
    status: str
    answer: str
    choice_index: int | None = None
    free_text: bool = False


class InvestigatorOutput(BaseModel):
    """Evidence dossier assembled by the Investigator agent."""

    alert_id: str
    user_principal_name: str
    user_profile: dict[str, Any] | None = None
    sign_in_history: list[dict[str, Any]] = Field(default_factory=list)
    device_trust: dict[str, Any] | None = None
    directory_audits: list[dict[str, Any]] = Field(default_factory=list)
    risk_indicators: list[str] = Field(default_factory=list)
    mitre_attack_mapping: list[str] = Field(default_factory=list)
    mitre_attack_evidence: dict[str, list[str]] = Field(default_factory=dict)
    analyst_context: list[AnalystAnswer] = Field(default_factory=list)
    data_gaps: list[str] = Field(default_factory=list)
    is_critical_gap: bool = False

    @model_validator(mode="after")
    def _enforce_critical_gap(self) -> "InvestigatorOutput":
        """A critical gap is defined by data, never by the caller's claim.

        Critical only when we cannot identify the user OR have no sign-in
        history. Missing directory audits alone is not critical.
        """
        critical = self.user_profile is None or len(self.sign_in_history) == 0
        self.is_critical_gap = critical
        return self


class ContainmentStep(BaseModel):
    """A single containment action, paired with its rollback."""

    step: str
    rollback: str


class AdjudicatorOutput(BaseModel):
    """Incident report produced by the Adjudicator agent."""

    verdict: Verdict
    confidence: float = Field(ge=0.0, le=1.0)
    narrative: str
    containment_steps: list[ContainmentStep] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    mitre_techniques_observed: list[str] = Field(default_factory=list)
    audit_notes: str = ""
    # Set by code (adjudicator.apply_action_claim_guard), never by the model:
    # phrases where the report claims an action was already taken.
    action_claims: list[str] = Field(default_factory=list)
    # Set by code (adjudicator.apply_unsafe_rollback_guard), never by the model:
    # indexes of containment steps whose rollback would restore a credential.
    unsafe_rollbacks: list[int] = Field(default_factory=list)
    # Set by code (adjudicator.apply_thin_evidence_guard), never by the model:
    # a FALSE_POSITIVE on thin evidence was turned into INSUFFICIENT_DATA.
    thin_evidence: bool = False


CONFIDENCE_THRESHOLD = 0.7


def apply_confidence_guardrail(report: AdjudicatorOutput) -> AdjudicatorOutput:
    """Coerce low-confidence verdicts to INSUFFICIENT_DATA.

    Policy lives in code, not in the schema: an LLM may honestly report 0.6
    confidence for a FALSE_POSITIVE, and the orchestrator handles that
    transparently instead of letting the model fake certainty.
    """
    if report.confidence < CONFIDENCE_THRESHOLD and report.verdict != Verdict.INSUFFICIENT_DATA:
        note = (
            f"Verdict coerced from {report.verdict.value} to "
            f"INSUFFICIENT_DATA: confidence {report.confidence:.2f} is below "
            f"the {CONFIDENCE_THRESHOLD:.2f} threshold."
        )
        report.audit_notes = f"{report.audit_notes}\n{note}".strip()
        report.verdict = Verdict.INSUFFICIENT_DATA
    return report
