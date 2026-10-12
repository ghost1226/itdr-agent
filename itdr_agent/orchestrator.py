"""Checkpoint 6 — Orchestrator, governance, and human oversight (HITL).

Flow for one alert:

1. Anonymization gate (no non-synthetic email domains).
2. Investigator → dossier. A critical gap short-circuits to
   ``INSUFFICIENT_DATA`` **without** calling the model.
3. Adjudicator → report (confidence coercion + MITRE evidence guard).
4. If the report is ``INSUFFICIENT_DATA`` or confidence < 0.7, ask the analyst
   **one** targeted question and re-adjudicate **at most once**. A cancelled
   ask stores exactly ``"no decision has been supplied"`` and does not
   re-adjudicate.
5. Review each containment step: approve / edit / reject.
6. Append a run entry (hashes, tool calls, counters) to ``logs/audit.jsonl``.

No live tokens: tests inject mocked LLMs and a ``ScriptedReviewer``.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .adjudicator import Adjudicator, UnsupportedMitreClaimError
from .human import Reviewer
from .schemas import (
    CONFIDENCE_THRESHOLD,
    AdjudicatorOutput,
    AnalystAnswer,
    ContainmentStep,
    InvestigatorOutput,
    Verdict,
    apply_confidence_guardrail,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_AUDIT_LOG = PROJECT_ROOT / "logs" / "audit.jsonl"

ALLOWED_EMAIL_DOMAINS = {"contoso.com"}
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@([A-Za-z0-9.\-]+)")


class AnonymizationError(Exception):
    """A non-synthetic email domain appeared in the payload."""


class OrchestrationError(Exception):
    """Base class for orchestration failures."""


def assert_synthetic(payload: Any) -> None:
    """Governance gate: refuse to run if a real email domain leaked in."""
    blob = json.dumps(payload, default=str)
    for domain in _EMAIL_RE.findall(blob):
        if domain.lower() not in ALLOWED_EMAIL_DOMAINS:
            raise AnonymizationError(f"non-synthetic email domain: {domain}")


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class OrchestrationResult:
    alert_id: str
    dossier: InvestigatorOutput
    report: AdjudicatorOutput
    llm_called: bool
    short_circuited: bool
    questions_asked: int
    re_adjudications: int
    audit_path: Path
    run_id: str


class Orchestrator:
    """Runs the two agents, governance checks, and the HITL review."""

    def __init__(
        self,
        investigator: Any,
        adjudicator: Adjudicator,
        reviewer: Reviewer,
        audit_log: str | Path | None = None,
        timeout_seconds: int = 120,
    ) -> None:
        self.investigator = investigator
        self.adjudicator = adjudicator
        self.reviewer = reviewer
        self.audit_log = Path(audit_log) if audit_log else DEFAULT_AUDIT_LOG
        self.timeout_seconds = timeout_seconds
        self._questions_asked = 0
        self._re_adjudications = 0

    # --- public ------------------------------------------------------------

    def run(
        self, alert: dict[str, Any], run_id: str | None = None
    ) -> OrchestrationResult:
        self._questions_asked = 0
        self._re_adjudications = 0
        self.audit_log.parent.mkdir(parents=True, exist_ok=True)
        alert_id = alert.get("id", "")
        run_id = run_id or f"{alert_id}_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}_{uuid.uuid4().hex[:6]}"

        assert_synthetic(alert)  # governance: no real domains

        dossier = self.investigator.investigate(alert)
        tool_calls = getattr(self.investigator, "tool_calls_made", 0)
        llm_called = False
        short_circuited = False

        if dossier.is_critical_gap:
            short_circuited = True
            report = self._critical_gap_report()
        else:
            report = self._adjudicate(dossier, run_id)  # logs+raises on bad MITRE
            llm_called = True
            if self._should_ask(report):
                report = self._ask_and_maybe_readjudicate(
                    alert_id, dossier, report, run_id
                )

        report = self._review_containment(alert_id, report, run_id)
        report = apply_confidence_guardrail(report)

        self._append(
            run_id,
            {
                "event": "run",
                "timestamp": _now(),
                "alert_id": alert_id,
                "tool_calls": tool_calls,
                "dossier_hash": _sha256(dossier.model_dump_json()),
                "report_hash": _sha256(report.model_dump_json()),
                "verdict": report.verdict.value,
                "confidence": report.confidence,
                "short_circuited": short_circuited,
                "llm_called": llm_called,
                "questions_asked": self._questions_asked,
                "re_adjudications": self._re_adjudications,
            },
        )
        return OrchestrationResult(
            alert_id=alert_id,
            dossier=dossier,
            report=report,
            llm_called=llm_called,
            short_circuited=short_circuited,
            questions_asked=self._questions_asked,
            re_adjudications=self._re_adjudications,
            audit_path=self.audit_log,
            run_id=run_id,
        )

    # --- internals ---------------------------------------------------------

    def _adjudicate(
        self, dossier: InvestigatorOutput, run_id: str
    ) -> AdjudicatorOutput:
        try:
            return self.adjudicator.adjudicate(dossier)
        except UnsupportedMitreClaimError as exc:
            self._append(
                run_id,
                {
                    "event": "mitre_rejection",
                    "timestamp": _now(),
                    "alert_id": dossier.alert_id,
                    "error": str(exc),
                },
            )
            raise

    @staticmethod
    def _should_ask(report: AdjudicatorOutput) -> bool:
        return (
            report.verdict is Verdict.INSUFFICIENT_DATA
            or report.confidence < CONFIDENCE_THRESHOLD
        )

    @staticmethod
    def _critical_gap_report() -> AdjudicatorOutput:
        return AdjudicatorOutput(
            verdict=Verdict.INSUFFICIENT_DATA,
            confidence=0.0,
            narrative=(
                "Critical data gap: the user profile or sign-in history is "
                "missing, so the model was not called."
            ),
            containment_steps=[],
            recommended_actions=[
                "Confirm the alert's user principal name",
                "Gather the missing user profile and sign-in history",
            ],
            mitre_techniques_observed=[],
            audit_notes="Short-circuited on a critical gap; no LLM call.",
        )

    def _ask_and_maybe_readjudicate(
        self,
        alert_id: str,
        dossier: InvestigatorOutput,
        report: AdjudicatorOutput,
        run_id: str,
    ) -> AdjudicatorOutput:
        if self._questions_asked >= 1:
            return report
        question = (
            f"The dossier for {dossier.user_principal_name} produced verdict "
            f"{report.verdict.value} with confidence {report.confidence:.2f}. "
            "Do you have context that changes this assessment?"
        )
        options = [
            {"label": "The activity is expected/benign"},
            {"label": "The activity is suspicious/malicious"},
            {"label": "I don't know"},
        ]
        result = self.reviewer.ask(question, options, True)
        self._questions_asked += 1
        self._append(
            run_id,
            {
                "event": "ask_user",
                "timestamp": _now(),
                "alert_id": alert_id,
                "question": question,
                "status": result.status,
                "answer": result.answer,
                "choice_index": result.choice_index,
                "free_text": result.free_text,
            },
        )
        dossier.analyst_context.append(
            AnalystAnswer(
                question=question,
                status=result.status,
                answer=result.answer,
                choice_index=result.choice_index,
                free_text=result.free_text,
            )
        )
        if result.status == "cancelled":
            return report  # no fabricated choice, no re-adjudication
        if self._re_adjudications >= 1:
            return report

        self._re_adjudications += 1
        new_report = self._adjudicate(dossier, run_id)
        self._append(
            run_id,
            {
                "event": "re_adjudication",
                "timestamp": _now(),
                "alert_id": alert_id,
                "verdict": new_report.verdict.value,
                "confidence": new_report.confidence,
            },
        )
        return new_report

    def _review_containment(
        self, alert_id: str, report: AdjudicatorOutput, run_id: str
    ) -> AdjudicatorOutput:
        kept: list[ContainmentStep] = []
        for index, step in enumerate(report.containment_steps):
            decision = self.reviewer.review_step(index, step.step, step.rollback)
            final_step: str | None = step.step
            if decision.decision == "approve":
                kept.append(step)
            elif decision.decision == "edit":
                edited = (decision.edited_step or "").strip()
                if not edited:
                    raise OrchestrationError("edit must provide a step")
                if not step.rollback.strip():
                    raise OrchestrationError("edited step must keep a rollback")
                kept.append(ContainmentStep(step=edited, rollback=step.rollback))
                final_step = edited
            elif decision.decision == "reject":
                final_step = None
            else:
                raise OrchestrationError(
                    f"unknown containment decision: {decision.decision}"
                )
            self._append(
                run_id,
                {
                    "event": "containment_decision",
                    "timestamp": _now(),
                    "alert_id": alert_id,
                    "step_index": index,
                    "original_step": step.step,
                    "decision": decision.decision,
                    "final_step": final_step,
                    "reason": decision.reason,
                },
            )
        report.containment_steps = kept
        return report

    def _append(self, run_id: str, entry: dict[str, Any]) -> None:
        entry = {"run_id": run_id, **entry}
        with self.audit_log.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, default=str) + "\n")
