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

Total timeout: ``timeout_seconds`` (``TIMEOUT_SECONDS``, default 120) caps the
machine's time for one alert. The Investigator checks the deadline before each
model turn, and the orchestrator checks it before the Adjudicator and before a
re-adjudication. Time the analyst spends answering the one question does not
count. Overrun → a ``timeout`` audit line and ``OrchestrationTimeoutError``.

No live tokens: tests inject mocked LLMs and a ``ScriptedReviewer``.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from . import config
from .adjudicator import (
    UNSAFE_ROLLBACK_WARNING,
    Adjudicator,
    UnsupportedMitreClaimError,
    find_unsafe_rollbacks,
)
from .human import Reviewer
from .investigator import InvestigationTimeoutError
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


class OrchestrationTimeoutError(OrchestrationError, TimeoutError):
    """The run went past its total timeout (TIMEOUT_SECONDS)."""


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
        timeout_seconds: int | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.investigator = investigator
        self.adjudicator = adjudicator
        self.reviewer = reviewer
        self.audit_log = Path(audit_log) if audit_log else DEFAULT_AUDIT_LOG
        self.timeout_seconds = (
            config.TIMEOUT_SECONDS if timeout_seconds is None else timeout_seconds
        )
        self.clock = clock
        self._deadline = 0.0
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

        self._deadline = self.clock() + self.timeout_seconds
        if hasattr(self.investigator, "deadline"):
            self.investigator.deadline = self._deadline
            self.investigator.clock = self.clock
        try:
            dossier = self.investigator.investigate(alert)
        except InvestigationTimeoutError as exc:
            self._log_timeout(run_id, alert_id, "investigation")
            raise OrchestrationTimeoutError(str(exc)) from exc
        tool_calls = getattr(self.investigator, "tool_calls_made", 0)
        llm_called = False
        short_circuited = False

        if dossier.is_critical_gap:
            short_circuited = True
            report = self._critical_gap_report()
        else:
            self._check_deadline(run_id, alert_id, "adjudication")
            report = self._adjudicate(dossier, run_id)  # logs+raises on bad MITRE
            llm_called = True
            if self._should_ask(report):
                self._show_report(report, dossier)
                report = self._ask_and_maybe_readjudicate(
                    alert_id, dossier, report, run_id
                )

        report = self._review_containment(alert_id, dossier, report, run_id)
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

    def _check_deadline(self, run_id: str, alert_id: str, stage: str) -> None:
        if self.clock() >= self._deadline:
            self._log_timeout(run_id, alert_id, stage)
            raise OrchestrationTimeoutError(
                f"total timeout of {self.timeout_seconds}s reached before {stage}"
            )

    def _log_timeout(self, run_id: str, alert_id: str, stage: str) -> None:
        self._append(
            run_id,
            {
                "event": "timeout",
                "timestamp": _now(),
                "alert_id": alert_id,
                "stage": stage,
                "timeout_seconds": self.timeout_seconds,
            },
        )

    def _adjudicate(
        self, dossier: InvestigatorOutput, run_id: str
    ) -> AdjudicatorOutput:
        try:
            report = self.adjudicator.adjudicate(dossier)
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
        if report.unsafe_rollbacks:
            self._append(
                run_id,
                {
                    "event": "unsafe_rollback",
                    "timestamp": _now(),
                    "alert_id": dossier.alert_id,
                    "step_indexes": report.unsafe_rollbacks,
                },
            )
        if report.action_claims:
            self._append(
                run_id,
                {
                    "event": "action_claim",
                    "timestamp": _now(),
                    "alert_id": dossier.alert_id,
                    "claims": report.action_claims,
                },
            )
        return report

    def _show_report(self, report: AdjudicatorOutput, dossier: InvestigatorOutput) -> None:
        """Show the verdict before the analyst decides, if the reviewer can.

        Optional hook: ``ScriptedReviewer`` has no ``show_report``, so the
        evaluation path is a no-op and its audit lines are unchanged.
        """
        show = getattr(self.reviewer, "show_report", None)
        if callable(show):
            show(report, dossier)

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
        asked_at = self.clock()
        result = self.reviewer.ask(question, options, True)
        self._deadline += self.clock() - asked_at  # analyst time doesn't count
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

        self._check_deadline(run_id, alert_id, "re_adjudication")
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
        self,
        alert_id: str,
        dossier: InvestigatorOutput,
        report: AdjudicatorOutput,
        run_id: str,
    ) -> AdjudicatorOutput:
        if report.containment_steps:
            self._show_report(report, dossier)  # refreshed after re-adjudication
        kept: list[ContainmentStep] = []
        unsafe = set(report.unsafe_rollbacks)
        for index, step in enumerate(report.containment_steps):
            warning = UNSAFE_ROLLBACK_WARNING if index in unsafe else ""
            decision = self.reviewer.review_step(
                index, step.step, step.rollback, warning=warning
            )
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
        report.unsafe_rollbacks = find_unsafe_rollbacks(report)  # final indexes
        return report

    def _append(self, run_id: str, entry: dict[str, Any]) -> None:
        entry = {"run_id": run_id, **entry}
        with self.audit_log.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, default=str) + "\n")
