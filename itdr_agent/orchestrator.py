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
6. Append a run entry (hashes, tool calls, counters, tokens) to ``logs/audit.jsonl``.

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
import subprocess
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
    is_unsafe_rollback,
)
from .human import Reviewer
from .investigator import InvestigationTimeoutError
from .trace import RUNS_DIRNAME, RunTrace
from .usage import TokenMeter
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


def _tree_is_dirty(repo: Path = PROJECT_ROOT) -> bool:
    """True if tracked files differ from HEAD (untracked files ignored)."""
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), "status", "--porcelain", "--untracked-files=no"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except Exception:  # git missing, not a repo, or timeout: treat as clean
        return False
    return bool(result.stdout.strip())


def _git_short_hash(repo: Path = PROJECT_ROOT) -> str:
    """The current commit's short hash, or ``unknown`` outside a repo."""
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except Exception:
        return "unknown"
    if result.returncode != 0:
        return "unknown"
    return result.stdout.strip() or "unknown"


def build_analyst_question(
    alert: dict[str, Any],
    dossier: InvestigatorOutput,
    report: AdjudicatorOutput,
) -> tuple[str, str]:
    """Return ``(trigger, question)`` chosen by code, never by the LLM.

    Triggers, in order:
      * ``thin_evidence`` -- the guard flipped a FALSE_POSITIVE because the
        user has too little history; ask about the alert's own sign-in.
      * ``new_country`` -- the alert's country is not in the user's earlier
        sign-ins; ask whether the travel is expected.
      * ``default`` -- the verdict and confidence, then an open question.
    """
    upn = dossier.user_principal_name
    location = alert.get("location") or {}
    city = location.get("city") or "an unknown city"
    country = location.get("countryOrRegion") or ""
    date = (alert.get("createdDateTime") or "")[:10] or "an unknown date"

    if report.thin_evidence:
        sign_ins = report.baseline_sign_ins
        if sign_ins is None:
            sign_ins = len(dossier.sign_in_history)
        return (
            "thin_evidence",
            f"{upn} has only {sign_ins} sign-ins in the last 7 days. Is a "
            f"sign-in from {city}, {country or 'an unknown country'} on "
            f"{date} normal for this user?",
        )

    alert_time = alert.get("createdDateTime") or ""
    earlier_countries = {
        (event.get("location") or {}).get("countryOrRegion")
        for event in dossier.sign_in_history
        if event.get("createdDateTime", "") < alert_time
    } - {None, ""}
    if earlier_countries and country and country not in earlier_countries:
        return (
            "new_country",
            f"Is {upn} traveling in {country}, or expected to sign in from "
            "there?",
        )

    return (
        "default",
        f"The model said {report.verdict.value} ({report.confidence:.2f}). "
        "What context would help?",
    )

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
    tokens: dict[str, int] | None = None
    trace_path: Path | None = None


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
        token_meter: TokenMeter | None = None,
        model: str | None = None,
        mode: str = "unknown",
        dirty: bool | None = None,
    ) -> None:
        self.investigator = investigator
        self.adjudicator = adjudicator
        self.reviewer = reviewer
        self.model = model
        self.mode = mode
        self._dirty = dirty
        self._commit: str | None = None
        self._trace: RunTrace | None = None
        self.audit_log = Path(audit_log) if audit_log else DEFAULT_AUDIT_LOG
        if mode in ("mock", "offline"):
            # A run that never touches a live model stays out of the live log.
            self.audit_log = self.audit_log.with_name("audit-mock.jsonl")
        self.timeout_seconds = (
            config.TIMEOUT_SECONDS if timeout_seconds is None else timeout_seconds
        )
        self.clock = clock
        self.token_meter = token_meter
        self._deadline = 0.0
        self._questions_asked = 0
        self._re_adjudications = 0

    # --- public ------------------------------------------------------------

    def run(
        self, alert: dict[str, Any], run_id: str | None = None
    ) -> OrchestrationResult:
        self._questions_asked = 0
        self._re_adjudications = 0
        if self.token_meter is not None:
            self.token_meter.reset()
        self.audit_log.parent.mkdir(parents=True, exist_ok=True)
        alert_id = alert.get("id", "")
        run_id = run_id or f"{alert_id}_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}_{uuid.uuid4().hex[:6]}"
        trace_path = self.audit_log.parent / RUNS_DIRNAME / f"{run_id}.json"
        self._trace = RunTrace(alert_id, run_id, meter=self.token_meter)
        for target in (self.investigator, self.adjudicator):
            if hasattr(target, "trace"):
                target.trace = self._trace

        dossier: InvestigatorOutput | None = None
        report: AdjudicatorOutput | None = None
        try:
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
                        alert, dossier, report, run_id
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
                    "model": self.model,
                    "mode": self.mode,
                    "commit": self._commit_label(),
                    "trace_path": str(trace_path),
                    **self._token_fields(),
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
                tokens=self._tokens(),
                trace_path=trace_path,
            )
        except BaseException as exc:
            self._trace.record_error(exc)
            raise
        finally:
            # Write the trace even when the run fails (timeout, MITRE
            # rejection, any exception), so a bad run leaves evidence too.
            self._trace.write(trace_path, dossier=dossier, report=report)

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
                **self._token_fields(),
            },
        )

    def _adjudicate(
        self, dossier: InvestigatorOutput, run_id: str, stage: str = "adjudication"
    ) -> AdjudicatorOutput:
        try:
            report = self.adjudicator.adjudicate(dossier, stage=stage)
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
        if report.thin_evidence:
            self._append(
                run_id,
                {
                    "event": "thin_evidence",
                    "timestamp": _now(),
                    "alert_id": dossier.alert_id,
                    "model_verdict": "FALSE_POSITIVE",
                    "sign_ins": (
                        report.baseline_sign_ins
                        if report.baseline_sign_ins is not None
                        else len(dossier.sign_in_history)
                    ),
                    "directory_audits": (
                        report.baseline_directory_audits
                        if report.baseline_directory_audits is not None
                        else len(dossier.directory_audits)
                    ),
                },
            )
        if report.moved_containment_steps:
            self._append(
                run_id,
                {
                    "event": "containment_moved",
                    "timestamp": _now(),
                    "alert_id": dossier.alert_id,
                    "verdict": report.verdict.value,
                    "steps": report.moved_containment_steps,
                },
            )
        if report.ip_range_reasoning:
            self._append(
                run_id,
                {
                    "event": "ip_range_reasoning",
                    "timestamp": _now(),
                    "alert_id": dossier.alert_id,
                    "phrases": report.ip_range_reasoning,
                },
            )
        if report.standard_rollbacks:
            self._append(
                run_id,
                {
                    "event": "standard_rollback",
                    "timestamp": _now(),
                    "alert_id": dossier.alert_id,
                    "step_indexes": report.standard_rollbacks,
                },
            )
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
        alert: dict[str, Any],
        dossier: InvestigatorOutput,
        report: AdjudicatorOutput,
        run_id: str,
    ) -> AdjudicatorOutput:
        if self._questions_asked >= 1:
            return report
        alert_id = alert.get("id", "")
        trigger, question = build_analyst_question(alert, dossier, report)
        options = [
            {"label": "The activity is expected/benign"},
            {"label": "The activity is suspicious/malicious"},
            {"label": "I don't know"},
        ]
        asked_at = self.clock()
        result = self.reviewer.ask(question, options, True)
        self._deadline += self.clock() - asked_at  # analyst time doesn't count
        self._questions_asked += 1
        if self._trace is not None:
            self._trace.record_analyst_answer(result)
        self._append(
            run_id,
            {
                "event": "ask_user",
                "timestamp": _now(),
                "alert_id": alert_id,
                "trigger": trigger,
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
        new_report = self._adjudicate(dossier, run_id, stage="re_adjudication")
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
            final_rollback: str | None = step.rollback
            if decision.decision == "approve":
                kept.append(step)
            elif decision.decision == "edit":
                new_step = (decision.edited_step or "").strip()
                new_rollback = (getattr(decision, "edited_rollback", None) or "").strip()
                if not (new_step or new_rollback):
                    raise OrchestrationError("edit must change the step or the rollback")
                final_step = new_step or step.step
                final_rollback = new_rollback or step.rollback
                if not final_rollback.strip():
                    raise OrchestrationError("edited step must keep a rollback")
                kept.append(ContainmentStep(step=final_step, rollback=final_rollback))
            elif decision.decision == "reject":
                final_step = None
                final_rollback = None
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
                    "rollback": step.rollback,
                    "unsafe_rollback": index in unsafe,
                    "final_rollback": final_rollback,
                    "final_unsafe_rollback": (
                        None if final_rollback is None
                        else is_unsafe_rollback(final_rollback)
                    ),
                    "reason": decision.reason,
                },
            )
        report.containment_steps = kept
        report.unsafe_rollbacks = find_unsafe_rollbacks(report)  # final indexes
        return report

    def _commit_label(self) -> str:
        if self._commit is None:
            self._commit = _git_short_hash()
        if self._dirty is None:
            self._dirty = _tree_is_dirty()
        return f"{self._commit}+dirty" if self._dirty else self._commit

    def _tokens(self) -> dict[str, int] | None:
        return None if self.token_meter is None else self.token_meter.snapshot()

    def _token_fields(self) -> dict[str, Any]:
        """Audit fields; null (not 0) when nothing was counting."""
        snap = self._tokens()
        keys = ("tokens_in", "tokens_out", "llm_requests", "requests_without_usage")
        return {k: (None if snap is None else snap[k]) for k in keys}

    def _append(self, run_id: str, entry: dict[str, Any]) -> None:
        entry = {"run_id": run_id, **entry}
        with self.audit_log.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, default=str) + "\n")
