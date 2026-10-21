"""Checkpoint 6 — frozen ``ask_user`` contract and the reviewer interface.

Mirrors the HW4 Pi extension contract: an answer is ``answered`` or
``cancelled``; a cancel is exactly ``"no decision has been supplied"`` and no
caller may invent a choice. The analyst may approve, edit, or reject each
containment step.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from .summary import report_summary_lines

CANCELLED_ANSWER = "no decision has been supplied"

# The one question's options, shared by the orchestrator (which asks) and the
# thin-evidence guard (which decides whether the answer counts as context).
# Review 2026-10-21 finding 1: "I don't know" used to switch the guard off.
ANALYST_OPTIONS = (
    "The activity is expected/benign",
    "The activity is suspicious/malicious",
    "I don't know",
)
CONTEXT_CHOICE_INDEX = 0
NO_CONTEXT_ANSWER = ANALYST_OPTIONS[2]


def supplies_context(answer: Any) -> bool:
    """True when an analyst answer gives the baseline the thin guard lacks.

    Only "expected/benign" (the analyst knows this user's normal) or typed
    context counts. "I don't know", "suspicious" and a cancel say nothing
    about what is normal for the user, so the guard stays on.
    """
    if getattr(answer, "status", None) != "answered":
        return False
    text = (getattr(answer, "answer", "") or "").strip().lower()
    if text == NO_CONTEXT_ANSWER.lower():
        return False
    if getattr(answer, "free_text", False):
        return True
    return getattr(answer, "choice_index", None) == CONTEXT_CHOICE_INDEX


class ReviewAbortedError(RuntimeError, EOFError):
    """The analyst's input ended before a valid containment decision.

    Raised instead of fall-through-to-approve so closed stdin can never
    silently approve a containment step. Inherits from ``EOFError`` so callers
    that already handle end-of-input still catch it.
    """


@dataclass(frozen=True)
class AskUserResult:
    status: str  # "answered" | "cancelled"
    answer: str
    choice_index: int | None = None
    free_text: bool = False


def cancelled_result() -> AskUserResult:
    """The one and only cancel result; no invented choice."""
    return AskUserResult(
        status="cancelled",
        answer=CANCELLED_ANSWER,
        choice_index=None,
        free_text=False,
    )


@dataclass(frozen=True)
class ContainmentDecision:
    decision: str  # "approve" | "edit" | "reject"
    edited_step: str | None = None  # None/blank keeps the step
    edited_rollback: str | None = None  # None/blank keeps the rollback
    reason: str | None = None


@runtime_checkable
class Reviewer(Protocol):
    def review_step(
        self, step_index: int, step: str, rollback: str, warning: str = ""
    ) -> ContainmentDecision: ...

    def ask(
        self,
        question: str,
        options: list[dict[str, Any]] | None = None,
        allow_free_text: bool = True,
    ) -> AskUserResult: ...


class ScriptedReviewer:
    """Deterministic reviewer for tests and offline demos."""

    def __init__(
        self,
        decisions: list[ContainmentDecision] | None = None,
        answers: list[AskUserResult] | None = None,
    ) -> None:
        self._decisions = list(decisions or [])
        self._answers = list(answers or [])
        self.reviewed: list[int] = []
        self.asked: list[str] = []

    def review_step(
        self, step_index: int, step: str, rollback: str, warning: str = ""
    ) -> ContainmentDecision:
        self.reviewed.append(step_index)
        if self._decisions:
            return self._decisions.pop(0)
        return ContainmentDecision(decision="approve")

    def ask(
        self,
        question: str,
        options: list[dict[str, Any]] | None = None,
        allow_free_text: bool = True,
    ) -> AskUserResult:
        self.asked.append(question)
        if self._answers:
            return self._answers.pop(0)
        return cancelled_result()


class CliReviewer:
    """Interactive reviewer for the CLI (tests inject ``input()``).

    Accepts only ``approve`` / ``edit`` / ``reject`` (case- and
    space-insensitive). Anything else, including a blank line, re-asks. Edit
    asks for a new step and a new rollback (blank keeps each); an edit that
    changes neither re-asks. EOF before a valid answer raises
    :class:`ReviewAbortedError` and never approves.
    """

    PROMPT = "approve / edit / reject? "
    INVALID = "Please type approve, edit, or reject."

    def show_report(self, report: Any, dossier: Any) -> None:
        """Print the verdict summary before the analyst decides (feature 1)."""
        print("\n".join(report_summary_lines(report, dossier)))

    def review_step(
        self, step_index: int, step: str, rollback: str, warning: str = ""
    ) -> ContainmentDecision:
        print(f"\n[{step_index}] {step}\n    rollback: {rollback}")
        if warning:
            print(f"    WARNING: {warning}")
        while True:
            choice = self._read_choice()
            if choice == "approve":
                return ContainmentDecision(decision="approve")
            if choice == "reject":
                return ContainmentDecision(decision="reject", reason="analyst rejected")
            if choice == "edit":
                edited = self._read_edit("new step (blank keeps it): ")
                rollback = self._read_edit("new rollback (blank keeps it): ")
                if edited or rollback:
                    return ContainmentDecision(
                        decision="edit",
                        edited_step=edited or None,
                        edited_rollback=rollback or None,
                    )
            print(self.INVALID)

    @classmethod
    def _read_choice(cls) -> str:
        try:
            return input(cls.PROMPT).strip().lower()
        except EOFError as exc:
            raise ReviewAbortedError(
                "input ended before an approve/edit/reject decision"
            ) from exc

    @classmethod
    def _read_edit(cls, prompt: str) -> str:
        try:
            return input(prompt).strip()
        except EOFError as exc:
            raise ReviewAbortedError(
                "input ended before the edited step was supplied"
            ) from exc

    def ask(
        self,
        question: str,
        options: list[dict[str, Any]] | None = None,
        allow_free_text: bool = True,
    ) -> AskUserResult:
        print(f"\n{question}")
        for index, option in enumerate(options or [], start=1):
            print(f"  {index}. {option.get('label', option)}")
        raw = input("answer (blank to cancel): ").strip()
        if not raw:
            return cancelled_result()
        return AskUserResult(
            status="answered",
            answer=raw,
            choice_index=None,
            free_text=True,
        )
