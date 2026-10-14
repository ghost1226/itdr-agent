"""Checkpoint 6 — frozen ``ask_user`` contract and the reviewer interface.

Mirrors the HW4 Pi extension contract: an answer is ``answered`` or
``cancelled``; a cancel is exactly ``"no decision has been supplied"`` and no
caller may invent a choice. The analyst may approve, edit, or reject each
containment step.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

CANCELLED_ANSWER = "no decision has been supplied"


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
    edited_step: str | None = None
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
    space-insensitive). Anything else, including a blank line, re-asks. A
    blank edit re-asks too. EOF before a valid answer raises
    :class:`ReviewAbortedError` and never approves.
    """

    PROMPT = "approve / edit / reject? "
    INVALID = "Please type approve, edit, or reject."

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
                edited = self._read_edit()
                if edited:
                    return ContainmentDecision(decision="edit", edited_step=edited)
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
    def _read_edit(cls) -> str:
        try:
            return input("new step: ").strip()
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
