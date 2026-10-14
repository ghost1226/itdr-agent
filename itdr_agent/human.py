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
    """Interactive reviewer for the CLI demo (not used in tests)."""

    def review_step(
        self, step_index: int, step: str, rollback: str, warning: str = ""
    ) -> ContainmentDecision:
        print(f"\n[{step_index}] {step}\n    rollback: {rollback}")
        if warning:
            print(f"    WARNING: {warning}")
        choice = input("approve / edit / reject? ").strip().lower()
        if choice == "edit":
            return ContainmentDecision(
                decision="edit", edited_step=input("new step: ").strip()
            )
        if choice == "reject":
            return ContainmentDecision(
                decision="reject", reason="analyst rejected"
            )
        return ContainmentDecision(decision="approve")

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
