"""Run controller for the local web GUI (``app.py``).

``GuiRun`` runs the real orchestrator on a worker thread and is the reviewer
the orchestrator waits on. When the orchestrator asks its one question or
needs a containment decision, the worker blocks and ``status`` / ``pending``
tell the page what to show; the page answers with ``answer()`` or
``decide()``. The orchestrator, guardrails, and audit log are unchanged; this
module only swaps the CLI's ``input()`` for a hand-off between two threads.

Every tool call goes through a recording executor so the page can show what
the Investigator looked at, including failed attempts.

``BatchRunner`` runs several ``GuiRun``s one at a time: it starts the next
run as soon as the current one leaves ``running`` (parked on a question or a
containment step, finished, or failed). Only one alert is ever investigating,
so a batch never bursts the free tier, while several runs can wait on the
analyst at once.

Kept free of any web framework so it is testable offline.
"""

from __future__ import annotations

import threading
import time
from typing import Any, Callable

from .human import AskUserResult, ContainmentDecision, cancelled_result
from .summary import describe_tool_result
from .sim_api import SimulatedGraphError
from .tools import call_tool

ToolCall = Callable[[str, dict[str, Any]], Any]
BuildOrchestrator = Callable[[Any, ToolCall], Any]

DECISIONS = ("approve", "edit", "reject")


class GuiRun:
    """One alert's run, shared between the worker thread and the page."""

    def __init__(
        self,
        build: BuildOrchestrator,
        alert: dict[str, Any],
        tool_call: ToolCall = call_tool,
    ) -> None:
        self._build = build
        self.alert = alert
        self._tool_call = tool_call
        self._cond = threading.Condition()
        self._thread: threading.Thread | None = None
        self._reply: Any = None
        self.status = "idle"  # idle | running | question | review | done | error
        self.pending: dict[str, Any] | None = None
        self.tool_calls: list[dict[str, Any]] = []
        # step index -> "approve" | "edit" | "reject", as the analyst decides.
        self.decisions: dict[int, str] = {}
        self.result: Any = None
        self.error: str | None = None
        # Pre-decision report summary (feature 1): stored by show_report and
        # refreshed after a re-adjudication.
        self.shown_report: Any = None
        self.shown_dossier: Any = None
        # The orchestrator this run built, so the page can read its token meter
        # while the model works (batch progress line, 2026-10-23).
        self.orchestrator: Any = None
        self.started: float | None = None

    @property
    def meter(self) -> Any:
        return getattr(self.orchestrator, "token_meter", None)

    # --- page side ---------------------------------------------------------

    def start(self) -> None:
        with self._cond:
            if self._thread is not None:
                raise RuntimeError("this run has already started")
            self.status = "running"
            self._thread = threading.Thread(target=self._work, daemon=True)
        self._thread.start()

    def wait(self, timeout: float | None = None) -> str:
        """Block until the run needs the analyst, finishes, or fails."""
        with self._cond:
            self._cond.wait_for(lambda: self.status != "running", timeout)
            return self.status

    def answer(
        self, text: str | None = None, choice_index: int | None = None
    ) -> None:
        """Answer the question: pick an option, type text, or leave blank to cancel."""
        with self._cond:
            if self.status != "question":
                raise RuntimeError("no question is waiting for an answer")
            options = self.pending["options"]
            if choice_index is not None:
                if not 0 <= choice_index < len(options):
                    raise ValueError(f"no option {choice_index}")
                result = AskUserResult(
                    status="answered",
                    answer=options[choice_index]["label"],
                    choice_index=choice_index,
                    free_text=False,
                )
            elif text is None or not text.strip():
                result = cancelled_result()
            else:
                result = AskUserResult(
                    status="answered",
                    answer=text.strip(),
                    choice_index=None,
                    free_text=True,
                )
            self._hand_back(result)

    def decide(
        self,
        decision: str,
        edited_step: str | None = None,
        reason: str | None = None,
        edited_rollback: str | None = None,
    ) -> None:
        """Approve, edit, or reject the containment step on screen."""
        with self._cond:
            if self.status != "review":
                raise RuntimeError("no containment step is waiting for review")
            if decision not in DECISIONS:
                raise ValueError(f"unknown decision {decision!r}")
            if decision == "edit":
                edited_step = (edited_step or "").strip() or None
                edited_rollback = (edited_rollback or "").strip() or None
                if not (edited_step or edited_rollback):
                    raise ValueError("an edit needs a new step or a new rollback")
            self.decisions[self.pending["index"]] = decision
            self._hand_back(
                ContainmentDecision(
                    decision=decision,
                    edited_step=edited_step if decision == "edit" else None,
                    edited_rollback=edited_rollback if decision == "edit" else None,
                    reason=(reason or None) if decision == "reject" else None,
                )
            )

    # --- Reviewer protocol (worker side) -----------------------------------

    def show_report(self, report: Any, dossier: Any) -> None:
        """Store the verdict so the page can show it before the analyst decides."""
        with self._cond:
            self.shown_report = report
            self.shown_dossier = dossier
            self._cond.notify_all()

    def ask(
        self,
        question: str,
        options: list[dict[str, Any]] | None = None,
        allow_free_text: bool = True,
    ) -> AskUserResult:
        return self._wait_for_page(
            "question",
            {
                "kind": "question",
                "question": question,
                "options": list(options or []),
                "allow_free_text": allow_free_text,
            },
        )

    def review_step(
        self, step_index: int, step: str, rollback: str, warning: str = ""
    ) -> ContainmentDecision:
        return self._wait_for_page(
            "review",
            {
                "kind": "review",
                "index": step_index,
                "step": step,
                "rollback": rollback,
                "warning": warning,
            },
        )

    # --- internals ---------------------------------------------------------

    def _record_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        entry: dict[str, Any] = {
            "tool": name,
            "arguments": dict(arguments),
            "ok": True,
            "error": None,
            "summary": "",
        }
        try:
            result = self._tool_call(name, arguments)
        except SimulatedGraphError as exc:
            entry["ok"] = False
            entry["error"] = str(exc)
            entry["summary"] = f"failed: {exc.status_code}"
            raise
        except Exception as exc:
            entry["ok"] = False
            entry["error"] = str(exc)
            entry["summary"] = f"failed: {type(exc).__name__}"
            raise
        else:
            entry["summary"] = describe_tool_result(name, result)
            return result
        finally:
            with self._cond:
                self.tool_calls.append(entry)

    def _wait_for_page(self, status: str, pending: dict[str, Any]) -> Any:
        with self._cond:
            self._reply = None
            self.pending = pending
            self.status = status
            self._cond.notify_all()
            self._cond.wait_for(lambda: self._reply is not None)
            reply, self._reply = self._reply, None
            return reply

    def _hand_back(self, reply: Any) -> None:
        # Caller holds the lock.
        self.pending = None
        self.status = "running"
        self._reply = reply
        self._cond.notify_all()

    def _work(self) -> None:
        try:
            self.orchestrator = self._build(self, self._record_tool)
            self.started = time.time()
            result = self.orchestrator.run(self.alert)
        except Exception as exc:  # shown on the page, never swallowed
            with self._cond:
                self.error = f"{type(exc).__name__}: {exc}"
                self.status = "error"
                self.pending = None
                self._cond.notify_all()
            return
        with self._cond:
            self.result = result
            self.status = "done"
            self._cond.notify_all()


class BatchRunner:
    """Run a list of ``GuiRun``s one at a time on a worker thread."""

    def __init__(self, runs: list[GuiRun]) -> None:
        self.runs = list(runs)
        self.total = len(self.runs)
        self.completed = 0
        self.current: str | None = None
        self.order: list[str] = []
        self.status = "idle"  # idle | running | done
        self._cond = threading.Condition()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        with self._cond:
            if self._thread is not None:
                raise RuntimeError("this batch has already started")
            self.status = "running"
            self._thread = threading.Thread(target=self._work, daemon=True)
        self._thread.start()

    def wait(self, timeout: float | None = None) -> str:
        """Block until every run has started and left ``running``."""
        with self._cond:
            self._cond.wait_for(lambda: self.status != "running", timeout)
            return self.status

    def _work(self) -> None:
        for run in self.runs:
            alert_id = run.alert.get("id", "")
            with self._cond:
                self.current = alert_id
                self.order.append(alert_id)
            run.start()
            run.wait(None)  # parked on the analyst, done, or failed
            with self._cond:
                self.completed += 1
                self.current = None
        with self._cond:
            self.status = "done"
            self._cond.notify_all()
