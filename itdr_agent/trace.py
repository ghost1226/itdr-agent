"""Per-run trace: one JSON file beside the audit log.

Synthetic data only (AGENTS.md rule 1). A trace is local debugging evidence --
every tool call, every model request, the dossier, the report, and the
analyst's answers -- so a run can be inspected without re-spending tokens or
re-reading the audit log. Traces are gitignored like the audit log.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Callable

RUNS_DIRNAME = "runs"


def count_rows(result: Any) -> int:
    """Rows returned by a tool: a list's length, a record is one row, else 0."""
    if isinstance(result, list):
        return len(result)
    if isinstance(result, dict):
        return 1
    return 0


class RunTrace:
    """Collects the ordered evidence for one orchestrator run."""

    def __init__(
        self, alert_id: str, run_id: str, meter: Any | None = None
    ) -> None:
        self.alert_id = alert_id
        self.run_id = run_id
        self._meter = meter
        self.tool_calls: list[dict[str, Any]] = []
        self.llm_requests: list[dict[str, Any]] = []
        self.llm_replies: list[dict[str, Any]] = []
        self.analyst_answers: list[dict[str, Any]] = []
        self.error: str | None = None

    def record_tool_call(
        self, name: str, arguments: dict[str, Any], result: Any
    ) -> None:
        self.tool_calls.append(
            {"name": name, "arguments": arguments, "rows": count_rows(result)}
        )

    def record_tool_error(
        self, name: str, arguments: dict[str, Any], exc: BaseException
    ) -> None:
        self.tool_calls.append(
            {
                "name": name,
                "arguments": arguments,
                "error": type(exc).__name__,
            }
        )

    def record_baseline(self, upn: str, hours: int, counts: tuple[int, int]) -> None:
        """The thin-evidence guard's own two Graph lookups (review 2026-10-21, 4)."""
        for name, rows in zip(
            ("baseline:get_sign_in_history", "baseline:get_directory_audits"), counts
        ):
            self.tool_calls.append(
                {"name": name, "arguments": {"upn": upn, "hours": hours}, "rows": rows}
            )

    def record_error(self, exc: BaseException) -> None:
        """The run failed; keep the class name and the message (capped)."""
        message = str(exc)
        self.error = f"{type(exc).__name__}: {message}"[:600] if message else type(exc).__name__

    def record_llm_reply(
        self, stage: str, finish_reason: str, sample: str
    ) -> None:
        """Every model reply, success or failure (2026-10-23).

        The bad-reply retry kept the finish reason and a sample only when both
        tries failed, so a run that worked left no evidence of what the route
        sent. ``sample`` is the reply's first 300 characters -- evidence, never
        the whole reply.
        """
        self.llm_replies.append(
            {
                "stage": stage,
                "finish_reason": finish_reason,
                "sample": (sample or "")[:300],
            }
        )

    def record_analyst_answer(self, result: Any) -> None:
        self.analyst_answers.append(
            {
                "status": result.status,
                "answer": result.answer,
                "choice_index": result.choice_index,
                "free_text": result.free_text,
            }
        )

    def call_llm(self, stage: str, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        """Time one model call and record its per-request tokens from the meter."""
        before = self._meter.snapshot() if self._meter is not None else None
        started = time.monotonic()
        output = fn(*args, **kwargs)
        seconds = time.monotonic() - started
        after = self._meter.snapshot() if self._meter is not None else None
        self.llm_requests.append(
            {
                "stage": stage,
                "tokens_in": (
                    None if before is None else after["tokens_in"] - before["tokens_in"]
                ),
                "tokens_out": (
                    None
                    if before is None
                    else after["tokens_out"] - before["tokens_out"]
                ),
                "reasoning_tokens": (
                    None
                    if before is None
                    else after["reasoning_tokens"] - before["reasoning_tokens"]
                ),
                "seconds": round(seconds, 3),
            }
        )
        return output

    def to_dict(self, dossier: Any = None, report: Any = None) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "alert_id": self.alert_id,
            "tool_calls": self.tool_calls,
            "llm_requests": self.llm_requests,
            "llm_replies": self.llm_replies,
            "dossier": (
                dossier.model_dump(mode="json") if dossier is not None else None
            ),
            "report": (
                report.model_dump(mode="json") if report is not None else None
            ),
            "analyst_answers": self.analyst_answers,
            "error": self.error,
        }

    def write(self, path: str | Path, dossier: Any = None, report: Any = None) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.to_dict(dossier, report), indent=2, default=str),
            encoding="utf-8",
            newline="\n",
        )
        return path
