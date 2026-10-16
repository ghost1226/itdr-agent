"""Token counter for one run: what the model calls actually spent.

The live OpenRouter wrappers call ``TokenMeter.add`` with each reply's
``usage`` block; the orchestrator resets the meter at the start of a run and
writes its snapshot into the audit log. A reply without usage is counted as a
call, never silently as zero tokens.
"""

from __future__ import annotations

from typing import Any


class TokenMeter:
    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self.tokens_in = 0
        self.tokens_out = 0
        self.llm_requests = 0
        self.requests_without_usage = 0

    def add(self, usage: Any) -> None:
        """Record one model call from its ``usage`` block (may be None)."""
        self.llm_requests += 1
        prompt = getattr(usage, "prompt_tokens", None)
        completion = getattr(usage, "completion_tokens", None)
        if prompt is None and completion is None:
            self.requests_without_usage += 1
            return
        self.tokens_in += int(prompt or 0)
        self.tokens_out += int(completion or 0)

    def snapshot(self) -> dict[str, int]:
        return {
            "tokens_in": self.tokens_in,
            "tokens_out": self.tokens_out,
            "llm_requests": self.llm_requests,
            "requests_without_usage": self.requests_without_usage,
        }


def format_tokens(snapshot: dict[str, int] | None) -> str:
    """One line for the CLI and the GUI."""
    if snapshot is None:
        return "Tokens: not counted"
    calls = snapshot["llm_requests"]
    if calls == 0:
        return "Tokens: no model calls"
    line = (
        f"Tokens: {snapshot['tokens_in']:,} in / {snapshot['tokens_out']:,} out "
        f"across {calls} model call{'s' if calls != 1 else ''}"
    )
    missing = snapshot["requests_without_usage"]
    if missing:
        line += f" ({missing} call{'s' if missing != 1 else ''} did not report usage)"
    return line
