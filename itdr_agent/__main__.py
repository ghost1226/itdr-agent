"""CLI: ``python -m itdr_agent --alert-id ALERT_001``.

Uses the real OpenRouter free model and an interactive reviewer. Manual only
(spends live tokens); tests never import this module. For an offline
deterministic demo, run ``python scripts/demo_orchestrator.py``.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

from . import config
from .adjudicator import DEFAULT_MODEL, Adjudicator
from .fixture_store import get_store
from .human import CliReviewer, ReviewAbortedError
from .investigator import Investigator
from .orchestrator import Orchestrator
from .usage import TokenMeter, format_tokens

# Windows: a redirected stdout (``> dossier.json``) may be cp1252, and the
# model's narrative is free text. UTF-8 keeps a non-ASCII character from
# crashing the run. A real console is already UTF-8 on every OS.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")


class BadReplyError(RuntimeError):
    """The model's reply was not JSON on two tries (2026-10-23).

    Six of nine Opus runs through OpenRouter died with a bare JSONDecodeError
    while the same alerts ran clean minutes later, so a bad reply is retried
    once; the error carries the finish reason and a sample of the text.
    """


def _json_text(response: Any) -> tuple[str, str]:
    """``(content, finish_reason)`` of the first choice, with ``None`` as ``""``."""
    choice = response.choices[0]
    return (choice.message.content or ""), str(getattr(choice, "finish_reason", ""))


def _bad_reply(stage: str, attempts: list[tuple[str, str]]) -> BadReplyError:
    content, finish = attempts[-1]
    sample = content[:300] if content else "None"
    return BadReplyError(
        f"{stage}: model reply was not JSON twice "
        f"(finish_reason={finish or 'unknown'}); last reply: {sample!r}"
    )


class _OpenRouterInvestigatorLLM:
    def __init__(
        self, api_key: str, model: str, timeout: int,
        meter: TokenMeter | None = None,
    ) -> None:
        from openai import OpenAI

        self.client = OpenAI(
            base_url="https://openrouter.ai/api/v1",
            api_key=api_key,
            timeout=timeout,
        )
        self.model = model
        self.meter = meter

    def next_action(self, messages: list[dict]) -> dict[str, Any]:
        attempts: list[tuple[str, str]] = []
        for _ in range(2):  # one retry on a reply that is not JSON
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=0,
                response_format={"type": "json_object"},
                max_tokens=config.MAX_OUTPUT_TOKENS,
            )
            if self.meter is not None:
                self.meter.add(getattr(response, "usage", None))
            content, finish = _json_text(response)
            attempts.append((content, finish))
            try:
                return json.loads(content)
            except json.JSONDecodeError:
                continue
        raise _bad_reply("investigator", attempts)


class _OpenRouterAdjudicatorLLM:
    def __init__(
        self, api_key: str, model: str, timeout: int,
        meter: TokenMeter | None = None,
    ) -> None:
        from openai import OpenAI

        self.client = OpenAI(
            base_url="https://openrouter.ai/api/v1",
            api_key=api_key,
            timeout=timeout,
        )
        self.model = model
        self.meter = meter

    def complete(self, messages: list[dict]) -> str:
        from .adjudicator import _strip_code_fences

        attempts: list[tuple[str, str]] = []
        for _ in range(2):  # one retry on a reply that is not JSON
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=0,
                response_format={"type": "json_object"},
                max_tokens=config.MAX_OUTPUT_TOKENS,
            )
            if self.meter is not None:
                self.meter.add(getattr(response, "usage", None))
            content, finish = _json_text(response)
            attempts.append((content, finish))
            try:
                json.loads(_strip_code_fences(content))  # the Adjudicator parses for real
            except json.JSONDecodeError:
                continue
            return content
        raise _bad_reply("adjudicator", attempts)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="itdr_agent")
    parser.add_argument("--alert-id", default="ALERT_001")
    args = parser.parse_args(argv)

    if not config.OPENROUTER_API_KEY:
        print("OPENROUTER_API_KEY is not set. Add it to .env (gitignored).")
        return 2

    alerts = {alert["id"]: alert for alert in get_store().alerts}
    if args.alert_id not in alerts:
        print(f"Unknown alert id {args.alert_id!r}. Known: {sorted(alerts)}")
        return 2

    model = os.getenv("EVAL_MODEL", DEFAULT_MODEL)
    timeout = min(config.TIMEOUT_SECONDS, 90)
    meter = TokenMeter()
    investigator = Investigator(
        _OpenRouterInvestigatorLLM(config.OPENROUTER_API_KEY, model, timeout, meter)
    )
    adjudicator = Adjudicator(
        _OpenRouterAdjudicatorLLM(config.OPENROUTER_API_KEY, model, timeout, meter)
    )
    try:
        result = Orchestrator(
            investigator,
            adjudicator,
            CliReviewer(),
            token_meter=meter,
            model=model,
            mode="live",
        ).run(alerts[args.alert_id])
    except ReviewAbortedError as exc:
        print(f"Review aborted: {exc}. Nothing was approved; the run has an "
              "'aborted' line in logs/audit.jsonl.")
        return 3
    print(result.report.model_dump_json(indent=2))
    print(format_tokens(result.tokens))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
