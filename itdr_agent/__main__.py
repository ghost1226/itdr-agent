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
from typing import Any, Callable

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


def _first_json_object(text: str) -> str | None:
    """The first balanced ``{...}`` in ``text``, or None (2026-10-23).

    Opus sometimes writes a sentence before the JSON it was told to send
    alone (ALERT_009). Braces inside JSON strings are skipped.
    """
    start = text.find("{")
    if start == -1:
        return None
    depth, in_string, escaped = 0, False, False
    for i in range(start, len(text)):
        ch = text[i]
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return None


def _json_in(content: str, strip_fences=None) -> str | None:
    """``content`` itself if it parses (after fence stripping), else the first
    embedded JSON object if that parses, else None."""
    candidates = [strip_fences(content) if strip_fences else content]
    embedded = _first_json_object(content)
    if embedded is not None:
        candidates.append(embedded)
    for candidate in candidates:
        try:
            json.loads(candidate)
        except json.JSONDecodeError:
            continue
        return candidate
    return None


# Sent as one extra user turn on the retry: resending the same prompt at
# temperature 0 returns the same prose (ALERT_003's markdown wrap-up).
INVESTIGATOR_JSON_NUDGE = (
    "Reply with only the JSON object, no prose before or after it. "
    'If the investigation is done, reply {"action": "final"}.'
)
ADJUDICATOR_JSON_NUDGE = (
    "Reply with only the JSON object for the report, no prose before or after it."
)


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
        on_reply: Callable[..., None] | None = None,
    ) -> None:
        from openai import OpenAI

        self.client = OpenAI(
            base_url="https://openrouter.ai/api/v1",
            api_key=api_key,
            timeout=timeout,
        )
        self.model = model
        self.meter = meter
        # Called with (stage, finish_reason, sample) for every attempt,
        # success or failure; the orchestrator points it at the run trace.
        self.on_reply = on_reply

    def next_action(self, messages: list[dict]) -> dict[str, Any]:
        attempts: list[tuple[str, str]] = []
        nudge = {"role": "user", "content": INVESTIGATOR_JSON_NUDGE}
        for attempt in range(2):  # one retry, with the nudge, on a reply with no JSON
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages if attempt == 0 else [*messages, nudge],
                temperature=0,
                response_format={"type": "json_object"},
                max_tokens=config.MAX_OUTPUT_TOKENS,
            )
            if self.meter is not None:
                self.meter.add(getattr(response, "usage", None))
            content, finish = _json_text(response)
            attempts.append((content, finish))
            hook = getattr(self, "on_reply", None)
            if hook is not None:
                hook("investigation", finish, content[:300])
            found = _json_in(content)
            if found is not None:
                return json.loads(found)
        raise _bad_reply("investigator", attempts)


class _OpenRouterAdjudicatorLLM:
    def __init__(
        self, api_key: str, model: str, timeout: int,
        meter: TokenMeter | None = None,
        on_reply: Callable[..., None] | None = None,
    ) -> None:
        from openai import OpenAI

        self.client = OpenAI(
            base_url="https://openrouter.ai/api/v1",
            api_key=api_key,
            timeout=timeout,
        )
        self.model = model
        self.meter = meter
        # Called with (stage, finish_reason, sample) for every attempt,
        # success or failure; the orchestrator points it at the run trace.
        self.on_reply = on_reply

    def complete(self, messages: list[dict]) -> str:
        from .adjudicator import _strip_code_fences

        attempts: list[tuple[str, str]] = []
        nudge = {"role": "user", "content": ADJUDICATOR_JSON_NUDGE}
        for attempt in range(2):  # one retry, with the nudge, on a reply with no JSON
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages if attempt == 0 else [*messages, nudge],
                temperature=0,
                response_format={"type": "json_object"},
                max_tokens=config.MAX_OUTPUT_TOKENS,
            )
            if self.meter is not None:
                self.meter.add(getattr(response, "usage", None))
            content, finish = _json_text(response)
            attempts.append((content, finish))
            hook = getattr(self, "on_reply", None)
            if hook is not None:
                hook("adjudication", finish, content[:300])
            found = _json_in(content, _strip_code_fences)
            if found is not None:
                # Unchanged when the reply parses as sent (fences included: the
                # Adjudicator strips them); the embedded object otherwise.
                return content if found == _strip_code_fences(content) else found
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
