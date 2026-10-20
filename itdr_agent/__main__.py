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
from .human import CliReviewer
from .investigator import Investigator
from .orchestrator import Orchestrator
from .usage import TokenMeter, format_tokens


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
        response = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=0,
            response_format={"type": "json_object"},
            max_tokens=config.MAX_OUTPUT_TOKENS,
        )
        if self.meter is not None:
            self.meter.add(getattr(response, "usage", None))
        return json.loads(response.choices[0].message.content or "{}")


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
        response = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=0,
            response_format={"type": "json_object"},
            max_tokens=config.MAX_OUTPUT_TOKENS,
        )
        if self.meter is not None:
            self.meter.add(getattr(response, "usage", None))
        return response.choices[0].message.content or ""


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
    result = Orchestrator(
        investigator,
        adjudicator,
        CliReviewer(),
        token_meter=meter,
        model=model,
        mode="live",
    ).run(alerts[args.alert_id])
    print(result.report.model_dump_json(indent=2))
    print(format_tokens(result.tokens))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
