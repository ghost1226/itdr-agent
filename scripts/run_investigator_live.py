"""Live Investigator runner — MANUAL ONLY, never imported by tests.

Reads ``OPENROUTER_API_KEY`` from ``.env`` (via itdr_agent.config). Refuses
to run without a key. This script is intentionally excluded from the test
suite and must not be executed until Joe gives the go.

Usage:
    python scripts/run_investigator_live.py ALERT_001
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from itdr_agent import config  # noqa: E402
from itdr_agent.fixture_store import get_store  # noqa: E402
from itdr_agent.investigator import Investigator  # noqa: E402


class OpenRouterLLM:
    """OpenRouter-backed next_action provider for the Investigator loop."""

    def __init__(self, api_key: str, model: str, timeout: int) -> None:
        from openai import OpenAI

        self.client = OpenAI(
            base_url="https://openrouter.ai/api/v1",
            api_key=api_key,
            timeout=timeout,
        )
        self.model = model

    def next_action(self, messages: list[dict]) -> dict:
        response = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=0,
            response_format={"type": "json_object"},
        )
        return json.loads(response.choices[0].message.content)


def main() -> int:
    # Key comes from .env only; never hardcoded.
    if not config.OPENROUTER_API_KEY:
        print("OPENROUTER_API_KEY is not set. Add it to .env (gitignored).")
        return 2

    # A free model must be verified before real use (Checkpoint 5 open item).
    model = os.getenv("OPENROUTER_MODEL")
    if not model:
        print("Set OPENROUTER_MODEL in .env to a verified model id.")
        return 2

    alert_id = sys.argv[1] if len(sys.argv) > 1 else "ALERT_001"
    alerts = {a["id"]: a for a in get_store().alerts}
    if alert_id not in alerts:
        print(f"Unknown alert id {alert_id!r}. Known: {sorted(alerts)}")
        return 2

    llm = OpenRouterLLM(
        config.OPENROUTER_API_KEY,
        model,
        timeout=min(config.TIMEOUT_SECONDS, 90),
    )
    dossier = Investigator(llm).investigate(alerts[alert_id])
    print(dossier.model_dump_json(indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
