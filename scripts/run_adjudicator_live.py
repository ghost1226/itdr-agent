"""Live Adjudicator runner — MANUAL ONLY, never imported by tests.

Reads ``OPENROUTER_API_KEY`` from ``.env`` (via ``itdr_agent.config``) and a
dossier JSON file produced by ``scripts/run_investigator_live.py``. Refuses to
run without a key and a dossier. This spends live tokens, so it is **not** run
until Joe says go.

Usage:
    python scripts/run_adjudicator_live.py dossier.json [model]
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from itdr_agent import config  # noqa: E402
from itdr_agent.adjudicator import (  # noqa: E402
    DEFAULT_MODEL,
    Adjudicator,
)
from itdr_agent.schemas import InvestigatorOutput  # noqa: E402


class OpenRouterChat:
    """OpenRouter-backed single-shot completion for the Adjudicator."""

    def __init__(self, api_key: str, model: str, timeout: int) -> None:
        from openai import OpenAI

        self.client = OpenAI(
            base_url="https://openrouter.ai/api/v1",
            api_key=api_key,
            timeout=timeout,
        )
        self.model = model

    def complete(self, messages: list[dict]) -> str:
        response = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=0,
            response_format={"type": "json_object"},
            max_tokens=config.MAX_OUTPUT_TOKENS,
        )
        return response.choices[0].message.content or ""


def main() -> int:
    # Key comes from .env only; never hardcoded.
    if not config.OPENROUTER_API_KEY:
        print("OPENROUTER_API_KEY is not set. Add it to .env (gitignored).")
        return 2
    if len(sys.argv) < 2:
        print(
            "Usage: python scripts/run_adjudicator_live.py dossier.json [model]"
        )
        return 2

    dossier_path = Path(sys.argv[1])
    if not dossier_path.exists():
        print(f"Dossier not found: {dossier_path}")
        return 2

    model = (
        sys.argv[2]
        if len(sys.argv) > 2
        else os.getenv("EVAL_MODEL", DEFAULT_MODEL)
    )
    dossier = InvestigatorOutput.model_validate_json(
        dossier_path.read_text(encoding="utf-8")
    )
    llm = OpenRouterChat(
        config.OPENROUTER_API_KEY,
        model,
        timeout=min(config.TIMEOUT_SECONDS, 90),
    )
    report = Adjudicator(llm).adjudicate(dossier)
    print(report.model_dump_json(indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
