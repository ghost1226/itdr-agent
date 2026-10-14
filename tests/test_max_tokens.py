"""Every model call caps its output tokens (offline, no API key, no network).

Without ``max_tokens``, OpenRouter reserves the model's whole context window
(~234k tokens) per request, so a key with credits or a spending limit fails
with 402 before the model runs. The live modules are parsed, never imported.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path
from types import SimpleNamespace

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

import evaluate  # noqa: E402
from itdr_agent import config  # noqa: E402

LIVE_CALL_FILES = [
    "itdr_agent/__main__.py",
    "scripts/evaluate.py",
    "scripts/run_investigator_live.py",
    "scripts/run_adjudicator_live.py",
]


def _create_calls(path: Path) -> list[ast.Call]:
    tree = ast.parse(path.read_text())
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "create"
        and ast.unparse(node.func).endswith("chat.completions.create")
    ]


def test_output_cap_is_a_sane_positive_int():
    assert isinstance(config.MAX_OUTPUT_TOKENS, int)
    assert 1024 <= config.MAX_OUTPUT_TOKENS <= 32_768


def test_every_live_create_call_passes_the_config_cap():
    found = 0
    for rel in LIVE_CALL_FILES:
        for call in _create_calls(PROJECT_ROOT / rel):
            found += 1
            kwargs = {kw.arg: ast.unparse(kw.value) for kw in call.keywords}
            assert kwargs.get("max_tokens") == "config.MAX_OUTPUT_TOKENS", (
                f"{rel}:{call.lineno} has no max_tokens=config.MAX_OUTPUT_TOKENS"
            )
    assert found == 5


def test_eval_chat_sends_max_tokens():
    sent = {}

    def create(**kwargs):
        sent.update(kwargs)
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content="{}"))],
            usage=None,
        )

    client = SimpleNamespace(
        chat=SimpleNamespace(completions=SimpleNamespace(create=create))
    )
    budget = SimpleNamespace(acquire=lambda: None, add_usage=lambda usage: None)
    evaluate._chat(client, "test/model", budget, [{"role": "user", "content": "x"}])
    assert sent["max_tokens"] == config.MAX_OUTPUT_TOKENS
