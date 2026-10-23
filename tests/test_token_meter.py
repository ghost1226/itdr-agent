"""Token counter: per-run token totals in the CLI, the GUI, and the audit log.

Offline: no network, no API key, no live tokens. The OpenRouter wrappers get a
fake client whose replies carry a ``usage`` block like the real API's.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(Path(__file__).parent))

try:
    from itdr_agent.usage import TokenMeter, format_tokens  # noqa: E402
except ModuleNotFoundError:  # red phase: module not written yet
    pass

from itdr_agent.adjudicator import Adjudicator  # noqa: E402
from itdr_agent.human import ScriptedReviewer  # noqa: E402
from itdr_agent.orchestrator import Orchestrator  # noqa: E402
from test_orchestrator import (  # noqa: E402
    CompleteLLM,
    FakeInvestigator,
    _dossier,
    _report,
)


def _usage(prompt: int, completion: int) -> SimpleNamespace:
    return SimpleNamespace(prompt_tokens=prompt, completion_tokens=completion)


def _usage_with_reasoning(prompt: int, completion: int, reasoning: int) -> SimpleNamespace:
    """OpenRouter puts hidden reasoning in completion_tokens_details."""
    return SimpleNamespace(
        prompt_tokens=prompt,
        completion_tokens=completion,
        completion_tokens_details=SimpleNamespace(reasoning_tokens=reasoning),
    )


def _reply(content: str, usage) -> SimpleNamespace:
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=content))],
        usage=usage,
    )


class FakeClient:
    """Stands in for ``openai.OpenAI``; returns scripted replies."""

    def __init__(self, replies: list[SimpleNamespace]) -> None:
        self.replies = list(replies)
        self.chat = SimpleNamespace(
            completions=SimpleNamespace(create=self._create)
        )

    def _create(self, **kwargs):
        return self.replies.pop(0)


# --- the meter itself -------------------------------------------------------


def test_meter_adds_up_calls():
    meter = TokenMeter()
    meter.add(_usage(100, 20))
    meter.add(_usage(50, 5))
    assert meter.snapshot() == {
        "tokens_in": 150,
        "tokens_out": 25,
        "reasoning_tokens": 0,
        "llm_requests": 2,
        "requests_without_usage": 0,
    }


def test_meter_counts_reasoning_tokens():
    meter = TokenMeter()
    meter.add(_usage_with_reasoning(100, 200, 150))
    meter.add(_usage_with_reasoning(50, 80, 40))
    snap = meter.snapshot()
    assert snap["reasoning_tokens"] == 190
    assert snap["tokens_out"] == 280  # completion still includes the reasoning


def test_reasoning_defaults_to_zero_when_absent():
    meter = TokenMeter()
    meter.add(_usage(100, 20))
    meter.add(None)
    assert meter.snapshot()["reasoning_tokens"] == 0


def test_reasoning_reads_a_dict_details_block():
    meter = TokenMeter()
    meter.add(SimpleNamespace(
        prompt_tokens=1,
        completion_tokens=2,
        completion_tokens_details={"reasoning_tokens": 42},
    ))
    assert meter.snapshot()["reasoning_tokens"] == 42


def test_format_tokens_shows_reasoning_when_present():
    line = format_tokens({"tokens_in": 9540, "tokens_out": 1274,
                          "reasoning_tokens": 860,
                          "llm_requests": 5, "requests_without_usage": 0})
    assert line == "Tokens: 9,540 in / 1,274 out (860 reasoning) across 5 model calls"


def test_format_tokens_omits_reasoning_when_zero():
    assert format_tokens({"tokens_in": 10, "tokens_out": 1,
                          "reasoning_tokens": 0,
                          "llm_requests": 1, "requests_without_usage": 0}) == (
        "Tokens: 10 in / 1 out across 1 model call"
    )


def test_missing_usage_is_counted_not_hidden():
    meter = TokenMeter()
    meter.add(None)
    meter.add(SimpleNamespace(prompt_tokens=None, completion_tokens=None))
    meter.add(_usage(10, 1))
    snap = meter.snapshot()
    assert snap["llm_requests"] == 3
    assert snap["requests_without_usage"] == 2
    assert (snap["tokens_in"], snap["tokens_out"]) == (10, 1)


def test_reset_starts_a_new_run():
    meter = TokenMeter()
    meter.add(_usage(100, 20))
    meter.reset()
    assert meter.snapshot()["llm_requests"] == 0
    assert meter.snapshot()["tokens_in"] == 0


def test_format_tokens():
    assert (
        format_tokens({"tokens_in": 9540, "tokens_out": 1274,
                       "llm_requests": 5, "requests_without_usage": 0})
        == "Tokens: 9,540 in / 1,274 out across 5 model calls"
    )
    assert (
        format_tokens({"tokens_in": 10, "tokens_out": 1,
                       "llm_requests": 1, "requests_without_usage": 0})
        == "Tokens: 10 in / 1 out across 1 model call"
    )
    assert format_tokens({"tokens_in": 0, "tokens_out": 0,
                          "llm_requests": 0, "requests_without_usage": 0}) == (
        "Tokens: no model calls"
    )
    assert format_tokens(None) == "Tokens: not counted"
    line = format_tokens({"tokens_in": 10, "tokens_out": 1,
                          "llm_requests": 3, "requests_without_usage": 2})
    assert line.endswith("(2 calls did not report usage)")


# --- the live wrappers record into the meter -------------------------------


def test_openrouter_wrappers_record_usage():
    from itdr_agent.__main__ import (
        _OpenRouterAdjudicatorLLM,
        _OpenRouterInvestigatorLLM,
    )

    meter = TokenMeter()
    inv = _OpenRouterInvestigatorLLM.__new__(_OpenRouterInvestigatorLLM)
    inv.client = FakeClient([_reply('{"action": "final"}', _usage(300, 40))])
    inv.model, inv.meter = "m", meter
    adj = _OpenRouterAdjudicatorLLM.__new__(_OpenRouterAdjudicatorLLM)
    adj.client = FakeClient([_reply("{}", _usage(200, 60))])
    adj.model, adj.meter = "m", meter

    inv.next_action([{"role": "user", "content": "x"}])
    adj.complete([{"role": "user", "content": "x"}])
    assert meter.snapshot()["tokens_in"] == 500
    assert meter.snapshot()["tokens_out"] == 100
    assert meter.snapshot()["llm_requests"] == 2


def test_usage_is_recorded_even_when_the_reply_is_not_json():
    from itdr_agent.__main__ import _OpenRouterInvestigatorLLM

    meter = TokenMeter()
    inv = _OpenRouterInvestigatorLLM.__new__(_OpenRouterInvestigatorLLM)
    # Two bad replies: the wrapper retries once (2026-10-23), so both are metered.
    inv.client = FakeClient([_reply("not json", _usage(70, 9)), _reply("still not", _usage(70, 9))])
    inv.model, inv.meter = "m", meter
    from itdr_agent.__main__ import BadReplyError
    with pytest.raises(BadReplyError):
        inv.next_action([{"role": "user", "content": "x"}])
    assert meter.snapshot()["tokens_in"] == 140


# --- the orchestrator logs the totals --------------------------------------


class MeteredCompleteLLM(CompleteLLM):
    def __init__(self, responses, meter, usage):
        super().__init__(responses)
        self.meter, self.usage = meter, usage

    def complete(self, messages):
        self.meter.add(self.usage)
        return super().complete(messages)


def _run_entries(path: Path, event: str) -> list[dict]:
    return [
        e for e in map(json.loads, path.read_text().splitlines())
        if e["event"] == event
    ]


def test_run_line_and_result_carry_the_tokens(tmp_path):
    meter = TokenMeter()
    meter.add(_usage(999, 999))  # left over from an earlier run: must reset
    llm = MeteredCompleteLLM([_report()], meter, _usage(1200, 300))
    orch = Orchestrator(
        FakeInvestigator(_dossier()),
        Adjudicator(llm),
        ScriptedReviewer(),
        audit_log=tmp_path / "audit.jsonl",
        token_meter=meter,
    )
    result = orch.run({"id": "ALERT_001"})
    (line,) = _run_entries(tmp_path / "audit.jsonl", "run")
    assert line["tokens_in"] == 1200
    assert line["tokens_out"] == 300
    assert line["llm_requests"] == 1
    assert result.tokens == meter.snapshot()


def test_without_a_meter_tokens_are_null_not_zero(tmp_path):
    orch = Orchestrator(
        FakeInvestigator(_dossier()),
        Adjudicator(CompleteLLM([_report()])),
        ScriptedReviewer(),
        audit_log=tmp_path / "audit.jsonl",
    )
    result = orch.run({"id": "ALERT_001"})
    (line,) = _run_entries(tmp_path / "audit.jsonl", "run")
    assert line["tokens_in"] is None and line["llm_requests"] is None
    assert result.tokens is None


def test_timeout_line_carries_the_tokens_spent(tmp_path):
    from itdr_agent.orchestrator import OrchestrationTimeoutError

    meter = TokenMeter()
    times = iter([0.0, 500.0, 500.0, 500.0])

    class SlowInvestigator(FakeInvestigator):
        def investigate(self, alert):
            meter.add(_usage(800, 100))  # spent before the deadline hit
            return super().investigate(alert)

    orch = Orchestrator(
        SlowInvestigator(_dossier()),
        Adjudicator(CompleteLLM([])),
        ScriptedReviewer(),
        audit_log=tmp_path / "audit.jsonl",
        token_meter=meter,
        clock=lambda: next(times),
    )
    with pytest.raises(OrchestrationTimeoutError):
        orch.run({"id": "ALERT_001"})
    (line,) = _run_entries(tmp_path / "audit.jsonl", "timeout")
    assert line["tokens_in"] == 800 and line["llm_requests"] == 1


# --- CLI and GUI show the line ---------------------------------------------


def test_cli_prints_the_token_line(monkeypatch, capsys):
    import itdr_agent.__main__ as cli
    from itdr_agent import config

    monkeypatch.setattr(config, "OPENROUTER_API_KEY", "sk-or-v1-TEST")

    def fake_inv(key, model, timeout, meter=None):
        return SimpleNamespace(meter=meter)

    class FakeOrchestrator:
        def __init__(self, investigator, adjudicator, reviewer, token_meter=None,
                     **kwargs):
            self.meter = token_meter

        def run(self, alert):
            self.meter.add(_usage(9540, 1274))
            report = SimpleNamespace(model_dump_json=lambda indent=None: "{}")
            return SimpleNamespace(report=report, tokens=self.meter.snapshot())

    monkeypatch.setattr(cli, "_OpenRouterInvestigatorLLM", fake_inv)
    monkeypatch.setattr(cli, "_OpenRouterAdjudicatorLLM", fake_inv)
    monkeypatch.setattr(cli, "Investigator", lambda llm: llm)
    monkeypatch.setattr(cli, "Adjudicator", lambda llm: llm)
    monkeypatch.setattr(cli, "Orchestrator", FakeOrchestrator)
    assert cli.main(["--alert-id", "ALERT_001"]) == 0
    assert "Tokens: 9,540 in / 1,274 out across 1 model call" in capsys.readouterr().out


def test_gui_report_shows_the_token_line(tmp_path, monkeypatch):
    pytest.importorskip("streamlit")
    from test_app import _app, _page_text, _start

    monkeypatch.setenv("ITDR_GUI_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    at = _start(_app(), "ALERT_010")  # unknown user: short-circuits, no review
    assert "Tokens: no model calls" in _page_text(at)
    # The GUI offline mode is a mock run: the orchestrator writes audit-mock.
    (line,) = _run_entries(tmp_path / "audit-mock.jsonl", "run")
    assert line["llm_requests"] == 0
