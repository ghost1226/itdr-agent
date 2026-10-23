"""Bad model replies through OpenRouter (2026-10-23): offline, fake client.

Six of nine Opus runs in the GUI died with a bare ``JSONDecodeError`` while
the same alerts ran clean from the CLI minutes later: some replies on the
route come back as something that is not JSON. The two OpenRouter wrappers
now retry such a reply once and, if it happens twice, raise ``BadReplyError``
carrying the finish reason and a sample of the text, and the run trace keeps
the error message, not only its class name.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from itdr_agent import __main__ as cli  # noqa: E402
from itdr_agent.trace import RunTrace  # noqa: E402


def _reply(content, finish: str = "stop") -> SimpleNamespace:
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=content), finish_reason=finish)],
        usage=None,
    )


class FakeClient:
    """Stands in for ``openai.OpenAI``; returns scripted replies, counts calls."""

    def __init__(self, replies: list[SimpleNamespace]) -> None:
        self.replies = list(replies)
        self.calls = 0
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        self.calls += 1
        self.last_messages = list(kwargs.get("messages") or [])
        return self.replies.pop(0)


def _wrapper(cls, replies, on_reply=None):
    llm = cls.__new__(cls)  # skip __init__: no real OpenAI client
    llm.client = FakeClient(replies)
    llm.model = "test/model"
    llm.meter = None
    llm.on_reply = on_reply  # the real wrappers set this in __init__
    return llm


# --- investigator wrapper ---------------------------------------------------

def test_investigator_retries_a_non_json_reply_once():
    llm = _wrapper(cli._OpenRouterInvestigatorLLM, [
        _reply("<html>502 Bad Gateway</html>"),
        _reply('{"action": "final"}'),
    ])
    assert llm.next_action([{"role": "user", "content": "x"}]) == {"action": "final"}
    assert llm.client.calls == 2


def test_investigator_treats_an_empty_reply_as_bad():
    llm = _wrapper(cli._OpenRouterInvestigatorLLM, [
        _reply(None, finish="content_filter"),
        _reply('{"action": "final"}'),
    ])
    assert llm.next_action([]) == {"action": "final"}
    assert llm.client.calls == 2


def test_investigator_raises_bad_reply_error_with_the_evidence_after_two_failures():
    llm = _wrapper(cli._OpenRouterInvestigatorLLM, [
        _reply("Sure! Here is the plan:", finish="stop"),
        _reply(None, finish="content_filter"),
    ])
    with pytest.raises(cli.BadReplyError) as info:
        llm.next_action([])
    text = str(info.value)
    assert "content_filter" in text  # the second attempt's finish reason
    assert "Sure! Here is the plan" in text or "None" in text  # a sample of what came back
    assert llm.client.calls == 2


# --- adjudicator wrapper ----------------------------------------------------

def test_adjudicator_accepts_fenced_json_without_a_retry():
    fenced = '```json\n{"verdict": "FALSE_POSITIVE"}\n```'
    llm = _wrapper(cli._OpenRouterAdjudicatorLLM, [_reply(fenced)])
    assert llm.complete([]) == fenced  # parse + fence stripping stay in the Adjudicator
    assert llm.client.calls == 1


def test_adjudicator_retries_then_raises_on_non_json():
    llm = _wrapper(cli._OpenRouterAdjudicatorLLM, [
        _reply("I cannot help with that."),
        _reply("", finish="length"),
    ])
    with pytest.raises(cli.BadReplyError) as info:
        llm.complete([])
    assert "length" in str(info.value)
    assert llm.client.calls == 2


# --- trace ------------------------------------------------------------------

def test_trace_keeps_the_error_message():
    trace = RunTrace(alert_id="ALERT_001", run_id="r-msg")
    trace.record_error(cli.BadReplyError("model reply was not JSON twice (finish_reason=content_filter)"))
    assert trace.error.startswith("BadReplyError: model reply was not JSON twice")
    assert "content_filter" in trace.error


# --- embedded JSON and the corrective retry (the 2026-10-23 Opus reruns) -----
# Real replies from logs/runs: ALERT_009 put a sentence before the JSON;
# ALERT_003 wrote its wrap-up as markdown instead of {"action": "final"}.
# Resending the same prompt at temperature 0 returned the same text, so the
# retry has to say what was wrong.

REPLY_009 = (
    "Directory audits came back empty. Next I'll check the trust and compliance "
    "status of the one device seen in the sign-ins.\n\n"
    '{"action": "tool", "tool": "get_device_trust", '
    '"arguments": {"device_id": "5a0a0add-c992-c017-3cbd-1eec0e3c3648"}}'
)
REPLY_003 = (
    "I have enough evidence, so I'm ending the investigation here. All five tools "
    "have been used and the three devices in the sign-in history have been checked."
    "\n\n**What points to compromise:**\n- **Anonymized IP:** The alerting sign-in "
    "came from 185.220.101.9, which is flagged as anonymized."
)


def test_investigator_takes_the_json_object_embedded_in_prose_without_a_retry():
    llm = _wrapper(cli._OpenRouterInvestigatorLLM, [_reply(REPLY_009)])
    action = llm.next_action([{"role": "user", "content": "x"}])
    assert action["tool"] == "get_device_trust"
    assert action["arguments"]["device_id"].startswith("5a0a0add")
    assert llm.client.calls == 1


def test_investigator_retry_tells_the_model_to_send_json_only():
    llm = _wrapper(cli._OpenRouterInvestigatorLLM, [
        _reply(REPLY_003),
        _reply('{"action": "final"}'),
    ])
    assert llm.next_action([{"role": "user", "content": "x"}]) == {"action": "final"}
    assert llm.client.calls == 2
    nudge = llm.client.last_messages[-1]
    assert nudge["role"] == "user"
    assert "JSON" in nudge["content"] and '{"action": "final"}' in nudge["content"]


def test_first_json_object_handles_braces_inside_strings():
    text = 'note {"a": "x } y", "b": {"c": 1}} trailing {'
    assert cli._first_json_object(text) == '{"a": "x } y", "b": {"c": 1}}'
    assert cli._first_json_object("no json here") is None
    assert cli._first_json_object("{unbalanced") is None


# --- every attempt is logged in the run trace, not only failures (2026-10-23) --
# The retry/error path kept the evidence; a run that works kept nothing, so a
# later question about what the route sent had no answer. Both wrappers now
# report each reply through an optional on_reply hook the orchestrator wires
# to the trace.


def test_a_successful_call_records_one_llm_reply():
    trace = RunTrace(alert_id="ALERT_001", run_id="r-one")
    llm = _wrapper(
        cli._OpenRouterInvestigatorLLM,
        [_reply('{"action": "final"}', finish="stop")],
        on_reply=trace.record_llm_reply,
    )
    assert llm.next_action([{"role": "user", "content": "x"}]) == {"action": "final"}
    assert trace.llm_replies == [
        {
            "stage": "investigation",
            "finish_reason": "stop",
            "sample": '{"action": "final"}',
        }
    ]


def test_a_two_attempt_call_records_both_replies():
    trace = RunTrace(alert_id="ALERT_001", run_id="r-two")
    llm = _wrapper(
        cli._OpenRouterInvestigatorLLM,
        [_reply("Sure! Here is the plan:"), _reply('{"action": "final"}')],
        on_reply=trace.record_llm_reply,
    )
    assert llm.next_action([]) == {"action": "final"}
    assert [reply["finish_reason"] for reply in trace.llm_replies] == ["stop", "stop"]
    assert [reply["sample"] for reply in trace.llm_replies] == [
        "Sure! Here is the plan:",
        '{"action": "final"}',
    ]


def test_the_adjudicator_records_replies_under_its_own_stage():
    trace = RunTrace(alert_id="ALERT_001", run_id="r-adj")
    llm = _wrapper(
        cli._OpenRouterAdjudicatorLLM,
        [_reply('{"verdict": "FALSE_POSITIVE"}')],
        on_reply=trace.record_llm_reply,
    )
    assert llm.complete([]) == '{"verdict": "FALSE_POSITIVE"}'
    assert [reply["stage"] for reply in trace.llm_replies] == ["adjudication"]


def test_the_recorded_sample_never_exceeds_300_characters():
    trace = RunTrace(alert_id="ALERT_001", run_id="r-long")
    llm = _wrapper(
        cli._OpenRouterInvestigatorLLM,
        [_reply("x" * 900), _reply('{"action": "final"}')],
        on_reply=trace.record_llm_reply,
    )
    llm.next_action([])
    assert trace.llm_replies[0]["sample"] == "x" * 300


def test_orchestrator_wires_the_hook_so_the_run_json_lists_every_reply(tmp_path):
    """End to end: an orchestrator run writes every reply to runs/<id>.json."""
    from test_orchestrator import _report
    from test_trace import ALERT, fake_tool

    from itdr_agent.adjudicator import Adjudicator
    from itdr_agent.human import ScriptedReviewer
    from itdr_agent.investigator import Investigator
    from itdr_agent.orchestrator import Orchestrator

    investigator = Investigator(
        _wrapper(
            cli._OpenRouterInvestigatorLLM,
            [
                _reply('{"action": "tool", "tool": "get_user_profile", "arguments": {"upn": "x"}}'),
                _reply('{"action": "tool", "tool": "get_sign_in_history", "arguments": {"upn": "x"}}'),
                _reply('{"action": "final"}'),
            ],
        ),
        tool_executor=fake_tool,
    )
    adjudicator = Adjudicator(
        _wrapper(cli._OpenRouterAdjudicatorLLM, [_reply(_report())]),
        baseline=None,
    )
    Orchestrator(
        investigator,
        adjudicator,
        ScriptedReviewer(),
        audit_log=tmp_path / "audit.jsonl",
        mode="mock",
        dirty=False,
        model="test/model",
    ).run(ALERT, run_id="r-replies-e2e")

    payload = json.loads(
        (tmp_path / "runs" / "r-replies-e2e.json").read_text(encoding="utf-8")
    )
    stages = [reply["stage"] for reply in payload["llm_replies"]]
    assert stages.count("investigation") == 3  # 2 tool turns + the final turn
    assert stages.count("adjudication") == 1
    assert all(reply["finish_reason"] == "stop" for reply in payload["llm_replies"])


def test_adjudicator_takes_the_embedded_report_and_retries_with_the_nudge():
    llm = _wrapper(cli._OpenRouterAdjudicatorLLM, [
        _reply('Here is my report:\n{"verdict": "FALSE_POSITIVE"}\nLet me know.'),
    ])
    assert llm.complete([]) == '{"verdict": "FALSE_POSITIVE"}'
    assert llm.client.calls == 1
    llm = _wrapper(cli._OpenRouterAdjudicatorLLM, [
        _reply("**Verdict:** false positive, see below."),
        _reply('{"verdict": "FALSE_POSITIVE"}'),
    ])
    assert llm.complete([]) == '{"verdict": "FALSE_POSITIVE"}'
    assert "JSON" in llm.client.last_messages[-1]["content"]
