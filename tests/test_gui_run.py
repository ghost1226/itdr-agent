"""GUI run controller tests (mocked, offline).

``GuiRun`` runs the real orchestrator on a worker thread and is the reviewer
it waits on: the web page reads its state and answers through it. No
Streamlit, no network, no API key, no live tokens.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from itdr_agent.adjudicator import UNSAFE_ROLLBACK_WARNING, Adjudicator  # noqa: E402
from itdr_agent.fixture_store import get_store  # noqa: E402
from itdr_agent.human import CANCELLED_ANSWER  # noqa: E402
from itdr_agent.investigator import Investigator  # noqa: E402
from itdr_agent.orchestrator import Orchestrator  # noqa: E402

try:
    from itdr_agent.gui_run import GuiRun  # noqa: E402
except ModuleNotFoundError:  # red phase: module not written yet
    GuiRun = None

WAIT = 5.0


class ToolScriptLLM:
    """Fake Investigator LLM: replays a fixed list of actions."""

    def __init__(self, actions: list[dict]) -> None:
        self.actions = list(actions)

    def next_action(self, messages: list[dict]) -> dict:
        return self.actions.pop(0) if self.actions else {"action": "final"}


class CompleteLLM:
    def __init__(self, responses: list[str]) -> None:
        self.responses = list(responses)
        self.calls = 0

    def complete(self, messages: list[dict]) -> str:
        self.calls += 1
        if not self.responses:
            raise AssertionError("Adjudicator called more than scripted")
        return self.responses.pop(0)


def _alert(alert_id: str = "ALERT_001") -> dict:
    return next(a for a in get_store().alerts if a["id"] == alert_id)


def _report(**overrides) -> str:
    report = {
        "verdict": "COMPROMISED",
        "confidence": 0.9,
        "narrative": "test narrative",
        "containment_steps": [
            {"step": "Disable the account", "rollback": "Re-enable the account"}
        ],
        "recommended_actions": ["Contact the user"],
        "mitre_techniques_observed": [],
        "audit_notes": "",
    }
    report.update(overrides)
    return json.dumps(report)


def _make(tmp_path, responses, alert_id="ALERT_001", timeout_seconds=None):
    """Return (run, adjudicator llm, audit path)."""
    upn = _alert(alert_id)["userPrincipalName"]
    audit = tmp_path / "audit.jsonl"
    llm = CompleteLLM(responses)

    def build(reviewer, tool_executor):
        investigator = Investigator(
            ToolScriptLLM(
                [
                    {"action": "tool", "tool": "get_user_profile",
                     "arguments": {"upn": upn}},
                    {"action": "tool", "tool": "get_sign_in_history",
                     "arguments": {"upn": upn, "hours": 10000}},
                    {"action": "final"},
                ]
            ),
            tool_executor=tool_executor,
        )
        return Orchestrator(
            investigator, Adjudicator(llm), reviewer, audit_log=audit,
            timeout_seconds=timeout_seconds,
        )

    run = GuiRun(build, _alert(alert_id))
    return run, llm, audit


def _events(audit: Path, name: str) -> list[dict]:
    return [
        entry
        for entry in map(json.loads, audit.read_text(encoding="utf-8").splitlines())
        if entry["event"] == name
    ]


def test_module_exists():
    assert GuiRun is not None, "itdr_agent/gui_run.py is missing"


def test_tool_calls_are_recorded_in_order(tmp_path):
    run, _, _ = _make(tmp_path, [_report()])
    run.start()
    run.wait(WAIT)
    assert [c["tool"] for c in run.tool_calls] == [
        "get_user_profile",
        "get_sign_in_history",
        "get_directory_audits",
        "get_user_profile",
        "get_sign_in_history",
    ]
    assert all(c["ok"] for c in run.tool_calls)
    assert run.tool_calls[0]["arguments"] == {"upn": _alert()["userPrincipalName"]}
    assert run.tool_calls[1]["arguments"]["hours"] == 168


def test_waits_for_review_then_approve_finishes(tmp_path):
    run, _, audit = _make(tmp_path, [_report()])
    run.start()
    run.wait(WAIT)
    assert run.status == "review"
    assert run.pending == {
        "kind": "review",
        "index": 0,
        "step": "Disable the account",
        "rollback": "Re-enable the account",
        "warning": "",
    }
    run.decide("approve")
    run.wait(WAIT)
    assert run.status == "done"
    assert run.pending is None
    assert [s.step for s in run.result.report.containment_steps] == [
        "Disable the account"
    ]
    (line,) = _events(audit, "containment_decision")
    assert line["decision"] == "approve"
    assert line["run_id"] == run.result.run_id


def test_edit_replaces_the_step_and_is_logged(tmp_path):
    run, _, audit = _make(tmp_path, [_report()])
    run.start()
    run.wait(WAIT)
    run.decide("edit", edited_step="Revoke sessions only")
    run.wait(WAIT)
    assert [s.step for s in run.result.report.containment_steps] == [
        "Revoke sessions only"
    ]
    assert _events(audit, "containment_decision")[0]["final_step"] == (
        "Revoke sessions only"
    )


def test_blank_edit_is_refused_and_keeps_waiting(tmp_path):
    run, _, _ = _make(tmp_path, [_report()])
    run.start()
    run.wait(WAIT)
    with pytest.raises(ValueError):
        run.decide("edit", edited_step="   ")
    assert run.status == "review"
    run.decide("approve")
    run.wait(WAIT)
    assert run.status == "done"


def test_reject_drops_the_step_and_logs_the_reason(tmp_path):
    run, _, audit = _make(tmp_path, [_report()])
    run.start()
    run.wait(WAIT)
    run.decide("reject", reason="not needed")
    run.wait(WAIT)
    assert run.result.report.containment_steps == []
    line = _events(audit, "containment_decision")[0]
    assert (line["decision"], line["reason"]) == ("reject", "not needed")


def test_unknown_decision_is_refused(tmp_path):
    run, _, _ = _make(tmp_path, [_report()])
    run.start()
    run.wait(WAIT)
    with pytest.raises(ValueError):
        run.decide("skip")
    assert run.status == "review"
    run.decide("approve")
    run.wait(WAIT)


def test_unsafe_rollback_warning_reaches_the_page(tmp_path):
    steps = [{"step": "Lock the account",
              "rollback": "Restore the old password"}]
    run, _, _ = _make(tmp_path, [_report(containment_steps=steps)])
    run.start()
    run.wait(WAIT)
    assert run.pending["warning"] == UNSAFE_ROLLBACK_WARNING
    run.decide("reject", reason="unsafe rollback")
    run.wait(WAIT)


def test_low_confidence_asks_one_question_with_options(tmp_path):
    run, _, _ = _make(
        tmp_path,
        [_report(confidence=0.5, containment_steps=[]), _report(containment_steps=[])],
    )
    run.start()
    run.wait(WAIT)
    assert run.status == "question"
    assert run.pending["kind"] == "question"
    # ALERT_001's real dossier has no earlier US sign-in, so the new-country
    # trigger wins over the default verdict/confidence question.
    assert run.pending["question"] == (
        "Is alice.traveler@contoso.com traveling in US, or expected to sign "
        "in from there?"
    )
    assert [o["label"] for o in run.pending["options"]] == [
        "The activity is expected/benign",
        "The activity is suspicious/malicious",
        "I don't know",
    ]
    run.answer(choice_index=0)
    run.wait(WAIT)


def test_choosing_an_option_answers_and_readjudicates(tmp_path):
    run, llm, audit = _make(
        tmp_path,
        [_report(confidence=0.5, containment_steps=[]), _report(containment_steps=[])],
    )
    run.start()
    run.wait(WAIT)
    run.answer(choice_index=1)
    run.wait(WAIT)
    assert run.status == "done"
    assert llm.calls == 2
    (line,) = _events(audit, "ask_user")
    assert line["status"] == "answered"
    assert line["answer"] == "The activity is suspicious/malicious"
    assert line["choice_index"] == 1
    assert line["free_text"] is False
    assert len(_events(audit, "re_adjudication")) == 1


def test_free_text_answer(tmp_path):
    run, _, audit = _make(
        tmp_path,
        [_report(confidence=0.5, containment_steps=[]), _report(containment_steps=[])],
    )
    run.start()
    run.wait(WAIT)
    run.answer("The user is at a conference in London")
    run.wait(WAIT)
    (line,) = _events(audit, "ask_user")
    assert line["answer"] == "The user is at a conference in London"
    assert line["free_text"] is True
    assert line["choice_index"] is None


@pytest.mark.parametrize("text", [None, "", "   "])
def test_blank_answer_cancels_without_readjudication(tmp_path, text):
    run, llm, audit = _make(
        tmp_path, [_report(confidence=0.5, containment_steps=[])]
    )
    run.start()
    run.wait(WAIT)
    run.answer(text)
    run.wait(WAIT)
    assert run.status == "done"
    assert llm.calls == 1
    (line,) = _events(audit, "ask_user")
    assert (line["status"], line["answer"]) == ("cancelled", CANCELLED_ANSWER)
    assert _events(audit, "re_adjudication") == []


def test_bad_option_index_is_refused(tmp_path):
    run, _, _ = _make(
        tmp_path,
        [_report(confidence=0.5, containment_steps=[]), _report(containment_steps=[])],
    )
    run.start()
    run.wait(WAIT)
    with pytest.raises(ValueError):
        run.answer(choice_index=7)
    assert run.status == "question"
    run.answer(choice_index=2)
    run.wait(WAIT)


def test_answering_when_nothing_is_asked_is_refused(tmp_path):
    run, _, _ = _make(tmp_path, [_report()])
    run.start()
    run.wait(WAIT)
    assert run.status == "review"
    with pytest.raises(RuntimeError):
        run.answer("hello")
    run.decide("approve")
    run.wait(WAIT)
    with pytest.raises(RuntimeError):
        run.decide("approve")


def test_analyst_think_time_does_not_count_against_the_timeout(tmp_path):
    run, llm, _ = _make(
        tmp_path,
        [_report(confidence=0.5, containment_steps=[]), _report(containment_steps=[])],
        timeout_seconds=1,
    )
    run.start()
    run.wait(WAIT)
    assert run.status == "question"
    time.sleep(1.3)  # longer than the whole machine budget
    run.answer(choice_index=0)
    run.wait(WAIT)
    assert run.status == "done", run.error
    assert llm.calls == 2


def test_orchestrator_errors_end_the_run_with_a_message(tmp_path):
    run, _, _ = _make(
        tmp_path, [_report(mitre_techniques_observed=["T9999"])]
    )
    run.start()
    run.wait(WAIT)
    assert run.status == "error"
    assert "T9999" in run.error
    assert run.result is None


def test_failed_tool_call_is_recorded_and_the_run_continues(tmp_path):
    from itdr_agent.sim_api import SimulatedGraphError

    upn = _alert()["userPrincipalName"]
    audit = tmp_path / "audit.jsonl"

    def flaky(name, arguments):
        raise SimulatedGraphError(429)

    def build(reviewer, tool_executor):
        investigator = Investigator(
            ToolScriptLLM(
                [{"action": "tool", "tool": "get_user_profile",
                  "arguments": {"upn": upn}}, {"action": "final"}]
            ),
            tool_executor=tool_executor,
        )
        return Orchestrator(
            investigator, Adjudicator(CompleteLLM([])), reviewer, audit_log=audit
        )

    run = GuiRun(build, _alert(), tool_call=flaky)
    run.start()
    run.wait(WAIT)
    # Each of the 3 pre-fetches is retried once; all fail, critical gap ->
    # no model call.
    assert [(c["tool"], c["ok"]) for c in run.tool_calls] == [
        ("get_user_profile", False),
        ("get_user_profile", False),
        ("get_sign_in_history", False),
        ("get_sign_in_history", False),
        ("get_directory_audits", False),
        ("get_directory_audits", False),
    ]
    assert "429" in run.tool_calls[0]["error"]
    assert run.status == "done"
    assert run.result.short_circuited is True


def test_start_twice_is_refused(tmp_path):
    run, _, _ = _make(tmp_path, [_report()])
    run.start()
    with pytest.raises(RuntimeError):
        run.start()
    run.wait(WAIT)
    run.decide("approve")
    run.wait(WAIT)


def test_core_does_not_import_streamlit():
    source = (PROJECT_ROOT / "itdr_agent" / "gui_run.py").read_text(encoding="utf-8")
    assert "streamlit" not in source


# --- Feature 1: the verdict is available before the analyst decides ---------


def test_show_report_is_stored_before_review(tmp_path):
    run, _, _ = _make(tmp_path, [_report()])
    run.start()
    run.wait(WAIT)
    assert run.status == "review"
    assert run.shown_report is not None
    assert run.shown_report.verdict.value == "COMPROMISED"
    assert run.shown_dossier is not None
    run.decide("approve")
    run.wait(WAIT)


def test_show_report_is_stored_before_the_question_and_refreshed(tmp_path):
    first = _report(verdict="SUSPICIOUS", confidence=0.5)
    second = _report(verdict="COMPROMISED", confidence=0.9)
    run, _, _ = _make(tmp_path, [first, second])
    run.start()
    run.wait(WAIT)
    assert run.status == "question"
    # The confidence guardrail coerces the 0.5 SUSPICIOUS report first.
    assert run.shown_report.verdict.value == "INSUFFICIENT_DATA"
    run.answer(choice_index=1)
    run.wait(WAIT)
    assert run.shown_report.verdict.value == "COMPROMISED"
    run.decide("approve")
    run.wait(WAIT)


def test_edit_rollback_only_from_the_page(tmp_path):
    run, _, audit = _make(tmp_path, [_report()])
    run.start()
    run.wait(WAIT)
    run.decide("edit", edited_rollback="Have the user sign in again")
    run.wait(WAIT)
    (step,) = run.result.report.containment_steps
    assert step.rollback == "Have the user sign in again"
    line = _events(audit, "containment_decision")[0]
    assert line["final_rollback"] == "Have the user sign in again"


# --- Voice + batch step 3: BatchRunner runs alerts one at a time -------------
# A run that reaches the analyst (question/review) is parked on its own thread
# and the batch moves on, so several runs can wait on Joe while only one is
# ever investigating.

try:
    from itdr_agent.gui_run import BatchRunner  # noqa: E402
except ImportError:  # red phase
    BatchRunner = None


def _batch(tmp_path, alert_ids):
    runs = []
    for alert_id in alert_ids:
        run, _, _ = _make(tmp_path, [_report()], alert_id=alert_id)
        runs.append(run)
    return runs, BatchRunner(runs)


def test_batch_runner_parks_waiting_runs_and_moves_on(tmp_path):
    runs, batch = _batch(tmp_path, ["ALERT_001", "ALERT_002", "ALERT_010"])
    assert batch.total == 3 and batch.status == "idle"
    assert [r.status for r in runs] == ["idle", "idle", "idle"]
    batch.start()
    assert batch.wait(WAIT) == "done"
    assert [r.status for r in runs] == ["review", "review", "done"]
    assert batch.order == ["ALERT_001", "ALERT_002", "ALERT_010"]
    assert batch.completed == 3 and batch.current is None
    for run in runs[:2]:
        run.decide("approve")
        run.wait(WAIT)
    assert all(r.status == "done" for r in runs)


def test_batch_runner_start_twice_is_refused(tmp_path):
    _runs, batch = _batch(tmp_path, ["ALERT_010"])
    batch.start()
    with pytest.raises(RuntimeError):
        batch.start()
    batch.wait(WAIT)


def test_batch_runner_counts_progress_while_running(tmp_path):
    runs, batch = _batch(tmp_path, ["ALERT_001", "ALERT_002"])
    batch.start()
    batch.wait(WAIT)
    assert batch.completed == batch.total == 2
    assert all(r.status == "review" for r in runs)


# --- GUI rebuild checkpoint 4: the recorded tool calls carry a summary -------


def test_tool_calls_carry_a_plain_summary(tmp_path):
    run, _, _ = _make(tmp_path, [_report()])
    run.start()
    run.wait(WAIT)
    by_name = {}
    for call in run.tool_calls:
        by_name.setdefault(call["tool"], call)
    assert "sign-ins" in by_name["get_sign_in_history"]["summary"]
    assert by_name["get_user_profile"]["summary"]  # job title, department
    assert all("summary" in c for c in run.tool_calls)
    run.decide("approve")
    run.wait(WAIT)


def test_failed_tool_call_summary_says_so(tmp_path):
    from itdr_agent.sim_api import SimulatedGraphError

    upn = _alert()["userPrincipalName"]

    def flaky(name, arguments):
        raise SimulatedGraphError(429)

    def build(reviewer, tool_executor):
        investigator = Investigator(
            ToolScriptLLM([{"action": "final"}]), tool_executor=tool_executor
        )
        return Orchestrator(
            investigator, Adjudicator(CompleteLLM([])), reviewer,
            audit_log=tmp_path / "audit.jsonl",
        )

    run = GuiRun(build, _alert(), tool_call=flaky)
    run.start()
    run.wait(WAIT)
    assert run.tool_calls[0]["ok"] is False
    assert "429" in run.tool_calls[0]["summary"]
