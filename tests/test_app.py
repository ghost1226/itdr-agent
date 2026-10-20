"""Local web GUI tests (``app.py``), offline mode only.

Uses Streamlit's own ``AppTest`` runner: no browser, no server, no network,
no API key, no live tokens. Skipped when the optional GUI dependency
(``requirements-gui.txt``) is not installed.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest  # noqa: E402

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from itdr_agent import config  # noqa: E402

APP = str(PROJECT_ROOT / "app.py")
FAKE_KEY = "sk-or-v1-THIS-IS-A-TEST-SECRET"


@pytest.fixture
def audit(tmp_path, monkeypatch):
    # The GUI's offline mode is a mock run, so the orchestrator writes
    # ``audit-mock.jsonl`` beside the configured path.
    monkeypatch.setenv("ITDR_GUI_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    # Never let a test see a real key, and prove the page never prints one.
    monkeypatch.setattr(config, "OPENROUTER_API_KEY", FAKE_KEY)
    return tmp_path / "audit-mock.jsonl"


def _app() -> AppTest:
    at = AppTest.from_file(APP, default_timeout=30)
    at.run()
    assert not at.exception, at.exception
    return at


def _start(at: AppTest, alert_id: str) -> AppTest:
    at.selectbox(key="alert_id").set_value(alert_id)
    at.button(key="start").click()
    at.run()
    assert not at.exception, at.exception
    return at


def _page_text(at: AppTest) -> str:
    parts = []
    for kind in ("markdown", "caption", "text", "code", "info", "warning",
                 "error", "success", "subheader", "header", "title"):
        parts.extend(str(el.value) for el in getattr(at, kind))
    return "\n".join(parts)


def _events(path: Path, name: str) -> list[dict]:
    if not path.exists():
        return []
    return [
        entry
        for entry in map(json.loads, path.read_text(encoding="utf-8").splitlines())
        if entry["event"] == name
    ]


def test_page_loads_in_offline_mode_with_all_ten_alerts(audit):
    at = _app()
    assert at.radio(key="mode").value.startswith("Offline")
    options = at.selectbox(key="alert_id").options
    # AppTest returns the displayed labels ("ALERT_001  (user@contoso.com)")
    assert [o.split()[0] for o in options] == [f"ALERT_{n:03d}" for n in range(1, 11)]
    assert "canned" in _page_text(at).lower()


def test_offline_run_shows_tool_calls_then_waits_for_review(audit):
    at = _start(_app(), "ALERT_001")
    text = _page_text(at)
    for tool in ("get_user_profile", "get_sign_in_history", "get_device_trust",
                 "get_directory_audits", "get_risky_user_report"):
        assert tool in text
    assert "Disable the account pending analyst review" in text
    assert at.button(key="approve_0")
    assert at.button(key="reject_0")
    assert at.button(key="edit_0")


def test_approve_finishes_and_shows_report_and_audit_trail(audit):
    at = _start(_app(), "ALERT_001")
    at.button(key="approve_0").click()
    at.run()
    assert not at.exception, at.exception
    text = _page_text(at)
    assert "COMPROMISED" in text
    assert "T1078.004" in text
    assert "containment_decision" in text  # audit trail on the page
    (line,) = _events(audit, "containment_decision")
    assert line["decision"] == "approve"


def test_reject_with_reason(audit):
    at = _start(_app(), "ALERT_001")
    at.text_input(key="reject_reason_0").set_value("too disruptive")
    at.button(key="reject_0").click()
    at.run()
    (line,) = _events(audit, "containment_decision")
    assert (line["decision"], line["reason"]) == ("reject", "too disruptive")


def test_edit_with_new_text(audit):
    at = _start(_app(), "ALERT_001")
    at.text_input(key="edited_step_0").set_value("Revoke all sessions")
    at.button(key="edit_0").click()
    at.run()
    (line,) = _events(audit, "containment_decision")
    assert (line["decision"], line["final_step"]) == ("edit", "Revoke all sessions")
    assert "Revoke all sessions" in _page_text(at)


def test_blank_edit_shows_an_error_and_keeps_the_step(audit):
    at = _start(_app(), "ALERT_001")
    at.button(key="edit_0").click()
    at.run()
    assert not at.exception, at.exception
    assert at.error, "expected an error message for a blank edit"
    assert at.button(key="approve_0")  # still waiting on the same step
    assert _events(audit, "containment_decision") == []


def test_question_pick_an_option(audit):
    at = _start(_app(), "ALERT_009")
    assert "Do you have context that changes this assessment?" in _page_text(at)
    at.radio(key="answer_choice").set_value("The activity is expected/benign")
    at.button(key="submit_answer").click()
    at.run()
    assert not at.exception, at.exception
    (line,) = _events(audit, "ask_user")
    assert (line["status"], line["choice_index"]) == ("answered", 0)
    assert len(_events(audit, "re_adjudication")) == 1


def test_question_typed_answer(audit):
    at = _start(_app(), "ALERT_009")
    at.text_area(key="answer_text").set_value("User is on leave this week")
    at.button(key="submit_answer").click()
    at.run()
    (line,) = _events(audit, "ask_user")
    assert (line["answer"], line["free_text"]) == ("User is on leave this week", True)


def test_question_skip_cancels(audit):
    at = _start(_app(), "ALERT_009")
    at.button(key="skip_answer").click()
    at.run()
    (line,) = _events(audit, "ask_user")
    assert (line["status"], line["answer"]) == (
        "cancelled",
        "no decision has been supplied",
    )
    assert _events(audit, "re_adjudication") == []


def test_submit_with_nothing_chosen_shows_an_error(audit):
    at = _start(_app(), "ALERT_009")
    at.button(key="submit_answer").click()
    at.run()
    assert at.error
    assert _events(audit, "ask_user") == []


def test_unknown_user_short_circuits_without_a_model(audit):
    at = _start(_app(), "ALERT_010")
    text = _page_text(at)
    assert "INSUFFICIENT_DATA" in text
    assert "model was not called" in text
    (run,) = _events(audit, "run")
    assert run["llm_called"] is False


def test_live_mode_shows_key_status_but_never_the_key(audit):
    at = _app()
    at.radio(key="mode").set_value(at.radio(key="mode").options[1])
    at.run()
    text = _page_text(at)
    assert "key is set" in text.lower()
    assert FAKE_KEY not in text
    assert FAKE_KEY[-8:] not in text


def test_live_mode_without_a_key_blocks_the_run(audit, monkeypatch):
    monkeypatch.setattr(config, "OPENROUTER_API_KEY", None)
    at = _app()
    at.radio(key="mode").set_value(at.radio(key="mode").options[1])
    at.run()
    assert at.button(key="start").disabled
    assert "OPENROUTER_API_KEY" in _page_text(at)


def test_new_run_after_finishing(audit):
    at = _start(_app(), "ALERT_010")
    at = _start(at, "ALERT_001")
    assert at.button(key="approve_0")
    assert len(_events(audit, "run")) == 1  # second run still waiting


def test_slow_run_does_not_rerun_the_whole_page_while_working(audit, monkeypatch):
    """A live model takes 30-60 s. Rerunning the page every poll made it flash."""
    import time

    import streamlit
    from itdr_agent import sim_api

    real = sim_api.get_user_profile

    def slow_profile(*args, **kwargs):
        time.sleep(1.5)
        return real(*args, **kwargs)

    monkeypatch.setattr(sim_api, "get_user_profile", slow_profile)
    reruns = []
    real_rerun = streamlit.rerun

    def counting_rerun(*args, **kwargs):
        reruns.append(1)
        return real_rerun(*args, **kwargs)

    monkeypatch.setattr(streamlit, "rerun", counting_rerun)
    at = _start(_app(), "ALERT_001")
    assert at.button(key="approve_0")  # reached the step in the same click
    assert len(reruns) <= 1, f"page reran {len(reruns)} times while working"


# --- Feature 1: the verdict is shown before the analyst decides -------------


def test_review_screen_shows_the_verdict_before_deciding(audit):
    at = _start(_app(), "ALERT_001")
    text = _page_text(at)
    assert "COMPROMISED" in text
    assert "unlikely-travel" in text  # the model narrative is on screen
    assert at.button(key="approve_0")  # still waiting on the analyst


def test_question_screen_shows_the_verdict_before_answering(audit):
    at = _start(_app(), "ALERT_009")
    text = _page_text(at)
    assert "INSUFFICIENT_DATA" in text
    # The model narrative is on screen before the analyst answers, not only
    # in the question text.
    assert "Insufficient data to reach a verdict" in text
    assert "Do you have context that changes this assessment?" in text


# --- Feature 3: incident queue home view -----------------------------------


def _queue(at: AppTest):
    return at.dataframe[0].value


def test_queue_renders_all_ten_alerts(audit):
    at = _app()
    df = _queue(at)
    assert len(df) == 10
    assert list(df.columns) == ["Name", "Alert ID", "Severity", "Stage", "Status"]
    assert set(df["Alert ID"]) == {f"ALERT_{n:03d}" for n in range(1, 11)}
    assert set(df["Status"]) == {"Not started"}
    assert "10 alerts" in _page_text(at)


def test_queue_search_narrows_rows(audit):
    at = _app()
    at.text_input(key="queue_search").set_value("alice")
    at.run()
    assert not at.exception, at.exception
    df = _queue(at)
    assert list(df["Alert ID"]) == ["ALERT_001"]
    assert "1 alert" in _page_text(at)


def test_queue_severity_filter_narrows_rows(audit):
    at = _app()
    at.multiselect(key="queue_severity").select("High")
    at.run()
    assert not at.exception, at.exception
    df = _queue(at)
    assert len(df) == 4
    assert set(df["Severity"]) == {"■■■ High"}


def test_queue_status_filter_narrows_rows(audit):
    at = _app()
    at.multiselect(key="queue_status").select("Closed")
    at.run()
    assert not at.exception, at.exception
    assert len(_queue(at)) == 0


def test_selecting_a_row_opens_the_run_page(audit):
    at = _app()
    at.session_state["queue"] = {
        "selection": {"rows": [2], "columns": [], "cells": []}
    }
    at.run()
    assert not at.exception, at.exception
    assert "ALERT_003" in _page_text(at)
    assert at.button(key="start")
    assert at.button(key="back_to_queue")


def test_back_to_queue_returns_home(audit):
    at = _app()
    at.session_state["queue"] = {
        "selection": {"rows": [0], "columns": [], "cells": []}
    }
    at.run()
    at.button(key="back_to_queue").click()
    at.run()
    assert not at.exception, at.exception
    assert len(_queue(at)) == 10


def test_status_updates_to_closed_after_offline_run(audit):
    at = _start(_app(), "ALERT_010")
    assert "INSUFFICIENT_DATA" in _page_text(at)
    at.button(key="back_to_queue").click()
    at.run()
    assert not at.exception, at.exception
    df = _queue(at)
    row = df[df["Alert ID"] == "ALERT_010"].iloc[0]
    assert row["Status"] == "Closed: INSUFFICIENT_DATA"


def test_incident_note_is_shown_on_the_report(audit):
    at = _start(_app(), "ALERT_010")
    text = _page_text(at)
    assert "Alert: ALERT_010" in text
    assert "IP reputation: not available in this dataset." in text
    assert "No action required" in text


def test_edit_the_rollback_on_the_page(audit):
    at = _start(_app(), "ALERT_001")
    at.text_input(key="edited_rollback_0").set_value("Re-enable after ID check")
    at.button(key="edit_0").click()
    at.run()
    assert not at.exception, at.exception
    line = _events(audit, "containment_decision")[0]
    assert line["final_rollback"] == "Re-enable after ID check"
