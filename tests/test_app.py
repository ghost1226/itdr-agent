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
    path = tmp_path / "audit.jsonl"
    monkeypatch.setenv("ITDR_GUI_AUDIT_LOG", str(path))
    # Never let a test see a real key, and prove the page never prints one.
    monkeypatch.setattr(config, "OPENROUTER_API_KEY", FAKE_KEY)
    return path


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
    assert [o for o in options] == [f"ALERT_{n:03d}" for n in range(1, 11)]
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
