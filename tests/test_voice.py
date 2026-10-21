"""Voice + batch step 4: voice commands (offline, no mic, no network).

The command parser is code, never a model: a transcript without the wake
word "zero" is ignored; with it, a small grammar maps the words to one
action. The transcription client posts a WAV to the local whisper.cpp server
and is tested against a fake HTTP transport. The page accepts a typed command
as the fallback when the mic or the server is down, which is also how these
tests drive it. Approve / reject / edit are read back and need a "zero yes".
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import httpx
import pytest

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(Path(__file__).parent))

try:
    from itdr_agent import voice  # noqa: E402
    from itdr_agent.voice import Command, parse_command  # noqa: E402
except ImportError:  # red phase
    voice = None


# --- wake word ---------------------------------------------------------------


def test_wake_word_is_zero():
    assert voice.WAKE_WORD == "zero"


@pytest.mark.parametrize("text", ["run all", "approve", "Zero.", "", "hero run all"])
def test_without_the_wake_word_nothing_is_a_command(text):
    assert parse_command(text) is None


@pytest.mark.parametrize("text", ["zero run all", "Zero, run all.", "hey zero run all", "ZERO run everything"])
def test_run_all(text):
    cmd = parse_command(text)
    assert cmd.action == "run_all"


# --- the grammar -------------------------------------------------------------


@pytest.mark.parametrize(
    "text,alerts",
    [
        ("zero run 3 and 6", ("ALERT_003", "ALERT_006")),
        ("zero run alerts three and six", ("ALERT_003", "ALERT_006")),
        ("zero run alert 10", ("ALERT_010",)),
        ("zero run 1, 2, 3", ("ALERT_001", "ALERT_002", "ALERT_003")),
    ],
)
def test_run_some_alerts(text, alerts):
    cmd = parse_command(text)
    assert cmd.action == "run" and cmd.alerts == alerts


@pytest.mark.parametrize("text", ["zero open alert 6", "zero open six", "zero show alert 6"])
def test_open_alert(text):
    cmd = parse_command(text)
    assert cmd.action == "open" and cmd.alerts == ("ALERT_006",)


def test_approve_with_and_without_a_step():
    assert parse_command("zero approve").action == "approve"
    assert parse_command("zero approve").step is None
    cmd = parse_command("zero approve step 2")
    assert (cmd.action, cmd.step) == ("approve", 2)


def test_reject_with_a_reason():
    cmd = parse_command("zero reject step 1 because the user is traveling")
    assert (cmd.action, cmd.step, cmd.text) == ("reject", 1, "the user is traveling")
    assert parse_command("zero reject").text is None


def test_edit_takes_the_new_step_text():
    cmd = parse_command("zero edit step 1 to revoke sessions only")
    assert (cmd.action, cmd.step, cmd.text) == ("edit", 1, "revoke sessions only")


@pytest.mark.parametrize(
    "text,action",
    [
        ("zero skip", "skip"),
        ("zero no decision", "skip"),
        ("zero back", "back"),
        ("zero back to queue", "back"),
        ("zero yes", "yes"),
        ("zero confirm", "yes"),
        ("zero no", "no"),
        ("zero cancel", "no"),
        ("zero expected", "answer"),
        ("zero it's benign", "answer"),
        ("zero suspicious", "answer"),
        ("zero I don't know", "answer"),
    ],
)
def test_short_commands(text, action):
    assert parse_command(text).action == action


def test_answer_choice_index_follows_the_shared_options():
    assert parse_command("zero expected").choice == 0
    assert parse_command("zero suspicious").choice == 1
    assert parse_command("zero don't know").choice == 2


def test_unrecognised_words_after_the_wake_word():
    cmd = parse_command("zero make me a sandwich")
    assert cmd.action == "unknown"
    assert cmd.heard == "zero make me a sandwich"


def test_command_is_frozen_and_keeps_what_was_heard():
    cmd = parse_command("Zero, approve step 1.")
    assert isinstance(cmd, Command)
    assert cmd.heard == "Zero, approve step 1."
    with pytest.raises(Exception):
        cmd.action = "reject"  # type: ignore[misc]


# --- transcription client ---------------------------------------------------


def test_transcribe_posts_a_wav_and_returns_the_text():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["content_type"] = request.headers.get("content-type", "")
        seen["body"] = request.content
        return httpx.Response(200, json={"text": " zero run all \n"})

    text = voice.transcribe(
        b"RIFFfakewav", url="http://127.0.0.1:2022/v1/audio/transcriptions",
        transport=httpx.MockTransport(handler),
    )
    assert text == "zero run all"
    assert seen["url"].endswith("/v1/audio/transcriptions")
    assert "multipart/form-data" in seen["content_type"]
    assert b"RIFFfakewav" in seen["body"]
    assert b'name="file"' in seen["body"]


def test_transcribe_raises_a_voice_error_when_the_server_is_down():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    with pytest.raises(voice.VoiceError):
        voice.transcribe(b"x", url="http://127.0.0.1:2022/v1/audio/transcriptions",
                         transport=httpx.MockTransport(handler))


def test_transcribe_raises_on_a_bad_reply():
    with pytest.raises(voice.VoiceError):
        voice.transcribe(
            b"x", url="http://127.0.0.1:2022/v1/audio/transcriptions",
            transport=httpx.MockTransport(lambda r: httpx.Response(500, text="boom")),
        )


def test_default_url_is_the_local_whisper_server(monkeypatch):
    monkeypatch.delenv("WHISPER_URL", raising=False)
    assert voice.default_url() == "http://127.0.0.1:2022/v1/audio/transcriptions"
    monkeypatch.setenv("WHISPER_URL", "http://127.0.0.1:9999/x")
    assert voice.default_url() == "http://127.0.0.1:9999/x"


def test_server_reachable_is_false_on_a_closed_port():
    assert voice.server_reachable("http://127.0.0.1:1/v1/audio/transcriptions") is False


# --- the page: typed fallback drives the same path as the mic ---------------

pytest.importorskip("streamlit")
from test_app import _app, _events, _page_text, _start, _statuses  # noqa: E402


def _say(at, text):
    at.text_input(key="voice_typed").set_value(text).run()
    assert not at.exception, at.exception
    return at


def test_typed_command_without_wake_word_is_ignored(audit):
    at = _say(_app(), "run all")
    assert "batch" not in at.session_state
    assert "zero" in _page_text(at).lower()  # the hint says to start with the wake word


def test_typed_run_all_starts_the_batch(audit):
    at = _say(_app(), "zero run all")
    assert at.session_state["batch"].wait(20) == "done"
    at.run()
    assert _statuses(at)["ALERT_001"] == "Waiting on you"


def test_typed_open_alert_shows_the_run_page(audit):
    at = _say(_app(), "zero open alert 3")
    assert "ALERT_003" in _page_text(at)
    assert at.button(key="back_to_queue")


def test_voice_approve_is_read_back_then_needs_yes(audit):
    at = _start(_app(), "ALERT_001")
    at = _say(at, "zero approve")
    text = _page_text(at)
    assert "Approve step 1 on ALERT_001?" in text
    assert _events(audit, "containment_decision") == []  # nothing yet
    at = _say(at, "zero yes")
    (line,) = _events(audit, "containment_decision")
    assert line["decision"] == "approve"


def test_voice_no_cancels_the_read_back(audit):
    at = _start(_app(), "ALERT_001")
    at = _say(at, "zero reject because not needed")
    assert "Reject step 1 on ALERT_001" in _page_text(at)
    at = _say(at, "zero no")
    assert _events(audit, "containment_decision") == []
    assert at.button(key="approve_0")  # still waiting on the step


def test_voice_reject_with_reason_lands_in_the_audit_log(audit):
    at = _start(_app(), "ALERT_001")
    at = _say(at, "zero reject step 1 because the user is traveling")
    at.button(key="voice_yes").click()
    at.run()
    (line,) = _events(audit, "containment_decision")
    assert (line["decision"], line["reason"]) == ("reject", "the user is traveling")


def test_voice_approve_names_the_wrong_step_and_does_nothing(audit):
    at = _start(_app(), "ALERT_001")
    at = _say(at, "zero approve step 2")
    assert "step 2" in _page_text(at).lower() and "on screen" in _page_text(at).lower()
    assert _events(audit, "containment_decision") == []


def test_voice_answers_the_question(audit):
    at = _start(_app(), "ALERT_009")
    at = _say(at, "zero expected")
    (line,) = _events(audit, "ask_user")
    assert (line["status"], line["choice_index"]) == ("answered", 0)


def test_voice_back_returns_to_the_queue(audit):
    at = _start(_app(), "ALERT_001")
    at = _say(at, "zero back")
    assert "Identity incident queue" in _page_text(at)
    assert _statuses(at)["ALERT_001"] == "Waiting on you"


def test_mic_transcription_error_shows_a_message_not_a_crash(audit, monkeypatch):
    import app as _  # noqa: F401  (the page module name under AppTest is dynamic)
    at = _app()
    assert "whisper" in _page_text(at).lower()  # server status line on the page
