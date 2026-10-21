"""Voice + batch step 4: voice commands (offline, no mic, no network).

The command parser is code, never a model: a transcript without the wake
word "z" is ignored; with it, a small grammar maps the words to one
action. The transcription client posts a WAV to the local whisper.cpp server
and is tested against a fake HTTP transport. The page accepts a typed command
as the fallback when the mic or the server is down, which is also how these
tests drive it. Approve / reject / edit are read back and need a "z yes".
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
    assert voice.WAKE_WORD == "z"
    assert voice.WAKE_SPELLINGS == {"z", "zee", "zed"}


@pytest.mark.parametrize("text", ["run all", "approve", "Z.", "", "zero run all", "zesty run all"])
def test_without_the_wake_word_nothing_is_a_command(text):
    assert parse_command(text) is None


@pytest.mark.parametrize("text", ["z run all", "Z, run all.", "Zee run all", "Zed run everything", "hey z run all"])
def test_run_all(text):
    cmd = parse_command(text)
    assert cmd.action == "run_all"


# --- the grammar -------------------------------------------------------------


@pytest.mark.parametrize(
    "text,alerts",
    [
        ("z run 3 and 6", ("ALERT_003", "ALERT_006")),
        ("z run alerts three and six", ("ALERT_003", "ALERT_006")),
        ("z run alert 10", ("ALERT_010",)),
        ("z run 1, 2, 3", ("ALERT_001", "ALERT_002", "ALERT_003")),
    ],
)
def test_run_some_alerts(text, alerts):
    cmd = parse_command(text)
    assert cmd.action == "run" and cmd.alerts == alerts


@pytest.mark.parametrize("text", ["z open alert 6", "z open six", "z show alert 6"])
def test_open_alert(text):
    cmd = parse_command(text)
    assert cmd.action == "open" and cmd.alerts == ("ALERT_006",)


def test_approve_with_and_without_a_step():
    assert parse_command("z approve").action == "approve"
    assert parse_command("z approve").step is None
    cmd = parse_command("z approve step 2")
    assert (cmd.action, cmd.step) == ("approve", 2)


def test_reject_with_a_reason():
    cmd = parse_command("z reject step 1 because the user is traveling")
    assert (cmd.action, cmd.step, cmd.text) == ("reject", 1, "the user is traveling")
    assert parse_command("z reject").text is None


def test_edit_takes_the_new_step_text():
    cmd = parse_command("z edit step 1 to revoke sessions only")
    assert (cmd.action, cmd.step, cmd.text) == ("edit", 1, "revoke sessions only")


@pytest.mark.parametrize(
    "text,action",
    [
        ("z skip", "skip"),
        ("z no decision", "skip"),
        ("z back", "back"),
        ("z back to queue", "back"),
        ("z yes", "yes"),
        ("z confirm", "yes"),
        ("z no", "no"),
        ("z cancel", "no"),
        ("z expected", "answer"),
        ("z it's benign", "answer"),
        ("z suspicious", "answer"),
        ("z I don't know", "answer"),
    ],
)
def test_short_commands(text, action):
    assert parse_command(text).action == action


def test_answer_choice_index_follows_the_shared_options():
    assert parse_command("z expected").choice == 0
    assert parse_command("z suspicious").choice == 1
    assert parse_command("z don't know").choice == 2


@pytest.mark.parametrize(
    "text,action",
    [
        ("Z Approved Step 1.", "approve"),   # Whisper's spelling of "approve"
        ("Z rejected step 1", "reject"),
        ("Z opened alert 6", "open"),
        ("Z running all", "run_all"),
        ("Z edited step 1 to lock it", "edit"),
    ],
)
def test_inflected_verbs_still_parse(text, action):
    assert parse_command(text).action == action


def test_unrecognised_words_after_the_wake_word():
    cmd = parse_command("z make me a sandwich")
    assert cmd.action == "unknown"
    assert cmd.heard == "z make me a sandwich"


def test_command_is_frozen_and_keeps_what_was_heard():
    cmd = parse_command("Z, approve step 1.")
    assert isinstance(cmd, Command)
    assert cmd.heard == "Z, approve step 1."
    with pytest.raises(Exception):
        cmd.action = "reject"  # type: ignore[misc]


# --- transcription client ---------------------------------------------------


def test_transcribe_posts_a_wav_and_returns_the_text():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["content_type"] = request.headers.get("content-type", "")
        seen["body"] = request.content
        return httpx.Response(200, json={"text": " z  run all \n"})

    text = voice.transcribe(
        b"RIFFfakewav", url="http://127.0.0.1:2022/v1/audio/transcriptions",
        transport=httpx.MockTransport(handler),
    )
    assert text == "z run all"
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
from test_app import _app, _events, _page_text, _start, _statuses, audit  # noqa: E402, F401


def _say(at, text):
    at.text_input(key="voice_typed").set_value(text).run()
    assert not at.exception, at.exception
    return at


def test_typed_command_without_wake_word_is_ignored(audit):
    at = _say(_app(), "run all")
    assert "batch" not in at.session_state
    assert "zero" in _page_text(at).lower()  # the hint says to start with the wake word


def test_typed_run_all_starts_the_batch(audit):
    at = _say(_app(), "z run all")
    assert at.session_state["batch"].wait(20) == "done"
    at.run()
    assert _statuses(at)["ALERT_001"] == "Waiting on you"


def test_typed_open_alert_shows_the_run_page(audit):
    at = _say(_app(), "z open alert 3")
    assert "ALERT_003" in _page_text(at)
    assert at.button(key="back_to_queue")


def test_voice_approve_is_read_back_then_needs_yes(audit):
    at = _start(_app(), "ALERT_001")
    at = _say(at, "z approve")
    text = _page_text(at)
    assert "Approve step 1 on ALERT_001?" in text
    assert _events(audit, "containment_decision") == []  # nothing yet
    at = _say(at, "z yes")
    (line,) = _events(audit, "containment_decision")
    assert line["decision"] == "approve"


def test_voice_no_cancels_the_read_back(audit):
    at = _start(_app(), "ALERT_001")
    at = _say(at, "z reject because not needed")
    assert "Reject step 1 on ALERT_001" in _page_text(at)
    at = _say(at, "z no")
    assert _events(audit, "containment_decision") == []
    assert at.button(key="approve_0")  # still waiting on the step


def test_voice_reject_with_reason_lands_in_the_audit_log(audit):
    at = _start(_app(), "ALERT_001")
    at = _say(at, "z reject step 1 because the user is traveling")
    at.button(key="voice_yes").click()
    at.run()
    (line,) = _events(audit, "containment_decision")
    assert (line["decision"], line["reason"]) == ("reject", "the user is traveling")


def test_voice_approve_names_the_wrong_step_and_does_nothing(audit):
    at = _start(_app(), "ALERT_001")
    at = _say(at, "z approve step 2")
    assert "step 2" in _page_text(at).lower() and "on screen" in _page_text(at).lower()
    assert _events(audit, "containment_decision") == []


def test_voice_answers_the_question(audit):
    at = _start(_app(), "ALERT_009")
    at = _say(at, "z expected")
    (line,) = _events(audit, "ask_user")
    assert (line["status"], line["choice_index"]) == ("answered", 0)


def test_voice_back_returns_to_the_queue(audit):
    at = _start(_app(), "ALERT_001")
    at = _say(at, "z back")
    assert "Identity incident queue" in _page_text(at)
    assert _statuses(at)["ALERT_001"] == "Waiting on you"


def test_page_shows_the_whisper_server_status(audit):
    at = _app()
    assert "whisper server" in _page_text(at).lower()
