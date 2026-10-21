"""Voice commands for the GUI: wake word, a code parser, and the Whisper client.

Nothing here calls a model. A transcript is a command only when it starts
with the wake word (``zero``, Joe's pick 2026-10-21); after that a small,
fixed grammar maps the words to one action. Approve / reject / edit are never
acted on straight from speech: the page reads the command back and waits for
"zero yes" (or the Yes button), so a misheard word can't approve the wrong
thing. Audio goes to the local whisper.cpp server only (``WHISPER_URL``,
default ``http://127.0.0.1:2022/v1/audio/transcriptions``); it never leaves
the machine.
"""

from __future__ import annotations

import os
import re
import socket
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import httpx

from .human import ANALYST_OPTIONS

WAKE_WORD = "zero"
DEFAULT_WHISPER_URL = "http://127.0.0.1:2022/v1/audio/transcriptions"
TRANSCRIBE_TIMEOUT = 30.0

_NUMBER_WORDS = {
    "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6,
    "seven": 7, "eight": 8, "nine": 9, "ten": 10, "eleven": 11, "twelve": 12,
    "thirteen": 13, "fourteen": 14, "fifteen": 15, "sixteen": 16,
    "seventeen": 17, "eighteen": 18, "nineteen": 19, "twenty": 20,
}
# Spoken answers to the one question, mapped onto human.ANALYST_OPTIONS.
_ANSWER_WORDS = (
    (("don't know", "dont know", "not sure", "unsure", "no idea"), 2),
    (("suspicious", "malicious", "compromised", "attack"), 1),
    (("expected", "benign", "normal", "legit", "legitimate", "fine"), 0),
)


class VoiceError(Exception):
    """The local Whisper server could not transcribe the audio."""


@dataclass(frozen=True)
class Command:
    action: str  # run_all | run | open | approve | reject | edit | skip | back | yes | no | answer | unknown
    heard: str = ""
    alerts: tuple[str, ...] = ()
    step: int | None = None  # 1-based, as spoken
    text: str | None = None  # reject reason or the edited step
    choice: int | None = None  # index into ANALYST_OPTIONS


def normalize(text: str) -> str:
    text = text.lower().replace("’", "'")
    text = re.sub(r"[^a-z0-9' ]+", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def strip_wake_word(text: str) -> str | None:
    """The words after the wake word, or None when it is not there."""
    words = normalize(text).split()
    if words and words[0] in ("hey", "ok", "okay", "hi"):
        words = words[1:]
    if len(words) < 2 or words[0] != WAKE_WORD:
        return None  # no wake word, or the wake word alone: nothing to do
    return " ".join(words[1:])


def _numbers(text: str) -> list[int]:
    found: list[int] = []
    for word in text.split():
        if word.isdigit():
            found.append(int(word))
        elif word in _NUMBER_WORDS:
            found.append(_NUMBER_WORDS[word])
    return found


def _alert_ids(text: str) -> tuple[str, ...]:
    return tuple(f"ALERT_{n:03d}" for n in _numbers(text))


def _step(text: str) -> int | None:
    match = re.search(r"\bstep\s+(\d+|[a-z]+)\b", text)
    if not match:
        return None
    token = match.group(1)
    return int(token) if token.isdigit() else _NUMBER_WORDS.get(token)


def parse_command(text: str) -> Command | None:
    """Map a transcript to a Command; None without the wake word."""
    rest = strip_wake_word(text)
    if rest is None:
        return None
    heard = text
    words = rest.split()
    head = words[0] if words else ""

    if head == "run":
        if re.search(r"\b(all|everything|every)\b", rest) or len(words) == 1:
            return Command("run_all", heard)
        ids = _alert_ids(rest)
        return Command("run", heard, alerts=ids) if ids else Command("unknown", heard)
    if head in ("open", "show"):
        ids = _alert_ids(rest)
        return Command("open", heard, alerts=ids[:1]) if ids else Command("unknown", heard)
    if head == "approve":
        return Command("approve", heard, step=_step(rest))
    if head == "reject":
        reason = None
        match = re.search(r"\bbecause\b\s*(.+)$", rest)
        if match:
            reason = match.group(1).strip() or None
        return Command("reject", heard, step=_step(rest), text=reason)
    if head in ("edit", "change"):
        match = re.search(r"\bto\b\s*(.+)$", rest)
        new_text = match.group(1).strip() if match else None
        return Command("edit", heard, step=_step(rest), text=new_text or None)
    if head == "skip" or rest.startswith("no decision"):
        return Command("skip", heard)
    if head in ("back", "queue", "home"):
        return Command("back", heard)
    if head in ("yes", "confirm", "do", "go", "yep", "yeah"):
        return Command("yes", heard)
    if head in ("no", "cancel", "nope", "never", "stop"):
        return Command("no", heard)
    for phrases, index in _ANSWER_WORDS:
        if any(phrase in rest for phrase in phrases):
            return Command("answer", heard, choice=index, text=ANALYST_OPTIONS[index])
    return Command("unknown", heard)


# --- the local Whisper server ----------------------------------------------


def default_url() -> str:
    return os.getenv("WHISPER_URL") or DEFAULT_WHISPER_URL


def server_reachable(url: str | None = None, timeout: float = 0.3) -> bool:
    """True when something listens on the server's host:port (no request sent)."""
    parsed = urlparse(url or default_url())
    host, port = parsed.hostname or "127.0.0.1", parsed.port or 80
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def transcribe(
    wav_bytes: bytes,
    url: str | None = None,
    timeout: float = TRANSCRIBE_TIMEOUT,
    transport: Any = None,
) -> str:
    """POST the WAV to whisper.cpp and return the transcript (stripped)."""
    url = url or default_url()
    try:
        with httpx.Client(timeout=timeout, transport=transport) as client:
            response = client.post(
                url,
                files={"file": ("command.wav", wav_bytes, "audio/wav")},
                data={"response_format": "json", "temperature": "0"},
            )
    except httpx.HTTPError as exc:
        raise VoiceError(f"Whisper server not reachable at {url}: {exc}") from exc
    if response.status_code != 200:
        raise VoiceError(f"Whisper server returned {response.status_code}")
    try:
        text = response.json().get("text", "")
    except ValueError as exc:
        raise VoiceError("Whisper server returned no JSON") from exc
    return " ".join(str(text).split())
