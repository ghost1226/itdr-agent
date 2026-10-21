"""Local web GUI for the ITDR agent (Countersign: Layer Zero).

Run:  python -m streamlit run app.py   (needs requirements-gui.txt)

Runs on this machine only (bound to localhost in .streamlit/config.toml,
usage stats off). Same orchestrator, guardrails, and audit log as the CLI:
pick an alert, watch the Investigator's tool calls, answer the one question
if it asks, then approve / edit / reject each containment step.

Two modes:
- Offline demo: scripted tool calls and a canned verdict built from the
  answer key. No key, no model, no tokens. It shows how the screens work;
  it does not test the AI.
- Live: the real OpenRouter model with your own key from .env (never shown).

Runs live in ``st.session_state["runs"]`` keyed by alert id, so Back to queue
leaves a run that waits on the analyst exactly where it is; the queue shows
every run's live status and a row can be reopened.

Voice: a mic button records a command, the local whisper.cpp server turns it
into text, and ``itdr_agent.voice`` parses it in code (wake word "z"). A
typed command box takes the same path when the mic or the server is down.
Approve / reject / edit are read back and wait for "z yes" or the button.

Anything the model wrote is shown with st.text, never rendered as markdown.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from pathlib import Path

import streamlit as st

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from itdr_agent import config, voice  # noqa: E402
from itdr_agent.adjudicator import DEFAULT_MODEL, Adjudicator  # noqa: E402
from itdr_agent.fixture_store import get_store  # noqa: E402
from itdr_agent.gui_run import BatchRunner, GuiRun  # noqa: E402
from itdr_agent.investigator import Investigator  # noqa: E402
from itdr_agent.orchestrator import DEFAULT_AUDIT_LOG, Orchestrator  # noqa: E402
from itdr_agent.usage import TokenMeter, format_tokens  # noqa: E402
from itdr_agent.summary import (  # noqa: E402
    incident_note,
    severity,
    short_summary,
    stage,
    ticket_lines,
    verdict_line,
    what,
    what_happened,
)

APP_NAME = "Countersign: Layer Zero"
OFFLINE = "Offline demo (no key, no model)"
LIVE = "Live (OpenRouter, your own key)"
POLL_SECONDS = 0.5
WIDGET_PREFIXES = ("edited_step_", "edited_rollback_", "reject_reason_", "answer_")
STATUS_WORDS = {
    "idle": "Queued",
    "running": "Running",
    "question": "Waiting on you",
    "review": "Waiting on you",
    "error": "Closed: ERROR",
}
# Free-tier arithmetic for the cost line: one live run is about 6-10 requests
# of a free account's 50 a day (README, "Run the GUI").
REQUESTS_PER_RUN = (6, 10)
FREE_DAILY_CAP = 50
BATCH_POLL_SECONDS = 2.0
_W = voice.WAKE_WORD
VOICE_HINT = (
    f"Start with the wake word \"{_W}\" (said as the letter): \"{_W} run all\", "
    f"\"{_W} open alert 6\", \"{_W} approve\", \"{_W} reject because …\", "
    f"\"{_W} edit step 1 to …\", \"{_W} expected\", \"{_W} skip\", \"{_W} back\"."
)
READ_BACK = {"approve": "Approve", "reject": "Reject", "edit": "Edit"}


def _audit_path() -> Path:
    return Path(os.getenv("ITDR_GUI_AUDIT_LOG") or DEFAULT_AUDIT_LOG)


def _alerts() -> dict[str, dict]:
    return {alert["id"]: alert for alert in get_store().alerts}


# --- building one run ------------------------------------------------------


def _offline_builder(alert_id: str, audit: Path):
    import samples  # scripts/samples.py: reads the answer key, demo only

    dossier, alert = samples.build_dossier(alert_id)
    label = samples._ground_truth()[alert_id]
    reply = samples.build_mock_report(
        dossier, label["scenario"], label["expected_verdict"]
    )
    upn = alert["userPrincipalName"]
    events = get_store().sign_in_history(upn, 10_000)
    device_id = events[0]["deviceDetail"]["deviceId"] if events else ""

    def build(reviewer, tool_executor):
        investigator = Investigator(
            samples._ScriptedToolLLM(samples._tool_script(upn, device_id)),
            tool_executor=tool_executor,
        )
        adjudicator = Adjudicator(samples._MockCompleteLLM(reply))
        # Mock LLMs never report usage, so the page shows "no model calls".
        return Orchestrator(investigator, adjudicator, reviewer, audit_log=audit,
                            token_meter=TokenMeter(), mode="offline",
                            model="offline-demo")

    return build


def _live_builder(model: str, audit: Path):
    from itdr_agent.__main__ import (
        _OpenRouterAdjudicatorLLM,
        _OpenRouterInvestigatorLLM,
    )

    timeout = min(config.TIMEOUT_SECONDS, 90)  # per request, same as the CLI

    def build(reviewer, tool_executor):
        key = config.OPENROUTER_API_KEY
        meter = TokenMeter()
        investigator = Investigator(
            _OpenRouterInvestigatorLLM(key, model, timeout, meter),
            tool_executor=tool_executor,
        )
        adjudicator = Adjudicator(
            _OpenRouterAdjudicatorLLM(key, model, timeout, meter)
        )
        return Orchestrator(investigator, adjudicator, reviewer, audit_log=audit,
                            token_meter=meter, mode="live", model=model)

    return build


# --- callbacks (run before the page redraws) -------------------------------


def _clear_widgets() -> None:
    """Per-step widget keys are shared across run pages; reset on a switch."""
    for key in list(st.session_state):
        if key.startswith(WIDGET_PREFIXES):
            del st.session_state[key]
    st.session_state.pop("flash", None)


def _runs() -> dict[str, GuiRun]:
    return st.session_state.setdefault("runs", {})


def _build_for(alert_id: str, mode: str, model: str):
    audit = _audit_path()
    if mode == LIVE:
        return _live_builder(model, audit)
    return _offline_builder(alert_id, audit)


def _open(alert_id: str) -> None:
    _clear_widgets()
    st.session_state["open"] = alert_id
    st.session_state.pop("selected_alert", None)


def _start(mode: str, model: str) -> None:
    alert_id = (
        st.session_state.get("selected_alert") or st.session_state["alert_id"]
    )
    run = GuiRun(_build_for(alert_id, mode, model), _alerts()[alert_id])
    _runs()[alert_id] = run  # a new run for this alert replaces the old one
    _open(alert_id)
    run.start()


def _status_of(run: GuiRun) -> str:
    """The queue's status word, derived from the live run, never cached."""
    if run.status == "done":
        return f"Closed: {run.result.report.verdict.value}"
    return STATUS_WORDS.get(run.status, run.status)


def _batch() -> BatchRunner | None:
    return st.session_state.get("batch")


def _batch_running() -> bool:
    batch = _batch()
    return batch is not None and batch.status == "running"


def _start_batch(alert_ids: list[str]) -> None:
    """Queue the alerts (status "Queued") and run them one at a time."""
    if not alert_ids or _batch_running():
        return
    mode = st.session_state.get("mode", OFFLINE)
    model = os.getenv("EVAL_MODEL", DEFAULT_MODEL)
    if mode == LIVE and not config.OPENROUTER_API_KEY:
        st.session_state["flash"] = "OPENROUTER_API_KEY is not set. Add it to .env."
        return
    alerts = _alerts()
    runs = []
    for alert_id in alert_ids:
        run = GuiRun(_build_for(alert_id, mode, model), alerts[alert_id])
        _runs()[alert_id] = run
        runs.append(run)
    batch = BatchRunner(runs)
    st.session_state["batch"] = batch
    st.session_state.pop("flash", None)
    batch.start()


def _run_selected_clicked() -> None:
    _start_batch(_selected_ids())


def _run_all_clicked() -> None:
    _start_batch(list(st.session_state.get("queue_rows") or []))


def _cost_line(count: int, mode: str) -> None:
    """What a batch will spend, shown before it starts."""
    if mode != LIVE:
        st.caption(f"Offline demo: {count} alert{'s' if count != 1 else ''}, no requests used.")
        return
    low, high = REQUESTS_PER_RUN[0] * count, REQUESTS_PER_RUN[1] * count
    text = (
        f"{count} alert{'s' if count != 1 else ''} ≈ {low}-{high} requests of a "
        f"free account's {FREE_DAILY_CAP} a day."
    )
    if high > FREE_DAILY_CAP:
        st.warning(f"{text} That may not fit today's daily cap; runs stop at 429 and can be re-run tomorrow.")
    else:
        st.caption(text)


def _guarded(action) -> None:
    try:
        action()
        st.session_state.pop("flash", None)
    except (ValueError, RuntimeError) as exc:
        st.session_state["flash"] = str(exc)


def _decide(run: GuiRun, index: int, decision: str) -> None:
    state = st.session_state
    _guarded(
        lambda: run.decide(
            decision,
            edited_step=state.get(f"edited_step_{index}"),
            edited_rollback=state.get(f"edited_rollback_{index}"),
            reason=state.get(f"reject_reason_{index}") or "analyst rejected",
        )
    )


def _submit_answer(run: GuiRun) -> None:
    state = st.session_state
    labels = [o["label"] for o in run.pending["options"]]
    choice = state.get("answer_choice")
    text = (state.get("answer_text") or "").strip()
    if choice is not None:
        _guarded(lambda: run.answer(choice_index=labels.index(choice)))
    elif text:
        _guarded(lambda: run.answer(text))
    else:
        state["flash"] = "Pick an option or type an answer, or press Skip."


def _skip_answer(run: GuiRun) -> None:
    _guarded(lambda: run.answer(None))


# --- voice -------------------------------------------------------------------


def _say(message: str) -> None:
    st.session_state["voice_message"] = message


def _typed_command() -> None:
    """on_change of the typed box: hand the text to the same path as the mic."""
    text = (st.session_state.get("voice_typed") or "").strip()
    if text:
        st.session_state["voice_text"] = text
    st.session_state["voice_typed"] = ""


def _current_run() -> GuiRun | None:
    open_id = st.session_state.get("open")
    return _runs().get(open_id) if open_id else None


def _execute_pending() -> None:
    pending = st.session_state.pop("voice_pending", None)
    if not pending:
        return
    run = _runs().get(pending["alert_id"])
    if run is None or run.status != "review" or run.pending["index"] != pending["index"]:
        _say("That step is no longer on screen; nothing was done.")
        return
    action = pending["action"]
    try:
        if action == "approve":
            run.decide("approve")
        elif action == "reject":
            run.decide("reject", reason=pending.get("text") or "analyst rejected")
        else:
            run.decide("edit", edited_step=pending.get("text"))
    except (ValueError, RuntimeError) as exc:
        _say(str(exc))
        return
    _say(f"{READ_BACK[action]}d step {pending['index'] + 1} on {pending['alert_id']}.")


def _apply_command(cmd: voice.Command | None, heard: str) -> None:
    st.session_state["voice_heard"] = heard
    if cmd is None:
        _say(f"No wake word heard. {VOICE_HINT}")
        return
    run = _current_run()
    alerts = _alerts()
    if cmd.action == "unknown":
        _say(f"Didn't understand \"{heard}\". {VOICE_HINT}")
    elif cmd.action == "run_all":
        _start_batch(list(st.session_state.get("queue_rows") or alerts))
        _say("Running every alert in the queue, one at a time.")
    elif cmd.action == "run":
        known = [a for a in cmd.alerts if a in alerts]
        if not known:
            _say(f"No such alert: {', '.join(cmd.alerts)}.")
        else:
            _start_batch(known)
            _say(f"Running {', '.join(known)}.")
    elif cmd.action == "open":
        alert_id = cmd.alerts[0] if cmd.alerts else ""
        if alert_id in alerts:
            _open_or_select(alert_id)
            _say(f"Opened {alert_id}.")
        else:
            _say(f"No such alert: {alert_id}.")
    elif cmd.action == "back":
        st.session_state.pop("open", None)
        st.session_state.pop("selected_alert", None)
        st.session_state.pop("voice_pending", None)
        _say("Back to the queue.")
    elif cmd.action == "yes":
        if st.session_state.get("voice_pending"):
            _execute_pending()
        else:
            _say("Nothing is waiting for a yes.")
    elif cmd.action == "no":
        if st.session_state.pop("voice_pending", None):
            _say("Cancelled; the step is still waiting for your decision.")
        else:
            _say("Nothing to cancel.")
    elif cmd.action == "skip":
        if run is not None and run.status == "question":
            _guarded(lambda: run.answer(None))
            _say("Skipped the question (no decision has been supplied).")
        else:
            _say("No question is on screen.")
    elif cmd.action == "answer":
        if run is not None and run.status == "question":
            _guarded(lambda: run.answer(choice_index=cmd.choice))
            _say(f"Answered: {cmd.text}.")
        else:
            _say("No question is on screen.")
    elif cmd.action in READ_BACK:
        if run is None or run.status != "review":
            _say("No containment step is on screen to decide.")
            return
        index = run.pending["index"]
        if cmd.step is not None and cmd.step != index + 1:
            _say(f"You said step {cmd.step}, but step {index + 1} is the one on screen. Nothing was done.")
            return
        if cmd.action == "edit" and not cmd.text:
            _say(f"Say what the step should become: \"{_W} edit step 1 to …\".")
            return
        st.session_state["voice_pending"] = {
            "action": cmd.action, "alert_id": run.alert["id"], "index": index,
            "text": cmd.text,
        }
        _say("")


def _process_voice_text() -> None:
    """Runs first on every draw: consume a transcript the mic or the box left."""
    text = st.session_state.pop("voice_text", None)
    if text:
        _apply_command(voice.parse_command(text), text)


def _read_back_line() -> str | None:
    pending = st.session_state.get("voice_pending")
    if not pending:
        return None
    line = f"{READ_BACK[pending['action']]} step {pending['index'] + 1} on {pending['alert_id']}?"
    if pending.get("text"):
        line += f" ({'reason' if pending['action'] == 'reject' else 'new step'}: {pending['text']})"
    return line


def _voice_panel() -> None:
    with st.expander("Voice command", expanded=bool(st.session_state.get("voice_pending"))):
        n = st.session_state.get("voice_mic_n", 0)
        audio = st.audio_input("Say a command", key=f"voice_mic_{n}")
        if audio is not None:
            data = audio.getvalue()
            digest = hashlib.sha1(data).hexdigest()
            if data and digest != st.session_state.get("voice_mic_seen"):
                st.session_state["voice_mic_seen"] = digest
                st.session_state["voice_mic_n"] = n + 1
                try:
                    st.session_state["voice_text"] = voice.transcribe(data)
                except voice.VoiceError as exc:
                    _say(f"Couldn't transcribe: {exc}")
                st.rerun()
        st.text_input("Or type a command", key="voice_typed",
                      placeholder=f"{_W} run all", on_change=_typed_command)
        st.caption(VOICE_HINT)
        heard = st.session_state.get("voice_heard")
        if heard:
            st.text(f"Heard: {heard}")
        line = _read_back_line()
        if line:
            st.warning(f"{line} Say \"{_W} yes\" or press Yes.")
            yes, no = st.columns(2)
            yes.button("Yes", key="voice_yes", type="primary", on_click=_execute_pending)
            no.button("No", key="voice_no", on_click=lambda: st.session_state.pop("voice_pending", None))
        message = st.session_state.get("voice_message")
        if message:
            st.text(message)


# --- page ------------------------------------------------------------------


def _sidebar() -> tuple[str, str, bool]:
    st.sidebar.title(APP_NAME)
    st.sidebar.caption("ITDR agent: investigate, decide, you approve.")
    mode = st.sidebar.radio("Mode", [OFFLINE, LIVE], key="mode")
    model = os.getenv("EVAL_MODEL", DEFAULT_MODEL)
    ready = True
    if mode == OFFLINE:
        st.sidebar.caption(
            "Offline demo: scripted tool calls and a canned verdict built from "
            "the answer key. It shows how the screens work; it does not test "
            "the AI."
        )
    else:
        st.sidebar.caption(f"Model: {model} (set EVAL_MODEL to change)")
        if config.OPENROUTER_API_KEY:
            st.sidebar.caption("OpenRouter key is set (read from .env, never shown).")
        else:
            ready = False
            st.sidebar.error("OPENROUTER_API_KEY is not set. Add it to .env.")
        st.sidebar.caption("Each live run uses about 6-10 requests of your daily limit.")
    if voice.server_reachable():
        st.sidebar.caption("Whisper server: reachable, the mic works.")
    else:
        st.sidebar.caption(
            "Whisper server: not running (typed commands still work). Start it: "
            "whisper-server --host 127.0.0.1 --port 2022 -m ~/whisper-models/ggml-small.en.bin "
            "--inference-path /v1/audio/transcriptions"
        )
    alerts = _alerts()
    st.sidebar.selectbox(
        "Alert",
        list(alerts),
        key="alert_id",
        format_func=lambda a: f"{a}  ({alerts[a]['userPrincipalName']})",
    )
    st.sidebar.button(
        "Run investigation",
        key="start",
        disabled=not ready,
        on_click=_start,
        args=(mode, model),
        type="primary",
    )
    return mode, model, ready


def _tool_calls(run: GuiRun) -> None:
    st.subheader("Investigator tool calls")
    if not run.tool_calls:
        st.caption("No tool calls yet.")
        return
    lines = []
    for number, call in enumerate(list(run.tool_calls), start=1):
        args = ", ".join(f"{k}={v}" for k, v in call["arguments"].items())
        outcome = "ok" if call["ok"] else f"FAILED: {call['error']}"
        lines.append(f"{number}. {call['tool']}({args})  {outcome}")
    st.text("\n".join(lines))


def _report_summary(run: GuiRun) -> None:
    """Show the verdict before the analyst decides (feature 1).

    Uses only code-owned report fields plus the dossier's evidence ids. The
    model narrative goes through st.text, never markdown.
    """
    report = run.shown_report
    dossier = run.shown_dossier
    if report is None:
        return
    with st.container(border=True):
        st.markdown(f"**{verdict_line(report)}**")
        st.text(report.narrative)
        evidence = dossier.mitre_attack_evidence if dossier is not None else {}
        techniques = report.mitre_techniques_observed or []
        st.text(
            "\n".join(
                f"{t}: evidence {', '.join(evidence.get(t, []))}"
                for t in techniques
            )
            or "MITRE ATT&CK techniques: none"
        )
        st.text("\n".join(ticket_lines(run.alert, report, dossier)))


def _question(run: GuiRun) -> None:
    _report_summary(run)
    pending = run.pending
    st.subheader("The agent has one question for you")
    st.text(pending["question"])
    st.radio(
        "Pick one",
        [o["label"] for o in pending["options"]],
        index=None,
        key="answer_choice",
    )
    st.text_area("Or type your own answer", key="answer_text")
    left, right = st.columns(2)
    left.button("Submit answer", key="submit_answer", type="primary",
                on_click=_submit_answer, args=(run,))
    right.button("Skip (no decision)", key="skip_answer",
                 on_click=_skip_answer, args=(run,))
    st.caption("Skipping records \"no decision has been supplied\" and the "
               "agent does not re-check.")


def _review(run: GuiRun) -> None:
    _report_summary(run)
    pending = run.pending
    index = pending["index"]
    st.subheader(f"Containment step {index + 1}: your decision")
    st.caption("The agent only recommends. Nothing runs until you approve.")
    st.markdown("**Step**")
    st.text(pending["step"])
    st.markdown("**Rollback (how to undo it)**")
    st.text(pending["rollback"])
    if pending["warning"]:
        st.warning(pending["warning"])
    st.text_input("New step text (for Edit; blank keeps it)", key=f"edited_step_{index}")
    st.text_input("New rollback (for Edit; blank keeps it)", key=f"edited_rollback_{index}")
    st.text_input("Reason (for Reject, optional)", key=f"reject_reason_{index}")
    approve, edit, reject = st.columns(3)
    approve.button("Approve", key=f"approve_{index}", type="primary",
                   on_click=_decide, args=(run, index, "approve"))
    edit.button("Edit", key=f"edit_{index}",
                on_click=_decide, args=(run, index, "edit"))
    reject.button("Reject", key=f"reject_{index}",
                  on_click=_decide, args=(run, index, "reject"))


def _report(run: GuiRun) -> None:
    result = run.result
    report = result.report
    st.subheader("Report")
    # Ready-to-paste note; st.code has a copy button. The model narrative is
    # inside it, so it stays a code block rather than rendered markdown.
    st.code(incident_note(run.alert, result), language="text")
    st.text(f"Verdict: {report.verdict.value}    Confidence: {report.confidence:.2f}")
    st.text(format_tokens(result.tokens))
    if result.short_circuited:
        st.info("Critical data gap: the model was not called.")
    st.markdown("**Narrative**")
    st.text(report.narrative)
    st.markdown("**MITRE ATT&CK techniques (each backed by evidence)**")
    evidence = result.dossier.mitre_attack_evidence
    st.text("\n".join(
        f"{t}: evidence {', '.join(evidence.get(t, []))}"
        for t in report.mitre_techniques_observed
    ) or "none")
    st.markdown("**Containment steps you kept**")
    st.text("\n".join(
        f"- {s.step}  (rollback: {s.rollback})" for s in report.containment_steps
    ) or "none")
    st.markdown("**Recommended actions**")
    st.text("\n".join(f"- {a}" for a in report.recommended_actions) or "none")
    if report.action_claims:
        st.warning("The model claimed actions were already taken. They were not; "
                   "the agent executes nothing. Flagged: "
                   + "; ".join(report.action_claims))
    if report.audit_notes:
        st.markdown("**Audit notes**")
        st.text(report.audit_notes)
    with st.expander("Dossier (the evidence the verdict was based on)"):
        st.json(result.dossier.model_dump(mode="json"))
    st.subheader("Audit trail")
    st.caption(f"From {result.audit_path}, this run only ({result.run_id}).")
    path = result.audit_path
    lines = [
        line for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and json.loads(line).get("run_id") == result.run_id
    ] if path.exists() else []
    st.code("\n".join(lines) or "no audit lines found", language="json")


# --- feature 3: incident queue home ----------------------------------------


def _home() -> None:
    """The incident queue: count, search, severity/status filters, table."""
    st.title("Identity incident queue")
    alerts = list(_alerts().values())
    runs = _runs()
    search = st.text_input("Search by name, user, or ID", key="queue_search")
    severity_filter = st.multiselect(
        "Severity", ["High", "Medium", "Low", "None"], key="queue_severity"
    )
    status_filter = st.multiselect(
        "Status",
        ["Not started", "Queued", "Running", "Waiting on you", "Closed"],
        key="queue_status",
    )
    rows: list[dict[str, str]] = []
    needle = (search or "").strip().lower()
    for alert in alerts:
        name = what(alert)
        sev = severity(alert)
        run = runs.get(alert["id"])
        run_status = _status_of(run) if run is not None else "Not started"
        haystack = f"{name} {alert['userPrincipalName']} {alert['id']}".lower()
        if needle and needle not in haystack:
            continue
        if severity_filter and sev.rsplit(" ", 1)[-1] not in severity_filter:
            continue
        if status_filter and not any(
            run_status.startswith(prefix) for prefix in status_filter
        ):
            continue
        rows.append(
            {
                "Name": name,
                "Alert ID": alert["id"],
                "Severity": sev,
                "Stage": stage(alert),
                "Status": run_status,
            }
        )
    st.markdown(f"**{len(rows)} alert{'s' if len(rows) != 1 else ''}**")
    event = st.dataframe(
        rows,
        key="queue",
        on_select="rerun",
        selection_mode="single-row",
        hide_index=True,
    )
    # Remember the selection and the rows as drawn: a button callback runs
    # before the next draw, and the table's own selection may be gone by then.
    selected = [rows[i]["Alert ID"] for i in event.selection.rows]
    st.session_state["queue_selected"] = selected
    st.session_state["queue_rows"] = [row["Alert ID"] for row in rows]
    if len(selected) == 1:
        # Set the sidebar alert before _sidebar() creates the selectbox
        # widget; Streamlit forbids changing a widget key after creation.
        st.session_state["alert_id"] = selected[0]
    mode = st.session_state.get("mode", OFFLINE)
    busy = _batch_running()
    _cost_line(len(selected) if selected else len(rows), mode)
    open_col, sel_col, all_col = st.columns(3)
    open_col.button(
        "Open selected" if len(selected) == 1 else "Open selected (pick one row)",
        key="open_selected",
        disabled=len(selected) != 1,
        on_click=_open_clicked,
    )
    sel_col.button(
        f"Run selected ({len(selected)})",
        key="run_selected",
        disabled=not selected or busy,
        on_click=_run_selected_clicked,
    )
    all_col.button(
        f"Run all ({len(rows)})",
        key="run_all",
        type="primary",
        disabled=not rows or busy,
        on_click=_run_all_clicked,
    )
    _voice_panel()
    if busy:
        batch = _batch()
        now = f", now {batch.current}" if batch.current else ""
        st.caption(
            f"Batch running: {batch.completed} of {batch.total} started and "
            f"parked or finished{now}. One alert investigates at a time."
        )
        time.sleep(BATCH_POLL_SECONDS)
        st.rerun()


def _selected_ids() -> list[str]:
    """Alert ids selected in the queue table at its last draw."""
    return list(st.session_state.get("queue_selected") or [])


def _open_clicked() -> None:
    selected = _selected_ids()
    if len(selected) != 1:
        return
    _open_or_select(selected[0])


def _open_or_select(alert_id: str) -> None:
    """An existing run reopens where it is; otherwise show the start page."""
    if alert_id in _runs():
        _open(alert_id)
    else:
        st.session_state["selected_alert"] = alert_id
        st.session_state.pop("open", None)


def _back_to_queue() -> bool:
    return st.button("Back to queue", key="back_to_queue")


def _what_happened(run: GuiRun) -> None:
    """Code-built summary, right below the alert line once there is a verdict."""
    if run.result is not None:
        report, dossier = run.result.report, run.result.dossier
    else:
        report, dossier = run.shown_report, run.shown_dossier
    if report is None:
        return
    st.markdown("**What happened:**")
    st.text(what_happened(run.alert, report, dossier))


def _run_page(run: GuiRun) -> None:
    st.caption(f"Alert {run.alert['id']} for {run.alert['userPrincipalName']}")
    st.text(short_summary(run.alert))
    status = run.wait(POLL_SECONDS)  # first, so a finished run shows its summary
    _what_happened(run)
    if _back_to_queue():
        # The run stays in session_state["runs"]; its thread keeps waiting.
        st.session_state.pop("open", None)
        st.session_state.pop("selected_alert", None)
        st.rerun()
    if st.session_state.get("flash"):
        st.error(st.session_state["flash"])
    _voice_panel()
    if status == "running":
        # Update only the tool-call list in place while the model works; a
        # full-page rerun on every poll made the page flash (30-60 s live).
        live = st.empty()
        with st.spinner("The agent is working..."):
            while status == "running":
                with live.container():
                    _tool_calls(run)
                status = run.wait(POLL_SECONDS)
        st.rerun()  # once: draw the question, the step, or the report
    _tool_calls(run)
    if status == "question":
        _question(run)
    elif status == "review":
        _review(run)
    elif status == "error":
        st.error(f"The run stopped: {run.error}")
    elif status == "done":
        _report(run)


def _selected_page(alert: dict) -> None:
    st.text(short_summary(alert))
    st.info("Press Run investigation in the sidebar to start.")
    if _back_to_queue():
        st.session_state.pop("selected_alert", None)
        st.rerun()


def main() -> None:
    st.set_page_config(page_title="Countersign: Layer Zero", layout="wide")
    _process_voice_text()  # a command from the mic or the typed box, if any
    open_id: str | None = st.session_state.get("open")
    run: GuiRun | None = _runs().get(open_id) if open_id else None
    selected: str | None = st.session_state.get("selected_alert")
    on_home = run is None and selected is None
    if on_home:
        # Draw the queue first so a row selection can set the sidebar alert
        # before the selectbox widget is created.
        _home()
    _sidebar()
    if on_home:
        return
    st.title("Identity incident review")
    if run is None:
        _selected_page(_alerts()[selected])
    else:
        _run_page(run)


main()
