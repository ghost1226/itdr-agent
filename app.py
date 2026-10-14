"""Local web GUI for the ITDR agent.

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

Anything the model wrote is shown with st.text, never rendered as markdown.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import streamlit as st

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from itdr_agent import config  # noqa: E402
from itdr_agent.adjudicator import DEFAULT_MODEL, Adjudicator  # noqa: E402
from itdr_agent.fixture_store import get_store  # noqa: E402
from itdr_agent.gui_run import GuiRun  # noqa: E402
from itdr_agent.investigator import Investigator  # noqa: E402
from itdr_agent.orchestrator import DEFAULT_AUDIT_LOG, Orchestrator  # noqa: E402

OFFLINE = "Offline demo (no key, no model)"
LIVE = "Live (OpenRouter, your own key)"
POLL_SECONDS = 0.5
WIDGET_PREFIXES = ("edited_step_", "reject_reason_", "answer_")


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
        return Orchestrator(investigator, adjudicator, reviewer, audit_log=audit)

    return build


def _live_builder(model: str, audit: Path):
    from itdr_agent.__main__ import (
        _OpenRouterAdjudicatorLLM,
        _OpenRouterInvestigatorLLM,
    )

    timeout = min(config.TIMEOUT_SECONDS, 90)  # per request, same as the CLI

    def build(reviewer, tool_executor):
        key = config.OPENROUTER_API_KEY
        investigator = Investigator(
            _OpenRouterInvestigatorLLM(key, model, timeout),
            tool_executor=tool_executor,
        )
        adjudicator = Adjudicator(_OpenRouterAdjudicatorLLM(key, model, timeout))
        return Orchestrator(investigator, adjudicator, reviewer, audit_log=audit)

    return build


# --- callbacks (run before the page redraws) -------------------------------


def _start(mode: str, model: str) -> None:
    for key in list(st.session_state):
        if key.startswith(WIDGET_PREFIXES):
            del st.session_state[key]
    st.session_state.pop("flash", None)
    alert_id = st.session_state["alert_id"]
    audit = _audit_path()
    if mode == LIVE:
        build = _live_builder(model, audit)
    else:
        build = _offline_builder(alert_id, audit)
    run = GuiRun(build, _alerts()[alert_id])
    st.session_state["run"] = run
    run.start()


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


# --- page ------------------------------------------------------------------


def _sidebar() -> tuple[str, str, bool]:
    st.sidebar.title("ITDR Agent")
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


def _question(run: GuiRun) -> None:
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
    st.text_input("New step text (for Edit)", key=f"edited_step_{index}")
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
    st.text(f"Verdict: {report.verdict.value}    Confidence: {report.confidence:.2f}")
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
    st.caption(f"From {_audit_path()}, this run only ({result.run_id}).")
    path = _audit_path()
    lines = [
        line for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and json.loads(line).get("run_id") == result.run_id
    ] if path.exists() else []
    st.code("\n".join(lines) or "no audit lines found", language="json")


def main() -> None:
    st.set_page_config(page_title="ITDR Agent", layout="wide")
    _sidebar()
    st.title("Identity incident review")
    run: GuiRun | None = st.session_state.get("run")
    if run is None:
        st.info("Pick an alert in the sidebar and press Run investigation.")
        return
    status = run.wait(POLL_SECONDS)
    st.caption(f"Alert {run.alert['id']} for {run.alert['userPrincipalName']}")
    if st.session_state.get("flash"):
        st.error(st.session_state["flash"])
    _tool_calls(run)
    if status == "running":
        st.caption("Working...")
        st.rerun()
    elif status == "question":
        _question(run)
    elif status == "review":
        _review(run)
    elif status == "error":
        st.error(f"The run stopped: {run.error}")
    elif status == "done":
        _report(run)


main()
