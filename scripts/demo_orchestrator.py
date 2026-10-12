"""Offline demo of the Checkpoint 6 orchestrator + HITL. No live tokens.

Run: python scripts/demo_orchestrator.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from itdr_agent.adjudicator import Adjudicator, UnsupportedMitreClaimError  # noqa: E402
from itdr_agent.human import (  # noqa: E402
    AskUserResult,
    ContainmentDecision,
    ScriptedReviewer,
    cancelled_result,
)
from itdr_agent.orchestrator import Orchestrator  # noqa: E402
import samples  # noqa: E402  (scripts/samples.py)

AUDIT = PROJECT_ROOT / "logs" / "audit.jsonl"


class CompleteLLM:
    def __init__(self, responses: list[str]) -> None:
        self.responses = list(responses)
        self.calls = 0
        self.messages: list[list[dict]] = []

    def complete(self, messages: list[dict]) -> str:
        self.calls += 1
        self.messages.append(messages)
        if not self.responses:
            raise AssertionError("model called with no scripted response")
        return self.responses.pop(0)


def _report(
    verdict="COMPROMISED",
    confidence=0.9,
    steps=None,
    techniques=None,
    narrative="demo",
) -> str:
    return json.dumps(
        {
            "verdict": verdict,
            "confidence": confidence,
            "narrative": narrative,
            "containment_steps": steps
            if steps is not None
            else [
                {"step": "Disable the account", "rollback": "Re-enable if benign"}
            ],
            "recommended_actions": ["Contact the user"],
            "mitre_techniques_observed": techniques
            if techniques is not None
            else ["T1078.004"],
            "audit_notes": "",
        }
    )


def _run(alert_id, responses, reviewer):
    investigator, alert = samples.build_investigator(alert_id)
    llm = CompleteLLM(responses)
    orch = Orchestrator(
        investigator, Adjudicator(llm), reviewer, audit_log=AUDIT
    )
    return orch.run(alert), llm


def _lines(event_name):
    if not AUDIT.exists():
        return []
    out = []
    for line in AUDIT.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        entry = json.loads(line)
        if entry["event"] == event_name:
            out.append(entry)
    return out


def _show(title, result, llm=None):
    print(f"\n===== {title} =====")
    print(
        f"alert={result.alert_id} verdict={result.report.verdict.value} "
        f"confidence={result.report.confidence} llm_called={result.llm_called} "
        f"short_circuited={result.short_circuited} "
        f"questions={result.questions_asked} "
        f"re_adjudications={result.re_adjudications}"
    )
    if llm is not None:
        for index, messages in enumerate(llm.messages):
            for message in messages:
                if message["role"] == "user" and "analyst_input" in message["content"]:
                    print(f"  adjudicator call {index}: {message['content']!r}")


def main() -> int:
    if AUDIT.exists():
        AUDIT.unlink()
    AUDIT.parent.mkdir(parents=True, exist_ok=True)

    # 1. approve / edit / reject -------------------------------------------------
    reviewer = ScriptedReviewer(
        decisions=[
            ContainmentDecision("approve"),
            ContainmentDecision(
                "edit", edited_step="Isolate the device and quarantine it"
            ),
            ContainmentDecision("reject", reason="not needed for this alert"),
        ]
    )
    result, _ = _run(
        "ALERT_001",
        [
            _report(
                steps=[
                    {"step": "Disable the account", "rollback": "Re-enable if benign"},
                    {"step": "Isolate the device", "rollback": "Re-enable the device"},
                    {"step": "Reset the password", "rollback": "Restore the old password"},
                ]
            )
        ],
        reviewer,
    )
    _show("1. HITL approve / edit / reject", result)
    for step in result.report.containment_steps:
        print(f"    kept: {step.step} | rollback: {step.rollback}")

    # 2. cancelled ask -----------------------------------------------------------
    reviewer = ScriptedReviewer(answers=[cancelled_result()])
    result, _ = _run(
        "ALERT_009",
        [_report(verdict="SUSPICIOUS", confidence=0.6, techniques=[])],
        reviewer,
    )
    _show("2. cancelled ask_user (no re-adjudication)", result)

    # 3. one question, one re-adjudication --------------------------------------
    reviewer = ScriptedReviewer(
        answers=[
            AskUserResult(
                "answered",
                "This is expected travel for a conference",
                1,
                False,
            )
        ]
    )
    result, llm = _run(
        "ALERT_009",
        [
            _report(verdict="INSUFFICIENT_DATA", confidence=0.5, techniques=[]),
            _report(verdict="INSUFFICIENT_DATA", confidence=0.55, techniques=[]),
        ],
        reviewer,
    )
    _show(
        "3. ALERT_009 one question / one re-adjudication / no second ask", result, llm
    )

    # 4. MITRE guard -------------------------------------------------------------
    try:
        _run(
            "ALERT_001",
            [_report(techniques=["T1078.004", "T9999"])],
            ScriptedReviewer(),
        )
        print("\n===== 4. MITRE guard: unexpectedly accepted =====")
    except UnsupportedMitreClaimError as exc:
        print(f"\n===== 4. MITRE guard rejected: {exc} =====")

    # 5. ALERT_010 short-circuit -------------------------------------------------
    result, llm = _run("ALERT_010", [], ScriptedReviewer())
    _show("5. ALERT_010 unknown user short-circuit", result, llm)

    # audit lines -----------------------------------------------------------------
    print("\n===== audit.jsonl: containment_decision =====")
    for entry in _lines("containment_decision"):
        print(json.dumps(entry))
    print("\n===== audit.jsonl: ask_user =====")
    for entry in _lines("ask_user"):
        print(json.dumps(entry))
    print("\n===== audit.jsonl: re_adjudication =====")
    for entry in _lines("re_adjudication"):
        print(json.dumps(entry))
    print("\n===== audit.jsonl: mitre_rejection =====")
    for entry in _lines("mitre_rejection"):
        print(json.dumps(entry))
    print("\n===== audit.jsonl: run (ALERT_010) =====")
    for entry in _lines("run"):
        if entry["alert_id"] == "ALERT_010":
            print(json.dumps(entry))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
