"""Deterministic mocked sample reports (offline; no API key, no network).

Used by tests and review demos. The mocked Adjudicator reply is composed from
the real dossier evidence, so the narrative cannot claim anything absent from
the fixtures. Verdicts are read from ``ground_truth.jsonl`` only to make the
samples illustrative; the model itself never sees ground truth.

Run:
    python -m itdr_agent.samples ALERT_001 ALERT_007
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from .adjudicator import Adjudicator
from .fixture_store import get_store
from .investigator import Investigator

DEFAULT_ALERTS = ("ALERT_001", "ALERT_007")
_GROUND_TRUTH = (
    Path(__file__).resolve().parent.parent
    / "data"
    / "fixtures"
    / "ground_truth.jsonl"
)

TECHNIQUE_NOTES = {
    "T1078.004": "unlikely-travel sign-ins",
    "T1621": "a burst of MFA denials",
    "T1090.003": "a sign-in from an anonymizing proxy",
    "T1528": "an application consent after a risky sign-in",
    "T1098.003": "an in-window role assignment targeting the user",
}


class _ScriptedToolLLM:
    """Fake Investigator LLM: calls every tool once, then stops."""

    def __init__(self, actions: list[dict]) -> None:
        self._actions = list(actions)

    def next_action(self, messages: list[dict]) -> dict:
        return self._actions.pop(0) if self._actions else {"action": "final"}


class _MockCompleteLLM:
    """Fake Adjudicator LLM: returns a fixed, evidence-derived reply."""

    def __init__(self, response: str) -> None:
        self.response = response
        self.messages: list[dict] = []

    def complete(self, messages: list[dict]) -> str:
        self.messages = messages
        return self.response


def _ground_truth() -> dict[str, dict]:
    entries = [
        json.loads(line)
        for line in _GROUND_TRUTH.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    return {entry["alert_id"]: entry for entry in entries}


def _tool_script(upn: str, device_id: str) -> list[dict]:
    return [
        {"action": "tool", "tool": "get_user_profile", "arguments": {"upn": upn}},
        {
            "action": "tool",
            "tool": "get_sign_in_history",
            "arguments": {"upn": upn, "hours": 10000},
        },
        {
            "action": "tool",
            "tool": "get_device_trust",
            "arguments": {"device_id": device_id},
        },
        {
            "action": "tool",
            "tool": "get_directory_audits",
            "arguments": {"upn": upn, "hours": 10000},
        },
        {
            "action": "tool",
            "tool": "get_risky_user_report",
            "arguments": {"upn": upn},
        },
        {"action": "final"},
    ]


def build_dossier(alert_id: str) -> tuple[Any, dict]:
    """Build a real dossier for an alert using scripted (offline) LLMs."""
    store = get_store()
    alert = next(a for a in store.alerts if a["id"] == alert_id)
    upn = alert["userPrincipalName"]
    events = store.sign_in_history(upn, 10_000)
    device_id = events[0]["deviceDetail"]["deviceId"] if events else ""
    llm = _ScriptedToolLLM(_tool_script(upn, device_id))
    return Investigator(llm).investigate(alert), alert


def _travel_note(dossier) -> str:
    events = [
        e
        for e in dossier.sign_in_history
        if "unlikelyTravel" in e.get("riskEventTypes_v2", [])
    ]
    if not events:
        return "unlikely-travel sign-ins"
    legs = " then ".join(
        f"{e['location']['city']} at {e['createdDateTime']}" for e in events
    )
    return f"unlikely-travel sign-ins ({legs})"


def _role_note(dossier) -> str:
    for audit in dossier.directory_audits:
        if audit.get("activityDisplayName") != "Add member to role":
            continue
        for target in audit.get("targetResources", []):
            if target.get("userPrincipalName") == dossier.user_principal_name:
                return audit.get("resultReason") or (
                    "an in-window role add targeting this user"
                )
    return "an in-window role add targeting this user"


def build_mock_report(dossier, verdict: str) -> str:
    """Compose a mock reply from the dossier; never invent evidence."""
    techniques = sorted(dossier.mitre_attack_evidence)
    notes = []
    for technique in techniques:
        if technique == "T1078.004":
            notes.append(_travel_note(dossier))
        elif technique == "T1098.003":
            notes.append(_role_note(dossier))
        else:
            notes.append(TECHNIQUE_NOTES.get(technique, technique))
    cleaned = [note.strip().rstrip(".") for note in notes]
    evidence = (
        "; ".join(cleaned)
        if cleaned
        else "no evidence-backed MITRE technique"
    )

    if verdict == "FALSE_POSITIVE":
        narrative = (
            f"Evidence supports {evidence}, but the context is benign: the "
            "ticket-backed admin role add is expected helpdesk activity."
        )
        confidence = 0.88
    else:
        narrative = f"Evidence supports {evidence}."
        confidence = 0.9

    return json.dumps(
        {
            "verdict": verdict,
            "confidence": confidence,
            "narrative": narrative,
            "containment_steps": [
                {
                    "step": "Disable the account pending analyst review",
                    "rollback": (
                        "Re-enable the account if the activity is confirmed "
                        "legitimate."
                    ),
                }
            ],
            "recommended_actions": [
                "Confirm the activity with the user out-of-band"
            ],
            "mitre_techniques_observed": techniques,
            "audit_notes": "Evidence-backed techniques only.",
        }
    )


def sample_report(alert_id: str) -> tuple[Any, Any]:
    """Return (dossier, report) for a deterministic mocked sample."""
    dossier, _alert = build_dossier(alert_id)
    verdict = _ground_truth()[alert_id]["expected_verdict"]
    llm = _MockCompleteLLM(build_mock_report(dossier, verdict))
    return dossier, Adjudicator(llm).adjudicate(dossier)


def _main(argv: list[str]) -> int:
    for alert_id in argv or list(DEFAULT_ALERTS):
        dossier, report = sample_report(alert_id)
        print(f"===== {alert_id} ({dossier.user_principal_name}) =====")
        print(report.model_dump_json(indent=2))
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
