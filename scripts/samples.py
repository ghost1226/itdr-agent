"""Deterministic mocked sample reports — OFFLINE, no API key, no network.

This lives under ``scripts/`` because it reads ``ground_truth.jsonl`` (verdict
and scenario) to make the samples illustrative. Nothing under ``itdr_agent/``
may read ground truth; only tests and scripts do.

Each benign narrative is composed from that alert's own dossier evidence
(travel: same known device, hours apart; role add: the ticket in
``resultReason``; VPN: the trusted named network). Benign and insufficient
samples never suggest disabling the account.

Run:
    python scripts/samples.py ALERT_001 ALERT_006 ALERT_007 ALERT_008
"""

from __future__ import annotations

import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from itdr_agent.adjudicator import Adjudicator  # noqa: E402
from itdr_agent.fixture_store import get_store  # noqa: E402
from itdr_agent.investigator import Investigator  # noqa: E402

DEFAULT_ALERTS = ("ALERT_001", "ALERT_006", "ALERT_007", "ALERT_008")
GROUND_TRUTH = PROJECT_ROOT / "data" / "fixtures" / "ground_truth.jsonl"

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
        for line in GROUND_TRUTH.read_text(encoding="utf-8").splitlines()
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


def build_investigator(alert_id: str):
    """Return (investigator with scripted offline tools, alert)."""
    store = get_store()
    alert = next(a for a in store.alerts if a["id"] == alert_id)
    upn = alert["userPrincipalName"]
    events = store.sign_in_history(upn, 10_000)
    device_id = events[0]["deviceDetail"]["deviceId"] if events else ""
    llm = _ScriptedToolLLM(_tool_script(upn, device_id))
    return Investigator(llm), alert


def build_dossier(alert_id: str) -> tuple[Any, dict]:
    """Build a real dossier for an alert using scripted (offline) LLMs."""
    investigator, alert = build_investigator(alert_id)
    return investigator.investigate(alert), alert


def _hours_between(start: str, end: str) -> float:
    parse = lambda ts: datetime.fromisoformat(ts.replace("Z", "+00:00"))  # noqa: E731
    return abs((parse(end) - parse(start)).total_seconds()) / 3600.0


def _travel_note(dossier) -> str:
    risky = [
        e
        for e in dossier.sign_in_history
        if "unlikelyTravel" in e.get("riskEventTypes_v2", [])
    ]
    if len(risky) >= 2:
        legs = " then ".join(
            f"{e['location']['city']} at {e['createdDateTime']}" for e in risky
        )
        return f"unlikely-travel sign-ins ({legs})"
    # Benign travel: two sign-ins on the same known device, far apart.
    by_device: dict[str, list[dict]] = {}
    for event in dossier.sign_in_history:
        by_device.setdefault(
            event["deviceDetail"]["deviceId"], []
        ).append(event)
    best: tuple[float, dict, dict] | None = None
    for group in by_device.values():
        ordered = sorted(group, key=lambda e: e["createdDateTime"])
        for i in range(len(ordered)):
            for j in range(i + 1, len(ordered)):
                first, last = ordered[i], ordered[j]
                if (
                    first["location"]["countryOrRegion"]
                    == last["location"]["countryOrRegion"]
                ):
                    continue
                gap = _hours_between(
                    first["createdDateTime"], last["createdDateTime"]
                )
                if best is None or gap < best[0]:
                    best = (gap, first, last)
    if best is not None:
        gap, first, last = best
        return (
            f"two sign-ins on the same known compliant device "
            f"({first['deviceDetail']['displayName']}), "
            f"{first['location']['city']} then {last['location']['city']}, "
            f"{gap:.1f} hours apart — a plausible flight"
        )
    return "two sign-ins on the same known compliant device, hours apart"


def _vpn_note(dossier) -> str:
    for event in dossier.sign_in_history:
        for detail in event.get("networkLocationDetails") or []:
            names = detail.get("networkNames") or []
            if names:
                return (
                    f"sign-ins from the trusted named network {names[0]} "
                    f"(networkType={detail.get('networkType')})"
                )
    return "sign-ins from a trusted named corporate network"


def _role_note(dossier, *, benign: bool) -> str:
    for audit in dossier.directory_audits:
        if audit.get("activityDisplayName") != "Add member to role":
            continue
        for target in audit.get("targetResources", []):
            if target.get("userPrincipalName") != dossier.user_principal_name:
                continue
            reason = (audit.get("resultReason") or "an in-window role add")
            reason = reason.strip().rstrip(".")
            # Only call a role add "expected" for a benign verdict whose audit
            # actually cites a ticket; an attack role add is not expected.
            if benign and re.search(r"HD-\d+", reason):
                return f"the expected role add ({reason})"
            return f"an in-window role add ({reason})"
    return "an in-window role add targeting this user"


def _insufficient_note(dossier) -> str:
    if dossier.data_gaps:
        return "; ".join(dossier.data_gaps)
    return "the window has too little evidence (thin sign-in history, no audits)"


def _attack_note(dossier) -> str:
    notes = []
    for technique in sorted(dossier.mitre_attack_evidence):
        if technique == "T1078.004":
            notes.append(_travel_note(dossier))
        elif technique == "T1098.003":
            notes.append(_role_note(dossier, benign=False))
        else:
            notes.append(TECHNIQUE_NOTES.get(technique, technique))
    cleaned = [note.strip().rstrip(".") for note in notes]
    return "; ".join(cleaned) if cleaned else "no evidence-backed MITRE technique"


def _benign_note(dossier, scenario: str) -> str:
    if scenario == "benign_admin_role":
        return _role_note(dossier, benign=True)
    if scenario == "benign_vpn":
        return _vpn_note(dossier)
    if scenario == "benign_travel":
        return _travel_note(dossier)
    return "the activity is consistent with expected user behaviour"


def build_mock_report(dossier, scenario: str, verdict: str) -> str:
    """Compose a mock reply from the dossier; never invent evidence."""
    techniques = sorted(dossier.mitre_attack_evidence)

    if verdict == "FALSE_POSITIVE":
        narrative = (
            f"Benign: {_benign_note(dossier, scenario)}. "
            "No containment required; continue monitoring the account."
        )
        containment_steps = []
        recommended_actions = [
            "Continue monitoring the account",
            "Confirm the activity with the user out-of-band",
        ]
        confidence = 0.88
    elif verdict == "INSUFFICIENT_DATA":
        narrative = (
            "Insufficient data to reach a verdict: "
            f"{_insufficient_note(dossier)}."
        )
        containment_steps = []
        recommended_actions = [
            "Gather more sign-in history for the user",
            "Gather directory audits touching the user",
            "Re-adjudicate once the missing evidence is available",
        ]
        confidence = 0.4
    else:
        narrative = f"Evidence supports {_attack_note(dossier)}."
        containment_steps = [
            {
                "step": "Disable the account pending analyst review",
                "rollback": (
                    "Re-enable the account if the activity is confirmed "
                    "legitimate."
                ),
            }
        ]
        recommended_actions = ["Confirm the activity with the user out-of-band"]
        confidence = 0.9

    return json.dumps(
        {
            "verdict": verdict,
            "confidence": confidence,
            "narrative": narrative,
            "containment_steps": containment_steps,
            "recommended_actions": recommended_actions,
            "mitre_techniques_observed": techniques,
            "audit_notes": "Evidence-backed techniques only.",
        }
    )


def sample_report(alert_id: str) -> tuple[Any, Any]:
    """Return (dossier, report) for a deterministic mocked sample."""
    dossier, _alert = build_dossier(alert_id)
    entry = _ground_truth()[alert_id]
    llm = _MockCompleteLLM(
        build_mock_report(dossier, entry["scenario"], entry["expected_verdict"])
    )
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
