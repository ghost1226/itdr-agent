"""GUI batch 1 — pure alert summaries (no model, no network).

Every function here reads only fields from
``data_generator.ALERT_FIELD_ALLOWLIST``. Ground truth (``scenario`` /
``expected_verdict`` / ``expected_mitre`` / ``is_benign``) and the source IP
address are never read, so a summary cannot leak the answer key or an address.

The functions are deliberately deterministic and side-effect free so they can
be unit-tested and reused by the CLI and the GUI.
"""

from __future__ import annotations

from typing import Any

# riskEventTypes_v2 values (Graph beta) in plain words.
RISK_EVENT_WORDS: dict[str, str] = {
    "unlikelyTravel": "Unlikely travel",
    "anonymizedIPAddress": "Anonymous IP address",
    "unfamiliarFeatures": "Unfamiliar sign-in properties",
}

NO_RISK_DETECTION = "Sign-in flagged with no risk detection"

SEVERITY_BARS: dict[str, str] = {
    "high": "■■■ High",
    "medium": "■■□ Medium",
    "low": "■□□ Low",
    "none": "□□□ None",
}

CONCLUSIONS: dict[str, str] = {
    "COMPROMISED": "This appears to be likely account compromise.",
    "FALSE_POSITIVE": "This appears to be a false positive.",
    "INSUFFICIENT_DATA": (
        "Not enough data to decide; escalate for manual review."
    ),
}


def what(alert: dict[str, Any]) -> str:
    """The risk detections in plain words, joined with ``" + "``."""
    events = alert.get("riskEventTypes_v2") or []
    words = [RISK_EVENT_WORDS.get(event, event) for event in events]
    return " + ".join(words) if words else NO_RISK_DETECTION


def stage(alert: dict[str, Any]) -> str:
    """The authentication result. Never claims compromise."""
    status = alert.get("status") or {}
    code = status.get("errorCode", 0)
    if code == 0:
        return "Successful (session created)"
    if code == 500121:
        return "Blocked (MFA denied)"
    reason = status.get("failureReason") or "unknown reason"
    return f"Attempted (failed: {reason})"


def severity(alert: dict[str, Any]) -> str:
    """``riskLevelAggregated`` rendered as filled/empty bars plus a word."""
    level = str(alert.get("riskLevelAggregated") or "none").lower()
    return SEVERITY_BARS.get(level, SEVERITY_BARS["none"])


def _place(alert: dict[str, Any]) -> str:
    location = alert.get("location") or {}
    city = location.get("city") or "Unknown"
    country = location.get("countryOrRegion") or ""
    return f"{city}, {country}" if country else city


def short_summary(alert: dict[str, Any]) -> str:
    """One line for the queue and the run header."""
    return (
        f"{alert.get('id', '')} · {what(alert)} · "
        f"{alert.get('userPrincipalName', '')} · {_place(alert)} · "
        f"{stage(alert)}"
    )


def incident_note(alert: dict[str, Any], result: Any) -> str:
    """A ready-to-paste incident note built from the alert and the report.

    ``result`` is an orchestrator result with a ``.report``; only code-owned
    report fields and alert fields on the allowlist are read.
    """
    report = result.report
    verdict = (
        report.verdict.value
        if hasattr(report.verdict, "value")
        else str(report.verdict)
    )
    steps = [step.step for step in report.containment_steps]
    action = "; ".join(steps) if steps else "No action required"
    recommended = (
        "; ".join(report.recommended_actions)
        if report.recommended_actions
        else "none"
    )
    analysis = (
        f"Analysis: The affected user triggered {what(alert)} involving "
        f"{alert.get('appDisplayName', '')}. The sign-in originated from "
        f"{_place(alert)}. IP reputation: not available in this dataset. "
        f"Authentication result: {stage(alert)}.\n{report.narrative}"
    )
    return "\n".join(
        [
            f"Alert: {alert.get('id', '')}",
            f"What: {what(alert)} involving one user",
            f"User: {alert.get('userPrincipalName', '')}",
            analysis,
            f"Conclusion: {CONCLUSIONS.get(verdict, '')} Stage: {stage(alert)}.",
            f"Action: {action}. Recommended: {recommended}",
        ]
    )


def report_summary_lines(report: Any, dossier: Any) -> list[str]:
    """Verdict / confidence / narrative / MITRE evidence, shared by CLI + GUI.

    This is the pre-decision summary: it is shown before the analyst answers
    the question and before each containment step, so the human decides with
    the verdict in front of them.
    """
    evidence = getattr(dossier, "mitre_attack_evidence", {}) or {}
    techniques = report.mitre_techniques_observed or []
    lines = [
        f"Verdict: {report.verdict.value}    Confidence: {report.confidence:.2f}",
        "Narrative:",
        report.narrative,
        "MITRE ATT&CK techniques:",
    ]
    if techniques:
        for technique in techniques:
            ids = ", ".join(evidence.get(technique, [])) or "none"
            lines.append(f"  {technique}: evidence {ids}")
    else:
        lines.append("  none")
    return lines
