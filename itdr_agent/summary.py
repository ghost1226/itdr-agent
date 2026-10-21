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
    "SUSPICIOUS": (
        "This appears to be suspicious activity (possible credential "
        "exposure); verify with the user and monitor."
    ),
    "FALSE_POSITIVE": "This appears to be a false positive.",
    "INSUFFICIENT_DATA": (
        "Not enough data to decide; escalate for manual review."
    ),
}


# MITRE names (attack.mitre.org, confirmed in PROGRESS.md's checklist).
TECHNIQUE_NAMES: dict[str, str] = {
    "T1078.004": "Valid Accounts: Cloud Accounts",
    "T1621": "MFA Request Generation",
    "T1090.003": "Proxy: Multi-hop Proxy",
    "T1528": "Steal Application Access Token",
    "T1098.003": "Account Manipulation: Additional Cloud Roles",
}

# MITRE techniques the Investigator proved from evidence, in plain words.
TECHNIQUE_WORDS: dict[str, str] = {
    "T1078.004": "Unlikely travel",
    "T1090.003": "Anonymous IP address",
    "T1621": "MFA fatigue",
    "T1528": "App consent after a risky sign-in",
    "T1098.003": "Privileged role added",
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


def found(alert: dict[str, Any], dossier: Any) -> str:
    """The "What" after the investigation: the alert's own risk detections
    plus every technique the evidence proved, de-duplicated. Before there is
    a dossier, this is just ``what(alert)``.
    """
    evidence = getattr(dossier, "mitre_attack_evidence", None) or {}
    events = alert.get("riskEventTypes_v2") or []
    words = [RISK_EVENT_WORDS.get(event, event) for event in events]
    for technique in sorted(evidence):
        word = TECHNIQUE_WORDS.get(technique)
        if word and word not in words:
            words.append(word)
    return " + ".join(words) if words else what(alert)


def _sign_in_counts(dossier: Any) -> tuple[int, int, int, int]:
    """Total, succeeded, failed with MFA denied, failed for other reasons."""
    total = succeeded = denied = other = 0
    for event in getattr(dossier, "sign_in_history", None) or []:
        total += 1
        status = event.get("status") or {}
        if status.get("errorCode", 0) == 0:
            succeeded += 1
        elif "MFA" in (status.get("failureReason") or ""):
            denied += 1
        else:
            other += 1
    return total, succeeded, denied, other


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def _log_facts(dossier: Any) -> str:
    total, succeeded, denied, other = _sign_in_counts(dossier)
    parts = []
    if succeeded:
        parts.append(f"{succeeded} succeeded")
    if denied:
        parts.append(f"{denied} failed with MFA denied")
    if other:
        parts.append(f"{other} failed for other reasons")
    text = f"{_plural(total, 'sign-in')} in the window"
    return f"{text}: {', '.join(parts)}" if parts and total else text


def _verdict(report: Any) -> str:
    return (
        report.verdict.value
        if hasattr(report.verdict, "value")
        else str(report.verdict)
    )


def what_happened(alert: dict[str, Any], report: Any, dossier: Any) -> str:
    """One sentence at the top of the verdict box, built by code only."""
    sentences = [
        f"{alert.get('userPrincipalName', '')} had {_log_facts(dossier)}.",
        f"Alerted sign-in: {stage(alert)} on {alert.get('appDisplayName', '')} "
        f"from {_place(alert)}.",
    ]
    evidence = getattr(dossier, "mitre_attack_evidence", None) or {}
    if evidence:
        named = [
            f"{TECHNIQUE_WORDS.get(t, t)} ({t})" for t in sorted(evidence)
        ]
        sentences.append(f"Found: {', '.join(named)}.")
    sentences.append(CONCLUSIONS.get(_verdict(report), ""))
    return " ".join(s for s in sentences if s)


def ticket_lines(alert: dict[str, Any], report: Any, dossier: Any) -> list[str]:
    """Joe's incident-note format for the verdict box, before any review."""
    finding = found(alert, dossier)
    total, _succeeded, denied, other = _sign_in_counts(dossier)
    failures = []
    if denied:
        failures.append(f"{denied} failed with MFA denied")
    if other:
        failures.append(f"{other} failed for other reasons")
    logs = f"{_plural(total, 'sign-in')} in the window"
    if failures:
        logs += ", " + ", ".join(failures)
    audits = len(getattr(dossier, "directory_audits", None) or [])
    if audits:
        logs += f", and {_plural(audits, 'directory audit change')}"
    steps = [step.step for step in report.containment_steps]
    action = (
        "Proposed, each step needs your approval below: " + "; ".join(steps)
        if steps
        else "No containment proposed; monitor the user's account."
    )
    return [
        f"Alert: {alert.get('id', '')}",
        f"What: {finding} involving one user",
        f"User: {alert.get('userPrincipalName', '')}",
        f"Analysis: The user's account was flagged for {finding} on "
        f"{alert.get('appDisplayName', '')} from {_place(alert)}. The sign-in "
        f"logs show {logs}. IP reputation: not available in this dataset.",
        f"Action: {action}",
    ]


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
    verdict = _verdict(report)
    finding = found(alert, getattr(result, "dossier", None))
    steps = [step.step for step in report.containment_steps]
    action = "; ".join(steps) if steps else "No action required"
    recommended = (
        "; ".join(report.recommended_actions)
        if report.recommended_actions
        else "none"
    )
    analysis = (
        f"Analysis: The affected user triggered {finding} involving "
        f"{alert.get('appDisplayName', '')}. The sign-in originated from "
        f"{_place(alert)}. IP reputation: not available in this dataset. "
        f"Authentication result: {stage(alert)}.\n{report.narrative}"
    )
    return "\n".join(
        [
            f"Alert: {alert.get('id', '')}",
            f"What: {finding} involving one user",
            f"User: {alert.get('userPrincipalName', '')}",
            analysis,
            f"Conclusion: {CONCLUSIONS.get(verdict, '')} Stage: {stage(alert)}.",
            f"Action: {action}. Recommended: {recommended}",
        ]
    )


def verdict_line(report: Any) -> str:
    """The verdict box's first line.

    When the thin-evidence guard flipped the verdict, show what the model
    said and why it changed, so it never reads as "INSUFFICIENT_DATA 0.92".
    """
    model_verdict = getattr(report, "model_verdict", None)
    if model_verdict:
        confidence = getattr(report, "model_confidence", None)
        said = (
            f"{model_verdict} ({confidence:.2f})"
            if confidence is not None
            else model_verdict
        )
        sign_ins = getattr(report, "baseline_sign_ins", None)
        reason = (
            f"only {_plural(sign_ins, 'sign-in')} in the last 7 days"
            if sign_ins is not None
            else "thin evidence"
        )
        return f"Model said {said}. Changed to {_verdict(report)} because {reason}."
    return f"Verdict: {_verdict(report)}    Confidence: {report.confidence:.2f}"


def report_summary_lines(report: Any, dossier: Any) -> list[str]:
    """Verdict / confidence / narrative / MITRE evidence, shared by CLI + GUI.

    This is the pre-decision summary: it is shown before the analyst answers
    the question and before each containment step, so the human decides with
    the verdict in front of them.
    """
    evidence = getattr(dossier, "mitre_attack_evidence", {}) or {}
    techniques = report.mitre_techniques_observed or []
    lines = [
        verdict_line(report),
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


# --- GUI rebuild checkpoint 2: the alert line and the four cards ------------


def _short_what(alert: dict[str, Any]) -> str:
    if alert.get("riskEventTypes_v2"):
        return what(alert)
    code = (alert.get("status") or {}).get("errorCode", 0)
    if code == 500121:
        return "MFA denied"
    if code:
        return "Sign-in failed"
    return "Sign-in flagged"


def alert_line(alert: dict[str, Any]) -> str:
    """One mono line under the alert chip: what · app · place · time. No IP."""
    when = (alert.get("createdDateTime") or "").replace("T", " ")
    when = when[:16] + "Z" if len(when) >= 16 else when
    return " · ".join(
        part for part in (
            _short_what(alert), alert.get("appDisplayName") or "", _place(alert), when
        ) if part
    )


def technique_card(report: Any, dossier: Any) -> tuple[str, str, str]:
    """(id, name, detail) for the Technique card; the first proved technique."""
    techniques = list(getattr(report, "mitre_techniques_observed", None) or [])
    if not techniques:
        return ("None", "No technique proved", "no evidence-backed pattern")
    first = techniques[0]
    evidence = (getattr(dossier, "mitre_attack_evidence", None) or {}).get(first, [])
    detail = f"tied to {_plural(len(evidence), 'record')}"
    if len(techniques) > 1:
        detail += f" · +{len(techniques) - 1} more"
    return (first, TECHNIQUE_NAMES.get(first, first), detail)


def blast_radius(dossier: Any) -> tuple[str, str]:
    """(label, detail): how far the evidence reaches, from the audits in code.

    Account = nothing beyond the sign-ins; Apps = an app consent on the user;
    Roles = a role added TO the user (a role the user granted to someone else
    is not their blast radius).
    """
    upn = getattr(dossier, "user_principal_name", "")
    roles: list[str] = []
    apps: list[str] = []
    for audit in getattr(dossier, "directory_audits", None) or []:
        targets = audit.get("targetResources") or []
        is_target = any(
            t.get("type") == "User" and t.get("userPrincipalName") == upn for t in targets
        )
        if not is_target:
            continue
        activity = audit.get("activityDisplayName")
        if activity == "Add member to role":
            roles += [t.get("displayName", "a role") for t in targets if t.get("type") == "Role"]
        elif activity == "Consent to application":
            apps += [t.get("displayName", "an app") for t in targets if t.get("type") == "Application"]
    parts = []
    if roles:
        parts.append(f"{_plural(len(roles), 'role')} added: {', '.join(roles)}")
    if apps:
        parts.append(f"{_plural(len(apps), 'app consent')}: {', '.join(apps)}")
    label = "Roles" if roles else "Apps" if apps else "Account"
    return (label, "; ".join(parts) if parts else "No role, app or consent changes found")
