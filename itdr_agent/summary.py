"""GUI batch 1 — pure alert summaries (no model, no network).

Every function here reads only fields from
``data_generator.ALERT_FIELD_ALLOWLIST``. Ground truth (``scenario`` /
``expected_verdict`` / ``expected_mitre`` / ``is_benign``) and the source IP
address are never read, so a summary cannot leak the answer key or an address.

The functions are deliberately deterministic and side-effect free so they can
be unit-tested and reused by the CLI and the GUI.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta
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


# --- GUI rebuild checkpoint 3: the evidence tree ----------------------------

BURST_HOURS = 1  # a sign-in within an hour either side of the alert is "burst"


def _ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _device_label(event: dict[str, Any]) -> str:
    device = event.get("deviceDetail") or {}
    name = device.get("displayName") or "unknown device"
    os_name = device.get("operatingSystem")
    return f"{name} ({os_name})" if os_name else name


def _outcome(event: dict[str, Any]) -> str:
    status = event.get("status") or {}
    code = status.get("errorCode", 0)
    if code == 0:
        return "Success"
    if "MFA" in (status.get("failureReason") or ""):
        return "MFA denied"
    return f"Failed: {status.get('failureReason') or 'unknown reason'}"


def _place_of(events: list[dict[str, Any]]) -> str:
    places = Counter(_place(e) for e in events if e.get("location"))
    return places.most_common(1)[0][0] if places else "unknown place"


def _span(events: list[dict[str, Any]], key: str) -> str:
    stamps = sorted(_ts(e[key]) for e in events if e.get(key))
    if not stamps:
        return ""
    first, last = stamps[0], stamps[-1]
    if first.date() == last.date():
        return f"{first:%b %-d}, {first:%H:%M} to {last:%H:%M}"
    return f"{first:%b %-d} to {last:%b %-d}"


def evidence_tree(alert: dict[str, Any], dossier: Any) -> dict[str, Any]:
    """The evidence as a tree the page draws: user, baseline, burst, rows, audits.

    Code only, from the dossier; never the IP; the rows behind a technique in
    ``mitre_attack_evidence`` carry its id so the page can light them.
    """
    upn = alert.get("userPrincipalName", "")
    profile = getattr(dossier, "user_profile", None) or {}
    title = " · ".join(p for p in (profile.get("jobTitle"), profile.get("department")) if p)
    sign_ins = sorted(
        getattr(dossier, "sign_in_history", None) or [], key=lambda e: e["createdDateTime"]
    )
    audits = getattr(dossier, "directory_audits", None) or []
    evidence = getattr(dossier, "mitre_attack_evidence", None) or {}
    lit = {rid: technique for technique, ids in evidence.items() for rid in ids}

    alert_time = _ts(alert["createdDateTime"]) if alert.get("createdDateTime") else None
    window = timedelta(hours=BURST_HOURS)
    burst = [
        e for e in sign_ins
        if alert_time is not None and abs(_ts(e["createdDateTime"]) - alert_time) <= window
    ]
    baseline = [e for e in sign_ins if e not in burst]

    rows = [
        {
            "id": e.get("id", ""),
            "ts": e["createdDateTime"],
            "time": f"{_ts(e['createdDateTime']):%H:%M}",
            "app": e.get("appDisplayName") or "",
            "device": _device_label(e),
            "outcome": _outcome(e),
            "technique": lit.get(e.get("id", "")),
        }
        for e in burst
    ]
    label, detail = blast_radius(dossier)
    audit_detail = (
        detail if label != "Account" else "no roles, apps or consents touched"
    )
    times = sorted(
        [e["createdDateTime"] for e in sign_ins] + [a["activityDateTime"] for a in audits]
    )
    return {
        "user": {"upn": upn, "title": title},
        "baseline": {
            "count": len(baseline),
            "place": _place_of(baseline) if baseline else "",
            "devices": sorted({_device_label(e) for e in baseline}),
            "apps": sorted({e.get("appDisplayName") or "" for e in baseline} - {""}),
            "span": _span(baseline, "createdDateTime"),
        },
        "burst": {
            "count": len(burst),
            "place": _place_of(burst) if burst else "",
            "device_count": len({(e.get("deviceDetail") or {}).get("deviceId") for e in burst}),
            "span": _span(burst, "createdDateTime"),
        },
        "rows": rows,
        "audits": {"count": len(audits), "detail": audit_detail},
        "times": times,
    }


# --- GUI rebuild checkpoint 4: tool results in plain words -------------------

TOOL_LABELS: dict[str, str] = {
    "get_user_profile": "Checked the user's profile",
    "get_sign_in_history": "Pulled the sign-in history",
    "get_device_trust": "Checked the device's trust",
    "get_directory_audits": "Pulled the directory audits",
    "get_risky_user_report": "Checked the risky-user report",
}


def describe_tool_result(name: str, result: Any) -> str:
    """One short line about what a tool returned. Never the IP."""
    if name == "get_user_profile":
        if not result:
            return "no such user"
        parts = [result.get("jobTitle"), result.get("department")]
        return ", ".join(p for p in parts if p) or "profile found"
    if name == "get_sign_in_history":
        events = result or []
        if not events:
            return "no sign-ins"
        denied = sum(
            1 for e in events
            if (e.get("status") or {}).get("errorCode", 0)
            and "MFA" in ((e.get("status") or {}).get("failureReason") or "")
        )
        text = _plural(len(events), "sign-in")
        return f"{text}, {denied} MFA denied" if denied else text
    if name == "get_device_trust":
        if not result:
            return "unknown device"
        name_ = result.get("displayName") or "device"
        os_name = result.get("operatingSystem")
        label = f"{name_} ({os_name})" if os_name else name_
        return f"{label}, {'managed' if result.get('isManaged') else 'unmanaged'}"
    if name == "get_directory_audits":
        audits = result or []
        if not audits:
            return "0 changes"
        kinds = sorted({a.get("activityDisplayName") or "change" for a in audits})
        return f"{_plural(len(audits), 'change')}: {', '.join(kinds)}"
    if name == "get_risky_user_report":
        if not result:
            return "no risk report"
        return f"risk {result.get('riskLevel', 'none')}, {result.get('riskState', 'none')}"
    return "done"


# --- GUI rebuild checkpoint 7: evidence you can read ------------------------


def _stamp(iso: str) -> str:
    return iso.replace("T", " ")[:16] + "Z" if len(iso) >= 16 else iso


def evidence_detail(dossier: Any, technique: str) -> list[str]:
    """One readable line per evidence record behind a technique (never the IP).

    Sign-in: time · app · place · device · id. Audit: time · activity ·
    role/app · id. The id comes last so it can still be checked in the logs.
    """
    ids = (getattr(dossier, "mitre_attack_evidence", None) or {}).get(technique, [])
    if not ids:
        return []
    sign_ins = {e.get("id"): e for e in getattr(dossier, "sign_in_history", None) or []}
    audits = {a.get("id"): a for a in getattr(dossier, "directory_audits", None) or []}
    lines: list[str] = []
    for rid in ids:
        if rid in sign_ins:
            e = sign_ins[rid]
            lines.append(" · ".join([
                _stamp(e.get("createdDateTime") or ""),
                e.get("appDisplayName") or "unknown app",
                _place(e),
                _device_label(e),
                rid,
            ]))
        elif rid in audits:
            a = audits[rid]
            targets = [t.get("displayName") for t in a.get("targetResources") or []
                       if t.get("type") in ("Role", "Application") and t.get("displayName")]
            lines.append(" · ".join(p for p in [
                _stamp(a.get("activityDateTime") or ""),
                a.get("activityDisplayName") or "directory change",
                ", ".join(targets),
                rid,
            ] if p))
        else:
            lines.append(f"record {rid} (not in the dossier)")
    return lines
