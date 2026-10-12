"""Checkpoint 3 — Simulated Microsoft Graph layer tests.

Red-green TDD: defines the contract for the simulation layer before the
implementation exists.

Rules under test:
  * Each endpoint returns Microsoft Graph-shaped payloads.
  * Unknown users/devices return None or empty lists, never a guess.
  * 429/500 errors happen only when a test injects them, never at random.
"""

from __future__ import annotations

import sys
from datetime import timedelta
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

KNOWN_UPN = "alice.traveler@contoso.com"
CONSENT_UPN = "dave.consent@contoso.com"
UNKNOWN_UPN = "nobody@contoso.com"
UNKNOWN_DEVICE = "00000000-0000-0000-0000-000000000000"

USER_FIELDS = {
    "id",
    "userPrincipalName",
    "displayName",
    "department",
    "jobTitle",
    "manager",
    "hireDate",
    "accountEnabled",
}

SIGNIN_FIELDS = {
    "id",
    "createdDateTime",
    "userPrincipalName",
    "riskEventTypes_v2",
    "riskLevelAggregated",
    "riskState",
    "status",
    "deviceDetail",
    "location",
}

DEVICE_FIELDS = {
    "deviceId",
    "displayName",
    "operatingSystem",
    "browser",
    "isCompliant",
    "isManaged",
    "trustType",
}

AUDIT_FIELDS = {
    "id",
    "activityDateTime",
    "activityDisplayName",
    "category",
    "initiatedBy",
    "targetResources",
    "result",
}

RISK_FIELDS = {
    "id",
    "userDisplayName",
    "userPrincipalName",
    "riskLevel",
    "riskState",
    "riskDetail",
    "riskLastUpdatedDateTime",
    "isDeleted",
    "isProcessing",
}


def _parse(ts: str):
    from datetime import datetime

    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


# --- get_user_profile ------------------------------------------------------


def test_user_profile_known_user():
    from itdr_agent.sim_api import get_user_profile

    profile = get_user_profile(KNOWN_UPN)
    assert profile is not None
    assert USER_FIELDS <= set(profile)
    assert profile["userPrincipalName"] == KNOWN_UPN


def test_user_profile_unknown_returns_none():
    from itdr_agent.sim_api import get_user_profile

    assert get_user_profile(UNKNOWN_UPN) is None


# --- get_sign_in_history ---------------------------------------------------


def test_sign_in_history_known_user_shape():
    from itdr_agent.sim_api import get_sign_in_history

    history = get_sign_in_history(KNOWN_UPN, hours=10_000)
    assert history, "known user should have sign-ins"
    for event in history:
        assert SIGNIN_FIELDS <= set(event)
        assert event["userPrincipalName"] == KNOWN_UPN
        assert isinstance(event["riskEventTypes_v2"], list)


def test_sign_in_history_filters_by_hours():
    from itdr_agent.fixture_store import get_store
    from itdr_agent.sim_api import get_sign_in_history

    full = get_sign_in_history(KNOWN_UPN, hours=10_000)
    recent = get_sign_in_history(KNOWN_UPN, hours=1)
    assert len(recent) <= len(full)
    cutoff = get_store().now - timedelta(hours=1)
    assert all(_parse(e["createdDateTime"]) >= cutoff for e in recent)
    assert any(_parse(e["createdDateTime"]) < cutoff for e in full), (
        "hours=10000 should include events older than the 1-hour window"
    )


def test_sign_in_history_unknown_returns_empty_list():
    from itdr_agent.sim_api import get_sign_in_history

    assert get_sign_in_history(UNKNOWN_UPN, hours=24) == []


# --- get_device_trust ------------------------------------------------------


def test_device_trust_known_device():
    from itdr_agent.sim_api import get_device_trust, get_sign_in_history

    device_id = get_sign_in_history(KNOWN_UPN, hours=10_000)[0]["deviceDetail"][
        "deviceId"
    ]
    device = get_device_trust(device_id)
    assert device is not None
    assert DEVICE_FIELDS <= set(device)
    assert device["deviceId"] == device_id


def test_device_trust_unknown_returns_none():
    from itdr_agent.sim_api import get_device_trust

    assert get_device_trust(UNKNOWN_DEVICE) is None


# --- get_directory_audits --------------------------------------------------


def test_directory_audits_known_user():
    from itdr_agent.sim_api import get_directory_audits

    audits = get_directory_audits(CONSENT_UPN, hours=10_000)
    assert audits, "consent user should have a directory audit"
    for audit in audits:
        assert AUDIT_FIELDS <= set(audit)
    names = {a["activityDisplayName"] for a in audits}
    assert "Consent to application" in names


def test_directory_audits_unknown_returns_empty_list():
    from itdr_agent.sim_api import get_directory_audits

    assert get_directory_audits(UNKNOWN_UPN, hours=24) == []


# --- get_risky_user_report -------------------------------------------------


def test_risky_user_report_known_user():
    from itdr_agent.sim_api import get_risky_user_report

    report = get_risky_user_report(KNOWN_UPN)
    assert report is not None
    assert RISK_FIELDS <= set(report)
    assert report["userPrincipalName"] == KNOWN_UPN
    assert report["riskLevel"] in {"low", "medium", "high"}
    assert report["riskState"] == "atRisk"
    # riskEventTypes_v2 belongs to signIn, not riskyUser (graph-field-check).
    assert "riskEventTypes_v2" not in report


def test_risky_user_report_unknown_returns_none():
    from itdr_agent.sim_api import get_risky_user_report

    assert get_risky_user_report(UNKNOWN_UPN) is None


# --- Deterministic error injection -----------------------------------------


def test_injected_429_raises():
    from itdr_agent.sim_api import SimulatedGraphError, get_user_profile

    with pytest.raises(SimulatedGraphError) as excinfo:
        get_user_profile(KNOWN_UPN, injected_error="429")
    assert excinfo.value.status_code == 429


def test_injected_500_raises():
    from itdr_agent.sim_api import SimulatedGraphError, get_sign_in_history

    with pytest.raises(SimulatedGraphError) as excinfo:
        get_sign_in_history(KNOWN_UPN, hours=24, injected_error="500")
    assert excinfo.value.status_code == 500


def test_every_endpoint_honours_injection():
    from itdr_agent import sim_api

    calls = [
        lambda: sim_api.get_user_profile(KNOWN_UPN, injected_error="429"),
        lambda: sim_api.get_sign_in_history(KNOWN_UPN, 24, injected_error="429"),
        lambda: sim_api.get_device_trust(UNKNOWN_DEVICE, injected_error="429"),
        lambda: sim_api.get_directory_audits(KNOWN_UPN, 24, injected_error="429"),
        lambda: sim_api.get_risky_user_report(KNOWN_UPN, injected_error="429"),
    ]
    for call in calls:
        with pytest.raises(sim_api.SimulatedGraphError) as excinfo:
            call()
        assert excinfo.value.status_code == 429


def test_no_errors_without_injection():
    """Without injection, calls are deterministic and never raise."""
    from itdr_agent import sim_api

    for _ in range(25):
        assert sim_api.get_user_profile(KNOWN_UPN) is not None
        assert sim_api.get_sign_in_history(KNOWN_UPN, hours=10_000)
        assert sim_api.get_directory_audits(CONSENT_UPN, hours=10_000)
        assert sim_api.get_risky_user_report(KNOWN_UPN) is not None
