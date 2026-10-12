"""Checkpoint 1b — graph-field-check: every emitted Graph field is allowlisted.

The skill ``.agents/skills/graph-field-check/SKILL.md`` requires that every
field this project emits on a Graph-shaped record be confirmed on Microsoft
Learn and kept on an allowlist. A fixture record with a key that is not on
the allowlist fails these tests.

This is how the project caught ``riskyUser.riskEventTypes_v2``: that field
belongs to ``signIn``/``riskyUserHistoryItem``, not ``riskyUser``.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from itdr_agent.fixture_store import get_store

# --- Allowlists (confirmed on the Microsoft Learn pages below) --------------

SIGNIN_ALLOWLIST = {
    "id",
    "createdDateTime",
    "userDisplayName",
    "userPrincipalName",
    "appDisplayName",
    "ipAddress",
    "clientAppUsed",
    "correlationId",
    "conditionalAccessStatus",
    "riskDetail",
    "riskLevelAggregated",
    "riskLevelDuringSignIn",
    "riskState",
    "riskEventTypes_v2",
    "status",
    "deviceDetail",
    "mfaDetail",
    "location",
}

DEVICE_DETAIL_ALLOWLIST = {
    "deviceId",
    "displayName",
    "operatingSystem",
    "browser",
    "isCompliant",
    "isManaged",
    "trustType",
}

LOCATION_ALLOWLIST = {"city", "state", "countryOrRegion", "geoCoordinates"}
GEO_ALLOWLIST = {"latitude", "longitude"}
STATUS_ALLOWLIST = {"errorCode", "failureReason"}
MFADETAIL_ALLOWLIST = {"authDetail", "authMethod"}

AUDIT_ALLOWLIST = {
    "id",
    "activityDateTime",
    "activityDisplayName",
    "category",
    "correlationId",
    "initiatedBy",
    "targetResources",
    "result",
    "resultReason",
    "loggedByService",
}

TARGET_ALLOWLIST = {"id", "displayName", "type", "userPrincipalName", "modifiedProperties"}
INITIATED_BY_ALLOWLIST = {"user", "app"}

USER_ALLOWLIST = {
    "id",
    "userPrincipalName",
    "displayName",
    "department",
    "jobTitle",
    "manager",
    "hireDate",
    "accountEnabled",
}

# riskyUser has NO riskEventTypes_v2. That field is on signIn/HhistoryItem.
RISKY_USER_ALLOWLIST = {
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

ALERT_ALLOWLIST = {
    "id",
    "createdDateTime",
    "userPrincipalName",
    "appDisplayName",
    "ipAddress",
    "location",
    "riskLevelAggregated",
    "riskState",
    "riskEventTypes_v2",
    "status",
}

ALERT_FORBIDDEN = {"scenario", "expected_verdict", "expected_mitre", "is_benign"}

LEARN_URLS = {
    "signIn": "https://learn.microsoft.com/en-us/graph/api/resources/signin?view=graph-rest-1.0",
    "signInLocation": "https://learn.microsoft.com/en-us/graph/api/resources/signinlocation?view=graph-rest-1.0",
    "deviceDetail": "https://learn.microsoft.com/en-us/graph/api/resources/devicedetail?view=graph-rest-1.0",
    "directoryAudit": "https://learn.microsoft.com/en-us/graph/api/resources/directoryaudit?view=graph-rest-1.0",
    "user": "https://learn.microsoft.com/en-us/graph/api/resources/user?view=graph-rest-1.0",
    "riskyUser": "https://learn.microsoft.com/en-us/graph/api/resources/riskyuser?view=graph-rest-1.0",
    "mfaDetail": "https://learn.microsoft.com/en-us/graph/api/resources/mfadetail?view=graph-rest-beta",
}


def _keys(record: dict) -> set[str]:
    return set(record)


def test_signin_records_use_confirmed_fields():
    for event in get_store().sign_ins:
        assert _keys(event) <= SIGNIN_ALLOWLIST, (
            f"signIn has unconfirmed fields: {_keys(event) - SIGNIN_ALLOWLIST}"
        )
        assert _keys(event["deviceDetail"]) <= DEVICE_DETAIL_ALLOWLIST
        assert _keys(event["location"]) <= LOCATION_ALLOWLIST
        assert _keys(event["location"]["geoCoordinates"]) <= GEO_ALLOWLIST
        assert _keys(event["status"]) <= STATUS_ALLOWLIST
        if event.get("mfaDetail") is not None:
            assert _keys(event["mfaDetail"]) <= MFADETAIL_ALLOWLIST


def test_audit_records_use_confirmed_fields():
    for audit in get_store().directory_audits:
        assert _keys(audit) <= AUDIT_ALLOWLIST, (
            f"directoryAudit has unconfirmed fields: {_keys(audit) - AUDIT_ALLOWLIST}"
        )
        assert _keys(audit["initiatedBy"]) <= INITIATED_BY_ALLOWLIST
        for target in audit["targetResources"]:
            assert _keys(target) <= TARGET_ALLOWLIST


def test_user_records_use_confirmed_fields():
    for user in get_store().users:
        assert _keys(user) <= USER_ALLOWLIST, (
            f"user has unconfirmed fields: {_keys(user) - USER_ALLOWLIST}"
        )


def test_alert_records_use_confirmed_fields():
    for alert in get_store().alerts:
        assert _keys(alert) <= ALERT_ALLOWLIST, (
            f"alert has unconfirmed fields: {_keys(alert) - ALERT_ALLOWLIST}"
        )
        assert ALERT_FORBIDDEN.isdisjoint(alert), (
            f"alert leaked ground truth: {ALERT_FORBIDDEN & _keys(alert)}"
        )


def test_risky_user_report_uses_confirmed_fields():
    from itdr_agent.sim_api import get_risky_user_report

    report = get_risky_user_report("alice.traveler@contoso.com")
    assert report is not None
    assert _keys(report) <= RISKY_USER_ALLOWLIST, (
        f"riskyUser has unconfirmed fields: {_keys(report) - RISKY_USER_ALLOWLIST}"
    )
    assert "riskEventTypes_v2" not in report


def test_every_resource_has_a_confirmed_learn_url():
    required = {"signIn", "signInLocation", "deviceDetail", "directoryAudit", "user", "riskyUser", "mfaDetail"}
    assert required <= set(LEARN_URLS)
    for resource, url in LEARN_URLS.items():
        assert url.startswith("https://learn.microsoft.com/"), (
            f"{resource} has no Microsoft Learn source"
        )
