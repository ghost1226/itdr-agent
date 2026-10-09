"""Checkpoint 1 — Synthetic data generator tests.

Red-green TDD: these tests define the contract for the synthetic
Microsoft Entra ID dataset before the generator exists.

All data is synthetic. Nothing here touches real logs or tenants.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# --- Schema contracts ------------------------------------------------------

SIGNIN_REQUIRED = {
    "id": str,
    "createdDateTime": str,
    "userDisplayName": str,
    "userPrincipalName": str,
    "appDisplayName": str,
    "ipAddress": str,
    "location": dict,
    "status": dict,
    "riskState": str,
    "riskLevel": str,
    "riskEventTypes": list,
    "conditionalAccessStatus": str,
    "deviceDetail": dict,
    "clientAppUsed": str,
    "correlationId": str,
}

LOCATION_REQUIRED = {
    "city": str,
    "state": str,
    "countryOrRegion": str,
    "geoCoordinates": dict,
}

GEO_REQUIRED = {"latitude": float, "longitude": float}

STATUS_REQUIRED = {"errorCode": int, "failureReason": str}

DEVICE_REQUIRED = {
    "deviceId": str,
    "displayName": str,
    "operatingSystem": str,
    "browser": str,
    "isCompliant": bool,
    "isManaged": bool,
    "trustType": str,
}

AUDIT_REQUIRED = {
    "id": str,
    "activityDateTime": str,
    "activityDisplayName": str,
    "category": str,
    "correlationId": str,
    "initiatedBy": dict,
    "targetResources": list,
    "result": str,
    "resultReason": str,
    "loggedByService": str,
}

TARGET_RESOURCE_REQUIRED = {"id": str, "displayName": str, "type": str}

USER_REQUIRED = {
    "id": str,
    "userPrincipalName": str,
    "displayName": str,
    "department": str,
    "jobTitle": str,
    "manager": str,
    "hireDate": str,
    "accountEnabled": bool,
}

ALERT_REQUIRED = {
    "id": str,
    "createdDateTime": str,
    "userPrincipalName": str,
    "appDisplayName": str,
    "ipAddress": str,
    "location": dict,
    "riskLevel": str,
    "riskState": str,
    "riskEventTypes": list,
    "status": dict,
    "scenario": str,
}

# Five planted MITRE ATT&CK patterns.
SCENARIOS = {
    "impossible_travel": "T1078",
    "mfa_fatigue": "T1621",
    "anonymous_ip": "T1090",
    "app_consent": "T1550.001",
    "privilege_escalation": "T1098",
}


def _assert_shape(record: dict, required: dict, label: str) -> None:
    for field, expected_type in required.items():
        assert field in record, f"{label} missing field {field!r}"
        assert isinstance(record[field], expected_type), (
            f"{label}.{field} expected {expected_type.__name__}, "
            f"got {type(record[field]).__name__}"
        )


# --- Fixture / dataset fixture --------------------------------------------


@pytest.fixture(scope="module")
def dataset():
    from itdr_agent import data_generator

    return data_generator.generate_dataset(seed=1337)


@pytest.fixture(scope="module")
def scenario_upns():
    from itdr_agent import data_generator

    return data_generator.SCENARIO_UPNS


# --- Users ----------------------------------------------------------------


def test_users_have_required_fields(dataset):
    users = dataset["users"]
    assert len(users) >= 20, "expected a realistic tenant population"
    for user in users:
        _assert_shape(user, USER_REQUIRED, "user")


def test_users_are_unique(dataset):
    upns = [u["userPrincipalName"] for u in dataset["users"]]
    assert len(upns) == len(set(upns)), "UPNs must be unique"


# --- Sign-in logs ---------------------------------------------------------


def test_signins_have_required_schema(dataset):
    sign_ins = dataset["sign_ins"]
    assert len(sign_ins) >= 100, "plan requires >=100 sign-in records"
    for event in sign_ins:
        _assert_shape(event, SIGNIN_REQUIRED, "signin")
        _assert_shape(event["location"], LOCATION_REQUIRED, "signin.location")
        _assert_shape(
            event["location"]["geoCoordinates"], GEO_REQUIRED, "signin.geo"
        )
        _assert_shape(event["status"], STATUS_REQUIRED, "signin.status")
        _assert_shape(event["deviceDetail"], DEVICE_REQUIRED, "signin.device")
        # createdDateTime must be a parseable ISO-8601 timestamp.
        datetime.fromisoformat(event["createdDateTime"].replace("Z", "+00:00"))


def test_signins_reference_known_users(dataset):
    known = {u["userPrincipalName"] for u in dataset["users"]}
    for event in dataset["sign_ins"]:
        assert event["userPrincipalName"] in known


# --- Directory audits -----------------------------------------------------


def test_directory_audits_have_required_schema(dataset):
    audits = dataset["directory_audits"]
    assert len(audits) >= 50, "plan requires >=50 directory audit records"
    for audit in audits:
        _assert_shape(audit, AUDIT_REQUIRED, "audit")
        assert audit["targetResources"], "audit must target something"
        for target in audit["targetResources"]:
            _assert_shape(target, TARGET_RESOURCE_REQUIRED, "audit.target")
        datetime.fromisoformat(
            audit["activityDateTime"].replace("Z", "+00:00")
        )


# --- Determinism ----------------------------------------------------------


def test_generation_is_deterministic():
    from itdr_agent import data_generator

    first = data_generator.generate_dataset(seed=7)
    second = data_generator.generate_dataset(seed=7)
    assert first == second


def test_different_seeds_differ():
    from itdr_agent import data_generator

    a = data_generator.generate_dataset(seed=7)
    b = data_generator.generate_dataset(seed=8)
    assert a != b


# --- Planted MITRE ATT&CK patterns ----------------------------------------


def test_all_five_scenarios_are_present(dataset, scenario_upns):
    assert set(scenario_upns) == set(SCENARIOS), "expected exactly five scenarios"
    known = {u["userPrincipalName"] for u in dataset["users"]}
    for scenario, upn in scenario_upns.items():
        assert upn in known, f"scenario user {upn} missing from users"


def test_impossible_travel_pattern(dataset, scenario_upns):
    upn = scenario_upns["impossible_travel"]
    events = [e for e in dataset["sign_ins"] if e["userPrincipalName"] == upn]
    travel = [
        e for e in events if "impossibleTravel" in e["riskEventTypes"]
    ]
    assert len(travel) >= 2, "expected two impossible-travel sign-ins"
    travel.sort(key=lambda e: e["createdDateTime"])
    first, second = travel[0], travel[1]
    assert first["location"]["countryOrRegion"] != second["location"]["countryOrRegion"]
    t1 = datetime.fromisoformat(first["createdDateTime"].replace("Z", "+00:00"))
    t2 = datetime.fromisoformat(second["createdDateTime"].replace("Z", "+00:00"))
    assert abs((t2 - t1).total_seconds()) <= 60 * 60, "travel must be within an hour"


def test_mfa_fatigue_pattern(dataset, scenario_upns):
    upn = scenario_upns["mfa_fatigue"]
    events = [
        e for e in dataset["sign_ins"] if e["userPrincipalName"] == upn
    ]
    events.sort(key=lambda e: e["createdDateTime"])
    failures = [
        e for e in events if "MFA" in e["status"]["failureReason"]
    ]
    assert len(failures) >= 3, "expected repeated MFA failures"
    # A successful sign-in follows the fatigue burst.
    last_failure_time = failures[-1]["createdDateTime"]
    successes = [
        e
        for e in events
        if e["status"]["errorCode"] == 0
        and e["createdDateTime"] > last_failure_time
    ]
    assert successes, "expected a success after the MFA fatigue burst"


def test_anonymous_ip_pattern(dataset, scenario_upns):
    upn = scenario_upns["anonymous_ip"]
    events = [e for e in dataset["sign_ins"] if e["userPrincipalName"] == upn]
    anon = [e for e in events if "anonymizedIPAddress" in e["riskEventTypes"]]
    assert anon, "expected an anonymizing-proxy sign-in"
    assert any(e["riskLevel"] in {"medium", "high"} for e in anon)


def test_app_consent_after_foreign_signin_pattern(dataset, scenario_upns):
    upn = scenario_upns["app_consent"]
    sign_ins = [
        e
        for e in dataset["sign_ins"]
        if e["userPrincipalName"] == upn
        and "unfamiliarFeatures" in e["riskEventTypes"]
    ]
    assert sign_ins, "expected an anomalous foreign sign-in"
    anomalous_time = max(e["createdDateTime"] for e in sign_ins)
    consents = [
        a
        for a in dataset["directory_audits"]
        if a["activityDisplayName"] == "Consent to application"
        and upn in json.dumps(a["targetResources"])
    ]
    assert consents, "expected an app-consent audit"
    assert any(a["activityDateTime"] >= anomalous_time for a in consents), (
        "app consent must follow the foreign sign-in"
    )


def test_privilege_escalation_pattern(dataset, scenario_upns):
    upn = scenario_upns["privilege_escalation"]
    escalations = [
        a
        for a in dataset["directory_audits"]
        if a["activityDisplayName"] == "Add member to role"
        and "Global Administrator" in json.dumps(a["targetResources"])
        and upn in json.dumps(a["targetResources"])
    ]
    assert escalations, "expected a role-assignment escalation audit"


# --- Alerts ---------------------------------------------------------------


def test_alerts_have_required_schema(dataset):
    alerts = dataset["alerts"]
    assert len(alerts) == len(SCENARIOS)
    ids = {a["id"] for a in alerts}
    assert "ALERT_001" in ids
    for alert in alerts:
        _assert_shape(alert, ALERT_REQUIRED, "alert")
        assert alert["scenario"] in SCENARIOS
        _assert_shape(alert["location"], LOCATION_REQUIRED, "alert.location")
        _assert_shape(alert["status"], STATUS_REQUIRED, "alert.status")


# --- Persistence ----------------------------------------------------------


def test_write_fixtures_creates_jsonl(tmp_path):
    from itdr_agent import data_generator

    data_generator.write_fixtures(tmp_path, seed=1337)
    for name in ("users", "sign_ins", "directory_audits", "alerts"):
        path = tmp_path / f"{name}.jsonl"
        assert path.exists(), f"missing fixture {path}"
        lines = [
            json.loads(line)
            for line in path.read_text().splitlines()
            if line.strip()
        ]
        assert lines, f"fixture {path} is empty"
        # Every line must be valid JSON with an id and userPrincipalName where relevant.
        for record in lines:
            assert "id" in record
