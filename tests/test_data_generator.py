"""Checkpoint 1 / 1b — Synthetic data generator tests.

Red-green TDD: these tests define the contract for the synthetic
Microsoft Entra ID dataset before the generator exists.

Checkpoint 1b adds:
  * three benign (false-positive) scenarios and one thin-data alert;
  * a separate ground-truth file so labels never enter ``alerts.jsonl``;
  * a field allowlist for alert records (graph-field-check).

All data is synthetic. Nothing here touches real logs or tenants.

Graph schema references (field names follow Microsoft's published shapes):
  * signIn resource (v1.0): riskEventTypes_v2, riskDetail,
    riskLevelAggregated, riskLevelDuringSignIn, status, deviceDetail,
    signInLocation, clientAppUsed, conditionalAccessStatus.
    https://learn.microsoft.com/en-us/graph/api/resources/signin?view=graph-rest-1.0
  * mfaDetail is a beta signIn field.
    https://learn.microsoft.com/en-us/graph/api/resources/mfadetail?view=graph-rest-beta
  * directoryAudit resource (v1.0): activityDateTime, activityDisplayName,
    category, correlationId, initiatedBy, targetResources, result,
    resultReason, loggedByService.
    https://learn.microsoft.com/en-us/graph/api/resources/directoryaudit?view=graph-rest-1.0
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
    "clientAppUsed": str,
    "correlationId": str,
    "conditionalAccessStatus": str,
    "riskDetail": str,
    "riskLevelAggregated": str,
    "riskLevelDuringSignIn": str,
    "riskState": str,
    "riskEventTypes_v2": list,
    "status": dict,
    "deviceDetail": dict,
    "location": dict,
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

# Checkpoint 1b: alerts are Graph-shaped only. No scenario, no labels.
ALERT_REQUIRED = {
    "id": str,
    "createdDateTime": str,
    "userPrincipalName": str,
    "appDisplayName": str,
    "ipAddress": str,
    "location": dict,
    "riskLevelAggregated": str,
    "riskState": str,
    "riskEventTypes_v2": list,
    "status": dict,
}

ALERT_FORBIDDEN = {"scenario", "expected_verdict", "expected_mitre", "is_benign"}

GROUND_TRUTH_REQUIRED = {
    "alert_id": str,
    "scenario": str,
    "expected_verdict": str,
    "expected_mitre": list,
    "is_benign": bool,
}

VALID_VERDICTS = {"COMPROMISED", "SUSPICIOUS", "FALSE_POSITIVE", "INSUFFICIENT_DATA"}

# Every user/email must live in the synthetic domain.
SYNTHETIC_DOMAIN = "contoso.com"

# Five planted MITRE ATT&CK patterns and their expected technique IDs.
# (Checkpoint 5 upgrades impossible_travel to T1078.004.)
MITRE_EXPECTED = {
    "impossible_travel": "T1078",
    "mfa_fatigue": "T1621",
    "anonymous_ip": "T1090.003",
    "app_consent": "T1528",
    "privilege_escalation": "T1098.003",
}

ATTACK_SCENARIOS = list(MITRE_EXPECTED)
BENIGN_SCENARIOS = ["benign_travel", "benign_admin_role", "benign_vpn"]
ALL_SCENARIOS = ATTACK_SCENARIOS + BENIGN_SCENARIOS
ALERT_COUNT = 10

BENIGN_TRAVEL_IP_1 = "203.0.113.50"
BENIGN_TRAVEL_IP_2 = "203.0.113.51"


def _assert_shape(record: dict, required: dict, label: str) -> None:
    for field, expected_type in required.items():
        assert field in record, f"{label} missing field {field!r}"
        assert isinstance(record[field], expected_type), (
            f"{label}.{field} expected {expected_type.__name__}, "
            f"got {type(record[field]).__name__}"
        )


# --- Fixtures --------------------------------------------------------------


@pytest.fixture(scope="module")
def dataset():
    from itdr_agent import data_generator

    return data_generator.generate_dataset(seed=1337)


@pytest.fixture(scope="module")
def scenario_upns():
    from itdr_agent import data_generator

    return data_generator.SCENARIO_UPNS


@pytest.fixture(scope="module")
def ground_truth_by_id(dataset):
    return {entry["alert_id"]: entry for entry in dataset["ground_truth"]}


@pytest.fixture(scope="module")
def ground_truth_by_scenario(dataset):
    return {entry["scenario"]: entry for entry in dataset["ground_truth"]}


@pytest.fixture(scope="module")
def alerts_by_scenario(dataset, ground_truth_by_id):
    return {
        ground_truth_by_id[alert["id"]]["scenario"]: alert
        for alert in dataset["alerts"]
    }


# --- Users -----------------------------------------------------------------


def test_users_have_required_fields(dataset):
    users = dataset["users"]
    assert len(users) >= 20, "expected a realistic tenant population"
    for user in users:
        _assert_shape(user, USER_REQUIRED, "user")


def test_users_are_unique(dataset):
    upns = [u["userPrincipalName"] for u in dataset["users"]]
    assert len(upns) == len(set(upns)), "UPNs must be unique"


# --- Sign-in logs ----------------------------------------------------------


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
        datetime.fromisoformat(event["createdDateTime"].replace("Z", "+00:00"))


def test_signins_reference_known_users(dataset):
    known = {u["userPrincipalName"] for u in dataset["users"]}
    for event in dataset["sign_ins"]:
        assert event["userPrincipalName"] in known


# --- Directory audits ------------------------------------------------------


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


# --- Synthetic domain ------------------------------------------------------


def _upn_fields(record: dict):
    for key, value in record.items():
        if "PrincipalName" in key and isinstance(value, str):
            yield key, value
        elif key == "targetResources" and isinstance(value, list):
            for target in value:
                if "userPrincipalName" in target:
                    yield "targetResources.userPrincipalName", target[
                        "userPrincipalName"
                    ]


def test_every_user_and_email_uses_the_synthetic_domain(dataset):
    saw_a_upn = False
    for group in ("users", "sign_ins", "directory_audits", "alerts"):
        for record in dataset[group]:
            for key, value in _upn_fields(record):
                saw_a_upn = True
                assert value.endswith(f"@{SYNTHETIC_DOMAIN}"), (
                    f"{group}.{key} leaks non-synthetic domain: {value!r}"
                )
    assert saw_a_upn, "no userPrincipalName fields were found to check"


def test_no_non_synthetic_domains_appear_anywhere(dataset):
    blob = json.dumps(dataset)
    # Common Faker / example domains must never appear.
    for leak in ("@example.com", "@example.org", "@gmail.com", "@contoso.onmicrosoft.com"):
        assert leak not in blob, f"synthetic data leaked {leak}"


# --- Determinism -----------------------------------------------------------


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


def test_same_seed_is_byte_identical(tmp_path):
    from itdr_agent import data_generator

    first = tmp_path / "first"
    second = tmp_path / "second"
    data_generator.write_fixtures(first, seed=42)
    data_generator.write_fixtures(second, seed=42)
    for name in ("users", "sign_ins", "directory_audits", "alerts", "ground_truth"):
        a = (first / f"{name}.jsonl").read_bytes()
        b = (second / f"{name}.jsonl").read_bytes()
        assert a == b, f"{name}.jsonl differs between identical seeds"


def test_different_seeds_produce_different_bytes(tmp_path):
    from itdr_agent import data_generator

    first = tmp_path / "first"
    second = tmp_path / "second"
    data_generator.write_fixtures(first, seed=42)
    data_generator.write_fixtures(second, seed=43)
    assert (first / "sign_ins.jsonl").read_bytes() != (
        second / "sign_ins.jsonl"
    ).read_bytes()


# --- Planted MITRE ATT&CK patterns ----------------------------------------


def test_all_scenarios_are_present(dataset, scenario_upns):
    from itdr_agent import data_generator

    assert set(scenario_upns) == set(ALL_SCENARIOS), (
        "expected five attack and three benign scenarios"
    )
    known = {u["userPrincipalName"] for u in dataset["users"]}
    for scenario, upn in scenario_upns.items():
        assert upn in known, f"scenario user {upn} missing from users"
    for scenario, technique in MITRE_EXPECTED.items():
        assert (
            data_generator.SCENARIO_TECHNIQUES[scenario]
            == technique
        ), f"{scenario} maps to the wrong MITRE technique"


def test_impossible_travel_pattern(dataset, scenario_upns):
    from itdr_agent import data_generator

    scenario = "impossible_travel"
    assert data_generator.SCENARIO_TECHNIQUES[scenario] == "T1078"
    upn = scenario_upns[scenario]
    events = [e for e in dataset["sign_ins"] if e["userPrincipalName"] == upn]
    travel = [
        e for e in events if "unlikelyTravel" in e["riskEventTypes_v2"]
    ]
    assert len(travel) >= 2, "expected two unlikely-travel sign-ins"
    travel.sort(key=lambda e: e["createdDateTime"])
    first, second = travel[0], travel[1]
    assert first["location"]["countryOrRegion"] != second["location"]["countryOrRegion"]
    t1 = datetime.fromisoformat(first["createdDateTime"].replace("Z", "+00:00"))
    t2 = datetime.fromisoformat(second["createdDateTime"].replace("Z", "+00:00"))
    assert abs((t2 - t1).total_seconds()) <= 60 * 60, "travel must be within an hour"


def test_mfa_fatigue_pattern(dataset, scenario_upns):
    from itdr_agent import data_generator

    scenario = "mfa_fatigue"
    assert data_generator.SCENARIO_TECHNIQUES[scenario] == "T1621"
    upn = scenario_upns[scenario]
    events = [e for e in dataset["sign_ins"] if e["userPrincipalName"] == upn]
    events.sort(key=lambda e: e["createdDateTime"])
    failures = [e for e in events if "MFA" in e["status"]["failureReason"]]
    assert len(failures) >= 3, "expected repeated MFA failures"
    last_failure_time = failures[-1]["createdDateTime"]
    successes = [
        e
        for e in events
        if e["status"]["errorCode"] == 0 and e["createdDateTime"] > last_failure_time
    ]
    assert successes, "expected a success after the MFA fatigue burst"


def test_anonymous_ip_pattern(dataset, scenario_upns):
    from itdr_agent import data_generator

    scenario = "anonymous_ip"
    assert data_generator.SCENARIO_TECHNIQUES[scenario] == "T1090.003"
    upn = scenario_upns[scenario]
    events = [e for e in dataset["sign_ins"] if e["userPrincipalName"] == upn]
    anon = [e for e in events if "anonymizedIPAddress" in e["riskEventTypes_v2"]]
    assert anon, "expected an anonymizing-proxy sign-in in riskEventTypes_v2"
    assert any(e["riskLevelAggregated"] in {"medium", "high"} for e in anon)


def test_app_consent_after_foreign_signin_pattern(dataset, scenario_upns):
    from itdr_agent import data_generator

    scenario = "app_consent"
    assert data_generator.SCENARIO_TECHNIQUES[scenario] == "T1528"
    upn = scenario_upns[scenario]
    sign_ins = [
        e
        for e in dataset["sign_ins"]
        if e["userPrincipalName"] == upn
        and "unfamiliarFeatures" in e["riskEventTypes_v2"]
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
    from itdr_agent import data_generator

    scenario = "privilege_escalation"
    assert data_generator.SCENARIO_TECHNIQUES[scenario] == "T1098.003"
    upn = scenario_upns[scenario]
    escalations = [
        a
        for a in dataset["directory_audits"]
        if a["activityDisplayName"] == "Add member to role"
        and "Global Administrator" in json.dumps(a["targetResources"])
        and upn in json.dumps(a["targetResources"])
    ]
    assert escalations, "expected a role-assignment escalation audit"


# --- Checkpoint 1b: benign (false-positive) scenarios ---------------------


def test_benign_travel_pattern(dataset, scenario_upns, alerts_by_scenario):
    upn = scenario_upns["benign_travel"]
    events = [e for e in dataset["sign_ins"] if e["userPrincipalName"] == upn]
    travel = [
        e
        for e in events
        if e["ipAddress"] in {BENIGN_TRAVEL_IP_1, BENIGN_TRAVEL_IP_2}
    ]
    assert len(travel) == 2, "expected two dedicated benign-travel sign-ins"
    devices = {e["deviceDetail"]["deviceId"] for e in travel}
    assert len(devices) == 1, "benign travel must use the same known device"
    for event in travel:
        assert event["deviceDetail"]["isCompliant"] is True
        assert event["deviceDetail"]["isManaged"] is True
        assert event["riskEventTypes_v2"] == []
        assert event["riskState"] == "none"
    assert (
        travel[0]["location"]["countryOrRegion"]
        != travel[1]["location"]["countryOrRegion"]
    ), "benign travel is still travel across countries"
    assert alerts_by_scenario["benign_travel"]["userPrincipalName"] == upn


def test_benign_admin_role_pattern(dataset, scenario_upns, ground_truth_by_scenario):
    from itdr_agent import data_generator

    upn = scenario_upns["benign_admin_role"]
    role_adds = [
        a
        for a in dataset["directory_audits"]
        if a["activityDisplayName"] == "Add member to role"
        and upn in json.dumps(a["targetResources"])
    ]
    assert role_adds, "expected the ticket-backed admin role add"
    audit = role_adds[-1]
    assert "HD-1042" in audit["resultReason"], "the expected role add cites its ticket"
    initiator = audit["initiatedBy"]["user"]["userPrincipalName"]
    assert initiator in data_generator.ADMIN_UPNS
    assert initiator != upn, "the investigated user is the target, not the initiator"
    assert ground_truth_by_scenario["benign_admin_role"]["expected_mitre"] == [
        "T1098.003"
    ]


def test_benign_vpn_pattern(dataset, scenario_upns):
    from itdr_agent import data_generator

    upn = scenario_upns["benign_vpn"]
    events = [e for e in dataset["sign_ins"] if e["userPrincipalName"] == upn]
    vpn = [e for e in events if e["ipAddress"] in data_generator.KNOWN_VPN_EGRESS_IPS]
    assert vpn, "expected sign-ins from the known company VPN egress"
    for event in vpn:
        assert event["deviceDetail"]["isCompliant"] is True
        assert event["riskEventTypes_v2"] == []
        assert event["riskState"] == "none"


# --- Checkpoint 1b: thin-data and unknown alerts --------------------------


def test_thin_data_alert_is_sparse_but_not_critical(
    dataset, ground_truth_by_scenario
):
    from itdr_agent import data_generator
    from itdr_agent.schemas import InvestigatorOutput

    entry = ground_truth_by_scenario["thin_data"]
    assert entry["expected_verdict"] == "INSUFFICIENT_DATA"
    assert entry["expected_mitre"] == []

    upn = data_generator.THIN_DATA_UPN
    events = [e for e in dataset["sign_ins"] if e["userPrincipalName"] == upn]
    assert 1 <= len(events) <= 2, "thin data is 1-2 sign-ins"

    audits = [
        a
        for a in dataset["directory_audits"]
        if upn in json.dumps(a.get("targetResources", []))
        or a.get("initiatedBy", {}).get("user", {}).get("userPrincipalName") == upn
    ]
    assert audits == [], "thin-data user must have no directory audits"

    profile = next(u for u in dataset["users"] if u["userPrincipalName"] == upn)
    dossier = InvestigatorOutput(
        alert_id=entry["alert_id"],
        user_principal_name=upn,
        user_profile=profile,
        sign_in_history=events,
    )
    assert dossier.is_critical_gap is False

    alert = next(a for a in dataset["alerts"] if a["id"] == entry["alert_id"])
    assert alert["userPrincipalName"] == upn


def test_unknown_alert_user_is_not_in_users(dataset, ground_truth_by_scenario):
    from itdr_agent import data_generator

    entry = ground_truth_by_scenario["unknown"]
    assert entry["expected_verdict"] == "INSUFFICIENT_DATA"
    assert entry["expected_mitre"] == []
    alert = next(a for a in dataset["alerts"] if a["id"] == entry["alert_id"])
    known = {u["userPrincipalName"] for u in dataset["users"]}
    assert alert["userPrincipalName"] == data_generator.UNKNOWN_ALERT_UPN
    assert alert["userPrincipalName"] not in known


# --- Checkpoint 1b: ground truth is separate from the alert ----------------


def test_alerts_carry_no_ground_truth(dataset):
    from itdr_agent import data_generator

    allow = set(data_generator.ALERT_FIELD_ALLOWLIST)
    for alert in dataset["alerts"]:
        assert ALERT_FORBIDDEN.isdisjoint(set(alert)), (
            f"alert {alert['id']} leaked {ALERT_FORBIDDEN & set(alert)}"
        )
        assert set(alert) <= allow, (
            f"alert {alert['id']} has non-allowlisted fields: {set(alert) - allow}"
        )


def test_ground_truth_shape_and_coverage(dataset):
    gt = dataset["ground_truth"]
    assert len(gt) == ALERT_COUNT
    assert {entry["alert_id"] for entry in gt} == {a["id"] for a in dataset["alerts"]}
    for entry in gt:
        _assert_shape(entry, GROUND_TRUTH_REQUIRED, "ground_truth")
        assert entry["expected_verdict"] in VALID_VERDICTS
        assert all(
            isinstance(t, str) and t.startswith("T")
            for t in entry["expected_mitre"]
        )


def test_ground_truth_matches_scenario_maps(dataset):
    from itdr_agent import data_generator

    gt = {entry["scenario"]: entry for entry in dataset["ground_truth"]}
    assert set(data_generator.SCENARIO_EXPECTED_VERDICT) <= set(gt)
    for scenario, verdict in data_generator.SCENARIO_EXPECTED_VERDICT.items():
        assert gt[scenario]["expected_verdict"] == verdict
        assert (
            gt[scenario]["expected_mitre"]
            == data_generator.SCENARIO_EXPECTED_MITRE[scenario]
        )
    for scenario, technique in data_generator.SCENARIO_TECHNIQUES.items():
        assert gt[scenario]["expected_mitre"] == [technique]


def test_ground_truth_benign_mitre_is_only_admin_role(dataset):
    gt = {entry["scenario"]: entry for entry in dataset["ground_truth"]}
    benign = {s for s, entry in gt.items() if entry["is_benign"]}
    assert benign == set(BENIGN_SCENARIOS)
    for scenario in ("benign_travel", "benign_vpn"):
        assert gt[scenario]["expected_mitre"] == []
    assert gt["benign_admin_role"]["expected_mitre"] == ["T1098.003"]
    for scenario in ("thin_data", "unknown"):
        assert gt[scenario]["expected_mitre"] == []
        assert gt[scenario]["is_benign"] is False


# --- Alerts ----------------------------------------------------------------


def test_alerts_have_required_schema(dataset):
    alerts = dataset["alerts"]
    assert len(alerts) == ALERT_COUNT
    ids = {a["id"] for a in alerts}
    assert len(ids) == ALERT_COUNT
    assert "ALERT_001" in ids
    for alert in alerts:
        _assert_shape(alert, ALERT_REQUIRED, "alert")
        _assert_shape(alert["location"], LOCATION_REQUIRED, "alert.location")
        _assert_shape(alert["status"], STATUS_REQUIRED, "alert.status")


def test_alerts_reference_their_planted_evidence(dataset, alerts_by_scenario):
    """Each alert must point at a sign-in that actually shows its pattern.

    Alerts whose risk evidence is an MFA failure burst or a directory role
    change must still carry a matching signal, not a benign baseline sign-in.
    """
    risk_typed = {
        "impossible_travel": "unlikelyTravel",
        "anonymous_ip": "anonymizedIPAddress",
        "app_consent": "unfamiliarFeatures",
    }
    for scenario, expected in risk_typed.items():
        assert expected in alerts_by_scenario[scenario]["riskEventTypes_v2"], (
            f"{scenario} alert does not carry {expected}"
        )
    fatigue = alerts_by_scenario["mfa_fatigue"]
    assert "MFA" in fatigue["status"]["failureReason"], (
        "mfa_fatigue alert must reference an MFA-denied sign-in"
    )
    assert fatigue["status"]["errorCode"] != 0
    assert alerts_by_scenario["privilege_escalation"]["riskState"] == "atRisk", (
        "privilege_escalation alert must be flagged risky"
    )


# --- Persistence -----------------------------------------------------------


def test_write_fixtures_creates_jsonl(tmp_path):
    from itdr_agent import data_generator

    data_generator.write_fixtures(tmp_path, seed=1337)
    for name in ("users", "sign_ins", "directory_audits", "alerts", "ground_truth"):
        path = tmp_path / f"{name}.jsonl"
        assert path.exists(), f"missing fixture {path}"
        lines = [
            json.loads(line)
            for line in path.read_text().splitlines()
            if line.strip()
        ]
        assert lines, f"fixture {path} is empty"

    for record in [
        json.loads(line)
        for line in (tmp_path / "alerts.jsonl").read_text().splitlines()
        if line.strip()
    ]:
        assert "id" in record

    for record in [
        json.loads(line)
        for line in (tmp_path / "ground_truth.jsonl").read_text().splitlines()
        if line.strip()
    ]:
        assert "alert_id" in record
