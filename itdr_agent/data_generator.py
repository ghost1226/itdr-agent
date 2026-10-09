"""Checkpoint 1 — Synthetic Microsoft Entra ID data generator.

Generates a fully synthetic tenant: users, sign-in logs, directory audit
logs, device trust states, and risky sign-in alerts. Five MITRE ATT&CK
attack patterns are planted deterministically so downstream agents can
find them.

No real tenant, no real logs. Everything here is fabricated.
"""

from __future__ import annotations

import json
import random
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from faker import Faker

DEFAULT_SEED = 1337
BASE_TIME = datetime(2025, 1, 15, 9, 0, 0, tzinfo=timezone.utc)

# Public contract: scenario -> synthetic UPN. Tests key off this.
SCENARIO_UPNS: dict[str, str] = {
    "impossible_travel": "alice.traveler@contoso.com",
    "mfa_fatigue": "bob.fatigue@contoso.com",
    "anonymous_ip": "carol.anon@contoso.com",
    "app_consent": "dave.consent@contoso.com",
    "privilege_escalation": "erin.admin@contoso.com",
}

# MITRE ATT&CK technique IDs mapped from the plan.
SCENARIO_TECHNIQUES: dict[str, str] = {
    "impossible_travel": "T1078",
    "mfa_fatigue": "T1621",
    "anonymous_ip": "T1090",
    "app_consent": "T1550.001",
    "privilege_escalation": "T1098",
}

_NORMAL_LOCATIONS = [
    ("New York", "NY", "US", 40.7128, -74.0060),
    ("Seattle", "WA", "US", 47.6062, -122.3321),
    ("Austin", "TX", "US", 30.2672, -97.7431),
    ("Chicago", "IL", "US", 41.8781, -87.6298),
    ("London", "England", "GB", 51.5074, -0.1278),
    ("Toronto", "ON", "CA", 43.6532, -79.3832),
    ("Sydney", "NSW", "AU", -33.8688, 151.2093),
    ("Sao Paulo", "SP", "BR", -23.5505, -46.6333),
]

_APPS = ["Microsoft Teams", "Office 365 Exchange Online", "SharePoint Online",
         "Azure Portal", "Outlook", "OneDrive"]
_OS = ["Windows 10", "Windows 11", "macOS", "iOS", "Android"]
_BROWSERS = ["Edge", "Chrome", "Safari", "Firefox"]


# --- Low-level helpers -----------------------------------------------------


def _new_id(rng: random.Random) -> str:
    return str(uuid.UUID(int=rng.getrandbits(128)))


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _location(city: str, state: str, country: str, lat: float, lon: float) -> dict:
    return {
        "city": city,
        "state": state,
        "countryOrRegion": country,
        "geoCoordinates": {"latitude": float(lat), "longitude": float(lon)},
    }


def _random_ip(rng: random.Random) -> str:
    return ".".join(str(rng.randint(1, 254)) for _ in range(4))


def _device(rng: random.Random, managed: bool = True) -> dict:
    return {
        "deviceId": _new_id(rng),
        "displayName": f"LAPTOP-{rng.randint(1000, 9999)}",
        "operatingSystem": rng.choice(_OS),
        "browser": rng.choice(_BROWSERS),
        "isCompliant": managed,
        "isManaged": managed,
        "trustType": "AzureAD" if managed else "Unregistered",
    }


def _mfa(auth_method: str, detail: str) -> dict:
    return {"authMethod": auth_method, "authDetail": detail}


def _signin(
    rng: random.Random,
    *,
    user: dict,
    created: datetime,
    location: dict,
    ip: str,
    app: str | None = None,
    error_code: int = 0,
    failure_reason: str = "",
    risk_state: str = "none",
    risk_level: str = "none",
    risk_event_types: list[str] | None = None,
    ca_status: str = "success",
    managed_device: bool = True,
    mfa_detail: dict | None = None,
) -> dict:
    return {
        "id": _new_id(rng),
        "createdDateTime": _iso(created),
        "userDisplayName": user["displayName"],
        "userPrincipalName": user["userPrincipalName"],
        "appDisplayName": app or rng.choice(_APPS),
        "ipAddress": ip,
        "location": location,
        "status": {"errorCode": error_code, "failureReason": failure_reason},
        "riskState": risk_state,
        "riskLevel": risk_level,
        "riskEventTypes": risk_event_types or [],
        "conditionalAccessStatus": ca_status,
        "deviceDetail": _device(rng, managed=managed_device),
        "mfaDetail": mfa_detail,
        "clientAppUsed": "Browser",
        "correlationId": _new_id(rng),
    }


def _audit(
    rng: random.Random,
    *,
    created: datetime,
    activity: str,
    category: str,
    initiator: dict,
    targets: list[dict],
    result: str = "success",
    result_reason: str = "Activity completed successfully.",
    service: str = "AzureActiveDirectory",
) -> dict:
    return {
        "id": _new_id(rng),
        "activityDateTime": _iso(created),
        "activityDisplayName": activity,
        "category": category,
        "correlationId": _new_id(rng),
        "initiatedBy": {"user": initiator},
        "targetResources": targets,
        "result": result,
        "resultReason": result_reason,
        "loggedByService": service,
    }


def _user_record(fake: Faker, rng: random.Random, upn: str, display: str) -> dict:
    departments = ["Engineering", "Finance", "Sales", "HR", "Security", "IT"]
    titles = ["Engineer", "Analyst", "Manager", "Director", "Specialist"]
    return {
        "id": _new_id(rng),
        "userPrincipalName": upn,
        "displayName": display,
        "department": rng.choice(departments),
        "jobTitle": rng.choice(titles),
        "manager": fake.name(),
        "hireDate": _iso(BASE_TIME - timedelta(days=rng.randint(90, 2500))),
        "accountEnabled": True,
    }


# --- Generators ------------------------------------------------------------


def _generate_users(rng: random.Random, fake: Faker) -> list[dict]:
    users: list[dict] = []
    for scenario, upn in SCENARIO_UPNS.items():
        local = upn.split("@")[0].replace(".", " ").title()
        users.append(_user_record(fake, rng, upn, local))
    for i in range(20):
        name = fake.name()
        upn = f"user{i:02d}@contoso.com"
        users.append(_user_record(fake, rng, upn, name))
    return users


def _baseline_signins(rng: random.Random, users: list[dict]) -> list[dict]:
    events: list[dict] = []
    for user in users:
        for _ in range(4):
            created = BASE_TIME - timedelta(hours=rng.randint(1, 72))
            loc = _location(*rng.choice(_NORMAL_LOCATIONS))
            events.append(
                _signin(
                    rng,
                    user=user,
                    created=created,
                    location=loc,
                    ip=_random_ip(rng),
                )
            )
    return events


def _plant_scenario_signins(
    rng: random.Random, by_upn: dict[str, dict]
) -> list[dict]:
    events: list[dict] = []

    # 1. Impossible travel: New York -> Moscow within 25 minutes.
    alice = by_upn[SCENARIO_UPNS["impossible_travel"]]
    events.append(
        _signin(
            rng,
            user=alice,
            created=BASE_TIME,
            location=_location("New York", "NY", "US", 40.7128, -74.0060),
            ip="203.0.113.10",
            risk_state="atRisk",
            risk_level="high",
            risk_event_types=["impossibleTravel"],
        )
    )
    events.append(
        _signin(
            rng,
            user=alice,
            created=BASE_TIME + timedelta(minutes=25),
            location=_location("Moscow", "Moscow", "RU", 55.7558, 37.6173),
            ip="198.51.100.23",
            risk_state="atRisk",
            risk_level="high",
            risk_event_types=["impossibleTravel"],
            ca_status="failure",
        )
    )

    # 2. MFA fatigue: repeated denials, then a success.
    bob = by_upn[SCENARIO_UPNS["mfa_fatigue"]]
    for offset in (0, 2, 4, 6):
        events.append(
            _signin(
                rng,
                user=bob,
                created=BASE_TIME + timedelta(minutes=offset),
                location=_location("Seattle", "WA", "US", 47.6062, -122.3321),
                ip="192.0.2.55",
                error_code=500121,
                failure_reason="Authentication failed: MFA denied by user",
                risk_state="atRisk",
                risk_level="medium",
                risk_event_types=["mfaDenied"],
                ca_status="failure",
                mfa_detail=_mfa("PhoneAppNotification", "Push notification denied"),
            )
        )
    events.append(
        _signin(
            rng,
            user=bob,
            created=BASE_TIME + timedelta(minutes=8),
            location=_location("Seattle", "WA", "US", 47.6062, -122.3321),
            ip="192.0.2.55",
            risk_state="remediated",
            risk_level="medium",
            risk_event_types=["mfaDenied"],
            mfa_detail=_mfa("PhoneAppNotification", "Push notification approved"),
        )
    )

    # 3. Anonymous IP / anonymizing proxy.
    carol = by_upn[SCENARIO_UPNS["anonymous_ip"]]
    events.append(
        _signin(
            rng,
            user=carol,
            created=BASE_TIME + timedelta(minutes=30),
            location=_location("Amsterdam", "North Holland", "NL", 52.3676, 4.9041),
            ip="185.220.101.9",
            risk_state="atRisk",
            risk_level="high",
            risk_event_types=["anonymizedIPAddress"],
            ca_status="failure",
            managed_device=False,
        )
    )

    # 4. Foreign/anomalous sign-in preceding app consent.
    dave = by_upn[SCENARIO_UPNS["app_consent"]]
    events.append(
        _signin(
            rng,
            user=dave,
            created=BASE_TIME + timedelta(minutes=10),
            location=_location("Lagos", "Lagos", "NG", 6.5244, 3.3792),
            ip="102.89.34.77",
            risk_state="atRisk",
            risk_level="high",
            risk_event_types=["unfamiliarFeatures"],
            ca_status="failure",
            managed_device=False,
        )
    )
    return events


def _plant_scenario_audits(
    rng: random.Random, by_upn: dict[str, dict]
) -> list[dict]:
    audits: list[dict] = []

    # 4. App consent granted shortly after the foreign sign-in.
    dave = by_upn[SCENARIO_UPNS["app_consent"]]
    audits.append(
        _audit(
            rng,
            created=BASE_TIME + timedelta(minutes=40),
            activity="Consent to application",
            category="ApplicationManagement",
            initiator=dave,
            targets=[
                {"id": _new_id(rng), "displayName": "EvilSync", "type": "Application"},
                {
                    "id": dave["id"],
                    "displayName": dave["displayName"],
                    "type": "User",
                    "userPrincipalName": dave["userPrincipalName"],
                },
            ],
            result_reason="Consent granted to application EvilSync.",
        )
    )

    # 5. Privilege escalation: added to Global Administrator.
    erin = by_upn[SCENARIO_UPNS["privilege_escalation"]]
    audit = _audit(
        rng,
        created=BASE_TIME + timedelta(minutes=60),
        activity="Add member to role",
        category="RoleManagement",
        initiator=erin,
        targets=[
            {
                "id": _new_id(rng),
                "displayName": "Global Administrator",
                "type": "Role",
            },
            {
                "id": erin["id"],
                "displayName": erin["displayName"],
                "type": "User",
                "userPrincipalName": erin["userPrincipalName"],
            },
        ],
        result_reason="Member added to role Global Administrator.",
    )
    audits.append(audit)
    # The escalation is only meaningful if the user is genuinely a target.
    assert erin["userPrincipalName"] in json.dumps(audit["targetResources"])
    return audits


def _baseline_audits(
    rng: random.Random, users: list[dict], count: int = 50
) -> list[dict]:
    templates = [
        ("Reset user password", "UserManagement", "Password reset by administrator."),
        ("Add member to group", "GroupManagement", "Member added to group."),
        ("Remove member from group", "GroupManagement", "Member removed from group."),
        ("Update user", "UserManagement", "User properties updated."),
        ("Add member to role", "RoleManagement", "Member added to role Helpdesk Administrator."),
        ("Consent to application", "ApplicationManagement", "Consent granted."),
        ("Update conditional access policy", "Policy", "Policy updated."),
    ]
    audits: list[dict] = []
    for _ in range(count):
        actor = rng.choice(users)
        target = rng.choice(users)
        activity, category, reason = rng.choice(templates)
        targets = [
            {
                "id": target["id"],
                "displayName": target["displayName"],
                "type": "User",
                "userPrincipalName": target["userPrincipalName"],
            }
        ]
        if activity == "Add member to role":
            targets.insert(
                0,
                {
                    "id": _new_id(rng),
                    "displayName": "Helpdesk Administrator",
                    "type": "Role",
                },
            )
        elif activity == "Consent to application":
            targets.insert(
                0,
                {"id": _new_id(rng), "displayName": "Forms", "type": "Application"},
            )
        audits.append(
            _audit(
                rng,
                created=BASE_TIME - timedelta(hours=rng.randint(1, 168)),
                activity=activity,
                category=category,
                initiator=actor,
                targets=targets,
                result_reason=reason,
            )
        )
    return audits


def _generate_alerts(
    rng: random.Random, sign_ins: list[dict]
) -> list[dict]:
    alerts: list[dict] = []
    for index, (scenario, upn) in enumerate(SCENARIO_UPNS.items(), start=1):
        candidates = [
            e
            for e in sign_ins
            if e["userPrincipalName"] == upn and e["riskEventTypes"]
        ]
        source = candidates[0] if candidates else next(
            e for e in sign_ins if e["userPrincipalName"] == upn
        )
        alerts.append(
            {
                "id": f"ALERT_{index:03d}",
                "createdDateTime": source["createdDateTime"],
                "userPrincipalName": source["userPrincipalName"],
                "appDisplayName": source["appDisplayName"],
                "ipAddress": source["ipAddress"],
                "location": source["location"],
                "riskLevel": source["riskLevel"],
                "riskState": source["riskState"],
                "riskEventTypes": list(source["riskEventTypes"]),
                "status": dict(source["status"]),
                "scenario": scenario,
            }
        )
    return alerts


# --- Public API ------------------------------------------------------------


def generate_dataset(seed: int = DEFAULT_SEED) -> dict[str, list[dict]]:
    """Generate the full synthetic dataset deterministically for a given seed."""
    rng = random.Random(seed)
    fake = Faker()
    fake.seed_instance(seed)

    users = _generate_users(rng, fake)
    by_upn = {u["userPrincipalName"]: u for u in users}

    sign_ins = _baseline_signins(rng, users)
    sign_ins.extend(_plant_scenario_signins(rng, by_upn))

    directory_audits = _baseline_audits(rng, users)
    directory_audits.extend(_plant_scenario_audits(rng, by_upn))

    alerts = _generate_alerts(rng, sign_ins)

    return {
        "users": users,
        "sign_ins": sign_ins,
        "directory_audits": directory_audits,
        "alerts": alerts,
    }


def write_fixtures(
    out_dir: str | Path, seed: int = DEFAULT_SEED
) -> dict[str, Path]:
    """Persist the dataset as JSONL fixture files. Returns the paths written."""
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    dataset = generate_dataset(seed=seed)
    written: dict[str, Path] = {}
    for name, records in dataset.items():
        path = out_path / f"{name}.jsonl"
        with path.open("w", encoding="utf-8") as handle:
            for record in records:
                handle.write(json.dumps(record) + "\n")
        written[name] = path
    return written


if __name__ == "__main__":  # pragma: no cover - manual entry point
    fixture_dir = Path(__file__).resolve().parent.parent / "data" / "fixtures"
    paths = write_fixtures(fixture_dir)
    for name, path in paths.items():
        print(f"wrote {name}: {path}")
