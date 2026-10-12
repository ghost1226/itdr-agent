"""Checkpoint 1 — Synthetic Microsoft Entra ID data generator.

Generates a fully synthetic tenant: users, sign-in logs, directory audit
logs, device trust states, and risky sign-in alerts. Five MITRE ATT&CK
attack patterns are planted deterministically so downstream agents can
find them.

No real tenant, no real logs. Everything here is fabricated.

Field names follow Microsoft's published Graph shapes:
  * signIn (v1.0): riskEventTypes_v2, riskDetail, riskLevelAggregated,
    riskLevelDuringSignIn, riskState, status, deviceDetail, location,
    clientAppUsed, conditionalAccessStatus.
    https://learn.microsoft.com/en-us/graph/api/resources/signin?view=graph-rest-1.0
    Anonymous IP surfaces as riskEventTypes_v2 == ["anonymizedIPAddress"];
    impossible travel as ["unlikelyTravel"]. riskEventTypes exists but is
    deprecated, so it is deliberately not emitted.
  * mfaDetail (beta signIn):
    https://learn.microsoft.com/en-us/graph/api/resources/mfadetail?view=graph-rest-beta
  * directoryAudit (v1.0): activityDateTime, activityDisplayName, category,
    correlationId, initiatedBy, targetResources, result, resultReason,
    loggedByService.
    https://learn.microsoft.com/en-us/graph/api/resources/directoryaudit?view=graph-rest-1.0
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

# The only domain allowed in synthetic identity data.
SYNTHETIC_DOMAIN = "contoso.com"

# Privileged accounts. Background role changes are always initiated by one
# of these, so ordinary staff never look like they escalated a role.
ADMIN_UPNS: list[str] = ["it.admin@contoso.com", "sec.admin@contoso.com"]

# Public contract: scenario -> synthetic UPN. Tests key off this.
# Five attack scenarios, then three benign (false-positive) scenarios.
SCENARIO_UPNS: dict[str, str] = {
    "impossible_travel": f"alice.traveler@{SYNTHETIC_DOMAIN}",
    "mfa_fatigue": f"bob.fatigue@{SYNTHETIC_DOMAIN}",
    "anonymous_ip": f"carol.anon@{SYNTHETIC_DOMAIN}",
    "app_consent": f"dave.consent@{SYNTHETIC_DOMAIN}",
    "privilege_escalation": f"erin.admin@{SYNTHETIC_DOMAIN}",
    "benign_travel": f"frank.traveler@{SYNTHETIC_DOMAIN}",
    # The investigated user is the TARGET of the legitimate role add. This is
    # an ordinary helpdesk user, used by no other scenario, so it.admin (the
    # privilege-escalation initiator) never appears in the benign window.
    "benign_admin_role": f"helpdesk.agent@{SYNTHETIC_DOMAIN}",
    "benign_vpn": f"gina.vpn@{SYNTHETIC_DOMAIN}",
}

BENIGN_SCENARIOS: list[str] = [
    "benign_travel",
    "benign_admin_role",
    "benign_vpn",
]

# A known baseline user with intentionally sparse history: 1-2 sign-ins and
# no directory audits. Not a critical gap (profile + sign-ins both exist).
THIN_DATA_UPN: str = f"user05@{SYNTHETIC_DOMAIN}"
THIN_DATA_SCENARIO = "thin_data"
UNKNOWN_SCENARIO = "unknown"
UNKNOWN_ALERT_UPN: str = f"ghost.user@{SYNTHETIC_DOMAIN}"

# Company VPN egress IPs (RFC 5737 documentation range). Sign-ins from these
# addresses are expected and must not be treated as anonymizing. The beta
# signIn field networkLocationDetails marks the trusted named network.
KNOWN_VPN_EGRESS_IPS: list[str] = ["198.51.100.10", "198.51.100.11"]
VPN_NETWORK_NAME = "Contoso Corporate VPN"

# Home cities for the benign scenarios, so planted movement is physically
# plausible (New York -> London is a real 8h flight, not 15 minutes).
SCENARIO_HOME_CITIES: dict[str, str] = {
    "benign_travel": "New York",
    "benign_admin_role": "New York",
    "benign_vpn": "Seattle",
}

# Alerts are Graph-shaped only. Ground truth (scenario, expected verdict,
# expected MITRE, is_benign) lives in data/fixtures/ground_truth.jsonl and is
# never sent to the model.
ALERT_FIELD_ALLOWLIST: list[str] = [
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
]

# MITRE ATT&CK technique IDs mapped from the plan.
SCENARIO_TECHNIQUES: dict[str, str] = {
    "impossible_travel": "T1078.004",   # Valid Accounts: Cloud Accounts
    "mfa_fatigue": "T1621",             # MFA Request Generation
    "anonymous_ip": "T1090.003",        # Proxy: Multi-hop Proxy
    "app_consent": "T1528",             # Steal Application Access Token
    "privilege_escalation": "T1098.003",  # Account Manipulation: Additional Cloud Roles
}

# Ground truth for scoring (Checkpoint 7). Never sent to the model.
SCENARIO_EXPECTED_VERDICT: dict[str, str] = {
    "impossible_travel": "COMPROMISED",
    "mfa_fatigue": "COMPROMISED",
    "anonymous_ip": "COMPROMISED",
    "app_consent": "COMPROMISED",
    "privilege_escalation": "COMPROMISED",
    "benign_travel": "FALSE_POSITIVE",
    "benign_admin_role": "FALSE_POSITIVE",
    "benign_vpn": "FALSE_POSITIVE",
}

SCENARIO_EXPECTED_MITRE: dict[str, list[str]] = {
    **{scenario: [technique] for scenario, technique in SCENARIO_TECHNIQUES.items()},
    "benign_travel": [],
    # The mapper still emits T1098.003: the pattern is real. Deciding that it
    # is expected is the analyst's/Adjudicator's job, not the mapper's.
    "benign_admin_role": ["T1098.003"],
    "benign_vpn": [],
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
    risk_detail: str = "none",
    risk_level_aggregated: str = "none",
    risk_level_during_sign_in: str = "none",
    risk_state: str = "none",
    risk_event_types: list[str] | None = None,
    ca_status: str = "success",
    managed_device: bool = True,
    device: dict | None = None,
    network_location_details: list[dict] | None = None,
    mfa_detail: dict | None = None,
) -> dict:
    """Build one signIn resource using Microsoft Graph field names."""
    return {
        "id": _new_id(rng),
        "createdDateTime": _iso(created),
        "userDisplayName": user["displayName"],
        "userPrincipalName": user["userPrincipalName"],
        "appDisplayName": app or rng.choice(_APPS),
        "ipAddress": ip,
        "clientAppUsed": "Browser",
        "correlationId": _new_id(rng),
        "conditionalAccessStatus": ca_status,
        "riskDetail": risk_detail,
        "riskLevelAggregated": risk_level_aggregated,
        "riskLevelDuringSignIn": risk_level_during_sign_in,
        "riskState": risk_state,
        "riskEventTypes_v2": risk_event_types or [],
        "status": {"errorCode": error_code, "failureReason": failure_reason},
        "deviceDetail": (
            device
            if device is not None
            else _device(rng, managed=managed_device)
        ),
        "mfaDetail": mfa_detail,
        "networkLocationDetails": network_location_details or [],
        "location": location,
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
    seen: set[str] = set()

    def append_user(upn: str, display: str, **overrides) -> None:
        if upn in seen:
            return
        seen.add(upn)
        record = _user_record(fake, rng, upn, display)
        record.update(overrides)
        users.append(record)

    for scenario, upn in SCENARIO_UPNS.items():
        local = upn.split("@")[0].replace(".", " ").title()
        append_user(upn, local)
    for i in range(20):
        append_user(f"user{i:02d}@{SYNTHETIC_DOMAIN}", fake.name())
    for upn in ADMIN_UPNS:
        display = upn.split("@")[0].replace(".", " ").title()
        append_user(upn, display, department="IT", jobTitle="Administrator")
    return users


def _build_user_context(rng: random.Random, users: list[dict]) -> list[dict]:
    """Assign each user a home city, 1-2 stable devices, and a small IP set.

    These are project-side metadata (not Graph fields), used to keep baseline
    noise realistic: background sign-ins always come from the same home city,
    a known device, and a stable IP.
    """
    context: list[dict] = []
    for user in users:
        upn = user["userPrincipalName"]
        forced_city = None
        for scenario, city in SCENARIO_HOME_CITIES.items():
            if SCENARIO_UPNS[scenario] == upn:
                forced_city = city
                break
        if forced_city is not None:
            home = next(
                loc for loc in _NORMAL_LOCATIONS if loc[0] == forced_city
            )
        else:
            home = rng.choice(_NORMAL_LOCATIONS)
        context.append(
            {
                "userPrincipalName": upn,
                "homeLocation": _location(*home),
                "devices": [
                    _device(rng, managed=True)
                    for _ in range(rng.randint(1, 2))
                ],
                "ipAddresses": [
                    _random_ip(rng) for _ in range(rng.randint(2, 3))
                ],
            }
        )
    return context


def _baseline_signins(
    rng: random.Random, users: list[dict], context_by_upn: dict[str, dict]
) -> list[dict]:
    events: list[dict] = []
    for user in users:
        upn = user["userPrincipalName"]
        if upn == THIN_DATA_UPN:
            # Thin-data user gets an intentionally tiny, dedicated history.
            continue
        ctx = context_by_upn[upn]
        for _ in range(4):
            created = BASE_TIME - timedelta(hours=rng.randint(1, 72))
            events.append(
                _signin(
                    rng,
                    user=user,
                    created=created,
                    location=ctx["homeLocation"],
                    device=rng.choice(ctx["devices"]),
                    ip=rng.choice(ctx["ipAddresses"]),
                )
            )
    return events


def _plant_scenario_signins(
    rng: random.Random, by_upn: dict[str, dict], context_by_upn: dict[str, dict]
) -> tuple[list[dict], dict[str, dict]]:
    events: list[dict] = []
    evidence: dict[str, dict] = {}

    def add(scenario: str, event: dict, *, points_alert: bool = True) -> None:
        events.append(event)
        if points_alert:
            evidence[scenario] = event

    # 1. Impossible travel (T1078.004): New York -> Moscow within 25 minutes.
    alice = by_upn[SCENARIO_UPNS["impossible_travel"]]
    add(
        "impossible_travel",
        _signin(
            rng,
            user=alice,
            created=BASE_TIME,
            location=_location("New York", "NY", "US", 40.7128, -74.0060),
            ip="203.0.113.10",
            risk_state="atRisk",
            risk_level_aggregated="high",
            risk_level_during_sign_in="high",
            risk_event_types=["unlikelyTravel"],
        ),
    )
    add(
        "impossible_travel",
        _signin(
            rng,
            user=alice,
            created=BASE_TIME + timedelta(minutes=25),
            location=_location("Moscow", "Moscow", "RU", 55.7558, 37.6173),
            ip="198.51.100.23",
            risk_state="atRisk",
            risk_level_aggregated="high",
            risk_level_during_sign_in="high",
            risk_event_types=["unlikelyTravel"],
            ca_status="failure",
        ),
        points_alert=False,
    )

    # 2. MFA fatigue (T1621): repeated denials, then a success.
    bob = by_upn[SCENARIO_UPNS["mfa_fatigue"]]
    for offset in (0, 2, 4, 6):
        add(
            "mfa_fatigue",
            _signin(
                rng,
                user=bob,
                created=BASE_TIME + timedelta(minutes=offset),
                location=_location("Seattle", "WA", "US", 47.6062, -122.3321),
                ip="192.0.2.55",
                error_code=500121,
                failure_reason="Authentication failed: MFA denied by user",
                risk_state="atRisk",
                risk_level_aggregated="medium",
                risk_level_during_sign_in="medium",
                ca_status="failure",
                mfa_detail=_mfa("PhoneAppNotification", "Push notification denied"),
            ),
            points_alert=(offset == 0),
        )
    add(
        "mfa_fatigue",
        _signin(
            rng,
            user=bob,
            created=BASE_TIME + timedelta(minutes=8),
            location=_location("Seattle", "WA", "US", 47.6062, -122.3321),
            ip="192.0.2.55",
            risk_state="remediated",
            risk_level_aggregated="medium",
            risk_level_during_sign_in="medium",
            mfa_detail=_mfa("PhoneAppNotification", "Push notification approved"),
        ),
        points_alert=False,
    )

    # 3. Anonymous IP / anonymizing proxy (T1090.003).
    carol = by_upn[SCENARIO_UPNS["anonymous_ip"]]
    add(
        "anonymous_ip",
        _signin(
            rng,
            user=carol,
            created=BASE_TIME + timedelta(minutes=30),
            location=_location("Amsterdam", "North Holland", "NL", 52.3676, 4.9041),
            ip="185.220.101.9",
            risk_state="atRisk",
            risk_level_aggregated="high",
            risk_level_during_sign_in="high",
            risk_event_types=["anonymizedIPAddress"],
            ca_status="failure",
            managed_device=False,
        ),
    )

    # 4. Foreign/anomalous sign-in preceding app consent (T1528).
    dave = by_upn[SCENARIO_UPNS["app_consent"]]
    add(
        "app_consent",
        _signin(
            rng,
            user=dave,
            created=BASE_TIME + timedelta(minutes=10),
            location=_location("Lagos", "Lagos", "NG", 6.5244, 3.3792),
            ip="102.89.34.77",
            risk_state="atRisk",
            risk_level_aggregated="high",
            risk_level_during_sign_in="high",
            risk_event_types=["unfamiliarFeatures"],
            ca_status="failure",
            managed_device=False,
        ),
    )

    # 5. Privilege escalation (T1098.003): the role change follows a risky
    # session, so the alert has a real sign-in to point at.
    erin = by_upn[SCENARIO_UPNS["privilege_escalation"]]
    add(
        "privilege_escalation",
        _signin(
            rng,
            user=erin,
            created=BASE_TIME + timedelta(minutes=50),
            location=_location("Lagos", "Lagos", "NG", 6.5244, 3.3792),
            ip="102.89.34.78",
            risk_state="atRisk",
            risk_level_aggregated="high",
            risk_level_during_sign_in="high",
            risk_event_types=["unfamiliarFeatures"],
            ca_status="failure",
            managed_device=False,
        ),
    )

    # Real travel: same known, compliant device, no risk events afterwards.
    # New York -> London is a real ~8h flight, so the speed is plane-plausible.
    frank = by_upn[SCENARIO_UPNS["benign_travel"]]
    travel_device = context_by_upn[frank["userPrincipalName"]]["devices"][0]
    add(
        "benign_travel",
        _signin(
            rng,
            user=frank,
            created=BASE_TIME + timedelta(minutes=5),
            location=_location("New York", "NY", "US", 40.7128, -74.0060),
            ip="203.0.113.50",
            device=travel_device,
        ),
        points_alert=False,
    )
    add(
        "benign_travel",
        _signin(
            rng,
            user=frank,
            created=BASE_TIME + timedelta(hours=8, minutes=20),
            location=_location("London", "England", "GB", 51.5074, -0.1278),
            ip="203.0.113.51",
            device=travel_device,
        ),
    )

    # Expected admin role add: a dedicated sign-in on a known device so the
    # alert fires on the target and the in-window role add is visible.
    admin_target = by_upn[SCENARIO_UPNS["benign_admin_role"]]
    admin_device = context_by_upn[admin_target["userPrincipalName"]][
        "devices"
    ][0]
    add(
        "benign_admin_role",
        _signin(
            rng,
            user=admin_target,
            created=BASE_TIME + timedelta(minutes=25),
            location=_location("New York", "NY", "US", 40.7128, -74.0060),
            ip="203.0.113.60",
            device=admin_device,
        ),
    )

    # VPN user: sign-ins from the company's known egress, marked as a trusted
    # named network, on a known device, with no risk events.
    gina = by_upn[SCENARIO_UPNS["benign_vpn"]]
    gina_device = context_by_upn[gina["userPrincipalName"]]["devices"][0]
    vpn_details = [
        {"networkType": "namedNetwork", "networkNames": [VPN_NETWORK_NAME]}
    ]
    add(
        "benign_vpn",
        _signin(
            rng,
            user=gina,
            created=BASE_TIME + timedelta(minutes=5),
            location=_location("Seattle", "WA", "US", 47.6062, -122.3321),
            ip=KNOWN_VPN_EGRESS_IPS[0],
            device=gina_device,
            network_location_details=vpn_details,
        ),
        points_alert=False,
    )
    add(
        "benign_vpn",
        _signin(
            rng,
            user=gina,
            created=BASE_TIME + timedelta(minutes=15),
            location=_location("Seattle", "WA", "US", 47.6062, -122.3321),
            ip=KNOWN_VPN_EGRESS_IPS[1],
            device=gina_device,
            network_location_details=vpn_details,
        ),
    )

    return events, evidence


def _plant_thin_data_signins(
    rng: random.Random, by_upn: dict[str, dict], context_by_upn: dict[str, dict]
) -> tuple[list[dict], dict[str, dict]]:
    """One known user with 1-2 sign-ins and no directory audits."""
    thin = by_upn[THIN_DATA_UPN]
    ctx = context_by_upn[THIN_DATA_UPN]
    events = [
        _signin(
            rng,
            user=thin,
            created=BASE_TIME - timedelta(hours=2),
            location=ctx["homeLocation"],
            ip=ctx["ipAddresses"][0],
            device=ctx["devices"][0],
        ),
        _signin(
            rng,
            user=thin,
            created=BASE_TIME - timedelta(hours=1),
            location=ctx["homeLocation"],
            ip=ctx["ipAddresses"][-1],
            device=ctx["devices"][-1],
        ),
    ]
    return events, {THIN_DATA_SCENARIO: events[-1]}


def _plant_scenario_audits(
    rng: random.Random, by_upn: dict[str, dict]
) -> list[dict]:
    audits: list[dict] = []

    # 4. App consent granted shortly after the foreign sign-in (T1528).
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

    # 5. Privilege escalation (T1098.003): added to Global Administrator.
    erin = by_upn[SCENARIO_UPNS["privilege_escalation"]]
    audit = _audit(
        rng,
        created=BASE_TIME + timedelta(minutes=60),
        activity="Add member to role",
        category="RoleManagement",
        initiator=by_upn[ADMIN_UPNS[0]],
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
    assert erin["userPrincipalName"] in json.dumps(audit["targetResources"])

    # Benign: a legitimate, ticket-backed role add. The investigated user is an
    # ordinary helpdesk user (unique to this scenario) and the TARGET; an
    # ADMIN_UPNS account is the initiator. The mapper still emits T1098.003
    # (the pattern is real); the Adjudicator weighs the ticket context.
    benign_target = by_upn[SCENARIO_UPNS["benign_admin_role"]]
    initiator = by_upn[ADMIN_UPNS[1]]
    audits.append(
        _audit(
            rng,
            created=BASE_TIME + timedelta(minutes=30),
            activity="Add member to role",
            category="RoleManagement",
            initiator=initiator,
            targets=[
                {
                    "id": _new_id(rng),
                    "displayName": "Helpdesk Administrator",
                    "type": "Role",
                },
                {
                    "id": benign_target["id"],
                    "displayName": benign_target["displayName"],
                    "type": "User",
                    "userPrincipalName": benign_target["userPrincipalName"],
                },
            ],
            result_reason=(
                "Member added to role Helpdesk Administrator for helpdesk "
                "ticket HD-1042."
            ),
        )
    )
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
    # Baseline noise must never target a scenario user, and only admins may
    # initiate admin actions (password reset, role change, consent for others).
    scenario_users = set(SCENARIO_UPNS.values())
    eligible = [
        u
        for u in users
        if u["userPrincipalName"] != THIN_DATA_UPN
        and u["userPrincipalName"] not in scenario_users
    ]
    admin_users = [u for u in users if u["userPrincipalName"] in ADMIN_UPNS]
    for _ in range(count):
        activity, category, reason = rng.choice(templates)
        actor = rng.choice(admin_users)
        target = rng.choice(eligible)
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


def _alert_from_signin(alert_id: str, source: dict) -> dict:
    """Build a Graph-shaped alert from a sign-in record (no ground truth)."""
    return {
        "id": alert_id,
        "createdDateTime": source["createdDateTime"],
        "userPrincipalName": source["userPrincipalName"],
        "appDisplayName": source["appDisplayName"],
        "ipAddress": source["ipAddress"],
        "location": source["location"],
        "riskLevelAggregated": source["riskLevelAggregated"],
        "riskState": source["riskState"],
        "riskEventTypes_v2": list(source["riskEventTypes_v2"]),
        "status": dict(source["status"]),
    }


def _unknown_alert(alert_id: str) -> dict:
    """An alert whose user is absent from users.jsonl (critical gap)."""
    return {
        "id": alert_id,
        "createdDateTime": _iso(BASE_TIME + timedelta(minutes=90)),
        "userPrincipalName": UNKNOWN_ALERT_UPN,
        "appDisplayName": "Azure Portal",
        "ipAddress": "203.0.113.99",
        "location": _location("Unknown", "", "US", 0.0, 0.0),
        "riskLevelAggregated": "none",
        "riskState": "none",
        "riskEventTypes_v2": [],
        "status": {"errorCode": 0, "failureReason": ""},
    }


def _generate_alerts(
    evidence: dict[str, dict],
) -> tuple[list[dict], list[dict]]:
    """Return (alerts, ground_truth), kept strictly separate."""
    alerts: list[dict] = []
    ground_truth: list[dict] = []
    scenarios = list(SCENARIO_UPNS)

    for index, scenario in enumerate(scenarios, start=1):
        alert_id = f"ALERT_{index:03d}"
        alerts.append(_alert_from_signin(alert_id, evidence[scenario]))
        ground_truth.append(
            {
                "alert_id": alert_id,
                "scenario": scenario,
                "expected_verdict": SCENARIO_EXPECTED_VERDICT[scenario],
                "expected_mitre": list(SCENARIO_EXPECTED_MITRE[scenario]),
                "is_benign": scenario in BENIGN_SCENARIOS,
            }
        )

    thin_index = len(scenarios) + 1
    thin_id = f"ALERT_{thin_index:03d}"
    alerts.append(_alert_from_signin(thin_id, evidence[THIN_DATA_SCENARIO]))
    ground_truth.append(
        {
            "alert_id": thin_id,
            "scenario": THIN_DATA_SCENARIO,
            "expected_verdict": "INSUFFICIENT_DATA",
            "expected_mitre": [],
            "is_benign": False,
        }
    )

    unknown_id = f"ALERT_{thin_index + 1:03d}"
    alerts.append(_unknown_alert(unknown_id))
    ground_truth.append(
        {
            "alert_id": unknown_id,
            "scenario": UNKNOWN_SCENARIO,
            "expected_verdict": "INSUFFICIENT_DATA",
            "expected_mitre": [],
            "is_benign": False,
        }
    )
    return alerts, ground_truth


# --- Public API ------------------------------------------------------------


def generate_dataset(seed: int = DEFAULT_SEED) -> dict[str, list[dict]]:
    """Generate the full synthetic dataset deterministically for a given seed."""
    rng = random.Random(seed)
    fake = Faker()
    fake.seed_instance(seed)

    users = _generate_users(rng, fake)
    by_upn = {u["userPrincipalName"]: u for u in users}
    user_context = _build_user_context(rng, users)
    context_by_upn = {c["userPrincipalName"]: c for c in user_context}

    sign_ins = _baseline_signins(rng, users, context_by_upn)
    scenario_sign_ins, evidence = _plant_scenario_signins(
        rng, by_upn, context_by_upn
    )
    sign_ins.extend(scenario_sign_ins)
    thin_sign_ins, thin_evidence = _plant_thin_data_signins(
        rng, by_upn, context_by_upn
    )
    sign_ins.extend(thin_sign_ins)
    evidence.update(thin_evidence)

    directory_audits = _baseline_audits(rng, users)
    directory_audits.extend(_plant_scenario_audits(rng, by_upn))

    alerts, ground_truth = _generate_alerts(evidence)

    return {
        "users": users,
        "sign_ins": sign_ins,
        "directory_audits": directory_audits,
        "alerts": alerts,
        "ground_truth": ground_truth,
        "user_context": user_context,
    }


def write_fixtures(
    out_dir: str | Path, seed: int = DEFAULT_SEED
) -> dict[str, Path]:
    """Persist the dataset as JSONL. Same seed => byte-identical files."""
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
