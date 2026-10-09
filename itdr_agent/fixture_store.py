"""Checkpoint 3 — Fixture store for the simulated Graph layer.

Loads the committed synthetic JSONL fixtures once and answers lookups in
memory. If the fixtures are absent (fresh clone), it regenerates them from
the deterministic seed instead of failing.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from . import data_generator

FIXTURE_NAMES = ("users", "sign_ins", "directory_audits", "alerts")
DEFAULT_FIXTURES_DIR = Path(__file__).resolve().parent.parent / "data" / "fixtures"


def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


class FixtureStore:
    """In-memory view of the synthetic tenant."""

    def __init__(
        self,
        users: list[dict[str, Any]],
        sign_ins: list[dict[str, Any]],
        directory_audits: list[dict[str, Any]],
        alerts: list[dict[str, Any]],
    ) -> None:
        self.users = users
        self.sign_ins = sign_ins
        self.directory_audits = directory_audits
        self.alerts = alerts

        self._users_by_upn = {u["userPrincipalName"]: u for u in users}
        self._sign_ins_by_upn: dict[str, list[dict[str, Any]]] = {}
        for event in sign_ins:
            self._sign_ins_by_upn.setdefault(event["userPrincipalName"], []).append(
                event
            )
        self._devices: dict[str, dict[str, Any]] = {
            event["deviceDetail"]["deviceId"]: event["deviceDetail"]
            for event in sign_ins
        }
        self.now = self._compute_now()

    def _compute_now(self) -> datetime:
        """Deterministic 'current' time: the newest synthetic event."""
        stamps = [_parse(e["createdDateTime"]) for e in self.sign_ins]
        stamps += [_parse(a["activityDateTime"]) for a in self.directory_audits]
        return max(stamps)

    # --- lookups -----------------------------------------------------------

    def get_user(self, upn: str) -> dict[str, Any] | None:
        return self._users_by_upn.get(upn)

    def sign_in_history(self, upn: str, hours: int) -> list[dict[str, Any]]:
        events = self._sign_ins_by_upn.get(upn, [])
        cutoff = self.now - timedelta(hours=hours)
        return [e for e in events if _parse(e["createdDateTime"]) >= cutoff]

    def get_device(self, device_id: str) -> dict[str, Any] | None:
        return self._devices.get(device_id)

    def get_directory_audits(self, upn: str, hours: int) -> list[dict[str, Any]]:
        cutoff = self.now - timedelta(hours=hours)
        return [
            a
            for a in self.directory_audits
            if _parse(a["activityDateTime"]) >= cutoff and self._audit_touches(a, upn)
        ]

    @staticmethod
    def _audit_touches(audit: dict[str, Any], upn: str) -> bool:
        for target in audit.get("targetResources", []):
            if target.get("userPrincipalName") == upn:
                return True
        initiated = audit.get("initiatedBy", {}).get("user", {})
        return initiated.get("userPrincipalName") == upn

    def risky_user_report(self, upn: str) -> dict[str, Any] | None:
        events = self._sign_ins_by_upn.get(upn)
        if not events:
            return None
        rank = {"none": 0, "low": 1, "medium": 2, "high": 3}
        worst = max(events, key=lambda e: rank.get(e["riskLevelAggregated"], 0))
        states = [e["riskState"] for e in events]
        if "atRisk" in states:
            risk_state = "atRisk"
        elif "remediated" in states:
            risk_state = "remediated"
        else:
            risk_state = "none"
        types = sorted({t for e in events for t in e["riskEventTypes_v2"]})
        return {
            "userPrincipalName": upn,
            "riskLevel": worst["riskLevelAggregated"],
            "riskState": risk_state,
            "riskDetail": worst["riskDetail"],
            "riskEventTypes_v2": types,
            "isDeleted": False,
        }


def load_fixtures(directory: str | Path = DEFAULT_FIXTURES_DIR) -> FixtureStore:
    """Load committed fixtures, or regenerate deterministically if absent."""
    directory = Path(directory)
    paths = {name: directory / f"{name}.jsonl" for name in FIXTURE_NAMES}
    if all(path.exists() for path in paths.values()):
        return FixtureStore(**{name: _load_jsonl(path) for name, path in paths.items()})
    dataset = data_generator.generate_dataset()
    return FixtureStore(**{name: dataset[name] for name in FIXTURE_NAMES})


_STORE: FixtureStore | None = None


def get_store() -> FixtureStore:
    """Lazily construct and return the process-wide fixture store."""
    global _STORE
    if _STORE is None:
        _STORE = load_fixtures()
    return _STORE
