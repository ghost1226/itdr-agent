"""Checkpoint 3 — Simulated Microsoft Graph API layer.

Functions mirror real Graph endpoints but read the synthetic fixture store.
Every function accepts an optional ``injected_error`` (e.g. ``"429"`` or
``"500"``). Errors are raised only when a caller injects them, never at
random, so tests stay deterministic.

Unknown identifiers return ``None`` or an empty list, never a guess.
"""

from __future__ import annotations

from typing import Any

from .fixture_store import get_store


class SimulatedGraphError(Exception):
    """A simulated Microsoft Graph HTTP error."""

    def __init__(self, status_code: int, message: str | None = None) -> None:
        self.status_code = status_code
        super().__init__(message or f"Simulated Microsoft Graph error {status_code}")


def _maybe_inject(injected_error: str | None) -> None:
    if injected_error is not None:
        raise SimulatedGraphError(int(injected_error))


def get_user_profile(
    upn: str, injected_error: str | None = None
) -> dict[str, Any] | None:
    """GET /users/{upn} — returns None for an unknown user."""
    _maybe_inject(injected_error)
    return get_store().get_user(upn)


def get_sign_in_history(
    upn: str, hours: int = 24, injected_error: str | None = None
) -> list[dict[str, Any]]:
    """GET /auditLogs/signIns?$filter=userPrincipalName eq {upn} — newest window."""
    _maybe_inject(injected_error)
    return get_store().sign_in_history(upn, hours)


def get_device_trust(
    device_id: str, injected_error: str | None = None
) -> dict[str, Any] | None:
    """GET /devices/{deviceId} — returns None for an unknown device."""
    _maybe_inject(injected_error)
    return get_store().get_device(device_id)


def get_directory_audits(
    upn: str, hours: int = 24, injected_error: str | None = None
) -> list[dict[str, Any]]:
    """GET /auditLogs/directoryAudits touching {upn} — newest window."""
    _maybe_inject(injected_error)
    return get_store().get_directory_audits(upn, hours)


def get_risky_user_report(
    upn: str, injected_error: str | None = None
) -> dict[str, Any] | None:
    """GET /identityProtection/riskyUsers/{upn} — returns None if unknown."""
    _maybe_inject(injected_error)
    return get_store().risky_user_report(upn)
