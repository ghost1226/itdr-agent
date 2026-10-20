"""Dream Run 1 item 10: the unsafe-rollback warning fired on every run (offline).

All 5 after-fix COMPROMISED runs were flagged, for password-reset and MFA
steps. The prompt tells the model "never restore an old password", and the
model echoes it ("do not restore the previous password"), which the guard read
as unsafe. Two fixes in code:
  1. a restore phrase negated just before its verb is not unsafe;
  2. a known one-way step (password reset, MFA re-register, session revoke)
     whose rollback is still unsafe gets a standard safe rollback from code.
A step code doesn't know keeps the warning for the analyst.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(Path(__file__).parent))

from itdr_agent import adjudicator as adj  # noqa: E402
from itdr_agent.adjudicator import Adjudicator  # noqa: E402
from itdr_agent.schemas import AdjudicatorOutput  # noqa: E402
from test_orchestrator import CompleteLLM, _dossier, _report  # noqa: E402


@pytest.mark.parametrize(
    "rollback",
    [
        "Issue a new temporary password; do not restore the previous password.",
        "Issue a new temporary password; never restore the old password",
        "Have the user re-register MFA after verifying identity; do not restore the previous MFA methods.",
        "Don't revert to the old password; issue a new temporary one.",
    ],
)
def test_negated_restore_is_not_unsafe(rollback):
    assert not adj.is_unsafe_rollback(rollback), rollback


@pytest.mark.parametrize(
    "rollback",
    [
        "Revert the password to its previous value",
        "Without verifying, restore the old password",
        "Do not lock the user out; restore the old password",
        "If MFA re-enrollment fails, restore the previous MFA configuration.",
    ],
)
def test_unnegated_restore_is_still_unsafe(rollback):
    assert adj.is_unsafe_rollback(rollback), rollback


@pytest.mark.parametrize("text", list(adj.STANDARD_ROLLBACKS.values()))
def test_standard_rollbacks_are_safe(text):
    assert not adj.is_unsafe_rollback(text)


def _adjudicate(steps) -> AdjudicatorOutput:
    llm = CompleteLLM([_report(containment_steps=steps)])
    return Adjudicator(llm, baseline=None).adjudicate(_dossier())


def test_password_reset_gets_the_standard_rollback():
    unsafe = "Revert the password to its previous value"
    report = _adjudicate([{"step": "Force a password reset for the user",
                           "rollback": unsafe}])
    assert report.containment_steps[0].rollback == adj.STANDARD_ROLLBACKS["password_reset"]
    assert report.standard_rollbacks == [0]
    assert report.unsafe_rollbacks == []
    assert unsafe in report.audit_notes  # the model's text is kept for review


def test_mfa_reregister_gets_the_standard_rollback():
    report = _adjudicate([{"step": "Require the user to re-register MFA",
                           "rollback": "Restore the previous MFA configuration"}])
    assert report.containment_steps[0].rollback == adj.STANDARD_ROLLBACKS["mfa_reregister"]
    assert report.unsafe_rollbacks == []


def test_session_revoke_gets_the_standard_rollback():
    report = _adjudicate([{"step": "Revoke all refresh tokens and sessions",
                           "rollback": "Restore the old credentials"}])
    assert report.containment_steps[0].rollback == adj.STANDARD_ROLLBACKS["session_revoke"]


def test_unknown_step_keeps_the_warning():
    report = _adjudicate([{"step": "Lock the account",
                           "rollback": "Restore the old password"}])
    assert report.containment_steps[0].rollback == "Restore the old password"
    assert report.standard_rollbacks == []
    assert report.unsafe_rollbacks == [0]


def test_safe_rollback_on_a_known_step_is_left_alone():
    safe = "Issue a new temporary password and require a change at next sign-in."
    report = _adjudicate([{"step": "Reset the password", "rollback": safe}])
    assert report.containment_steps[0].rollback == safe
    assert report.standard_rollbacks == []
