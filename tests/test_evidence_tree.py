"""GUI rebuild checkpoint 3: the evidence tree, built by code from the dossier.

USER -> BASELINE (sign-ins outside the burst) -> BURST (sign-ins within an
hour either side of the alert) -> one row per burst sign-in, the rows behind
a proved technique lit with its id (only real evidence rows) -> AUDITS. Never an IP. Offline only.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))
sys.path.insert(0, str(Path(__file__).parent))

from itdr_agent.fixture_store import get_store  # noqa: E402

try:
    from itdr_agent.summary import evidence_tree  # noqa: E402
except ImportError:  # red phase
    evidence_tree = None


def _tree(alert_id: str):
    import samples

    dossier, alert = samples.build_dossier(alert_id)
    return evidence_tree(alert, dossier), alert, dossier


def test_mfa_fatigue_tree_has_the_burst_and_the_lit_success_row():
    tree, _alert, _dossier = _tree("ALERT_002")
    assert tree["user"]["upn"] == "bob.fatigue@contoso.com"
    assert "Sales" in tree["user"]["title"]
    assert tree["burst"]["count"] == 5
    assert tree["burst"]["place"] == "Seattle, US"
    assert tree["baseline"]["count"] == 4
    rows = tree["rows"]
    assert len(rows) == 5
    assert [r["outcome"] for r in rows] == ["MFA denied"] * 4 + ["Success"]
    # The four denials are the T1621 evidence; the success that follows is not
    # evidence on its own (derive_indicators), so it stays unlit.
    assert [r["technique"] for r in rows] == ["T1621"] * 4 + [None]
    assert rows[0]["time"] == "09:00" and rows[-1]["time"] == "09:08"
    assert "Microsoft Teams" in rows[0]["app"] or rows[0]["app"]
    assert tree["audits"]["count"] == 0
    assert "no roles, apps or consents" in tree["audits"]["detail"]


def test_privilege_escalation_tree_names_the_role():
    tree, _alert, _dossier = _tree("ALERT_005")
    assert tree["audits"]["count"] >= 1
    assert "Global Administrator" in tree["audits"]["detail"]
    lit = [r for r in tree["rows"] if r["technique"]]
    assert lit == []  # the technique here is an audit, not a sign-in


def test_impossible_travel_rows_are_lit_with_t1078_004():
    tree, _alert, _dossier = _tree("ALERT_001")
    lit = [r["technique"] for r in tree["rows"] if r["technique"]]
    assert lit == ["T1078.004", "T1078.004"]
    assert tree["burst"]["count"] == 2


def test_unknown_user_tree_is_empty_not_a_crash():
    tree, _alert, _dossier = _tree("ALERT_010")
    assert tree["rows"] == [] and tree["burst"]["count"] == 0
    assert tree["baseline"]["count"] == 0
    assert tree["user"]["upn"] == "ghost.user@contoso.com"


@pytest.mark.parametrize("alert_id", [f"ALERT_{n:03d}" for n in range(1, 11)])
def test_tree_never_carries_an_ip_or_the_answer_key(alert_id):
    tree, alert, dossier = _tree(alert_id)
    blob = json.dumps(tree)
    for event in dossier.sign_in_history:
        assert event["ipAddress"] not in blob
    assert alert["ipAddress"] not in blob
    for key in ("scenario", "expected_verdict", "expected_mitre", "is_benign"):
        assert key not in blob


def test_times_are_sorted_and_cover_every_event():
    tree, _alert, dossier = _tree("ALERT_002")
    times = tree["times"]
    assert times == sorted(times)
    assert len(times) == len(dossier.sign_in_history) + len(dossier.directory_audits)


# --- the page ----------------------------------------------------------------

pytest.importorskip("streamlit")
from test_app import _app, _page_text, _start, audit  # noqa: E402, F401


def test_run_page_draws_the_tree_and_the_scrubber(audit):
    at = _start(_app(), "ALERT_002")
    text = _page_text(at)
    assert "Evidence tree" in text
    for label in ("USER", "BASELINE", "BURST", "AUDITS"):
        assert label in text
    assert "bob.fatigue@contoso.com" in text
    assert "MFA denied" in text and "T1621" in text
    assert at.select_slider(key="replay")  # the time scrubber
    assert "203.0.113" not in text and "192.0.2" not in text
