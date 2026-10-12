"""The mocked sample reports must describe only real dossier evidence.

These samples are used for review/demo. The mock reply is composed from the
actual dossier, so it cannot claim events that are absent from the fixtures
(the earlier hand-written mock wrongly asserted a role add by Alice and a
conditional-access failure that were not in ALERT_001's evidence).
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from itdr_agent.schemas import Verdict


def test_alert001_sample_report_uses_only_real_evidence():
    from itdr_agent.samples import sample_report

    dossier, report = sample_report("ALERT_001")
    assert report.verdict is Verdict.COMPROMISED
    assert report.mitre_techniques_observed == ["T1078.004"]
    text = report.narrative.lower()
    assert "travel" in text
    assert "role" not in text
    assert "conditional" not in text
    assert all(step.rollback.strip() for step in report.containment_steps)


def test_alert007_sample_report_is_a_benign_role_add():
    from itdr_agent.samples import sample_report

    dossier, report = sample_report("ALERT_007")
    assert report.verdict is Verdict.FALSE_POSITIVE
    assert report.mitre_techniques_observed == ["T1098.003"]
    text = report.narrative.lower()
    assert "role" in text
    assert "benign" in text or "ticket" in text
    assert all(step.rollback.strip() for step in report.containment_steps)
