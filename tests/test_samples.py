"""The mocked sample reports must describe only real dossier evidence.

Samples live under ``scripts/`` because they read ``ground_truth.jsonl``
(verdict and scenario) to be illustrative; nothing under ``itdr_agent/`` may
read ground truth. Each benign narrative is built from that alert's own
evidence, and benign / insufficient reports never suggest disabling the
account.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from itdr_agent.schemas import Verdict

GROUND_TRUTH = PROJECT_ROOT / "data" / "fixtures" / "ground_truth.jsonl"


def _ground_truth() -> list[dict]:
    return [
        json.loads(line)
        for line in GROUND_TRUTH.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _sample(alert_id: str):
    import samples  # scripts/samples.py

    return samples.sample_report(alert_id)


def test_package_does_not_reference_ground_truth():
    """No agent module may read ground truth; data_generator is the producer."""
    offenders = []
    for path in sorted((PROJECT_ROOT / "itdr_agent").rglob("*.py")):
        if path.name == "data_generator.py":
            continue  # writes the labels; does not read them into the agent
        if "ground_truth" in path.read_text(encoding="utf-8"):
            offenders.append(str(path.relative_to(PROJECT_ROOT)))
    assert not offenders, f"itdr_agent must not reference ground truth: {offenders}"


def test_alert006_travel_narrative_uses_its_own_evidence():
    _dossier, report = _sample("ALERT_006")
    assert report.verdict is Verdict.FALSE_POSITIVE
    text = report.narrative.lower()
    assert "device" in text
    assert "new york" in text and "london" in text
    assert "hours apart" in text
    assert "8.2 hours apart" in text  # the real NY->London leg, not a baseline
    assert "ticket" not in text and "helpdesk" not in text
    assert "disable" not in report.model_dump_json().lower()


def test_alert007_role_narrative_uses_the_ticket():
    _dossier, report = _sample("ALERT_007")
    assert report.verdict is Verdict.FALSE_POSITIVE
    text = report.narrative.lower()
    assert "hd-1042" in text
    assert "role" in text
    assert "disable" not in report.model_dump_json().lower()


def test_alert008_vpn_narrative_uses_the_named_network():
    _dossier, report = _sample("ALERT_008")
    assert report.verdict is Verdict.FALSE_POSITIVE
    text = report.narrative.lower()
    assert "network" in text or "vpn" in text
    assert "disable" not in report.model_dump_json().lower()


def test_alert009_insufficient_recommends_gathering_not_disabling():
    _dossier, report = _sample("ALERT_009")
    assert report.verdict is Verdict.INSUFFICIENT_DATA
    assert report.containment_steps == []
    assert report.recommended_actions
    assert "disable" not in report.model_dump_json().lower()


def test_all_sample_reports_are_evidence_faithful():
    for entry in _ground_truth():
        alert_id = entry["alert_id"]
        dossier, report = _sample(alert_id)
        supported = set(dossier.mitre_attack_evidence)
        for technique in report.mitre_techniques_observed:
            assert technique in supported, (
                f"{alert_id} claimed {technique} without dossier evidence"
            )
        if entry["is_benign"] or report.verdict is Verdict.INSUFFICIENT_DATA:
            blob = report.model_dump_json().lower()
            assert "disable" not in blob, (
                f"{alert_id} suggested disabling for {report.verdict}"
            )
