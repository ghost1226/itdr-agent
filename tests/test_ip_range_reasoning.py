"""Dream Run 1 item 1: an IP's address range is never evidence (offline).

In all 3 ALERT_006 FALSE_POSITIVE runs (eval r2, r3, after-fix r1) the model
called the sign-in benign partly because 203.0.113.x is a TEST-NET
documentation range ("synthetic or test data"). The attacks use real-world
ranges, so the model learned a shortcut from the data set, not the behavior.
The prompt now forbids it, and code flags (never rejects) a report that leans
on it, the same way the action-claim guard works.
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
from test_orchestrator import CompleteLLM, _audit, _dossier, _orchestrator, _report  # noqa: E402


@pytest.mark.parametrize(
    "narrative",
    [
        "The London sign-in comes from 203.0.113.51, a TEST-NET-3 range.",
        "Both IPs are in a documentation range, which suggests synthetic or test data.",
        "The address is in a reserved range used for examples (RFC 5737).",
        "This looks like test data rather than a real attacker.",
    ],
)
def test_range_reasoning_is_flagged(narrative):
    report = AdjudicatorOutput.model_validate_json(_report(narrative=narrative))
    assert adj.find_ip_range_reasoning(report), narrative


@pytest.mark.parametrize(
    "narrative",
    [
        "Sign-in from London 8 hours after New York; travel is plausible by flight.",
        "The IP 185.220.101.9 is a known Tor exit node.",
        "The user's documentation of the trip is in the ticket.",
    ],
)
def test_behavior_reasoning_is_not_flagged(narrative):
    report = AdjudicatorOutput.model_validate_json(_report(narrative=narrative))
    assert adj.find_ip_range_reasoning(report) == [], narrative


def test_adjudicator_flags_but_keeps_the_verdict():
    raw = _report(
        verdict="FALSE_POSITIVE",
        confidence=0.9,
        narrative="Benign: 203.0.113.51 is a TEST-NET documentation address.",
        containment_steps=[],
        mitre_techniques_observed=[],
    )
    report = Adjudicator(CompleteLLM([raw]), baseline=None).adjudicate(_dossier())
    assert report.verdict.value == "FALSE_POSITIVE"
    assert report.ip_range_reasoning
    assert "IP-range guard" in report.audit_notes


def test_model_cannot_fill_the_flag_itself():
    import json

    raw = json.loads(_report())
    raw["ip_range_reasoning"] = ["TEST-NET"]
    report = Adjudicator(CompleteLLM([json.dumps(raw)]), baseline=None).adjudicate(_dossier())
    assert report.ip_range_reasoning == []


def test_flag_is_logged(tmp_path):
    raw = _report(narrative="The IP is in a TEST-NET range, so likely test data.")
    orch, _llm, audit = _orchestrator(tmp_path, _dossier(), [raw])
    orch.run({"id": "ALERT_001"}, run_id="r-ip")
    lines = [e for e in _audit(audit) if e["event"] == "ip_range_reasoning"]
    assert lines and lines[0]["phrases"]


def test_system_prompt_says_ip_range_is_never_evidence():
    assert "never evidence" in adj.SYSTEM_PROMPT
    assert "address range" in adj.SYSTEM_PROMPT
