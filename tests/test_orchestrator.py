"""Checkpoint 6 — Orchestrator + governance + HITL tests (mocked, offline).

No network, no API key, no live tokens. The Investigator and Adjudicator LLMs
are mocked; the analyst is a ScriptedReviewer.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

try:
    from itdr_agent.adjudicator import (  # noqa: E402
        Adjudicator,
        UnsupportedMitreClaimError,
    )
    from itdr_agent.human import (  # noqa: E402
        AskUserResult,
        ContainmentDecision,
        ScriptedReviewer,
        cancelled_result,
    )
    from itdr_agent.orchestrator import (  # noqa: E402
        AnonymizationError,
        Orchestrator,
    )
    from itdr_agent.schemas import InvestigatorOutput, Verdict  # noqa: E402
except ModuleNotFoundError:  # red phase: modules not written yet
    pass

ALICE = "alice.traveler@contoso.com"


class FakeInvestigator:
    def __init__(self, dossier: InvestigatorOutput) -> None:
        self.dossier = dossier
        self.calls = 0
        self.tool_calls_made = 0

    def investigate(self, alert: dict) -> InvestigatorOutput:
        self.calls += 1
        return self.dossier


class CompleteLLM:
    """Deterministic single-shot Adjudicator LLM."""

    def __init__(self, responses: list[str]) -> None:
        self.responses = list(responses)
        self.calls = 0
        self.messages: list[list[dict]] = []

    def complete(self, messages: list[dict]) -> str:
        self.calls += 1
        self.messages.append(messages)
        if not self.responses:
            raise AssertionError("Adjudicator called more than scripted")
        return self.responses.pop(0)


def _dossier(**overrides) -> InvestigatorOutput:
    base = dict(
        alert_id="ALERT_001",
        user_principal_name=ALICE,
        user_profile={"userPrincipalName": ALICE},
        sign_in_history=[
            {
                "id": "s1",
                "createdDateTime": "2025-01-15T09:00:00Z",
                "riskEventTypes_v2": ["unlikelyTravel"],
            }
        ],
        directory_audits=[],
        risk_indicators=["unlikelyTravel"],
        mitre_attack_mapping=["T1078.004"],
        mitre_attack_evidence={"T1078.004": ["s1"]},
    )
    base.update(overrides)
    return InvestigatorOutput(**base)


def _report(**overrides) -> str:
    report = {
        "verdict": "COMPROMISED",
        "confidence": 0.9,
        "narrative": "Evidence supports unlikely-travel sign-ins.",
        "containment_steps": [
            {"step": "Disable the account", "rollback": "Re-enable if benign"}
        ],
        "recommended_actions": ["Contact the user"],
        "mitre_techniques_observed": ["T1078.004"],
        "audit_notes": "",
    }
    report.update(overrides)
    return json.dumps(report)


def _audit(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _orchestrator(
    tmp_path,
    dossier,
    responses,
    reviewer=None,
    investigator=None,
):
    inv = investigator or FakeInvestigator(dossier)
    llm = CompleteLLM(responses)
    audit = tmp_path / "audit.jsonl"
    orch = Orchestrator(
        inv, Adjudicator(llm), reviewer or ScriptedReviewer(), audit_log=audit
    )
    return orch, llm, audit


# --- Happy path + audit ----------------------------------------------------


def test_end_to_end_returns_report_and_logs_run(tmp_path):
    orch, _llm, audit = _orchestrator(tmp_path, _dossier(), [_report()])
    result = orch.run({"id": "ALERT_001", "userPrincipalName": ALICE})
    assert result.report.verdict is Verdict.COMPROMISED
    assert result.report.containment_steps
    assert result.llm_called is True
    assert result.short_circuited is False
    assert result.run_id

    entries = _audit(audit)
    run = next(e for e in entries if e["event"] == "run")
    assert run["alert_id"] == "ALERT_001"
    assert len(run["dossier_hash"]) == 64
    assert len(run["report_hash"]) == 64
    assert run["dossier_hash"] == hashlib.sha256(
        result.dossier.model_dump_json().encode()
    ).hexdigest()
    assert run["run_id"] == result.run_id


def test_run_id_present_in_all_audit_entries(tmp_path):
    orch, _llm, audit = _orchestrator(tmp_path, _dossier(), [_report()])
    result = orch.run(
        {"id": "ALERT_001", "userPrincipalName": ALICE},
        run_id="test-run-001",
    )
    assert result.run_id == "test-run-001"
    entries = _audit(audit)
    for entry in entries:
        assert entry.get("run_id") == "test-run-001"


def test_run_id_auto_generated_when_not_provided(tmp_path):
    orch, _llm, audit = _orchestrator(tmp_path, _dossier(), [_report()])
    result = orch.run({"id": "ALERT_001", "userPrincipalName": ALICE})
    assert result.run_id
    assert result.run_id.startswith("ALERT_001")
    entries = _audit(audit)
    assert all(e.get("run_id") == result.run_id for e in entries)


# --- Critical gap short-circuit -------------------------------------------


def test_critical_gap_short_circuits_without_llm(tmp_path):
    dossier = _dossier(
        alert_id="ALERT_010",
        user_profile=None,
        sign_in_history=[],
        mitre_attack_mapping=[],
        mitre_attack_evidence={},
        risk_indicators=[],
    )
    orch, llm, audit = _orchestrator(tmp_path, dossier, [])
    result = orch.run(
        {"id": "ALERT_010", "userPrincipalName": "ghost.user@contoso.com"}
    )
    assert result.report.verdict is Verdict.INSUFFICIENT_DATA
    assert result.llm_called is False
    assert result.short_circuited is True
    assert llm.calls == 0
    entries = _audit(audit)
    run = next(e for e in entries if e["event"] == "run")
    assert run["short_circuited"] is True
    assert run["llm_called"] is False


# --- Containment review: approve / edit / reject ---------------------------


def test_containment_review_approve_edit_reject(tmp_path):
    dossier = _dossier()
    report = _report(
        containment_steps=[
            {"step": "Step A", "rollback": "Rollback A"},
            {"step": "Step B", "rollback": "Rollback B"},
            {"step": "Step C", "rollback": "Rollback C"},
        ]
    )
    reviewer = ScriptedReviewer(
        decisions=[
            ContainmentDecision("approve"),
            ContainmentDecision("edit", edited_step="Step B (edited)"),
            ContainmentDecision("reject", reason="not needed"),
        ]
    )
    orch, _llm, audit = _orchestrator(tmp_path, dossier, [report], reviewer=reviewer)
    result = orch.run({"id": "ALERT_001", "userPrincipalName": ALICE})

    assert [s.step for s in result.report.containment_steps] == [
        "Step A",
        "Step B (edited)",
    ]
    decisions = [e for e in _audit(audit) if e["event"] == "containment_decision"]
    assert [d["decision"] for d in decisions] == ["approve", "edit", "reject"]
    assert decisions[1]["final_step"] == "Step B (edited)"
    assert decisions[2]["final_step"] is None
    assert all(d["reason"] is not None or d["decision"] != "reject" for d in decisions)


# --- The one-question / one-re-adjudication path ---------------------------


def test_cancelled_ask_does_not_readjudicate(tmp_path):
    low = _report(
        verdict="SUSPICIOUS", confidence=0.6, mitre_techniques_observed=[]
    )
    reviewer = ScriptedReviewer(answers=[cancelled_result()])
    orch, llm, audit = _orchestrator(
        tmp_path, _dossier(alert_id="ALERT_009"), [low], reviewer=reviewer
    )
    result = orch.run({"id": "ALERT_009", "userPrincipalName": ALICE})

    assert result.questions_asked == 1
    assert result.re_adjudications == 0
    assert llm.calls == 1
    assert result.report.verdict is Verdict.INSUFFICIENT_DATA
    assert len(reviewer.asked) == 1

    asks = [e for e in _audit(audit) if e["event"] == "ask_user"]
    assert len(asks) == 1
    assert asks[0]["status"] == "cancelled"
    assert asks[0]["answer"] == "no decision has been supplied"


def test_one_question_one_readjudication_then_stop(tmp_path):
    first = _report(
        verdict="INSUFFICIENT_DATA",
        confidence=0.5,
        mitre_techniques_observed=[],
    )
    second = _report(
        verdict="INSUFFICIENT_DATA",
        confidence=0.55,
        mitre_techniques_observed=[],
    )
    reviewer = ScriptedReviewer(
        answers=[
            AskUserResult(
                status="answered",
                answer="This is expected travel for a conference",
                choice_index=1,
                free_text=False,
            )
        ]
    )
    orch, llm, audit = _orchestrator(
        tmp_path, _dossier(alert_id="ALERT_009"), [first, second], reviewer=reviewer
    )
    result = orch.run({"id": "ALERT_009", "userPrincipalName": ALICE})

    assert result.questions_asked == 1
    assert result.re_adjudications == 1
    assert llm.calls == 2
    assert len(reviewer.asked) == 1  # no second question
    assert result.report.verdict is Verdict.INSUFFICIENT_DATA

    # The analyst answer is wrapped in <analyst_input>, never raw, and not
    # inside the <microsoft_graph_data> dossier block.
    second_messages = llm.messages[1]
    analyst_blocks = [
        m["content"]
        for m in second_messages
        if m["role"] == "user" and "analyst_input" in m["content"]
    ]
    assert analyst_blocks
    block = analyst_blocks[0]
    assert block.startswith('<analyst_input untrusted="true">')
    assert "This is expected travel for a conference" in block
    dossier_block = next(
        m["content"]
        for m in second_messages
        if m["role"] == "user" and "microsoft_graph_data" in m["content"]
    )
    assert "expected travel for a conference" not in dossier_block


# --- MITRE guard inside an orchestrator run --------------------------------


def test_mitre_guard_rejects_unsupported_id_and_logs(tmp_path):
    report = _report(mitre_techniques_observed=["T1078.004", "T9999"])
    orch, _llm, audit = _orchestrator(tmp_path, _dossier(), [report])
    with pytest.raises(UnsupportedMitreClaimError):
        orch.run({"id": "ALERT_001", "userPrincipalName": ALICE})
    entries = _audit(audit)
    rejection = next(e for e in entries if e["event"] == "mitre_rejection")
    assert rejection["alert_id"] == "ALERT_001"
    assert "T9999" in rejection["error"]


# --- Anonymization gate ----------------------------------------------------


def test_anonymization_blocks_non_synthetic_domain(tmp_path):
    orch, _llm, _audit_path = _orchestrator(tmp_path, _dossier(), [])
    with pytest.raises(AnonymizationError):
        orch.run(
            {
                "id": "ALERT_X",
                "userPrincipalName": "real.person@realcorp.example",
                "userDisplayName": "Real Person",
            }
        )


# --- Total timeout (PLAN Checkpoint 6: TIMEOUT_SECONDS, default 120) --------


class FakeClock:
    """Monotonic clock the test moves by hand."""

    def __init__(self, start: float = 1000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now


class SlowInvestigator(FakeInvestigator):
    """Moves the clock forward while it 'investigates'."""

    def __init__(self, dossier, clock: FakeClock, seconds: float) -> None:
        super().__init__(dossier)
        self.clock, self.seconds = clock, seconds

    def investigate(self, alert: dict) -> InvestigatorOutput:
        self.clock.now += self.seconds
        return super().investigate(alert)


def test_timeout_error_is_a_timeout_error():
    from itdr_agent.orchestrator import OrchestrationError, OrchestrationTimeoutError

    # evaluate.classify_error records any TimeoutError as a "timeout" run
    assert issubclass(OrchestrationTimeoutError, TimeoutError)
    assert issubclass(OrchestrationTimeoutError, OrchestrationError)


def test_total_timeout_stops_before_adjudication(tmp_path):
    from itdr_agent.orchestrator import OrchestrationTimeoutError

    clock = FakeClock()
    inv = SlowInvestigator(_dossier(), clock, seconds=130)
    llm = CompleteLLM([_report()])
    audit = tmp_path / "audit.jsonl"
    orch = Orchestrator(
        inv, Adjudicator(llm), ScriptedReviewer(), audit_log=audit,
        timeout_seconds=120, clock=clock,
    )
    with pytest.raises(OrchestrationTimeoutError):
        orch.run({"id": "ALERT_001"}, run_id="r-timeout")
    assert llm.calls == 0  # the Adjudicator was never called
    events = _audit(audit)
    assert [e["event"] for e in events] == ["timeout"]
    assert events[0]["run_id"] == "r-timeout"
    assert events[0]["stage"] == "adjudication"
    assert events[0]["timeout_seconds"] == 120


def test_no_timeout_when_within_budget(tmp_path):
    clock = FakeClock()
    inv = SlowInvestigator(_dossier(), clock, seconds=119)
    llm = CompleteLLM([_report()])
    orch = Orchestrator(
        inv, Adjudicator(llm), ScriptedReviewer(),
        audit_log=tmp_path / "audit.jsonl", timeout_seconds=120, clock=clock,
    )
    result = orch.run({"id": "ALERT_001"})
    assert result.report.verdict is Verdict.COMPROMISED
    assert llm.calls == 1


def test_total_timeout_stops_before_readjudication(tmp_path):
    from itdr_agent.orchestrator import OrchestrationTimeoutError

    clock = FakeClock()

    class ClockMovingLLM(CompleteLLM):
        def complete(self, messages):
            clock.now += 125  # the first Adjudicator call is slow
            return super().complete(messages)

    llm = ClockMovingLLM([_report(confidence=0.5), _report()])
    reviewer = ScriptedReviewer(
        answers=[AskUserResult(status="answered", answer="The activity is suspicious/malicious", choice_index=1)]
    )
    audit = tmp_path / "audit.jsonl"
    orch = Orchestrator(
        FakeInvestigator(_dossier()), Adjudicator(llm), reviewer,
        audit_log=audit, timeout_seconds=120, clock=clock,
    )
    with pytest.raises(OrchestrationTimeoutError):
        orch.run({"id": "ALERT_001"})
    assert llm.calls == 1  # no second (re-)adjudication after the deadline
    assert _audit(audit)[-1]["event"] == "timeout"
    assert _audit(audit)[-1]["stage"] == "re_adjudication"


def test_orchestrator_hands_its_deadline_to_the_investigator(tmp_path):
    """A real Investigator stops between model turns once the deadline passes."""
    from itdr_agent.investigator import Investigator
    from itdr_agent.orchestrator import OrchestrationTimeoutError

    clock = FakeClock()

    class SlowToolLLM:
        def __init__(self):
            self.turns = 0

        def next_action(self, messages):
            self.turns += 1
            clock.now += 70  # each model turn takes 70 s
            return {"action": "tool", "tool": "get_user_profile",
                    "arguments": {"upn": ALICE}}

    tool_llm = SlowToolLLM()
    inv = Investigator(tool_llm, tool_executor=lambda name, args: {"userPrincipalName": ALICE})
    llm = CompleteLLM([_report()])
    audit = tmp_path / "audit.jsonl"
    orch = Orchestrator(
        inv, Adjudicator(llm), ScriptedReviewer(), audit_log=audit,
        timeout_seconds=120, clock=clock,
    )
    with pytest.raises(OrchestrationTimeoutError):
        orch.run({"id": "ALERT_001", "userPrincipalName": ALICE})
    assert tool_llm.turns == 2  # 70 s, 140 s → stops before a third turn
    assert llm.calls == 0
    assert _audit(audit)[-1]["stage"] == "investigation"


# --- Action-claim guard (the agent recommends; it never acts) --------------


def test_action_claim_is_logged_with_run_id(tmp_path):
    orch, _llm, audit = _orchestrator(
        tmp_path, _dossier(),
        [_report(audit_notes="Containment steps executed as per playbook.")],
    )
    result = orch.run({"id": "ALERT_001"}, run_id="r-claim")
    assert result.report.action_claims  # flagged, not rejected
    assert result.report.verdict is Verdict.COMPROMISED
    claims = [e for e in _audit(audit) if e["event"] == "action_claim"]
    assert len(claims) == 1
    assert claims[0]["run_id"] == "r-claim"
    assert claims[0]["claims"] == result.report.action_claims


def test_analyst_think_time_does_not_count_toward_the_timeout(tmp_path):
    """The 120 s budget is for the machine; a person answering takes what it takes."""
    clock = FakeClock()

    class SlowHuman(ScriptedReviewer):
        def ask(self, question, options, allow_free_text=True):
            clock.now += 500  # the analyst thinks for 500 s
            return super().ask(question, options, allow_free_text)

    reviewer = SlowHuman(
        answers=[AskUserResult(status="answered", answer="The activity is suspicious/malicious", choice_index=1)]
    )
    llm = CompleteLLM([_report(confidence=0.5), _report()])
    orch = Orchestrator(
        FakeInvestigator(_dossier()), Adjudicator(llm), reviewer,
        audit_log=tmp_path / "audit.jsonl", timeout_seconds=120, clock=clock,
    )
    result = orch.run({"id": "ALERT_001"})
    assert llm.calls == 2  # the re-adjudication still ran
    assert result.re_adjudications == 1


def test_default_total_timeout_comes_from_config(tmp_path, monkeypatch):
    from itdr_agent import config

    monkeypatch.setattr(config, "TIMEOUT_SECONDS", 77)
    orch = Orchestrator(
        FakeInvestigator(_dossier()), Adjudicator(CompleteLLM([])),
        ScriptedReviewer(), audit_log=tmp_path / "audit.jsonl",
    )
    assert orch.timeout_seconds == 77
