"""Per-run trace logging (Dream Run 1, item: per-run trace logging).

Covers: ``runs/<run_id>.json`` next to the audit log, the new ``run`` audit
fields (model, mode, trace_path), the ``+dirty`` mode suffix, and
mock/offline runs writing ``audit-mock.jsonl`` instead of ``audit.jsonl``.

Offline only: scripted LLMs and fake tools, no network, no API key.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(Path(__file__).parent))

from itdr_agent.adjudicator import Adjudicator  # noqa: E402
from itdr_agent.human import (  # noqa: E402
    AskUserResult,
    ScriptedReviewer,
)
from itdr_agent.investigator import Investigator  # noqa: E402
from itdr_agent.orchestrator import Orchestrator  # noqa: E402
from itdr_agent.usage import TokenMeter  # noqa: E402
from test_orchestrator import CompleteLLM, _report  # noqa: E402

ALICE = "alice.traveler@contoso.com"
ALERT = {
    "id": "ALERT_001",
    "userPrincipalName": ALICE,
    "createdDateTime": "2025-01-15T10:00:00Z",
}

SIGN_INS = [
    {
        "id": "s1",
        "createdDateTime": "2025-01-15T09:00:00Z",
        "riskEventTypes_v2": ["unlikelyTravel"],
        "status": {"errorCode": 0},
        "location": {"countryOrRegion": "US"},
        "deviceDetail": {"deviceId": "d1"},
    },
    {
        "id": "s2",
        "createdDateTime": "2025-01-15T09:30:00Z",
        "riskEventTypes_v2": [],
        "status": {"errorCode": 0},
        "location": {"countryOrRegion": "US"},
        "deviceDetail": {"deviceId": "d1"},
    },
]

TOOL_ACTIONS = [
    {"action": "tool", "tool": "get_user_profile", "arguments": {"upn": ALICE}},
    {"action": "tool", "tool": "get_sign_in_history", "arguments": {"upn": ALICE}},
    {"action": "final"},
]


class ScriptedToolLLM:
    def __init__(self, actions: list[dict]) -> None:
        self.actions = list(actions)

    def next_action(self, messages: list[dict]) -> dict:
        if self.actions:
            return self.actions.pop(0)
        return {"action": "final"}


def fake_tool(name: str, arguments: dict):
    if name == "get_user_profile":
        return {"userPrincipalName": ALICE, "displayName": "Alice"}
    if name == "get_sign_in_history":
        return SIGN_INS
    if name == "get_device_trust":
        return {"deviceId": "d1", "isManaged": True}
    return []


def make_investigator(actions: list[dict] | None = None) -> Investigator:
    return Investigator(
        ScriptedToolLLM(list(actions or TOOL_ACTIONS)),
        tool_executor=fake_tool,
    )


def run_entries(audit: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in audit.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def make_orchestrator(
    tmp_path: Path,
    *,
    mode: str = "mock",
    dirty: bool = False,
    responses: list[str] | None = None,
    reviewer=None,
    meter: TokenMeter | None = None,
    investigator: Investigator | None = None,
):
    audit = tmp_path / "audit.jsonl"
    orch = Orchestrator(
        investigator or make_investigator(),
        Adjudicator(CompleteLLM(responses or [_report()])),
        reviewer or ScriptedReviewer(),
        audit_log=audit,
        mode=mode,
        dirty=dirty,
        model="test/model",
        token_meter=meter,
    )
    return orch, audit


# --- trace file -------------------------------------------------------------


def test_trace_file_is_written_next_to_the_audit_log(tmp_path):
    orch, _audit = make_orchestrator(tmp_path, mode="mock")
    orch.run(ALERT, run_id="r-trace-1")

    trace = tmp_path / "runs" / "r-trace-1.json"
    assert trace.exists()
    payload = json.loads(trace.read_text(encoding="utf-8"))
    assert payload["alert_id"] == "ALERT_001"
    assert payload["run_id"] == "r-trace-1"


def test_trace_records_tool_calls_in_order_with_rows(tmp_path):
    orch, _audit = make_orchestrator(tmp_path, mode="mock")
    orch.run(ALERT, run_id="r-tools")

    payload = json.loads((tmp_path / "runs" / "r-tools.json").read_text())
    assert [call["name"] for call in payload["tool_calls"]] == [
        "get_user_profile",
        "get_sign_in_history",
    ]
    assert [call["rows"] for call in payload["tool_calls"]] == [1, 2]
    assert payload["tool_calls"][1]["arguments"] == {"upn": ALICE}


def test_trace_records_every_llm_request_with_stage_and_seconds(tmp_path):
    orch, _audit = make_orchestrator(tmp_path, mode="mock")
    orch.run(ALERT, run_id="r-llm")

    payload = json.loads((tmp_path / "runs" / "r-llm.json").read_text())
    stages = [request["stage"] for request in payload["llm_requests"]]
    assert stages.count("investigation") == 3  # 2 tool turns + the final turn
    assert stages.count("adjudication") == 1
    for request in payload["llm_requests"]:
        assert isinstance(request["seconds"], (int, float))
        assert request["seconds"] >= 0


def test_trace_holds_the_full_dossier_and_report(tmp_path):
    orch, _audit = make_orchestrator(tmp_path, mode="mock")
    orch.run(ALERT, run_id="r-full")

    payload = json.loads((tmp_path / "runs" / "r-full.json").read_text())
    assert payload["dossier"]["user_principal_name"] == ALICE
    assert payload["dossier"]["sign_in_history"]
    assert payload["report"]["narrative"] == _report_json()["narrative"]
    step = payload["report"]["containment_steps"][0]
    assert step["step"] and step["rollback"]


def _report_json() -> dict:
    return json.loads(_report())


def test_trace_records_the_analysts_answers(tmp_path):
    reviewer = ScriptedReviewer(
        answers=[AskUserResult("answered", "expected travel", 1, False)]
    )
    responses = [
        _report(verdict="INSUFFICIENT_DATA", confidence=0.5, techniques=[]),
        _report(verdict="INSUFFICIENT_DATA", confidence=0.5, techniques=[]),
    ]
    orch, _audit = make_orchestrator(
        tmp_path, mode="mock", responses=responses, reviewer=reviewer
    )
    orch.run(ALERT, run_id="r-ask")

    payload = json.loads((tmp_path / "runs" / "r-ask.json").read_text())
    assert payload["analyst_answers"][0]["status"] == "answered"
    assert payload["analyst_answers"][0]["answer"] == "expected travel"


# --- run audit line ---------------------------------------------------------


def test_run_line_has_model_mode_and_trace_path(tmp_path):
    orch, audit = make_orchestrator(tmp_path, mode="live", dirty=False)
    result = orch.run(ALERT, run_id="r-line")

    run = next(e for e in run_entries(audit) if e["event"] == "run")
    assert run["model"] == "test/model"
    assert run["mode"] == "live"
    assert run["trace_path"] == str(tmp_path / "runs" / "r-line.json")
    assert Path(run["trace_path"]).exists()
    assert result.trace_path == Path(run["trace_path"])


def test_run_line_has_a_commit_field_and_a_plain_mode(tmp_path):
    orch, audit = make_orchestrator(tmp_path, mode="live", dirty=False)
    orch.run(ALERT, run_id="r-commit")

    run = next(e for e in run_entries(audit) if e["event"] == "run")
    assert run["mode"] == "live"
    assert re.fullmatch(r"[0-9a-f]{7,40}", run["commit"])


def test_commit_gets_dirty_but_mode_stays_plain(tmp_path):
    orch, _audit = make_orchestrator(tmp_path, mode="mock", dirty=True)
    orch.run(ALERT, run_id="r-commit-dirty")

    run = next(
        e for e in run_entries(tmp_path / "audit-mock.jsonl") if e["event"] == "run"
    )
    assert run["mode"] == "mock"
    assert run["commit"].endswith("+dirty")


def test_default_mode_is_unknown(tmp_path):
    orch = Orchestrator(
        make_investigator(),
        Adjudicator(CompleteLLM([_report()])),
        ScriptedReviewer(),
        audit_log=tmp_path / "audit.jsonl",
        dirty=False,
        model="test/model",
    )
    orch.run(ALERT, run_id="r-default")

    run = next(
        e for e in run_entries(tmp_path / "audit.jsonl") if e["event"] == "run"
    )
    assert run["mode"] == "unknown"


def test_trace_is_written_on_failure_with_an_error_field(tmp_path):
    class RaisingAdjudicator:
        def __init__(self) -> None:
            self.trace = None

        def adjudicate(self, dossier, stage="adjudication"):
            raise RuntimeError("model exploded")

    orch = Orchestrator(
        make_investigator(),
        RaisingAdjudicator(),
        ScriptedReviewer(),
        audit_log=tmp_path / "audit.jsonl",
        mode="mock",
        dirty=False,
        model="test/model",
    )
    with pytest.raises(RuntimeError):
        orch.run(ALERT, run_id="r-fail")

    payload = json.loads((tmp_path / "runs" / "r-fail.json").read_text())
    assert payload["error"] == "RuntimeError"
    assert payload["dossier"] is not None
    assert payload["report"] is None


def test_tool_error_is_recorded_as_the_exception_class(tmp_path):
    def exploding_tool(name, arguments):
        raise ValueError("no such tool")

    investigator = Investigator(
        ScriptedToolLLM(
            [
                {
                    "action": "tool",
                    "tool": "get_user_profile",
                    "arguments": {"upn": ALICE},
                },
                {"action": "final"},
            ]
        ),
        tool_executor=exploding_tool,
    )
    orch = Orchestrator(
        investigator,
        Adjudicator(CompleteLLM([_report()])),
        ScriptedReviewer(),
        audit_log=tmp_path / "audit.jsonl",
        mode="mock",
        dirty=False,
        model="test/model",
    )
    with pytest.raises(ValueError):
        orch.run(ALERT, run_id="r-tool-error")

    payload = json.loads((tmp_path / "runs" / "r-tool-error.json").read_text())
    call = payload["tool_calls"][0]
    assert call["error"] == "ValueError"
    assert "rows" not in call


# --- mock / offline audit file ---------------------------------------------


@pytest.mark.parametrize(
    "mode,written,not_written",
    [
        ("live", "audit.jsonl", "audit-mock.jsonl"),
        ("mock", "audit-mock.jsonl", "audit.jsonl"),
        ("offline", "audit-mock.jsonl", "audit.jsonl"),
    ],
)
def test_mode_picks_the_audit_file(tmp_path, mode, written, not_written):
    orch, _audit = make_orchestrator(tmp_path, mode=mode)
    orch.run(ALERT, run_id=f"r-{mode}")

    assert (tmp_path / written).exists()
    assert not (tmp_path / not_written).exists()


# --- per-request tokens -----------------------------------------------------


def test_trace_records_per_request_tokens_from_the_meter(tmp_path):
    meter = TokenMeter()

    class MeteredCompleteLLM:
        def __init__(self) -> None:
            self.responses = [_report()]

        def complete(self, messages: list[dict]) -> str:
            meter.add(SimpleNamespace(prompt_tokens=100, completion_tokens=10))
            return self.responses.pop(0)

    orch = Orchestrator(
        make_investigator(),
        Adjudicator(MeteredCompleteLLM()),
        ScriptedReviewer(),
        audit_log=tmp_path / "audit.jsonl",
        mode="mock",
        dirty=False,
        model="test/model",
        token_meter=meter,
    )
    orch.run(ALERT, run_id="r-tokens")

    payload = json.loads((tmp_path / "runs" / "r-tokens.json").read_text())
    adjudication = [
        r for r in payload["llm_requests"] if r["stage"] == "adjudication"
    ]
    assert adjudication[0]["tokens_in"] == 100
    assert adjudication[0]["tokens_out"] == 10
