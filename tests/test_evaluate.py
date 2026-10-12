"""Checkpoint 7 — evaluation harness tests (offline, no API key, no network).

The harness drives the real orchestrator; here it is fed fake runners that
spend a known number of "requests" against the shared budget, so the budget,
resume, failure-row, and metric logic can be checked exactly.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

import openai  # noqa: E402

import evaluate  # noqa: E402
from itdr_agent.adjudicator import (  # noqa: E402
    AdjudicatorParseError,
    UnsupportedMitreClaimError,
)
from itdr_agent.schemas import AdjudicatorOutput, Verdict  # noqa: E402

FIXTURES = PROJECT_ROOT / "data" / "fixtures"
MODEL = "test/model:free"
DAY_1 = "2026-10-12"
DAY_2 = "2026-10-13"


# --- helpers ---------------------------------------------------------------


def _alerts():
    return evaluate.load_alerts(FIXTURES / "alerts.jsonl")


def _gt():
    return evaluate.load_ground_truth(FIXTURES / "ground_truth.jsonl")


class FakeClock:
    """Monotonic clock that only moves when the harness sleeps."""

    def __init__(self) -> None:
        self.now = 0.0
        self.stamps: list[float] = []

    def clock(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


def _result(verdict="COMPROMISED", confidence=0.9, techniques=None, evidence=None):
    techniques = techniques if techniques is not None else []
    report = AdjudicatorOutput(
        verdict=Verdict(verdict),
        confidence=confidence,
        narrative=f"narrative for {verdict}",
        containment_steps=[],
        recommended_actions=[],
        mitre_techniques_observed=techniques,
        audit_notes="",
    )
    dossier = SimpleNamespace(
        mitre_attack_evidence={t: ["ev"] for t in (evidence or techniques)}
    )
    return SimpleNamespace(report=report, dossier=dossier, short_circuited=False)


def _truth_runner(requests_per_run=7, raise_on=None, calls=None):
    """Answer every alert with its ground truth, spending N requests.

    ``raise_on`` maps (alert_id, run) -> exception instance raised after the
    requests are spent. ``calls`` collects every (alert_id, run) attempted.
    """
    gt = _gt()
    raise_on = dict(raise_on or {})

    def run(alert, run_index, run_id, budget):
        key = (alert["id"], run_index)
        if calls is not None:
            calls.append(key)
        for _ in range(requests_per_run):
            budget.acquire()
            budget.add_usage(SimpleNamespace(prompt_tokens=100, completion_tokens=10))
        if key in raise_on:
            raise raise_on.pop(key)
        entry = gt[alert["id"]]
        return _result(
            entry["expected_verdict"], 0.9, list(entry["expected_mitre"])
        )

    return run


def _run(tmp_path, runner, *, budget=10_000, today=DAY_1, alerts=None, runs=3):
    clock = FakeClock()
    summary = evaluate.run_evaluation(
        alerts if alerts is not None else _alerts(),
        _gt(),
        runner,
        runs_per_alert=runs,
        eval_dir=tmp_path,
        model=MODEL,
        daily_budget=budget,
        today=lambda: today,
        clock=clock.clock,
        sleep=clock.sleep,
    )
    return summary


def _records(tmp_path):
    path = tmp_path / "raw.jsonl"
    if not path.exists():
        return []
    return [json.loads(l) for l in path.read_text().splitlines() if l.strip()]


def _rate_limit_error():
    request = __import__("httpx").Request("POST", "https://openrouter.ai/api/v1")
    response = __import__("httpx").Response(429, request=request)
    return openai.RateLimitError("rate limited", response=response, body=None)


def _timeout_error():
    request = __import__("httpx").Request("POST", "https://openrouter.ai/api/v1")
    return openai.APITimeoutError(request=request)


# --- full run ---------------------------------------------------------------


def test_full_run_writes_30_records_and_both_files(tmp_path):
    summary = _run(tmp_path, _truth_runner())
    records = _records(tmp_path)
    assert len(records) == 30
    assert {(r["alert_id"], r["run"]) for r in records} == {
        (a["id"], n) for a in _alerts() for n in (1, 2, 3)
    }
    assert summary.stopped_reason is None
    assert summary.pending == 0
    results = (tmp_path / "results.md").read_text()
    for section in (
        "Exact verdict accuracy",
        "Attack-vs-benign detection",
        "False positives",
        "MITRE precision",
        "MITRE recall",
        "Multi-run agreement",
        "Failure table",
        MODEL,
    ):
        assert section in results


def test_each_record_has_required_fields_and_unique_run_id(tmp_path):
    _run(tmp_path, _truth_runner())
    records = _records(tmp_path)
    for record in records:
        for key in (
            "alert_id",
            "run",
            "run_id",
            "model",
            "verdict",
            "confidence",
            "mitre_techniques_observed",
            "tokens_in",
            "tokens_out",
            "seconds",
            "llm_requests",
            "error",
        ):
            assert key in record
        assert record["llm_requests"] == 7
        assert record["tokens_in"] == 700 and record["tokens_out"] == 70
    assert len({r["run_id"] for r in records}) == 30


def test_eval_reviewer_approves_steps_and_cancels_questions():
    reviewer = evaluate.make_eval_reviewer()
    assert reviewer.review_step(0, "Disable the account", "Re-enable").decision == "approve"
    answer = reviewer.ask("Context?", [{"label": "a"}], True)
    assert answer.status == "cancelled"
    assert answer.answer == "no decision has been supplied"
    assert answer.choice_index is None


# --- failure rows, never crashes ------------------------------------------


@pytest.mark.parametrize(
    "exc, kind",
    [
        (UnsupportedMitreClaimError("MITRE techniques without dossier evidence: ['T9999']"), "mitre_rejection"),
        (AdjudicatorParseError("Expecting value"), "invalid_json"),
        (json.JSONDecodeError("Expecting value", "", 0), "invalid_json"),
        (_timeout_error(), "timeout"),
        (TimeoutError("took too long"), "timeout"),
    ],
)
def test_failure_becomes_a_record_and_other_runs_continue(tmp_path, exc, kind):
    runner = _truth_runner(raise_on={("ALERT_002", 2): exc})
    summary = _run(tmp_path, runner)
    records = _records(tmp_path)
    assert len(records) == 30  # the failed run is complete, nothing crashed
    failed = [r for r in records if r["error"]]
    assert len(failed) == 1
    assert failed[0]["alert_id"] == "ALERT_002" and failed[0]["run"] == 2
    assert failed[0]["error"] == kind
    assert failed[0]["verdict"] is None
    assert summary.stopped_reason is None
    rows = evaluate.build_failure_rows(records, _gt())
    row = next(r for r in rows if r["alert_id"] == "ALERT_002" and r["run"] == 2)
    assert row["what"] and row["why"]


def test_rate_limit_stops_leaves_run_pending_and_resumes(tmp_path):
    calls: list = []
    runner = _truth_runner(raise_on={("ALERT_004", 1): _rate_limit_error()}, calls=calls)
    summary = _run(tmp_path, runner)
    assert summary.stopped_reason == "rate_limited"
    records = _records(tmp_path)
    assert ("ALERT_004", 1) not in {(r["alert_id"], r["run"]) for r in records}
    assert len(records) == 9  # ALERT_001..003 x 3
    interruptions = (tmp_path / "interruptions.jsonl").read_text().splitlines()
    assert len(interruptions) == 1
    assert json.loads(interruptions[0])["error"] == "rate_limited"
    assert "rate_limited" in (tmp_path / "results.md").read_text()

    # next session: same runner (the 429 was consumed), resumes exactly
    calls.clear()
    summary = _run(tmp_path, runner, today=DAY_2)
    records = _records(tmp_path)
    assert len(records) == 30
    assert calls[0] == ("ALERT_004", 1)
    assert len(calls) == 21  # no finished run is redone
    assert summary.stopped_reason is None


def test_auth_or_credit_error_stops_without_recording(tmp_path):
    request = __import__("httpx").Request("POST", "https://openrouter.ai/api/v1")
    response = __import__("httpx").Response(402, request=request)
    exc = openai.APIStatusError("payment required", response=response, body=None)
    summary = _run(tmp_path, _truth_runner(raise_on={("ALERT_001", 1): exc}))
    assert summary.stopped_reason.startswith("fatal")
    assert _records(tmp_path) == []


# --- daily budget ---------------------------------------------------------


def test_daily_budget_is_never_exceeded_and_resets_next_day(tmp_path):
    summary = _run(tmp_path, _truth_runner(requests_per_run=7), budget=45)
    assert summary.stopped_reason == "daily_budget"
    state = json.loads((tmp_path / "state.json").read_text())
    assert state["day"] == DAY_1
    assert state["requests_today"] <= 45
    # A run may only start with room for the worst case left.
    assert state["requests_today"] + evaluate.MAX_REQUESTS_PER_RUN > 45
    first_day = len(_records(tmp_path))
    assert first_day == 6

    # Same day again: nothing more may run.
    summary = _run(tmp_path, _truth_runner(requests_per_run=7), budget=45)
    assert len(_records(tmp_path)) == first_day

    # Next UTC day: the counter resets and the run continues.
    summary = _run(tmp_path, _truth_runner(requests_per_run=7), budget=45, today=DAY_2)
    state = json.loads((tmp_path / "state.json").read_text())
    assert state["day"] == DAY_2 and state["requests_today"] <= 45
    assert len(_records(tmp_path)) == 12


def test_budget_hard_guard_leaves_run_pending(tmp_path):
    budget = evaluate.RequestBudget(daily_budget=3, used_today=0)
    budget.acquire()
    budget.acquire()
    budget.acquire()
    with pytest.raises(evaluate.BudgetExhausted):
        budget.acquire()
    # A runner that blows through the budget mid-run is not recorded.
    summary = _run(
        tmp_path,
        _truth_runner(requests_per_run=50),
        budget=45,
    )
    assert summary.stopped_reason == "daily_budget"
    assert _records(tmp_path) == []


def test_requests_spent_by_failed_runs_are_counted(tmp_path):
    runner = _truth_runner(
        requests_per_run=3,
        raise_on={("ALERT_001", 1): AdjudicatorParseError("bad")},
    )
    _run(tmp_path, runner, alerts=[_alerts()[0]], runs=1)
    state = json.loads((tmp_path / "state.json").read_text())
    assert state["requests_today"] == 3
    assert _records(tmp_path)[0]["llm_requests"] == 3


def test_request_spacing_keeps_under_20_per_minute():
    clock = FakeClock()
    budget = evaluate.RequestBudget(
        daily_budget=1000, used_today=0, clock=clock.clock, sleep=clock.sleep
    )
    stamps = []
    for _ in range(45):
        budget.acquire()
        stamps.append(clock.now)
    for start in stamps:
        in_window = [t for t in stamps if start <= t <= start + 60]
        assert len(in_window) <= evaluate.MAX_REQUESTS_PER_MINUTE


def test_live_client_has_sdk_retries_disabled():
    client = evaluate.make_openrouter_client("sk-or-v1-test", timeout=30)
    assert client.max_retries == 0
    assert str(client.base_url).startswith("https://openrouter.ai/api/v1")


def test_estimate_days_reserves_worst_case_room():
    # 7 requests per run, budget 45, reserve 10: a run starts only while
    # used + 10 <= 45, so 6 runs (42 requests) fit per day.
    assert evaluate.estimate_days([7] * 30, daily_budget=45) == 5
    assert evaluate.estimate_days([7] * 6, daily_budget=45) == 1
    assert evaluate.estimate_days([evaluate.MAX_REQUESTS_PER_RUN] * 30, daily_budget=45) == 8


# --- metrics (pure) ---------------------------------------------------------


def _rec(alert_id, run, verdict, techniques=(), error=None, dossier_mitre=None):
    return {
        "alert_id": alert_id,
        "run": run,
        "run_id": f"{alert_id}-{run}",
        "model": MODEL,
        "verdict": verdict,
        "confidence": 0.9 if verdict else None,
        "mitre_techniques_observed": list(techniques),
        "dossier_mitre": dossier_mitre if dossier_mitre is not None else list(techniques),
        "tokens_in": 100,
        "tokens_out": 10,
        "seconds": 2.0,
        "llm_requests": 5,
        "error": error,
        "error_detail": "boom" if error else None,
        "narrative": "n",
        "audit_notes": "",
    }


GT = {
    "A1": {"alert_id": "A1", "scenario": "x", "expected_verdict": "COMPROMISED", "expected_mitre": ["T1621"], "is_benign": False},
    "B1": {"alert_id": "B1", "scenario": "y", "expected_verdict": "FALSE_POSITIVE", "expected_mitre": [], "is_benign": True},
    "T1": {"alert_id": "T1", "scenario": "thin", "expected_verdict": "INSUFFICIENT_DATA", "expected_mitre": [], "is_benign": False},
}


def test_exact_accuracy_counts_failed_runs_as_wrong():
    records = [
        _rec("A1", 1, "COMPROMISED", ["T1621"]),
        _rec("A1", 2, "SUSPICIOUS", ["T1621"]),
        _rec("A1", 3, None, error="timeout"),
        _rec("B1", 1, "FALSE_POSITIVE"),
    ]
    m = evaluate.compute_metrics(records, GT)
    assert m["total_runs"] == 4
    assert m["scored_runs"] == 3
    assert m["verdict_accuracy"] == pytest.approx(2 / 4)
    assert m["verdict_accuracy_scored"] == pytest.approx(2 / 3)
    assert m["failed_runs"] == 1


def test_majority_of_three_with_tie_counts_as_wrong():
    records = [
        _rec("A1", 1, "COMPROMISED"), _rec("A1", 2, "COMPROMISED"), _rec("A1", 3, "SUSPICIOUS"),
        _rec("B1", 1, "FALSE_POSITIVE"), _rec("B1", 2, "SUSPICIOUS"),  # tie -> wrong
        _rec("T1", 1, "SUSPICIOUS"), _rec("T1", 2, "SUSPICIOUS"), _rec("T1", 3, "INSUFFICIENT_DATA"),
    ]
    m = evaluate.compute_metrics(records, GT)
    assert m["majority_accuracy"] == pytest.approx(1 / 3)
    per = {row["alert_id"]: row for row in m["per_alert"]}
    assert per["A1"]["majority"] == "COMPROMISED" and per["A1"]["majority_correct"]
    assert per["B1"]["majority"] is None and not per["B1"]["majority_correct"]


def test_attack_vs_benign_detection_excludes_insufficient_data_alerts():
    records = [
        _rec("A1", 1, "SUSPICIOUS"),        # attack called suspicious: detected
        _rec("A1", 2, "FALSE_POSITIVE"),    # missed attack
        _rec("B1", 1, "FALSE_POSITIVE"),    # correct benign
        _rec("B1", 2, "INSUFFICIENT_DATA"), # benign, not flagged: correct
        _rec("T1", 1, "COMPROMISED"),       # thin-data alert: not in detection
    ]
    m = evaluate.compute_metrics(records, GT)
    assert m["detection_runs"] == 4
    assert m["detection_accuracy"] == pytest.approx(3 / 4)


def test_false_positives_count_benign_runs_flagged_as_attack():
    records = [
        _rec("B1", 1, "COMPROMISED"),
        _rec("B1", 2, "SUSPICIOUS"),
        _rec("B1", 3, "FALSE_POSITIVE"),
        _rec("A1", 1, "COMPROMISED"),
    ]
    m = evaluate.compute_metrics(records, GT)
    assert m["false_positives"] == 2
    assert m["benign_runs"] == 3


def test_mitre_precision_and_recall():
    records = [
        _rec("A1", 1, "COMPROMISED", ["T1621"]),               # TP 1
        _rec("A1", 2, "COMPROMISED", ["T1621", "T1078.004"]),  # TP 1, FP 1
        _rec("A1", 3, "COMPROMISED", []),                      # FN 1
        _rec("B1", 1, "FALSE_POSITIVE", ["T1090.003"]),        # FP 1
        _rec("A1", 4, None, error="invalid_json"),             # not scored
    ]
    m = evaluate.compute_metrics(records, GT)
    assert m["mitre_tp"] == 2 and m["mitre_fp"] == 2 and m["mitre_fn"] == 1
    assert m["mitre_precision"] == pytest.approx(2 / 4)
    assert m["mitre_recall"] == pytest.approx(2 / 3)


def test_mitre_precision_is_none_without_predictions():
    m = evaluate.compute_metrics([_rec("B1", 1, "FALSE_POSITIVE")], GT)
    assert m["mitre_precision"] is None
    assert m["mitre_recall"] is None


def test_multi_run_agreement_counts_errors_as_an_outcome():
    records = [
        _rec("A1", 1, "COMPROMISED"), _rec("A1", 2, "COMPROMISED"), _rec("A1", 3, None, error="timeout"),
        _rec("B1", 1, "FALSE_POSITIVE"), _rec("B1", 2, "FALSE_POSITIVE"), _rec("B1", 3, "FALSE_POSITIVE"),
        _rec("T1", 1, "INSUFFICIENT_DATA"),  # single run: not counted
    ]
    m = evaluate.compute_metrics(records, GT)
    assert m["multi_run_agreement"] == pytest.approx(((2 / 3) + 1.0) / 2)


def test_tokens_seconds_and_requests_totals_and_means():
    records = [_rec("A1", 1, "COMPROMISED"), _rec("A1", 2, None, error="timeout")]
    m = evaluate.compute_metrics(records, GT)
    assert m["tokens_in_total"] == 200 and m["tokens_out_total"] == 20
    assert m["tokens_in_mean"] == pytest.approx(100)
    assert m["seconds_mean"] == pytest.approx(2.0)
    assert m["requests_total"] == 10


# --- failure table ----------------------------------------------------------


def test_failure_rows_name_alert_failure_and_cause():
    records = [
        _rec("A1", 1, "FALSE_POSITIVE", [], dossier_mitre=["T1621"]),
        _rec("A1", 2, "COMPROMISED", [], dossier_mitre=[]),
        _rec("B1", 1, "FALSE_POSITIVE", ["T1090.003"]),
        _rec("T1", 1, None, error="mitre_rejection"),
        _rec("A1", 3, "COMPROMISED", ["T1621"]),  # fully correct: no row
    ]
    rows = evaluate.build_failure_rows(records, GT)
    by = {(r["alert_id"], r["run"], r["what"]): r for r in rows}
    assert ("A1", 1, "expected COMPROMISED, got FALSE_POSITIVE") in by
    missing_adj = by[("A1", 1, "missing technique T1621")]
    assert "Adjudicator" in missing_adj["why"]
    missing_inv = by[("A1", 2, "missing technique T1621")]
    assert "Investigator" in missing_inv["why"]
    assert ("B1", 1, "unexpected technique T1090.003") in by
    err = next(r for r in rows if r["alert_id"] == "T1")
    assert "MITRE" in err["what"] and err["why"] == "boom"
    assert not any(r["alert_id"] == "A1" and r["run"] == 3 for r in rows)


def test_results_md_escapes_pipes_and_flags_partial_runs(tmp_path):
    records = [_rec("A1", 1, None, error="invalid_json")]
    records[0]["error_detail"] = "bad | table\nbreak"
    evaluate.write_results_md(
        tmp_path / "results.md",
        records,
        [],
        GT,
        model=MODEL,
        runs_per_alert=3,
        daily_budget=45,
        dry_run=False,
    )
    text = (tmp_path / "results.md").read_text()
    assert "PARTIAL" in text
    assert "bad \\| table break" in text
    assert "scripted reviewer" in text.lower()


def test_generated_files_hold_no_secrets(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-v1-" + "a" * 64)
    _run(tmp_path, _truth_runner())
    for path in tmp_path.rglob("*"):
        if path.is_file():
            assert "sk-or-" not in path.read_text()


# --- CLI ---------------------------------------------------------------------


def test_dry_run_is_offline_and_prints_days(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)

    def no_network(*args, **kwargs):
        raise AssertionError("dry run must not build a network client")

    monkeypatch.setattr(evaluate, "make_openrouter_client", no_network)
    code = evaluate.main(["--dry-run", "--eval-dir", str(tmp_path)])
    out = capsys.readouterr().out
    assert code == 0
    assert "Estimated days" in out
    dry = tmp_path / "dry_run"
    assert len((dry / "raw.jsonl").read_text().splitlines()) == 30
    assert "DRY RUN" in (dry / "results.md").read_text()
    assert not (tmp_path / "raw.jsonl").exists()  # real results untouched


def test_live_run_requires_explicit_flag_and_key(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.setattr(evaluate.config, "OPENROUTER_API_KEY", None)
    assert evaluate.main(["--eval-dir", str(tmp_path)]) == 2
    assert evaluate.main(["--live", "--eval-dir", str(tmp_path)]) == 2
    assert "OPENROUTER_API_KEY" in capsys.readouterr().out


# --- live wiring (fake OpenAI client, no network) ----------------------------


class _FakeCompletions:
    """Scripted OpenAI-style client: tool turns, then an Adjudicator reply."""

    def __init__(self, contents: list[str]) -> None:
        self.contents = list(contents)
        self.kwargs: list[dict] = []

    def create(self, **kwargs):
        self.kwargs.append(kwargs)
        message = SimpleNamespace(content=self.contents.pop(0))
        return SimpleNamespace(
            choices=[SimpleNamespace(message=message)],
            usage=SimpleNamespace(prompt_tokens=1000, completion_tokens=50),
        )


def test_live_runner_drives_real_orchestrator_and_counts_every_request(
    tmp_path, monkeypatch
):
    alert = next(a for a in _alerts() if a["id"] == "ALERT_001")
    upn = alert["userPrincipalName"]
    report = {
        "verdict": "COMPROMISED",
        "confidence": 0.9,
        "narrative": "Unlikely travel from New York to Moscow.",
        "containment_steps": [{"step": "Disable the account", "rollback": "Re-enable it"}],
        "recommended_actions": [],
        "mitre_techniques_observed": ["T1078.004"],
        "audit_notes": "",
    }
    completions = _FakeCompletions(
        [
            json.dumps({"action": "tool", "tool": "get_user_profile", "arguments": {"upn": upn}}),
            json.dumps({"action": "tool", "tool": "get_sign_in_history", "arguments": {"upn": upn, "hours": 10000}}),
            json.dumps({"action": "final"}),
            json.dumps(report),
        ]
    )
    client = SimpleNamespace(chat=SimpleNamespace(completions=completions))
    monkeypatch.setattr(evaluate, "make_openrouter_client", lambda key, timeout: client)

    runner = evaluate.make_live_runner("sk-or-v1-test", MODEL, 30, tmp_path / "audit.jsonl")
    _run(tmp_path, runner, alerts=[alert], runs=1)

    record = _records(tmp_path)[0]
    assert record["verdict"] == "COMPROMISED"
    assert record["mitre_techniques_observed"] == ["T1078.004"]
    assert "T1078.004" in record["dossier_mitre"]
    assert record["llm_requests"] == 4  # 3 Investigator turns + 1 Adjudicator
    assert record["tokens_in"] == 4000 and record["tokens_out"] == 200
    state = json.loads((tmp_path / "state.json").read_text())
    assert state["requests_today"] == 4
    assert all(k["model"] == MODEL and k["temperature"] == 0 for k in completions.kwargs)
    audit = [json.loads(l) for l in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert audit and all(e["run_id"] == record["run_id"] for e in audit)


# --- review fixes: config errors stop, infrastructure errors skip, full plan --


def _status_error(code):
    request = __import__("httpx").Request("POST", "https://openrouter.ai/api/v1")
    response = __import__("httpx").Response(code, request=request)
    return openai.APIStatusError(f"status {code}", response=response, body=None)


@pytest.mark.parametrize("code", [400, 404])
def test_model_config_errors_stop_without_recording(tmp_path, code):
    summary = _run(tmp_path, _truth_runner(raise_on={("ALERT_001", 1): _status_error(code)}))
    assert summary.stopped_reason == f"fatal:{code}"
    assert _records(tmp_path) == []


def test_server_and_connection_errors_skip_the_run_and_continue(tmp_path):
    request = __import__("httpx").Request("POST", "https://openrouter.ai/api/v1")
    runner = _truth_runner(
        raise_on={
            ("ALERT_002", 1): _status_error(502),
            ("ALERT_003", 2): openai.APIConnectionError(request=request),
        }
    )
    summary = _run(tmp_path, runner)
    keys = {(r["alert_id"], r["run"]) for r in _records(tmp_path)}
    assert len(keys) == 28
    assert ("ALERT_002", 1) not in keys and ("ALERT_003", 2) not in keys
    assert summary.stopped_reason is None
    assert summary.pending == 2
    kinds = [json.loads(l)["error"] for l in (tmp_path / "interruptions.jsonl").read_text().splitlines()]
    assert kinds == ["api_error:502", "connection_error"]
    _run(tmp_path, runner, today=DAY_2)
    assert len(_records(tmp_path)) == 30


def test_subset_run_reports_against_the_full_plan(tmp_path):
    first = _alerts()[0]
    summary = evaluate.run_evaluation(
        _alerts(), _gt(), _truth_runner(),
        runs_per_alert=1, eval_dir=tmp_path, model=MODEL, daily_budget=10_000,
        today=lambda: DAY_1, clock=FakeClock().clock, sleep=lambda s: None,
        only={first["id"]},
    )
    assert len(_records(tmp_path)) == 1
    assert summary.pending == 29
    assert "1 of 30" in (tmp_path / "results.md").read_text()
