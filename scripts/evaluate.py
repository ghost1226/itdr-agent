"""Checkpoint 7 — evaluation harness.

Runs every alert through the **real orchestrator** several times and scores
the results against ``data/fixtures/ground_truth.jsonl`` (read only here and
in tests, never by the agents).

    python scripts/evaluate.py --dry-run     # offline, no key, no network
    python scripts/evaluate.py --live        # real free model (Joe's go only)

Scoring uses a scripted reviewer that approves every containment step and
cancels every ``ask_user`` question, so no human is in the loop and the
re-adjudication path never runs during scoring.

OpenRouter free-tier limits (50 requests/day without purchased credits,
20 requests/minute) are respected by a shared ``RequestBudget``:

* every model request is counted before it is sent (failed runs count too);
* requests are spaced so no 60-second window holds more than 20;
* a run only starts if the worst case (``MAX_REQUESTS_PER_RUN``) still fits
  under the daily budget (default 45, below the 50 cap);
* the OpenAI SDK's own retries are off, so one call is one request.

``eval/raw.jsonl`` gets one line per finished run and is the resume point:
a later session skips every (alert, run) already in it. A 429, the budget,
or an auth/credit error stops the session and leaves that run pending
(logged in ``eval/interruptions.jsonl``); it is retried next session.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import time
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from itdr_agent import config  # noqa: E402
from itdr_agent.adjudicator import (  # noqa: E402
    DEFAULT_MODEL,
    Adjudicator,
    AdjudicatorParseError,
    UnsupportedMitreClaimError,
)
from itdr_agent.human import ScriptedReviewer  # noqa: E402
from itdr_agent.investigator import MAX_TOOL_CALLS, Investigator  # noqa: E402
from itdr_agent.orchestrator import Orchestrator  # noqa: E402

RUNS_PER_ALERT = 3
DEFAULT_DAILY_BUDGET = 45  # OpenRouter free tier allows 50/day
MAX_REQUESTS_PER_MINUTE = 20
# 3.1 s apart keeps any inclusive 60-second window at 20 requests or fewer.
REQUEST_SPACING_SECONDS = 3.1
# Investigator: up to MAX_TOOL_CALLS tool turns + the turn that hits the cap
# or says "final". Adjudicator: one call. The scripted reviewer always
# cancels, so the re-adjudication call never happens during scoring.
MAX_REQUESTS_PER_RUN = MAX_TOOL_CALLS + 1 + 1
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
ATTACK_VERDICTS = {"COMPROMISED", "SUSPICIOUS"}
ERROR_OUTCOME = "ERROR"
TEXT_LIMIT = 300

FIXTURES = PROJECT_ROOT / "data" / "fixtures"


# --- loading ---------------------------------------------------------------


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def load_alerts(path: Path) -> list[dict[str, Any]]:
    return _read_jsonl(Path(path))


def load_ground_truth(path: Path) -> dict[str, dict[str, Any]]:
    return {entry["alert_id"]: entry for entry in _read_jsonl(Path(path))}


def _utc_today() -> str:
    return datetime.now(timezone.utc).date().isoformat()


def _clip(text: Any) -> str | None:
    if text is None:
        return None
    text = " ".join(str(text).split())
    return text if len(text) <= TEXT_LIMIT else text[: TEXT_LIMIT - 3] + "..."


# --- request budget ----------------------------------------------------------


class BudgetExhausted(Exception):
    """The daily request budget is used up."""


class RequestBudget:
    """Counts and paces every model request for one session."""

    def __init__(
        self,
        daily_budget: int,
        used_today: int = 0,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        spacing: float = REQUEST_SPACING_SECONDS,
    ) -> None:
        self.daily_budget = daily_budget
        self.used_today = used_today
        self._clock = clock
        self._sleep = sleep
        self._spacing = spacing
        self._last: float | None = None
        self.start_run()

    def start_run(self) -> None:
        self.run_requests = 0
        self.run_tokens_in = 0
        self.run_tokens_out = 0

    def can_start_run(self) -> bool:
        return self.used_today + MAX_REQUESTS_PER_RUN <= self.daily_budget

    def acquire(self) -> None:
        """Call before every model request."""
        if self.used_today >= self.daily_budget:
            raise BudgetExhausted(
                f"daily budget of {self.daily_budget} requests used"
            )
        if self._last is not None:
            wait = self._spacing - (self._clock() - self._last)
            if wait > 0:
                self._sleep(wait)
        self._last = self._clock()
        self.used_today += 1
        self.run_requests += 1

    def add_usage(self, usage: Any) -> None:
        if usage is None:
            return
        self.run_tokens_in += int(getattr(usage, "prompt_tokens", 0) or 0)
        self.run_tokens_out += int(getattr(usage, "completion_tokens", 0) or 0)


# --- runners -----------------------------------------------------------------


def make_eval_reviewer() -> ScriptedReviewer:
    """Approves every containment step and cancels every question."""
    return ScriptedReviewer()


def make_openrouter_client(api_key: str, timeout: int):
    from openai import OpenAI

    # max_retries=0: an SDK retry would be a second request against the cap.
    return OpenAI(
        base_url=OPENROUTER_BASE_URL,
        api_key=api_key,
        timeout=timeout,
        max_retries=0,
    )


def _chat(client: Any, model: str, budget: RequestBudget, messages: list) -> str:
    budget.acquire()
    response = client.chat.completions.create(
        model=model,
        messages=messages,
        temperature=0,
        response_format={"type": "json_object"},
    )
    budget.add_usage(getattr(response, "usage", None))
    return response.choices[0].message.content or ""


class _LiveInvestigatorLLM:
    def __init__(self, client: Any, model: str, budget: RequestBudget) -> None:
        self.client, self.model, self.budget = client, model, budget

    def next_action(self, messages: list[dict]) -> dict[str, Any]:
        return json.loads(_chat(self.client, self.model, self.budget, messages) or "{}")


class _LiveAdjudicatorLLM:
    def __init__(self, client: Any, model: str, budget: RequestBudget) -> None:
        self.client, self.model, self.budget = client, model, budget

    def complete(self, messages: list[dict]) -> str:
        return _chat(self.client, self.model, self.budget, messages)


def make_live_runner(api_key: str, model: str, timeout: int, audit_log: Path):
    client = make_openrouter_client(api_key, timeout)

    def run(alert, run_index, run_id, budget):
        orchestrator = Orchestrator(
            Investigator(_LiveInvestigatorLLM(client, model, budget)),
            Adjudicator(_LiveAdjudicatorLLM(client, model, budget)),
            make_eval_reviewer(),
            audit_log=audit_log,
            timeout_seconds=timeout,
        )
        return orchestrator.run(alert, run_id=run_id)

    return run


class _CountingToolLLM:
    """Wraps the offline scripted tool LLM so each turn counts as a request."""

    def __init__(self, inner: Any, budget: RequestBudget) -> None:
        self.inner, self.budget = inner, budget

    def next_action(self, messages: list[dict]) -> dict[str, Any]:
        self.budget.acquire()
        return self.inner.next_action(messages)


class _OfflineReportLLM:
    def __init__(self, response: str, budget: RequestBudget) -> None:
        self.response, self.budget = response, budget

    def complete(self, messages: list[dict]) -> str:
        self.budget.acquire()
        return self.response


def make_offline_runner(ground_truth: dict[str, dict], audit_log: Path):
    """Dry run: the real orchestrator with scripted, offline model stand-ins.

    The stand-in Adjudicator answers with the ground-truth verdict, so dry-run
    scores measure the harness, not a model.
    """
    import samples  # scripts/samples.py (reads ground truth; scripts only)

    def run(alert, run_index, run_id, budget):
        alert_id = alert["id"]
        investigator, _ = samples.build_investigator(alert_id)
        investigator.llm = _CountingToolLLM(investigator.llm, budget)
        dossier, _ = samples.build_dossier(alert_id)
        entry = ground_truth[alert_id]
        reply = samples.build_mock_report(
            dossier, entry["scenario"], entry["expected_verdict"]
        )
        orchestrator = Orchestrator(
            investigator,
            Adjudicator(_OfflineReportLLM(reply, budget)),
            make_eval_reviewer(),
            audit_log=audit_log,
        )
        return orchestrator.run(alert, run_id=run_id)

    return run


# --- error handling ---------------------------------------------------------


def classify_error(exc: BaseException) -> tuple[str, str]:
    """Return (kind, action). action: record | pending | fatal."""
    if isinstance(exc, BudgetExhausted):
        return "daily_budget", "pending"
    if isinstance(exc, UnsupportedMitreClaimError):
        return "mitre_rejection", "record"
    if isinstance(exc, (AdjudicatorParseError, json.JSONDecodeError)):
        return "invalid_json", "record"
    try:
        import openai

        if isinstance(exc, openai.APITimeoutError):
            return "timeout", "record"
    except ImportError:  # pragma: no cover
        pass
    if isinstance(exc, TimeoutError):
        return "timeout", "record"
    status = getattr(exc, "status_code", None)
    if status == 429:
        return "rate_limited", "pending"
    if status in (401, 402, 403):
        return f"fatal:{status}", "fatal"
    if status is not None:
        return f"api_error:{status}", "record"
    return f"error:{type(exc).__name__}", "record"


# --- the run loop -----------------------------------------------------------


@dataclass
class SessionSummary:
    completed_this_session: int
    pending: int
    stopped_reason: str | None
    requests_today: int


def _load_state(path: Path) -> dict[str, Any]:
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    return {}


def _save_state(path: Path, day: str, used: int, model: str) -> None:
    path.write_text(
        json.dumps(
            {"day": day, "requests_today": used, "model": model,
             "note": "day is UTC; requests_today counts every request sent"},
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def _append_jsonl(path: Path, record: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, default=str) + "\n")
        handle.flush()


def run_evaluation(
    alerts: list[dict[str, Any]],
    ground_truth: dict[str, dict[str, Any]],
    runner: Callable,
    *,
    runs_per_alert: int,
    eval_dir: Path,
    model: str,
    daily_budget: int,
    today: Callable[[], str] = _utc_today,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
    dry_run: bool = False,
) -> SessionSummary:
    eval_dir = Path(eval_dir)
    eval_dir.mkdir(parents=True, exist_ok=True)
    raw_path = eval_dir / "raw.jsonl"
    state_path = eval_dir / "state.json"
    interruptions_path = eval_dir / "interruptions.jsonl"

    day = today()
    state = _load_state(state_path)
    used = state.get("requests_today", 0) if state.get("day") == day else 0
    budget = RequestBudget(daily_budget, used, clock=clock, sleep=sleep)

    done = {
        (r["alert_id"], r["run"])
        for r in _read_jsonl(raw_path)
        if r.get("model") == model
    }
    todo = [
        (alert, n)
        for alert in alerts
        for n in range(1, runs_per_alert + 1)
        if (alert["id"], n) not in done
    ]

    completed = 0
    stopped: str | None = None
    try:
        for alert, run_index in todo:
            if not budget.can_start_run():
                stopped = "daily_budget"
                break
            budget.start_run()
            wall = time.monotonic()
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
            run_id = f"eval_{alert['id']}_r{run_index}_{stamp}"
            base = {
                "alert_id": alert["id"],
                "run": run_index,
                "run_id": run_id,
                "model": model,
                "day": day,
            }
            try:
                result = runner(alert, run_index, run_id, budget)
            except Exception as exc:  # every failure is data, never a crash
                kind, action = classify_error(exc)
                usage = {
                    "llm_requests": budget.run_requests,
                    "tokens_in": budget.run_tokens_in,
                    "tokens_out": budget.run_tokens_out,
                }
                if action == "record":
                    record = {
                        **base,
                        "verdict": None,
                        "confidence": None,
                        "mitre_techniques_observed": [],
                        "dossier_mitre": None,
                        "short_circuited": None,
                        **usage,
                        "seconds": round(time.monotonic() - wall, 3),
                        "error": kind,
                        "error_detail": _clip(exc),
                        "narrative": None,
                        "audit_notes": None,
                    }
                    _append_jsonl(raw_path, record)
                    completed += 1
                    continue
                _append_jsonl(
                    interruptions_path,
                    {**base, **usage, "error": kind, "error_detail": _clip(exc),
                     "timestamp": datetime.now(timezone.utc).isoformat()},
                )
                stopped = kind
                break
            report = result.report
            dossier = getattr(result, "dossier", None)
            record = {
                **base,
                "verdict": report.verdict.value,
                "confidence": report.confidence,
                "mitre_techniques_observed": list(report.mitre_techniques_observed),
                "dossier_mitre": sorted(
                    getattr(dossier, "mitre_attack_evidence", {}) or {}
                ),
                "short_circuited": getattr(result, "short_circuited", None),
                "llm_requests": budget.run_requests,
                "tokens_in": budget.run_tokens_in,
                "tokens_out": budget.run_tokens_out,
                "seconds": round(time.monotonic() - wall, 3),
                "error": None,
                "error_detail": None,
                "narrative": _clip(report.narrative),
                "audit_notes": _clip(report.audit_notes),
            }
            _append_jsonl(raw_path, record)
            completed += 1
    finally:
        _save_state(state_path, day, budget.used_today, model)

    records = [r for r in _read_jsonl(raw_path) if r.get("model") == model]
    interruptions = [
        r for r in _read_jsonl(interruptions_path) if r.get("model") == model
    ]
    in_scope = {a["id"] for a in alerts}
    write_results_md(
        eval_dir / "results.md",
        records,
        interruptions,
        {k: v for k, v in ground_truth.items() if k in in_scope} or ground_truth,
        model=model,
        runs_per_alert=runs_per_alert,
        daily_budget=daily_budget,
        dry_run=dry_run,
    )
    finished = {(r["alert_id"], r["run"]) for r in records}
    pending = sum(
        1
        for alert in alerts
        for n in range(1, runs_per_alert + 1)
        if (alert["id"], n) not in finished
    )
    return SessionSummary(completed, pending, stopped, budget.used_today)


def estimate_days(per_run_requests: list[int], daily_budget: int) -> int:
    """Days needed when a run starts only with worst-case room left."""
    if not per_run_requests:
        return 0
    days, used = 1, 0
    for requests in per_run_requests:
        if used + MAX_REQUESTS_PER_RUN > daily_budget:
            days += 1
            used = 0
        used += requests
    return days


# --- metrics (pure) ---------------------------------------------------------


def _outcome(record: dict[str, Any]) -> str:
    return record["verdict"] if record.get("verdict") else ERROR_OUTCOME


def _ratio(numerator: float, denominator: float) -> float | None:
    return numerator / denominator if denominator else None


def compute_metrics(
    records: list[dict[str, Any]], ground_truth: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    records = [r for r in records if r["alert_id"] in ground_truth]
    scored = [r for r in records if r.get("verdict")]
    total = len(records)

    exact = sum(
        1 for r in scored if r["verdict"] == ground_truth[r["alert_id"]]["expected_verdict"]
    )

    # Attack vs benign: only alerts labeled attack or benign (the two
    # INSUFFICIENT_DATA alerts test abstention and are scored by exact accuracy).
    detection_correct = detection_runs = 0
    false_positives = benign_runs = 0
    for r in records:
        truth = ground_truth[r["alert_id"]]
        is_attack = truth["expected_verdict"] in ATTACK_VERDICTS and not truth["is_benign"]
        if not (is_attack or truth["is_benign"]):
            continue
        detection_runs += 1
        flagged = r.get("verdict") in ATTACK_VERDICTS
        if r.get("verdict") and flagged == is_attack:
            detection_correct += 1
        if truth["is_benign"]:
            benign_runs += 1
            if flagged:
                false_positives += 1

    tp = fp = fn = 0
    for r in scored:
        expected = set(ground_truth[r["alert_id"]].get("expected_mitre", []))
        observed = set(r.get("mitre_techniques_observed") or [])
        tp += len(expected & observed)
        fp += len(observed - expected)
        fn += len(expected - observed)

    groups: dict[str, list[dict[str, Any]]] = {}
    for r in sorted(records, key=lambda x: (x["alert_id"], x["run"])):
        groups.setdefault(r["alert_id"], []).append(r)

    per_alert = []
    majority_correct = 0
    agreements = []
    for alert_id in sorted(groups):
        runs = groups[alert_id]
        counts = Counter(_outcome(r) for r in runs).most_common()
        top = counts[0][1]
        tied = len(counts) > 1 and counts[1][1] == top
        majority = None if tied else counts[0][0]
        expected = ground_truth[alert_id]["expected_verdict"]
        correct = majority == expected
        majority_correct += int(correct)
        if len(runs) >= 2:
            agreements.append(top / len(runs))
        per_alert.append(
            {
                "alert_id": alert_id,
                "scenario": ground_truth[alert_id]["scenario"],
                "expected": expected,
                "outcomes": [_outcome(r) for r in runs],
                "majority": majority,
                "majority_correct": correct,
            }
        )

    def total_of(key: str) -> float:
        return sum((r.get(key) or 0) for r in records)

    return {
        "total_runs": total,
        "scored_runs": len(scored),
        "failed_runs": total - len(scored),
        "verdict_accuracy": _ratio(exact, total),
        "verdict_accuracy_scored": _ratio(exact, len(scored)),
        "majority_accuracy": _ratio(majority_correct, len(groups)),
        "detection_accuracy": _ratio(detection_correct, detection_runs),
        "detection_runs": detection_runs,
        "false_positives": false_positives,
        "benign_runs": benign_runs,
        "mitre_tp": tp,
        "mitre_fp": fp,
        "mitre_fn": fn,
        "mitre_precision": _ratio(tp, tp + fp),
        "mitre_recall": _ratio(tp, tp + fn),
        "multi_run_agreement": _ratio(sum(agreements), len(agreements)),
        "tokens_in_total": int(total_of("tokens_in")),
        "tokens_out_total": int(total_of("tokens_out")),
        "tokens_in_mean": _ratio(total_of("tokens_in"), total),
        "tokens_out_mean": _ratio(total_of("tokens_out"), total),
        "seconds_total": total_of("seconds"),
        "seconds_mean": _ratio(total_of("seconds"), total),
        "requests_total": int(total_of("llm_requests")),
        "per_alert": per_alert,
    }


ERROR_LABELS = {
    "mitre_rejection": "MITRE rejection (technique without dossier evidence)",
    "invalid_json": "invalid JSON from the model",
    "timeout": "timeout",
}


def build_failure_rows(
    records: list[dict[str, Any]], ground_truth: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for r in sorted(records, key=lambda x: (x["alert_id"], x["run"])):
        truth = ground_truth.get(r["alert_id"])
        if truth is None:
            continue
        base = {"alert_id": r["alert_id"], "run": r["run"]}
        if r.get("error"):
            rows.append(
                {**base,
                 "what": ERROR_LABELS.get(r["error"], r["error"]),
                 "why": r.get("error_detail") or ""}
            )
            continue
        expected = truth["expected_verdict"]
        if r["verdict"] != expected:
            reason = " ".join(
                part for part in (r.get("audit_notes"), r.get("narrative")) if part
            )
            rows.append(
                {**base,
                 "what": f"expected {expected}, got {r['verdict']}",
                 "why": _clip(reason) or "no narrative returned"}
            )
        observed = set(r.get("mitre_techniques_observed") or [])
        in_dossier = set(r.get("dossier_mitre") or [])
        for technique in sorted(set(truth.get("expected_mitre", [])) - observed):
            why = (
                "in the dossier's evidence, but the Adjudicator did not list it"
                if technique in in_dossier
                else "not in the dossier's evidence: the Investigator did not "
                "gather the records that show it"
            )
            rows.append({**base, "what": f"missing technique {technique}", "why": why})
        for technique in sorted(observed - set(truth.get("expected_mitre", []))):
            rows.append(
                {**base,
                 "what": f"unexpected technique {technique}",
                 "why": "backed by dossier evidence but not in the ground-truth label"}
            )
    return rows


# --- report -------------------------------------------------------------------


def _cell(value: Any) -> str:
    text = " ".join(str(value).split())
    return text.replace("|", "\\|")


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.1%}"


def _num(value: float | None, digits: int = 1) -> str:
    return "n/a" if value is None else f"{value:.{digits}f}"


def write_results_md(
    path: Path,
    records: list[dict[str, Any]],
    interruptions: list[dict[str, Any]],
    ground_truth: dict[str, dict[str, Any]],
    *,
    model: str,
    runs_per_alert: int,
    daily_budget: int,
    dry_run: bool,
) -> None:
    m = compute_metrics(records, ground_truth)
    expected_runs = len(ground_truth) * runs_per_alert
    days = sorted({r.get("day") for r in records if r.get("day")})
    lines: list[str] = ["# ITDR Evaluation Results", ""]
    if dry_run:
        lines += [
            "> **DRY RUN.** Offline stand-ins replaced the model: the Adjudicator "
            "stand-in answers with the ground-truth verdict, so these scores test "
            "the harness, not a model. No API key, no network.",
            "",
        ]
    if m["total_runs"] < expected_runs:
        lines += [
            f"> **PARTIAL:** {m['total_runs']} of {expected_runs} runs complete. "
            "The evaluation resumes where it stopped; numbers will change.",
            "",
        ]
    model_line = (
        "- **Model:** none (offline stand-ins; see the note above)."
        if dry_run
        else f"- **Model:** `{model}` via OpenRouter (free tier), temperature 0."
    )
    limits_line = (
        "- **Limits:** none applied in a dry run (no requests are sent)."
        if dry_run
        else f"- **Limits:** at most {MAX_REQUESTS_PER_MINUTE} requests/minute and "
        f"{daily_budget} requests/UTC day (free cap 50); a run starts only with "
        f"room for its worst case ({MAX_REQUESTS_PER_RUN} requests)."
    )
    lines += [
        "## Method",
        "",
        model_line,
        f"- **Alerts:** {len(ground_truth)} synthetic Entra ID alerts "
        "(5 attacks, 3 benign, 1 thin-data, 1 unknown user), "
        f"{runs_per_alert} runs each, through the full orchestrator.",
        "- **Reviewer:** a scripted reviewer approves every containment step and "
        "cancels every `ask_user` question. No human is in the loop during "
        "scoring, so the one-question re-adjudication path is never exercised.",
        "- **Labels:** `data/fixtures/ground_truth.jsonl`, read only by this "
        "script and the tests; the agents never see it.",
        limits_line,
        f"- **Run days (UTC):** {', '.join(days) if days else 'none yet'}.",
        "",
        "## Headline metrics",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Runs complete | {m['total_runs']} of {expected_runs} "
        f"({m['failed_runs']} failed) |",
        f"| Exact verdict accuracy (primary; failed runs count as wrong) | "
        f"{_pct(m['verdict_accuracy'])} |",
        f"| Exact verdict accuracy, runs that returned a verdict | "
        f"{_pct(m['verdict_accuracy_scored'])} |",
        f"| Majority-of-{runs_per_alert} verdict accuracy (per alert) | "
        f"{_pct(m['majority_accuracy'])} |",
        f"| Attack-vs-benign detection (8 labeled alerts) | "
        f"{_pct(m['detection_accuracy'])} ({m['detection_runs']} runs) |",
        f"| False positives (benign runs called COMPROMISED/SUSPICIOUS) | "
        f"{m['false_positives']} of {m['benign_runs']} |",
        f"| MITRE precision | {_pct(m['mitre_precision'])} "
        f"(TP {m['mitre_tp']}, FP {m['mitre_fp']}) |",
        f"| MITRE recall | {_pct(m['mitre_recall'])} (FN {m['mitre_fn']}) |",
        f"| Multi-run agreement | {_pct(m['multi_run_agreement'])} |",
        f"| Model requests | {m['requests_total']} total |",
        f"| Tokens in / out | {m['tokens_in_total']} / {m['tokens_out_total']} total; "
        f"{_num(m['tokens_in_mean'])} / {_num(m['tokens_out_mean'])} per run |",
        f"| Seconds | {_num(m['seconds_total'])} total; "
        f"{_num(m['seconds_mean'])} per run |",
        "",
        "## Per alert",
        "",
        "| Alert | Scenario | Expected | Run outcomes | Majority | Correct |",
        "|---|---|---|---|---|---|",
    ]
    for row in m["per_alert"]:
        lines.append(
            f"| {row['alert_id']} | {row['scenario']} | {row['expected']} | "
            f"{', '.join(row['outcomes'])} | {row['majority'] or 'tie'} | "
            f"{'yes' if row['majority_correct'] else 'no'} |"
        )
    lines += ["", "## Per run", "",
              "| Alert | Run | Verdict | Confidence | Techniques | Requests | "
              "Tokens in/out | Seconds | Error |",
              "|---|---|---|---|---|---|---|---|---|"]
    for r in sorted(records, key=lambda x: (x["alert_id"], x["run"])):
        lines.append(
            f"| {r['alert_id']} | {r['run']} | {r.get('verdict') or '-'} | "
            f"{_num(r.get('confidence'), 2)} | "
            f"{_cell(', '.join(r.get('mitre_techniques_observed') or [])) or '-'} | "
            f"{r.get('llm_requests')} | {r.get('tokens_in')}/{r.get('tokens_out')} | "
            f"{_num(r.get('seconds'), 1)} | {r.get('error') or '-'} |"
        )
    rows = build_failure_rows(records, ground_truth)
    lines += ["", "## Failure table", ""]
    if rows:
        lines += ["| Alert | Run | What went wrong | Why |", "|---|---|---|---|"]
        lines += [
            f"| {row['alert_id']} | {row['run']} | {_cell(row['what'])} | "
            f"{_cell(row['why'])} |"
            for row in rows
        ]
    else:
        lines.append("No failures.")
    lines += ["", "## Interrupted attempts (retried in a later session)", ""]
    if interruptions:
        lines += ["| Alert | Run | Stop reason | Detail | Requests spent |",
                  "|---|---|---|---|---|"]
        lines += [
            f"| {i['alert_id']} | {i['run']} | {i['error']} | "
            f"{_cell(i.get('error_detail') or '')} | {i.get('llm_requests', 0)} |"
            for i in interruptions
        ]
    else:
        lines.append("None.")
    lines += [
        "",
        "## Caveats",
        "",
        "- Synthetic data only; no real tenant. Ten alerts is a small sample.",
        "- A free model can change or be rate-limited between days; runs are "
        "spread over several UTC days.",
        "- Labels come from the data generator. `benign_admin_role` keeps "
        "T1098.003 as expected because the role-add pattern is real; deciding "
        "it is legitimate is the verdict's job.",
        "- Questions are always cancelled, so these numbers show the agent "
        "without analyst help.",
        "",
    ]
    Path(path).write_text("\n".join(lines), encoding="utf-8")


# --- CLI -------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="evaluate")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true",
                      help="offline: no key, no network, writes eval/dry_run/")
    mode.add_argument("--live", action="store_true",
                      help="real free model; spends daily requests")
    parser.add_argument("--runs", type=int, default=RUNS_PER_ALERT)
    parser.add_argument("--alerts", nargs="+")
    parser.add_argument("--model", default=os.getenv("EVAL_MODEL", DEFAULT_MODEL))
    parser.add_argument("--daily-budget", type=int, default=DEFAULT_DAILY_BUDGET)
    parser.add_argument("--eval-dir", default=str(PROJECT_ROOT / "eval"))
    args = parser.parse_args(argv)

    eval_dir = Path(args.eval_dir)
    alerts = load_alerts(FIXTURES / "alerts.jsonl")
    ground_truth = load_ground_truth(FIXTURES / "ground_truth.jsonl")
    if args.alerts:
        unknown = sorted(set(args.alerts) - {a["id"] for a in alerts})
        if unknown:
            print(f"Unknown alert ids: {unknown}")
            return 2
        alerts = [a for a in alerts if a["id"] in args.alerts]

    if args.dry_run:
        dry_dir = eval_dir / "dry_run"
        if dry_dir.exists():
            shutil.rmtree(dry_dir)
        run_evaluation(
            alerts, ground_truth,
            make_offline_runner(ground_truth, dry_dir / "audit.jsonl"),
            runs_per_alert=args.runs, eval_dir=dry_dir, model="offline-dry-run",
            daily_budget=10**9, sleep=lambda _s: None, dry_run=True,
        )
        per_run = [r["llm_requests"] for r in _read_jsonl(dry_dir / "raw.jsonl")]
        total = sum(per_run)
        print(f"Alerts: {len(alerts)}  Runs per alert: {args.runs}  "
              f"Runs: {len(per_run)}")
        print(f"Requests per run (offline script): min {min(per_run)}, "
              f"mean {total / len(per_run):.1f}, max {max(per_run)}")
        print(f"Total estimated requests: {total}")
        print(f"Daily budget: {args.daily_budget} (worst case per run "
              f"{MAX_REQUESTS_PER_RUN} must fit before a run starts)")
        print(f"Estimated days: {estimate_days(per_run, args.daily_budget)} "
              f"(worst case: {estimate_days([MAX_REQUESTS_PER_RUN] * len(per_run), args.daily_budget)})")
        print(f"Dry-run results: {dry_dir / 'results.md'}")
        return 0

    if not args.live:
        print("Choose --dry-run (offline) or --live (spends free daily requests).")
        return 2
    if not config.OPENROUTER_API_KEY:
        print("OPENROUTER_API_KEY is not set. Add it to .env (gitignored).")
        return 2

    timeout = min(config.TIMEOUT_SECONDS, 90)
    summary = run_evaluation(
        alerts, ground_truth,
        make_live_runner(config.OPENROUTER_API_KEY, args.model, timeout,
                         eval_dir / "audit.jsonl"),
        runs_per_alert=args.runs, eval_dir=eval_dir, model=args.model,
        daily_budget=args.daily_budget,
    )
    print(f"Runs finished this session: {summary.completed_this_session}")
    print(f"Runs still pending: {summary.pending}")
    print(f"Requests used today (UTC): {summary.requests_today} of {args.daily_budget}")
    print(f"Stopped: {summary.stopped_reason or 'all runs complete'}")
    print(f"Results: {eval_dir / 'results.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
