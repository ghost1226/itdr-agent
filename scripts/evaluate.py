"""Checkpoint 7 — evaluation harness (red-phase stub; implemented in green)."""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from itdr_agent import config  # noqa: E402,F401

RUNS_PER_ALERT = 3
DEFAULT_DAILY_BUDGET = 45
MAX_REQUESTS_PER_MINUTE = 20
MAX_REQUESTS_PER_RUN = 10


class BudgetExhausted(Exception):
    """The daily request budget is used up."""


class RequestBudget:
    def __init__(self, *args, **kwargs):
        raise NotImplementedError


def load_alerts(path):
    raise NotImplementedError


def load_ground_truth(path):
    raise NotImplementedError


def make_eval_reviewer():
    raise NotImplementedError


def make_openrouter_client(api_key, timeout):
    raise NotImplementedError


def estimate_days(per_run_requests, daily_budget):
    raise NotImplementedError


def run_evaluation(*args, **kwargs):
    raise NotImplementedError


def compute_metrics(records, ground_truth):
    raise NotImplementedError


def build_failure_rows(records, ground_truth):
    raise NotImplementedError


def write_results_md(*args, **kwargs):
    raise NotImplementedError


def main(argv=None):
    raise NotImplementedError
