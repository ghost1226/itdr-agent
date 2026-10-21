"""One default model everywhere (problems #11 and #30), offline.

Gemma 4 31B (free) was rate-limited upstream again on 2026-10-16 when the GUI
was started without EVAL_MODEL. The evaluation has run on Nemotron 3 Super
(free) since 2026-10-12, so that is now the default for the CLI, the GUI, the
evaluation, and both live scripts. EVAL_MODEL still overrides it.
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from itdr_agent import adjudicator  # noqa: E402

NEMOTRON = "nvidia/nemotron-3-super-120b-a12b:free"


def test_default_is_nemotron():
    assert adjudicator.DEFAULT_MODEL == NEMOTRON


def test_evaluation_uses_the_same_default():
    import evaluate

    assert evaluate.EVAL_DEFAULT_MODEL == adjudicator.DEFAULT_MODEL


def test_no_code_file_still_names_gemma_as_a_model():
    files = [
        *sorted((PROJECT_ROOT / "itdr_agent").glob("*.py")),
        *sorted((PROJECT_ROOT / "scripts").glob("*.py")),
        PROJECT_ROOT / "app.py",
    ]
    for path in files:
        assert '"google/gemma' not in path.read_text(), path


def test_cli_uses_the_default_without_eval_model(monkeypatch, capsys):
    import itdr_agent.__main__ as cli
    from itdr_agent import config

    monkeypatch.delenv("EVAL_MODEL", raising=False)
    monkeypatch.setattr(config, "OPENROUTER_API_KEY", "sk-or-v1-TEST")
    seen = []

    def fake_llm(key, model, timeout, meter=None):
        seen.append(model)
        return SimpleNamespace()

    class FakeOrchestrator:
        def __init__(self, *args, **kwargs):
            pass

        def run(self, alert):
            report = SimpleNamespace(model_dump_json=lambda indent=None: "{}")
            return SimpleNamespace(report=report, tokens=None)

    monkeypatch.setattr(cli, "_OpenRouterInvestigatorLLM", fake_llm)
    monkeypatch.setattr(cli, "_OpenRouterAdjudicatorLLM", fake_llm)
    monkeypatch.setattr(cli, "Investigator", lambda llm: llm)
    monkeypatch.setattr(cli, "Adjudicator", lambda llm: llm)
    monkeypatch.setattr(cli, "Orchestrator", FakeOrchestrator)
    assert cli.main(["--alert-id", "ALERT_001"]) == 0
    assert seen == [NEMOTRON, NEMOTRON]


def test_eval_model_still_overrides(monkeypatch):
    import run_investigator_live

    monkeypatch.delenv("OPENROUTER_MODEL", raising=False)
    monkeypatch.setenv("EVAL_MODEL", "some/other-model:free")
    assert run_investigator_live.pick_model() == "some/other-model:free"


def test_investigator_script_no_longer_requires_openrouter_model(monkeypatch):
    import run_investigator_live

    monkeypatch.delenv("OPENROUTER_MODEL", raising=False)
    monkeypatch.delenv("EVAL_MODEL", raising=False)
    assert run_investigator_live.pick_model() == NEMOTRON
    monkeypatch.setenv("OPENROUTER_MODEL", "legacy/model")
    assert run_investigator_live.pick_model() == "legacy/model"


def test_env_example_names_the_default():
    text = (PROJECT_ROOT / ".env.example").read_text()
    assert f"EVAL_MODEL={NEMOTRON}" in text


# --- Review 2026-10-21 finding 7: the CLI reports an abort, no traceback -----


def test_cli_prints_a_message_when_the_review_is_aborted(monkeypatch, capsys):
    import itdr_agent.__main__ as cli
    from itdr_agent import config
    from itdr_agent.human import ReviewAbortedError

    monkeypatch.setattr(config, "OPENROUTER_API_KEY", "sk-or-v1-TEST")

    class AbortingOrchestrator:
        def __init__(self, *args, **kwargs):
            pass

        def run(self, alert):
            raise ReviewAbortedError("input ended before an approve/edit/reject decision")

    monkeypatch.setattr(cli, "_OpenRouterInvestigatorLLM", lambda *a, **k: SimpleNamespace())
    monkeypatch.setattr(cli, "_OpenRouterAdjudicatorLLM", lambda *a, **k: SimpleNamespace())
    monkeypatch.setattr(cli, "Investigator", lambda llm: llm)
    monkeypatch.setattr(cli, "Adjudicator", lambda llm: llm)
    monkeypatch.setattr(cli, "Orchestrator", AbortingOrchestrator)
    assert cli.main(["--alert-id", "ALERT_001"]) == 3
    out = capsys.readouterr().out
    assert "aborted" in out.lower() and "input ended" in out
