"""Skeleton tests — Checkpoint 0."""

import os
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


def test_venv_exists():
    """.venv lives inside the project folder.

    A fresh clone has no .venv yet; the setup step creates it. Skip rather
    than fail so the suite is green before dependencies are installed.
    """
    venv = PROJECT_ROOT / ".venv"
    if not venv.exists():
        pytest.skip(".venv absent (fresh clone); run the venv setup step first")
    assert venv.is_dir()


def test_env_example_exists():
    """Template for API keys exists."""
    assert (PROJECT_ROOT / ".env.example").exists(), ".env.example missing"


def test_gitignore_blocks_env():
    """.env must never be committed."""
    gitignore = (PROJECT_ROOT / ".gitignore").read_text()
    assert ".env" in gitignore, ".env not in .gitignore"


def test_all_requirements_importable():
    """Every production dependency can be imported."""
    import pytest  # noqa: F401
    import pydantic  # noqa: F401
    import faker  # noqa: F401
    import dotenv  # noqa: F401
    import httpx  # noqa: F401
    import openai  # noqa: F401
    import tenacity  # noqa: F401


def test_config_module_exists():
    """Configuration module loads settings from environment."""
    from itdr_agent import config  # noqa: F401


def test_timeout_default(monkeypatch):
    """TIMEOUT_SECONDS defaults to 120 when not in the environment or .env.

    Clear the env var first, and neutralise dotenv loading so a developer's
    real .env cannot leak into this default-value test.
    """
    monkeypatch.delenv("TIMEOUT_SECONDS", raising=False)
    monkeypatch.delenv("ITDR_TIMEOUT", raising=False)
    monkeypatch.setattr("dotenv.load_dotenv", lambda *args, **kwargs: None)
    import importlib
    from itdr_agent import config
    importlib.reload(config)
    assert config.TIMEOUT_SECONDS == 120


def test_timeout_reads_from_env(monkeypatch):
    """TIMEOUT_SECONDS respects the .env override."""
    monkeypatch.setenv("TIMEOUT_SECONDS", "90")
    monkeypatch.setattr("dotenv.load_dotenv", lambda *args, **kwargs: None)
    import importlib
    from itdr_agent import config
    importlib.reload(config)
    assert config.TIMEOUT_SECONDS == 90


# --- Review 2026-10-21 finding 6: pillow advisories in the GUI extra ---------
# pip-audit on requirements-gui.txt reports 5 advisories on pillow 12.3.0,
# fixed in 13.0.0, but every streamlit through 1.66.0 requires pillow<13.
# So: pin the version we actually run, say why in the file, and trip when
# streamlit finally allows 13 so the pin gets lifted.


def _gui_requirements() -> str:
    return (PROJECT_ROOT / "requirements-gui.txt").read_text(encoding="utf-8")


def test_gui_requirements_pin_pillow_and_name_the_advisories():
    text = _gui_requirements()
    assert "pillow==12.3.0" in text
    assert "GHSA-pchr-8j38-3x4p" in text  # the advisories are listed, not hidden
    assert "pillow<13" in text  # the reason the pin is not 13.0.0


def test_streamlit_still_blocks_pillow_13_otherwise_lift_the_pin():
    """When this fails, streamlit allows pillow 13: bump the pin and drop the note."""
    from importlib.metadata import requires

    pillow = [r for r in requires("streamlit") or [] if r.lower().startswith("pillow")]
    assert pillow and "<13" in pillow[0], (
        "streamlit no longer pins pillow<13: set pillow==13.x in "
        "requirements-gui.txt, re-run pip-audit, remove the advisory note"
    )
