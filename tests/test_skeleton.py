"""Skeleton tests — Checkpoint 0."""

import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


def test_venv_exists():
    """.venv lives inside the project folder."""
    assert (PROJECT_ROOT / ".venv").exists(), ".venv directory missing"


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
