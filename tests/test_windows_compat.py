"""Windows-compatibility pass (2026-10-23): offline, no key, no network.

The code was already pathlib-only with UTF-8 on every read and write. What a
Windows clone still hit: CRLF checkouts without a ``.gitattributes``, text
writes that Python turns into ``\\r\\n`` on Windows (so the "byte-identical"
fixture regeneration stops being identical to the committed files), a CLI
that can crash when its output is redirected to a file under a non-UTF-8
locale, bash-only setup steps in the README, and nothing proving any of it
on Windows. These tests pin each of those.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from itdr_agent import data_generator  # noqa: E402

# Every module that writes a text file. Reads are not checked: text mode
# already accepts both line endings on the way in.
WRITING_FILES = [
    "itdr_agent/data_generator.py",
    "itdr_agent/orchestrator.py",
    "itdr_agent/trace.py",
    "scripts/evaluate.py",
    "scripts/test_cases_table.py",
]
WORKFLOW = PROJECT_ROOT / ".github" / "workflows" / "tests.yml"


def _text_write_calls(path: Path) -> list[ast.Call]:
    """``x.open("w"/"a", ...)``, ``open(..., "w")`` and ``x.write_text(...)``."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: list[ast.Call] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = (
            node.func.attr if isinstance(node.func, ast.Attribute)
            else node.func.id if isinstance(node.func, ast.Name) else ""
        )
        if name == "write_text":
            found.append(node)
        elif name == "open":
            mode = next(
                (kw.value for kw in node.keywords if kw.arg == "mode"),
                node.args[1] if isinstance(node.func, ast.Name) and len(node.args) > 1
                else node.args[0] if isinstance(node.func, ast.Attribute) and node.args
                else None,
            )
            if isinstance(mode, ast.Constant) and isinstance(mode.value, str) \
                    and mode.value[0] in "wa" and "b" not in mode.value:
                found.append(node)
    return found


def test_gitattributes_forces_lf_on_checkout():
    text = (PROJECT_ROOT / ".gitattributes").read_text(encoding="utf-8")
    assert "eol=lf" in text, ".gitattributes must force LF so a Windows clone matches"


def test_every_text_write_passes_newline_lf():
    found = 0
    for rel in WRITING_FILES:
        for call in _text_write_calls(PROJECT_ROOT / rel):
            found += 1
            kwargs = {kw.arg: ast.unparse(kw.value) for kw in call.keywords}
            assert kwargs.get("newline") == "'\\n'", (
                f"{rel}:{call.lineno} text write without newline='\\n' "
                "(Windows would write \\r\\n)"
            )
    assert found == 8, f"expected the 8 known text writes, found {found}"


def test_fixtures_regenerate_with_lf_only(tmp_path):
    """The README's byte-identical claim must hold on Windows too."""
    written = data_generator.write_fixtures(tmp_path, seed=42)
    for name, path in written.items():
        assert b"\r" not in path.read_bytes(), f"{name}.jsonl has a carriage return"


def test_cli_reconfigures_stdout_to_utf8():
    """``python -m itdr_agent ... > out.json`` must not crash on a non-ASCII
    narrative under a cp1252 console; the GUI is unaffected."""
    text = (PROJECT_ROOT / "itdr_agent" / "__main__.py").read_text(encoding="utf-8")
    assert 'sys.stdout.reconfigure(encoding="utf-8"' in text


def test_check_progress_reconfigures_stdout_to_utf8():
    """Windows CI crashed printing a subject's arrow to cp1252 stdout
    (2026-10-23, commit c9f13d8): a UnicodeEncodeError on '\u2192'. The
    checker must set its own stdout to UTF-8, like the CLI and the re-run
    runner; the subprocess ``encoding=`` fix only covers decoding git's output.
    """
    text = (PROJECT_ROOT / "scripts" / "check_progress.py").read_text(encoding="utf-8")
    assert 'sys.stdout.reconfigure(encoding="utf-8"' in text


def test_readme_has_windows_setup_and_whisper_lines():
    text = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
    assert ".venv\\Scripts\\activate" in text, "README has no Windows venv activation line"
    assert "whisper-server.exe" in text, "README has no Windows Whisper server line"


def test_ci_workflow_runs_the_suite_on_windows():
    assert WORKFLOW.exists(), "no .github/workflows/tests.yml"
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "windows-latest" in text
    assert "ubuntu-latest" in text
    assert "pytest" in text
    assert "secrets." not in text, "the suite needs no key; CI must not pass one"


def test_no_unix_only_strftime_flags():
    """``%-d`` (no-padding) is glibc/BSD only; Windows strftime raises on it.
    The partner hit this on 2026-10-22 (``19fec28``); use ``.day`` instead."""
    import re

    for path in list((PROJECT_ROOT / "itdr_agent").glob("*.py")) + [PROJECT_ROOT / "app.py"]:
        text = path.read_text(encoding="utf-8")
        assert not re.search(r"%-[a-zA-Z]", text), f"{path.name} uses a %-x strftime flag"


# --- subprocess output is decoded as UTF-8, not the Windows ANSI codepage ----
# ``text=True`` with no ``encoding`` uses ``locale.getpreferredencoding(False)``,
# which is cp1252 on Windows. Git writes commit subjects in UTF-8, so a subject
# with a byte cp1252 leaves undefined (the same 0x8f that broke the app.py test
# read) raises ``UnicodeDecodeError``: uncaught in ``check_progress.py`` (it
# would fail CI's last step), swallowed as "clean" in
# ``orchestrator._tree_is_dirty`` (the run's commit would lose its ``+dirty``).
SUBPROCESS_FILES = (
    sorted((PROJECT_ROOT / "itdr_agent").glob("*.py"))
    + sorted((PROJECT_ROOT / "scripts").glob("*.py"))
    + [PROJECT_ROOT / "app.py"]
)


def _subprocess_text_calls(path: Path) -> list[ast.Call]:
    """``subprocess.run/Popen/check_output/check_call`` in text mode."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: list[ast.Call] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = (
            node.func.attr if isinstance(node.func, ast.Attribute)
            else node.func.id if isinstance(node.func, ast.Name) else ""
        )
        if name not in ("run", "Popen", "check_output", "check_call"):
            continue
        keywords = {kw.arg for kw in node.keywords}
        if keywords & {"text", "universal_newlines", "encoding"}:
            found.append(node)
    return found


def test_subprocess_text_calls_pass_an_explicit_encoding():
    found = 0
    for path in SUBPROCESS_FILES:
        rel = path.relative_to(PROJECT_ROOT)
        for call in _subprocess_text_calls(path):
            found += 1
            kwargs = {kw.arg: ast.unparse(kw.value) for kw in call.keywords}
            assert kwargs.get("encoding") == "'utf-8'", (
                f"{rel}:{call.lineno} decodes subprocess output with the locale "
                "encoding (cp1252 on Windows); pass encoding='utf-8'"
            )
    assert found == 3, f"expected the 3 known git calls, found {found}"
