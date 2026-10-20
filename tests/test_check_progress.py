"""Red/green tests for scripts/check_progress.py.

The checker fails when a commit newer than the baseline (d33eb1e) is not
listed in PROGRESS.md -- except HEAD, because a commit cannot contain its own
hash. Commits older than the baseline are not checked: their hashes live in
the frozen pre-move repo (~/ai-agents-class).

Every test runs against a throwaway git repo in tmp_path, so the real history
is never touched.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
SCRIPT = PROJECT_ROOT / "scripts" / "check_progress.py"


# --- Helpers ---------------------------------------------------------------


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def init_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q")
    git(repo, "config", "user.email", "check-progress@example.com")
    git(repo, "config", "user.name", "Check Progress")
    git(repo, "config", "commit.gpgsign", "false")
    return repo


def commit(repo: Path, message: str, files: dict[str, str]) -> str:
    for name, content in files.items():
        (repo / name).write_text(content, encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", message)
    return git(repo, "rev-parse", "HEAD")


def run_check(repo: Path, baseline: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--repo", str(repo), "--baseline", baseline],
        capture_output=True,
        text=True,
    )


# --- Tests -----------------------------------------------------------------


def test_missing_commit_exits_1_and_prints_hash(tmp_path: Path) -> None:
    repo = init_repo(tmp_path)
    baseline = commit(repo, "baseline", {"PROGRESS.md": "baseline\n"})
    unlisted = commit(repo, "unlisted change", {"code.txt": "x\n"})
    commit(repo, "head commit", {"other.txt": "y\n"})

    result = run_check(repo, baseline)

    assert result.returncode == 1, result.stdout + result.stderr
    assert unlisted[:7] in result.stdout


def test_head_is_skipped(tmp_path: Path) -> None:
    repo = init_repo(tmp_path)
    baseline = commit(repo, "baseline", {"PROGRESS.md": "baseline\n"})
    commit(repo, "only head, unlisted", {"code.txt": "x\n"})

    result = run_check(repo, baseline)

    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout == ""


def test_listed_commit_exits_0(tmp_path: Path) -> None:
    repo = init_repo(tmp_path)
    baseline = commit(repo, "baseline", {"PROGRESS.md": "baseline\n"})
    listed = commit(repo, "listed change", {"code.txt": "x\n"})
    # HEAD writes the previous commit's hash into PROGRESS.md.
    (repo / "PROGRESS.md").write_text(
        f"baseline\n- {listed[:7]} listed change\n", encoding="utf-8"
    )
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "record the change")

    result = run_check(repo, baseline)

    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout == ""


def test_commits_older_than_baseline_are_not_checked(tmp_path: Path) -> None:
    repo = init_repo(tmp_path)
    commit(repo, "old and unlisted", {"old.txt": "x\n"})  # before the baseline
    baseline = commit(repo, "baseline", {"PROGRESS.md": "baseline\n"})
    commit(repo, "new head, unlisted", {"code.txt": "y\n"})

    result = run_check(repo, baseline)

    assert result.returncode == 0, result.stdout + result.stderr


def test_every_missing_hash_is_printed(tmp_path: Path) -> None:
    repo = init_repo(tmp_path)
    baseline = commit(repo, "baseline", {"PROGRESS.md": "baseline\n"})
    first = commit(repo, "first unlisted", {"a.txt": "1\n"})
    second = commit(repo, "second unlisted", {"b.txt": "2\n"})
    commit(repo, "head commit", {"c.txt": "3\n"})

    result = run_check(repo, baseline)

    assert result.returncode == 1, result.stdout + result.stderr
    assert first[:7] in result.stdout
    assert second[:7] in result.stdout
