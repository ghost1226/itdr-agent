#!/usr/bin/env python3
"""Fail if a commit newer than the baseline is missing from PROGRESS.md.

AGENTS.md rule 10: run ``python scripts/check_progress.py`` before calling a
task done. Every commit after the baseline ``d33eb1e`` must have its
7-character hash somewhere in PROGRESS.md, except HEAD -- a commit cannot
contain its own hash. Commits older than the baseline are not checked: the
move to ``~/itdr-agent`` rewrote their hashes, so those live in the frozen
``~/ai-agents-class`` repo.

Exit 0 when every checked commit is listed, 1 when any is missing.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

BASELINE = "d33eb1e"
PROGRESS_NAME = "PROGRESS.md"

# Windows: a redirected stdout may be cp1252, and a commit subject can carry a
# character cp1252 cannot encode (Jessica's review, 2026-10-23: the "->" arrow
# in a subject raised UnicodeEncodeError on CI, commit ``c9f13d8``). The
# subprocess ``encoding=`` below only covers decoding git's output. Same guard
# as ``itdr_agent/__main__.py`` and ``scripts/rerun.py``.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return result.stdout


def missing_commits(repo: Path, baseline: str, progress: Path) -> list[tuple[str, str]]:
    """Return ``(short_hash, subject)`` for checked commits absent from PROGRESS.md."""
    head = _git(repo, "rev-parse", "HEAD").strip()
    listed = progress.read_text(encoding="utf-8")
    missing: list[tuple[str, str]] = []
    for full in _git(repo, "rev-list", f"{baseline}..HEAD").split():
        if full == head:
            continue  # HEAD cannot list its own hash
        short = full[:7]
        if short in listed:
            continue
        subject = _git(repo, "log", "-1", "--format=%s", full).strip()
        missing.append((short, subject))
    return missing


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    root = Path(__file__).resolve().parents[1]
    parser.add_argument("--repo", type=Path, default=root, help="git repo to check")
    parser.add_argument(
        "--baseline", default=BASELINE, help="commits after this one are checked"
    )
    parser.add_argument("--progress", type=Path, help="PROGRESS.md path")
    args = parser.parse_args(argv)

    progress = args.progress or (args.repo / PROGRESS_NAME)
    missing = missing_commits(args.repo, args.baseline, progress)
    if missing:
        print("Commits newer than the baseline are missing from PROGRESS.md:")
        for short, subject in missing:
            print(f"  {short}  {subject}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
