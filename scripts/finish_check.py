#!/usr/bin/env python3
"""finish-check: verify a task's markdown checklist before calling the task done.

Usage: python3 check.py <checklist.md>

Checklist line format (one step per line):
    - [x] Step description -> `path/one` `path/two{6}`
Paths are absolute or relative to the checklist's folder. A file must exist and
be non-empty. A folder must hold at least one non-empty file, or at least N
with the {N} suffix. `file::text` also requires the file to contain that text
(proves a wiring/edit step, not just that the file exists). A step with no
paths is checked for its tick only.

Exit 0 = PASS. Exit 1 = FAIL, with the failed steps and the nudge to send back.
Exit 2 = the checklist itself is missing or has no steps.
"""
import re
import sys
from pathlib import Path

NUDGE = (
    "NUDGE: Your work was just reviewed and it isn't finished. Either a step "
    "isn't checked off, or a step's output is missing or empty. Read the "
    "checklist and the output for each failed step below, find what you "
    "missed, and complete it. Tick a box only after its output exists."
)
STEP = re.compile(r"^\s*[-*]\s+\[( |x|X)\]\s+(.*)$")
PATH = re.compile(r"`([^`]+)`")
COUNT = re.compile(r"^(.*)\{(\d+)\}$")


def nonempty_files(folder: Path) -> int:
    return sum(1 for p in folder.rglob("*") if p.is_file() and p.stat().st_size > 0)


def check_path(raw: str, base: Path) -> str | None:
    want, needle = 1, None
    if "::" in raw:
        raw, needle = raw.split("::", 1)
    m = COUNT.match(raw)
    if m:
        raw, want = m.group(1), int(m.group(2))
    p = Path(raw).expanduser()
    if not p.is_absolute():
        p = base / p
    p = p.resolve()
    if not p.exists():
        return f"missing: {p}"
    if p.is_file():
        if p.stat().st_size == 0:
            return f"empty file: {p}"
        if needle and needle not in p.read_text(encoding="utf-8", errors="replace"):
            return f"does not contain {needle!r}: {p}"
        return None
    have = nonempty_files(p)
    return None if have >= want else f"folder has {have} non-empty file(s), needs {want}: {p}"


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    checklist = Path(sys.argv[1]).expanduser().resolve()
    if not checklist.is_file():
        print(f"FAIL: checklist not found: {checklist}")
        return 2
    base = checklist.parent
    steps, failures = 0, []
    for number, line in enumerate(checklist.read_text(encoding="utf-8").splitlines(), 1):
        m = STEP.match(line)
        if not m:
            continue
        steps += 1
        ticked, text = m.group(1).lower() == "x", m.group(2)
        label = text.split("->")[0].strip()
        problems = [] if ticked else ["not checked off"]
        if "->" in text:
            for raw in PATH.findall(text.split("->", 1)[1]):
                problem = check_path(raw, base)
                if problem:
                    problems.append(problem)
        if problems:
            failures.append((number, label, problems))
    if steps == 0:
        print(f"FAIL: no checklist steps found in {checklist}")
        return 2
    if not failures:
        print(f"PASS: {steps}/{steps} steps checked off, every output present ({checklist.name})")
        return 0
    print(f"FAIL: {len(failures)} of {steps} steps not finished ({checklist.name})")
    for number, label, problems in failures:
        print(f"  line {number}: {label}")
        for problem in problems:
            print(f"    - {problem}")
    print()
    print(NUDGE)
    return 1


if __name__ == "__main__":
    sys.exit(main())
