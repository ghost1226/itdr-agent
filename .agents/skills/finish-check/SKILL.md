---
name: finish-check
description: "Prove a task is finished before saying so: write checklists/<task>.md BEFORE any code, one step per line, each naming the file that step must produce; tick a box only after its file exists; run python scripts/finish_check.py checklists/<task>.md and report its PASS line with the raw test output and git log. Use on every task with more than one step or more than one output file (a fix set, a feature, a docs pass), and before claiming done on one."
---

# finish-check

Agents, this one included, skip steps and report work that isn't there. This skill makes "done" something the checker verifies instead of something the reply asserts. Written 2026-10-23 from two real runs in this repo (below), not from theory.

## The rule

1. **Checklist first.** Before touching code, write `checklists/<task>.md`. One line per step:
   ```
   - [ ] fix 1: check_progress.py reconfigures stdout to UTF-8 -> `../scripts/check_progress.py::sys.stdout.reconfigure(encoding="utf-8")`
   ```
   Paths are relative to the `checklists/` folder (so `../scripts/...`) or absolute. A file must exist and be non-empty. `file::text` also requires that exact text in the file; use it for every edit step, because "the file exists" proves nothing about an edit. A step with no path is checked for its tick only, so give every step a file when one exists (the test file, the changed source, the PROGRESS.md entry, the commit hash).
2. **Run the checker once before the work.** `python scripts/finish_check.py checklists/<task>.md` must FAIL every step, and every `does not contain` / `missing` line must name the file you expect. A path that resolves somewhere else is wrong now and will still be wrong after the work.
3. **Build red-green.** The red commit carries the checklist and the failing tests; the green commit carries the code.
4. **Tick a box only after its file exists.** Grep the file for the checklist's own `::text` first (copy it from the checklist, don't retype it); tick on a hit. Never tick everything at once and let the checker find the misses.
5. **Run the checker before saying done.** On FAIL, finish the step it names and run it again; at most two rounds, then stop and say which step is stuck. On PASS, do one content read of anything that states a fact (a number in README, a claim in PROGRESS.md) against its source. The checker proves presence, not truth.
6. **Report evidence, not a summary.** Paste the PASS line with the step count, the pytest tail, `scripts/check_progress.py`'s exit code, and `git log --oneline` for the new commits.

## Format traps (each one failed a real run elsewhere)

- `::text` is case-sensitive and literal. Copy it from the file or from the text you will write, never from memory of it.
- No backticks inside a step's description: every backtick span on the line is read as a path.
- `::text` cannot contain a backtick. Pick plain words.
- Pick `::text` that can only exist once the step is done. Text already in the file passes before any work (that is what the pre-work run catches).

## The two runs this was written from

- **Run 1 (reply log + rerun script, 2026-10-23):** the checklists were written AFTER the code and backfilled. Both passed 8/8 and the checker was run before claiming done, with raw output pasted. Honest about it in the file ("so this checklist verifies that work"), but a backfilled checklist cannot catch a skipped step, so it is not the method. Lesson: the checklist's value is in step 2, before the work.
- **Run 2 (five review fixes, 2026-10-23):** checklist-first. 12 steps written before code; first run FAIL 12/12 with every path right; red `7a3475b` carried the checklist and 4 failing tests; green `89616da`; PASS 12/12; 650 tests; PROGRESS corrected a wrong claim from the session before. The checker passed and the review still found one wrong fix (a `.gitignore` pattern that hid the live rerun evidence), which is step 5's point: PASS means present, a human read decides right.
