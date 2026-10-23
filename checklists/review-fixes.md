# Checklist — five fixes from Jessica's review (2026-10-23)

Task: five review fixes, no fixture changes, no `--live` runs, nothing outside
`~/itdr-agent`. Written before the code; red-green, then tick.

- [x] fix 1: `check_progress.py` reconfigures stdout to UTF-8 -> `../scripts/check_progress.py::sys.stdout.reconfigure(encoding="utf-8")`
- [x] fix 1 test: a test proves `check_progress.py` carries the guard -> `../tests/test_windows_compat.py::def test_check_progress_reconfigures_stdout_to_utf8`
- [x] fix 1: PROGRESS.md corrects the claim that the subprocess encoding fix stopped the stdout crash -> `../PROGRESS.md::that fix is about *decoding* git output`
- [x] fix 2: README states the current test count -> `../README.md::tests, no network, no API key needed`
- [x] fix 3: the results writer uses the subset's real total, not all 10 alerts -> `../scripts/evaluate.py::in_scope = set(only) if only is not None`
- [x] fix 3 test: a subset report counts only the alerts in scope -> `../tests/test_evaluate.py::def test_subset_run_reports_against_its_own_plan`
- [x] fix 3: the stale `eval/rerun/results.md` (0 of 30) is removed until runs exist
- [x] fix 4: `.gitignore` ignores only the dry-run scratch (`eval/**/dry_run/`), so `eval/rerun/` evidence stays committable -> `../.gitignore::eval/**/dry_run/`
- [x] fix 5: the eval commit stamp carries `+dirty` when `orchestrator._tree_is_dirty()` -> `../scripts/evaluate.py::_tree_is_dirty`
- [x] fix 5 test: a dirty tree is stamped `+dirty` -> `../tests/test_evaluate.py::def test_eval_commit_stamp_is_dirty_when_the_tree_is_dirty`
- [x] full suite green and `python scripts/check_progress.py` exits 0
- [x] the red and green commits are recorded in PROGRESS.md -> `../PROGRESS.md::review-fixes`
