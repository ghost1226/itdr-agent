# Checklist — one-command re-run (`scripts/rerun.py`)

Task (2026-10-23): encode Joe's post-fix re-run plan so it fires with one
command when the Nemotron free endpoint is back, reusing the eval harness so
the daily budget and resume state are shared. No fixture or prompt changes.

- [x] plan constant and grouping of alerts by run count -> `../scripts/rerun.py::RERUN_PLAN` `../scripts/rerun.py::group_plan`
- [x] `--alerts` / `--runs` override and the default plan -> `../scripts/rerun.py::build_plan`
- [x] offline and live modes; live refuses without a key -> `../scripts/rerun.py::OPENROUTER_API_KEY`
- [x] drives the shared eval harness per group and prints per-run verdicts -> `../scripts/rerun.py::run_evaluation` `../scripts/rerun.py::_report`
- [x] tests: the plan, grouping, overrides, dry-run counts, mode/key/unknown guards -> `../tests/test_rerun.py`
- [x] README documents the re-run commands -> `../README.md::scripts/rerun.py --live`
- [x] dry-run harness check passes 8 of 8 planned runs
- [x] full suite green (647 passed)
