# Checklist — assisted scoring mode (Task D, 2026-10-23)

Task: add --assisted to scripts/evaluate.py. The scripted reviewer answers the
one analyst question from the ground-truth scenario (benign -> expected,
attack -> suspicious, thin data -> does not know), and results.md reports the
assisted runs as their own row set, never mixed with the unassisted numbers.
Dry-run only; no live run. Closes open problem 6.

- [x] the answer mapping comes from the scenario -> `../scripts/evaluate.py::def assisted_choice`
- [x] an assisted reviewer answers instead of cancelling -> `../scripts/evaluate.py::def make_assisted_eval_reviewer`
- [x] both runners pick the assisted reviewer when asked -> `../scripts/evaluate.py::def _eval_reviewer`
- [x] each record is marked assisted or not -> `../scripts/evaluate.py::"assisted": assisted`
- [x] the report renders the assisted runs as a separate section -> `../scripts/evaluate.py::## Assisted runs`
- [x] the CLI takes --assisted -> `../scripts/evaluate.py::"--assisted"`
- [x] a test proves the mapping -> `../tests/test_evaluate.py::def test_assisted_choice_maps_each_scenario`
- [x] a test proves the separation -> `../tests/test_evaluate.py::def test_assisted_runs_are_a_separate_row_set`
- [x] PROGRESS.md records the task and closes open problem 6 -> `../PROGRESS.md::assisted-scoring`
- [x] the red and green commits are recorded in PROGRESS.md -> `../PROGRESS.md::assisted-scoring: red`
- [x] full suite green and check_progress exits 0
