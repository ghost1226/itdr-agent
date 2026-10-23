# Checklist — test-cases table (Task A, 2026-10-23)

Task: scripts/test_cases_table.py reads eval/final/raw.jsonl,
eval/after-fix/raw.jsonl and data/fixtures/ground_truth.jsonl and writes
docs/test-cases.md — one row per alert with scenario, expected verdict,
per-run verdict and confidence, MITRE expected vs observed, and a one-line
note for every miss. Deterministic; README links it. No fixture or prompt
changes.

- [x] the script loads the runs, builds the rows and renders the table -> `../scripts/test_cases_table.py::def render`
- [x] tests cover the rows, the notes, determinism and the real file -> `../tests/test_test_cases_table.py::def test_`
- [x] the real table is generated and committed -> `../docs/test-cases.md::ALERT_004`
- [x] README links the table -> `../README.md::docs/test-cases.md`
- [x] PROGRESS.md records the task -> `../PROGRESS.md::test-cases-table`
- [x] the red and green commits are recorded in PROGRESS.md -> `../PROGRESS.md::test-cases-table: red`
- [x] full suite green and check_progress exits 0
