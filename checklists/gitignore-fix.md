# Checklist — .gitignore correction (Jessica's review, 2026-10-23)

Task: keep only the dry-run scratch ignored. `eval/rerun/` evidence
(`raw.jsonl`, `results.md`, `interruptions.jsonl`) is committed like
`eval/final/` and `eval/after-fix/`; only `eval/rerun/dry_run/` is throwaway.

- [x] `.gitignore` ignores `eval/**/dry_run/` and no longer ignores `eval/**/rerun/` -> `../.gitignore::eval/**/dry_run/`
- [x] `checklists/review-fixes.md` names the new pattern -> `review-fixes.md::eval/**/dry_run/`
