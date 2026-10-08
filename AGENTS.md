# Project Rules — ITDR Identity Incident Builder

These rules stand for the life of the project. Read this and PROGRESS.md at the start of every session.

---

## Standing Rules

1. **Synthetic data only.** Never ask for real logs, alerts, users, or anything from work.
2. **Virtual environment inside the project folder.** Nothing installed globally.
3. **API keys only in `.env`.** `.env` is gitignored. Never hardcode a key.
4. **Red-green TDD.** Write the failing test first, then make it pass.
5. **Commit after every task** inside the existing `~/ai-agents-class` repo. Do **not** run `git init`.
6. **Ask before running any command outside the project folder.**
7. **Ask me only about scope, design, or missing facts.** Decide implementation details yourself.
8. **At the end of every task, update PROGRESS.md** (done, next, decisions, problems, commit hash) and commit it.

## Session Start Ritual

At the start of every session:
1. Read `PLAN.md`.
2. Read `PROGRESS.md`.
3. Then do what PROGRESS.md says is next.
