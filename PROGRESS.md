# Progress Diary — ITDR Identity Incident Builder

Updated: Checkpoint 0 complete.

---

## Current Checkpoint

**Checkpoint 1 — not started.**

## What's Done

- ✅ Checkpoint 0: Project skeleton, venv, pinned dependencies, pip-audit clean, red-green TDD.
  - Commit: `f186259`
  - All 7 skeleton tests pass.
  - pip-audit: **No known vulnerabilities found.**

## What's Next

1. Research Microsoft sign-in + directory audit log schemas.
2. Write failing tests for synthetic data generator.
3. Build `itdr_agent/data_generator.py` with Faker.
4. Plant 5 MITRE ATT&CK attack patterns in synthetic data.
5. Generate and commit fixture files to `data/fixtures/`.
6. Make tests pass.
7. Commit.

## Decisions Made

| Decision | Why |
|----------|-----|
| ITDR instead of DLP | Boss ranked DLP first, but Microsoft is shipping a Purview DLP Alert Triage Agent via Security Copilot (M365 E5, 2026). Gap is closing fast. ITDR correlation narrative is underserved and has more runway. |
| Two-agent architecture | Investigator (tool-calling) + Adjudicator (structured reasoning). Satisfies "at least two agentic workflows." |
| Synthetic data with Faker | No real tenant, no M365 developer sandbox eligibility. |
| OpenRouter free tier | Avoids Azure OpenAI / Security Copilot licensing and governance approval cycles. |
| Confidence coercion in code, not schema | Prevents fake certainty. LLM can honestly say 0.6; orchestrator handles it. |
| Short-circuit only on critical gaps | Missing user profile or sign-in history stops the LLM. Missing audit trails alone does not. |
| Deterministic errors via injection | No flaky tests. Tests pass explicit `injected_error` parameters. |
| Integration tests separate from unit tests | Unit tests mock the LLM. Real-model runs are manual scripts, not CI. |
| Timeout default 120s | Free models are slow. Configurable via `.env`. |
| Commit inside existing repo | `~/ai-agents-class` is already a git repo with a private GitHub remote. |
| Lightweight deps | Dropped `presidio-analyzer` (pulls spaCy + large model) and `python-docx` (unused). Synthetic domain regex check is sufficient for anonymization. |
| Fixtures: commit or generate | `data/fixtures/` is not gitignored. Small fake JSONL files will be committed. Tests also support generating from seed for a fresh start. |
| `get_risky_user_report` | Dropped from Investigator tool registry. The agent already infers risk from sign-in history and directory audits. Keeps tool count lean. |

## Open Problems

1. **Which free OpenRouter model?** Must verify existence and availability before Checkpoint 5. Candidates: `mistralai/mistral-7b-instruct:free`, `meta-llama/llama-3.1-8b-instruct:free`, `microsoft/phi-3-medium-128k-instruct:free`.
2. **Framework choice for Investigator.** `smolagents` vs. lightweight custom ReAct loop. Decision deferred to Checkpoint 4 implementation.

## Commit History

- `f186259` — checkpoint-0: skeleton, venv, pinned deps, pip-audit clean, red-green TDD
