# Progress Diary — ITDR Identity Incident Builder

Updated: Checkpoint 1 complete.

---

## Current Checkpoint

**Checkpoint 2 — not started.**

## What's Done

- ✅ Checkpoint 0: Project skeleton, venv, pinned dependencies, pip-audit clean, red-green TDD.
  - Commit: `f186259`
  - All 7 skeleton tests pass.
  - pip-audit: **No known vulnerabilities found.**
- ✅ Checkpoint 1: Synthetic Entra ID data generator with 5 planted MITRE ATT&CK patterns.
  - Commit: `cf443c5`
  - 15 new tests in `tests/test_data_generator.py`; full suite 22 passed.
  - Fixtures committed: `data/fixtures/users.jsonl` (25), `sign_ins.jsonl` (109),
    `directory_audits.jsonl` (52), `alerts.jsonl` (5).
  - Generation is deterministic given a seed (`generate_dataset(seed=1337)`).
  - pip-audit: **No known vulnerabilities found.**

## What's Next

Checkpoint 2 — Pydantic schemas + structured I/O contracts:
1. Write failing `tests/test_schemas.py`.
2. Define `InvestigatorOutput` (evidence dossier) with `is_critical_gap` rule.
3. Define `AdjudicatorOutput` (incident report) with `verdict` enum and containment/rollback.
4. Implement confidence coercion in code (<0.7 and verdict != INSUFFICIENT_DATA → INSUFFICIENT_DATA + audit note).
5. Make tests pass and commit.

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
| Deterministic IDs via seeded RNG, not Faker | `uuid.UUID(int=rng.getrandbits(128))` keeps IDs stable across code changes that alter Faker call order. |
| Alerts fixture included in Checkpoint 1 | The architecture and CLI need alert IDs; generating them alongside sign-ins keeps the simulator self-contained. |
| Scenario UPNs exposed as `SCENARIO_UPNS` | Tests and later tools need a stable way to locate the 5 planted attack patterns. |
| `impossibleTravel`/`anonymizedIPAddress`/`unfamiliarFeatures` in `riskEventTypes` | Matches real Graph `signInLogs` risk event taxonomy, so downstream detection stays realistic. |

## Open Problems

1. **Which free OpenRouter model?** Must verify existence and availability before Checkpoint 5. Candidates: `mistralai/mistral-7b-instruct:free`, `meta-llama/llama-3.1-8b-instruct:free`, `microsoft/phi-3-medium-128k-instruct:free`.
2. **Framework choice for Investigator.** `smolagents` vs. lightweight custom ReAct loop. Decision deferred to Checkpoint 4 implementation.

## Commit History

- `f186259` — checkpoint-0: skeleton, venv, pinned deps, pip-audit clean, red-green TDD
- `5528d5e` — checkpoint-0: update PROGRESS.md
- `cf443c5` — checkpoint-1: synthetic data generator with 5 MITRE ATT&CK patterns
