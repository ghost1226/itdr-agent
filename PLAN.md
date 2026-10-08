# ITDR Identity Incident Builder — Build Plan

## Goal
Build a two-agent system that takes a synthetic Entra ID risky sign-in alert, investigates identity context and directory audit activity, and drafts an ITDR incident narrative with containment and rollback recommendations.

- **Investigator** (tool-calling ReAct agent): gathers evidence from simulated Entra ID / Graph APIs.
- **Adjudicator** (single-shot structured reasoning agent): classifies identity risk and drafts the incident report.

All data is synthetic. No real tenant, no M365 developer sandbox.

---

## Architecture

```
synthetic_alert.json ──► Investigator ──► evidence_dossier.json ──► Adjudicator ──► incident_report.md
                              │
                              └── get_user_profile()
                              └── get_sign_in_history()
                              └── get_device_trust()
                              └── get_directory_audits()   <-- app consent, role changes, password resets
                              └── get_risky_user_report()
```

---

## Git Context
`~/ai-agents-class` is already a git repository with a private GitHub remote. Do **not** run `git init`. All commits are made inside this existing repo.

---

## Checkpoint 0: Project Skeleton + Environment + pip-audit

**Inputs:** None (green-field).

**Tasks:**
1. Create folder structure inside `~/ai-agents-class/itdr-agent/`.
2. Initialize Python virtual environment at `~/ai-agents-class/itdr-agent/.venv`.
3. Write `requirements.txt` with **pinned versions** (e.g., `pytest==8.3.3`, `pydantic==2.9.2`, `faker==30.1.0`, `python-dotenv==1.0.1`, `httpx==0.27.2`, `openai==1.51.0`, `tenacity==9.0.0`, `presidio-analyzer==2.2.355`, `python-docx==1.1.2`, `smolagents==1.1.0`).
4. Install dependencies into the venv.
5. Run `pip-audit` in the venv.
6. Write `.env.example` (OpenRouter key placeholder, `TIMEOUT_SECONDS=120`).
7. Write `.gitignore` (`.env`, `__pycache__`, `.venv`, `.pytest_cache`, `logs/`, `data/fixtures/`).
8. Write `tests/test_skeleton.py` asserting venv exists, `.env.example` exists, requirements are importable, and `TIMEOUT_SECONDS` reads from env with default 120.

**Files edited/created:**
- `.gitignore`
- `.env.example`
- `requirements.txt`
- `tests/test_skeleton.py`

**Acceptance criteria:**
- `pytest tests/test_skeleton.py` passes.
- `pip-audit` runs and result is shown (fix or document any findings).
- `.env` is not tracked by git.
- `git log --oneline` shows the commit.

**Depends on:** None.

**Evidence to show:** `pytest` output + `pip-audit` output + `git log --oneline` + `git status`.

---

## Checkpoint 1: Synthetic Data Generator (Microsoft Sign-In + Directory Audit Schema)

**Inputs:** Microsoft Entra ID sign-in log and directory audit log schemas (published Graph API reference).

**Tasks:**
1. Research and document required schema fields for:
   - `signInLogs`: `id`, `createdDateTime`, `userDisplayName`, `userPrincipalName`, `appDisplayName`, `ipAddress`, `location`, `status`, `riskState`, `riskLevel`, `conditionalAccessStatus`, `deviceDetail`, `mfaDetail`.
   - `directoryAudits`: `id`, `activityDateTime`, `activityDisplayName`, `category`, `correlationId`, `initiatedBy`, `targetResources`, `result`, `resultReason`.
2. Build `itdr_agent/data_generator.py` using `Faker` to generate:
   - Synthetic Entra ID users (UPN, display name, department, manager, tenure).
   - Synthetic sign-in events matching the schema.
   - Synthetic directory audit events (app consent, role changes, password resets, conditional access changes).
   - Synthetic device trust states.
3. **Plant at least 5 MITRE ATT&CK attack patterns** in the synthetic data:
   - **Impossible travel** (two sign-ins from distant locations within minutes).
   - **MFA fatigue** (multiple `mfaDetail` failures followed by a success).
   - **Anonymous IP / anonymizing proxy** (`riskEventType` or location anomaly).
   - **App consent after foreign sign-in** (suspicious app OAuth consent following an anomalous sign-in).
   - **Privilege escalation** (directory audit showing role assignment change, e.g., added to Global Admin).
4. Add MITRE ATT&CK technique IDs (e.g., `T1078`, `T1621`, `T1098`) to the dossier schema (Checkpoint 2).
5. Persist fixtures to `data/fixtures/` as JSONL.

**TDD:**
- Write `tests/test_data_generator.py` first. Assert every generated sign-in and directory audit record contains all mandatory schema fields with correct types. Assert the 5 attack patterns are deterministically planted (seeded Faker) and detectable by simple query logic.

**Files edited/created:**
- `itdr_agent/__init__.py`
- `itdr_agent/data_generator.py`
- `tests/test_data_generator.py`
- `data/fixtures/signins.jsonl`
- `data/fixtures/directory_audits.jsonl`
- `data/fixtures/users.jsonl`

**Acceptance criteria:**
- `pytest tests/test_data_generator.py` passes.
- Fixture files exist with ≥100 sign-in records and ≥50 directory audit records.
- The 5 attack patterns are queryable and verifiable in tests.
- Data generation is deterministic given a seed.

**Depends on:** Checkpoint 0.

**Evidence to show:** `pytest` output + `head -n 2` of each fixture file + MITRE pattern checklist.

---

## Checkpoint 2: Pydantic Schemas + Structured I/O Contracts

**Inputs:** None (design task).

**Tasks:**
1. Define `InvestigatorOutput` (evidence dossier):
   - `alert_id`, `user_principal_name`, `user_profile`, `sign_in_history`, `device_trust`, `directory_audits`, `risk_indicators`, `mitre_attack_mapping` (List of technique IDs), `data_gaps`, `is_critical_gap` (bool).
   - `is_critical_gap`: True **only** if `user_profile` is missing OR `sign_in_history` is empty. Missing `directory_audits` alone does **not** make this critical.
2. Define `AdjudicatorOutput` (incident report):
   - `verdict` (enum: COMPROMISED, SUSPICIOUS, FALSE_POSITIVE, INSUFFICIENT_DATA)
   - `confidence` (float 0.0–1.0)
   - `narrative` (str, multi-paragraph)
   - `containment_steps` (List[dict] with `step` and `rollback`)
   - `recommended_actions` (List[str])
   - `mitre_techniques_observed` (List[str])
   - `audit_notes` (str)
3. Implement confidence guardrail **in code, not as a Pydantic validator**:
   - If `confidence < 0.7` and `verdict != INSUFFICIENT_DATA`, the orchestrator **coerces** `verdict` to `INSUFFICIENT_DATA` and appends a note to `audit_notes`.
   - This allows the LLM to express honest 0.6 confidence for FALSE_POSITIVE; the system handles it transparently.

**TDD:**
- Write `tests/test_schemas.py` first. Assert valid objects serialize/deserialize, invalid objects raise `ValidationError`, and the confidence coercion logic works correctly.

**Files edited/created:**
- `itdr_agent/schemas.py`
- `tests/test_schemas.py`

**Acceptance criteria:**
- `pytest tests/test_schemas.py` passes.
- Invalid data is rejected.
- Confidence coercion: `0.6 + FALSE_POSITIVE → INSUFFICIENT_DATA` with audit note.
- Critical gap detection: only missing user profile or empty sign-in history triggers `is_critical_gap=True`.

**Depends on:** Checkpoint 0.

**Evidence to show:** `pytest` output + sample valid/invalid JSON snippets + coercion test results.

---

## Checkpoint 3: MS Graph Simulation Layer

**Inputs:** Synthetic fixture data from Checkpoint 1.

**Tasks:**
1. Build `itdr_agent/sim_api.py` — a module that exposes functions matching real Microsoft Graph endpoints but returning synthetic data:
   - `get_user_profile(upn: str)`
   - `get_sign_in_history(upn: str, hours: int)`
   - `get_device_trust(device_id: str)`
   - `get_directory_audits(upn: str, hours: int)`
   - `get_risky_user_report(upn: str)`
2. Each function queries the in-memory/synthetic fixture store and returns realistic payloads.
3. Simulate 429/500 responses via **explicit injection**, not randomness:
   - Accept an optional `injected_error: Optional[str] = None` parameter.
   - Tests pass specific error codes to verify retry behavior.
   - No non-deterministic failures.

**TDD:**
- Write `tests/test_sim_api.py` first. Assert each endpoint returns expected shape, handles injected 429/500, and returns `None` for unknown UPNs.

**Files edited/created:**
- `itdr_agent/sim_api.py`
- `tests/test_sim_api.py`
- `itdr_agent/fixture_store.py`

**Acceptance criteria:**
- `pytest tests/test_sim_api.py` passes.
- All five endpoints return data matching real Graph API response shapes.
- Unknown IDs return clean `None` or empty lists, not exceptions.
- Errors are injected deterministically by tests.

**Depends on:** Checkpoints 1, 2.

**Evidence to show:** `pytest` output + sample responses printed from a script.

---

## Checkpoint 4: Investigator Agent (Tool-Calling)

**Inputs:** A synthetic alert ID + the simulation layer.

**Tasks:**
1. Build `itdr_agent/investigator.py`.
2. Implement as a ReAct-style tool-calling agent using `smolagents` (or lightweight custom loop).
3. Register tools: `get_user_profile`, `get_sign_in_history`, `get_device_trust`, `get_directory_audits`.
4. The agent receives an alert payload and must populate an `InvestigatorOutput` dossier.
5. Hard cap: max 8 tool calls.
6. **Unit tests mock the LLM completely.** The agent must be testable without any real API call.
7. **Real-model integration is a separate script** (`scripts/run_investigator_live.py`), documented in README, not run in CI.

**TDD:**
- Write `tests/test_investigator.py` first. Mock all LLM responses and tool calls. Assert the investigator returns a valid `InvestigatorOutput` for a known synthetic alert, and that the dossier contains non-empty `sign_in_history` and `user_profile`.
- Test that the agent respects the max-turn limit.
- Test deterministic behavior given mocked LLM responses.

**Files edited/created:**
- `itdr_agent/investigator.py`
- `tests/test_investigator.py`
- `itdr_agent/tools.py`
- `scripts/run_investigator_live.py` (integration, not run in tests)

**Acceptance criteria:**
- `pytest tests/test_investigator.py` passes with mocked LLM.
- Agent never exceeds 8 tool calls.
- Missing data is flagged in `data_gaps`, not hallucinated.
- Critical gap detection works (missing user profile or sign-in history → `is_critical_gap=True`).
- Integration script exists but is not required for test pass.

**Depends on:** Checkpoints 2, 3.

**Evidence to show:** `pytest` output + printed sample dossier from a synthetic alert + note that integration script is separate.

---

## Checkpoint 5: Adjudicator Agent (Structured Reasoning)

**Inputs:** An `InvestigatorOutput` dossier.

**Tasks:**
1. Build `itdr_agent/adjudicator.py`.
2. Single-shot LLM call via OpenRouter. **Before any code, verify a free model exists on OpenRouter and document it.**
3. Construct a system prompt that:
   - Provides the dossier as JSON.
   - Requires output conforming to `AdjudicatorOutput` schema.
   - Includes MITRE ATT&CK technique IDs observed in the dossier.
   - Requires `rollback` for every `containment_step`.
4. Use JSON-mode or structured output where possible; fallback to Pydantic validation.
5. **Unit tests mock the LLM.** Integration with real model is a separate script (`scripts/run_adjudicator_live.py`).

**TDD:**
- Write `tests/test_adjudicator.py` first.
  - Test with a rich dossier → expects COMPROMISED or SUSPICIOUS.
  - Test with a sparse dossier (but not critical gap) → expects INSUFFICIENT_DATA if confidence < 0.7.
  - Test that output validates against `AdjudicatorOutput`.
  - Test that every containment step has a rollback.
  - Mock the LLM for speed.

**Files edited/created:**
- `itdr_agent/adjudicator.py`
- `tests/test_adjudicator.py`
- `scripts/run_adjudicator_live.py` (integration, not run in tests)

**Acceptance criteria:**
- `pytest tests/test_adjudicator.py` passes (mocked LLM).
- Containment steps all include rollback fields.
- MITRE techniques are present in output if observed in dossier.
- Confidence coercion works: <0.7 → INSUFFICIENT_DATA.
- Integration script exists but not required for test pass.

**Depends on:** Checkpoints 2, 4.

**Evidence to show:** `pytest` output + sample incident report + OpenRouter model verification.

---

## Checkpoint 6: Orchestration + Governance Hardening

**Inputs:** All prior components.

**Tasks:**
1. Build `itdr_agent/orchestrator.py`:
   - Accepts an alert ID.
   - Runs Investigator → validates dossier.
   - If `is_critical_gap` (no user profile OR no sign-in history), short-circuit to `INSUFFICIENT_DATA` **without calling the LLM**.
   - Runs Adjudicator → validates report.
   - Applies confidence coercion (<0.7 → INSUFFICIENT_DATA).
   - Returns final report + audit log.
2. Add governance guardrails:
   - **Audit logging:** Every run appends to `logs/audit.jsonl` with timestamp, alert_id, tool_calls, dossier_hash, report_hash.
   - **Anonymization pass:** Verify no real email/domain leaks before LLM call (synthetic data already clean, but validate).
   - **Rate-limit & timeout:** Total orchestrator timeout defaults to `TIMEOUT_SECONDS=120` (read from `.env`). OpenRouter call capped at 90s.
   - **Honest fallback:** Short-circuit only on critical gaps (see above).
3. Build a small CLI (`python -m itdr_agent --alert-id ALERT_001`) that prints the report.

**TDD:**
- Write `tests/test_orchestrator.py` first.
  - End-to-end: alert in → valid report out.
  - Test short-circuit: missing user profile → no LLM call, verdict INSUFFICIENT_DATA.
  - Test non-short-circuit: missing directory audits only → LLM still called.
  - Test audit log append.
  - Test timeout behavior.

**Files edited/created:**
- `itdr_agent/orchestrator.py`
- `itdr_agent/__main__.py`
- `tests/test_orchestrator.py`
- `logs/` (gitignored, created at runtime)

**Acceptance criteria:**
- `pytest tests/test_orchestrator.py` passes.
- CLI runs without errors.
- Audit log entry exists for every run.
- Short-circuit only on critical gaps (user profile or sign-in history missing).
- Non-critical gaps allow LLM call.
- All code is committed with clear messages.

**Depends on:** Checkpoints 4, 5.

**Evidence to show:** `pytest` output + CLI run output + `cat logs/audit.jsonl | head -n 1` + `git log --oneline`.

---

## Final Step: README

After all checkpoints pass, write `README.md` covering:
1. What the agent does.
2. How to create the venv and install deps.
3. How to set `.env` with an OpenRouter key and `TIMEOUT_SECONDS`.
4. How to run the synthetic data generator.
5. How to run tests (`pytest`).
6. How to run the CLI demo.
7. How to run integration tests with a real OpenRouter model.
8. Architecture diagram (ASCII or mermaid).
9. Governance guardrails summary.
10. Verification that free OpenRouter model was checked.
11. pip-audit result summary.

Then commit and say **"done."**

---

## Dependency Graph

```
0. Skeleton + pip-audit
    │
    ├──► 1. Data Generator
    │         │
    │         └──► 3. Sim API Layer ◄──┐
    │                                    │
    ├──► 2. Schemas ◄──────────────────┼──► 4. Investigator
    │                    │               │         │
    │                    └───────────────┘         │
    │                                              ▼
    │                                    ┌──► 5. Adjudicator
    │                                    │         │
    │                                    │         ▼
    │                                    └──► 6. Orchestrator + CLI
    │                                              │
    └──────────────────────────────────────────────┘
                                            │
                                            ▼
                                       README.md
```

---

## Commit Message Convention
Use `checkpoint-N-task: description` format:
- `checkpoint-0: add skeleton, venv, pip-audit`
- `checkpoint-1-test: add failing tests for synthetic data generator`
- `checkpoint-1-pass: generate synthetic sign-ins with MITRE patterns`

---

## Notes on Tools & Constraints
- **LLM Gateway:** OpenRouter free tier. I will verify a working free model (e.g., `mistralai/mistral-7b-instruct:free` or `meta-llama/llama-3.1-8b-instruct:free`) before writing any LLM-dependent code.
- **No Microsoft Copilot, no Azure OpenAI, no M365 sandbox.**
- **No global pip installs.** Everything lives in `.venv/`.
- **Timeout:** Default `TIMEOUT_SECONDS=120` (configurable in `.env`).
- **Tests are deterministic.** Simulated errors are injected, not random.
- **Integration tests are separate.** Unit tests mock the LLM; real-model runs are documented in README.
