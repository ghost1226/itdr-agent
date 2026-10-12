# Progress Diary — ITDR Identity Incident Builder

Updated: Checkpoint 1b complete; next Checkpoint 4 task 8 (alert wrapper), before Checkpoint 5.

---

## Current Checkpoint

**Checkpoint 1b — complete. Next: Checkpoint 4 task 8, then Checkpoint 5.**

## What's Done

- ✅ Checkpoint 0: Project skeleton, venv, pinned dependencies, pip-audit clean, red-green TDD.
  - Commit: `f186259` (diary `5528d5e`).
  - All 7 skeleton tests pass.
- ✅ Checkpoint 0 fixes (review feedback):
  - Commit: `19ec859`.
  - **A.** Bumped `openai` from `1.63.2` → `3.26.1` (current stable on PyPI). Re-ran `pip-audit`: **No known vulnerabilities found.**
  - **C.** `test_timeout_default` now clears `TIMEOUT_SECONDS`/`ITDR_TIMEOUT` with `monkeypatch.delenv` and neutralises `dotenv.load_dotenv`, so a developer's real `.env` cannot break it. Verified with a hostile `.env` (`TIMEOUT_SECONDS=999`): both timeout tests pass.
  - **B.** Red-green commits adopted from here on (see Checkpoint 1 below).
- ✅ Checkpoint 2: Pydantic schemas + structured I/O contracts.
  - Commit: `d445d00` (diary `703d310`).
  - 17 tests in `tests/test_schemas.py`; `InvestigatorOutput` enforces `is_critical_gap` from data; `AdjudicatorOutput` validates verdict/confidence/rollback; `apply_confidence_guardrail` lives in code, not a validator.
- ✅ Checkpoint 1: Synthetic Entra ID data generator (revised per review).
  - **Red:** `9f2d832` — tests only; `pytest tests/test_data_generator.py` → **7 failed, 12 passed**.
  - **Green:** `188a293` — implementation + fixtures; **19 passed**, full suite **43 passed**.
  - Fixtures committed: `users.jsonl` (25), `sign_ins.jsonl` (109), `directory_audits.jsonl` (52), `alerts.jsonl` (5).
  - Same seed ⇒ byte-identical files (verified by SHA-256 across two runs).
  - Every user/email uses `@contoso.com`; test rejects common leaked domains.
- ✅ Checkpoint 1 fix (review feedback):
  - **Red:** `86976df` — tests only; `pytest tests/test_data_generator.py` → **1 failed, 19 passed**.
  - **Green:** `d5cdcec` — scenario-aware alert selection; **20 passed**, full suite **44 passed**.
  - `ALERT_002` (MFA fatigue) now references an actual MFA-denied sign-in; `ALERT_005` (privilege escalation) references a risky session and is `atRisk`, instead of pointing at benign baseline sign-ins.
  - Review items 1–5 (openai 3.26.1, timeout `monkeypatch.delenv`, `riskEventTypes_v2`, corrected MITRE IDs, `@contoso.com` test) were already landed in `19ec859`, `9f2d832`, and `188a293`; this fix closes the remaining alert-matching gap.
- ✅ Governance: added AGENTS.md rule 9 — after each checkpoint, stop, show evidence, and wait for Joe's go before starting the next.
- ✅ Checkpoint 0 fix: `test_venv_exists` now skips on a fresh clone (no `.venv`) instead of failing. Commit `d022092`.
- ✅ Checkpoint 3: Simulated Microsoft Graph layer.
  - **Red:** `9922656` — tests only; `pytest tests/test_sim_api.py` → **15 failed** (module missing).
  - **Green:** `1e53f2d` — **15 passed**, full suite **59 passed**.
  - `itdr_agent/fixture_store.py` loads the committed JSONL fixtures (or regenerates from seed if absent) and indexes users/sign-ins/devices.
  - `itdr_agent/sim_api.py` exposes `get_user_profile`, `get_sign_in_history`, `get_device_trust`, `get_directory_audits`, `get_risky_user_report` with Graph-shaped payloads.
  - Unknown UPN/device → `None` or `[]`, never a guess.
  - 429/500 only via explicit `injected_error="429"`/`"500"` → `SimulatedGraphError.status_code`; no randomness anywhere. `test_no_errors_without_injection` calls each endpoint 25× to prove it.
- ✅ Checkpoint 4: Investigator agent (custom ReAct loop).
  - **Red:** `47e17ec` — tests only; `pytest tests/test_investigator.py` → **14 failed** (module missing).
  - **Green:** `5121f03` — **14 passed**, full suite **73 passed**.
  - `itdr_agent/tools.py`: 5 tools (`get_user_profile`, `get_sign_in_history`, `get_device_trust`, `get_directory_audits`, `get_risky_user_report`) + `wrap_tool_output`.
  - `itdr_agent/investigator.py`: custom loop, cap `MAX_TOOL_CALLS = 8`, retry-once on `SimulatedGraphError`, then record in `data_gaps` and continue.
  - Dossier factual fields assembled from verbatim tool output; risk indicators and MITRE mapping derived deterministically in code.
  - `scripts/run_investigator_live.py`: reads `OPENROUTER_API_KEY` from `.env` only, not run in tests, not executed yet.
  - No new dependency (no smolagents) → dependency set unchanged, pip-audit still clean.
- ✅ Checkpoint 4 fix: MITRE correctness + wrapper hardening.
  - **Red:** `541047f` — tests only; `pytest tests/test_investigator.py` → **7 failed**.
  - **Green:** `2d9a680` — **21 passed**, full suite **80 passed**; fixtures regenerated (users 27, sign-ins 118, audits 52).
  - MITRE derivation is now direction- and time-aware, and every technique carries its evidence ids (`mitre_attack_evidence`).
  - Tool-data wrapper escapes `<`/`>` (`\u003c`/`\u003e`) so a record cannot close the data block.
  - Background role changes are initiated only by `ADMIN_UPNS`; scenario users are never baseline role-add targets.
- ✅ Checkpoint 4 task 8: alert allowlist + untrusted-data wrapper (review requirement).
  - **Red:** `377d586` — tests only; `pytest` → **6 failed, 106 passed** (112 tests).
  - **Green:** `5dd360d` — **112 passed**.
  - `investigator.build_alert_prompt()` filters the alert through `ALERT_FIELD_ALLOWLIST` and wraps it as `<microsoft_graph_data tool="alert" untrusted="true">` with `<`/`>` escaped, so the model sees evidence and never the answer key.
  - System prompt now says the alert **and** tool output are untrusted data.
  - Tests: no answer key in any alert prompt, alert fields only inside the wrapper, breakout probe, instruction probe, round-trip `json.loads`, and the investigator's user message equals the wrapped alert.
- ✅ Checkpoint 1b: benign alerts, thin/unknown alerts, separate ground truth, graph-field-check.
  - **Red:** `d49281d` — tests only; `pytest` → **13 failed, 5 errors, 78 passed** (96 tests).
  - **Green:** `3e70589` — **96 passed**; fixtures regenerated (users 29, sign-ins 130, audits 53, alerts 10, ground_truth 10).
  - Three benign scenarios planted: `benign_travel` (same compliant device, no risk events), `benign_admin_role` (in-window, ticket-backed role add; investigated admin is the **target**), `benign_vpn` (known company egress IPs).
  - Added one `thin_data` alert (known user, 1–2 sign-ins, no audits, **not** a critical gap → `INSUFFICIENT_DATA`) and one `unknown` alert (UPN absent from `users.jsonl` → critical gap).
  - **Ground truth moved out of the model path:** `alerts.jsonl` is Graph-shaped only (`ALERT_FIELD_ALLOWLIST`); `scenario` / `expected_verdict` / `expected_mitre` / `is_benign` live in `data/fixtures/ground_truth.jsonl` (tests + `scripts/evaluate.py` only).
  - `benign_admin_role` keeps `expected_mitre == ["T1098.003"]`: the pattern is real, so the mapper still emits it; legitimacy is the analyst's call.
  - `tests/test_graph_fields.py` is the graph-field-check allowlist test (per resource). It caught `riskyUser.riskEventTypes_v2` — not a real `riskyUser` field — which is now removed and replaced with valid `riskyUser` fields.
  - Same seed ⇒ byte-identical for all five files (SHA-256 verified); pip-audit: **No known vulnerabilities found**.
- ✅ Checkpoint 1b fix (review): realistic baseline + physically plausible benign cases.
  - **Red:** `18a74d0` — tests only; `pytest` → **6 failed, 3 errors, 95 passed** (104 tests).
  - **Green:** `49edfdc` — **104 passed**; fixtures regenerated (users 29, sign-ins 129, audits 53, alerts 10, ground_truth 10, user_context 29).
  - Every user now has a home city, 1–2 stable devices, and a 2–3 IP set (`user_context.jsonl`); baseline sign-ins come only from those (no random city/device/IP).
  - `benign_travel` is now New York 09:05 → London 17:20 (8h15m, ~675 km/h), same known compliant device.
  - `benign_vpn` sign-ins carry the **beta** `networkLocationDetails` (`networkType: namedNetwork`, `networkNames: ["Contoso Corporate VPN"]`) on a known device.
  - Baseline audits are initiated only by `ADMIN_UPNS` and never target scenario users (the only non-admin initiator left is dave's self-consent).
  - New test `test_benign_alerts_are_physically_plausible`: whole investigation window on known devices, no consecutive leg > 900 km/h, no non-admin action on the user.
  - Same seed ⇒ byte-identical for all six files (SHA-256 verified); pip-audit: **No known vulnerabilities found**.
- ✅ Checkpoint 1b fix 2 (Jessica): benign target is no longer shared with the privilege-escalation attack.
  - **Red:** `72418ed` — tests only; `pytest` → **2 failed, 104 passed** (106 tests). The failure named the overlap exactly: `it.admin@contoso.com initiates privilege_escalation's planted audit`.
  - **Green:** `0438e4c` — **106 passed**; fixtures regenerated (users 30, sign-ins 133, audits 53, alerts 10, ground_truth 10, user_context 30).
  - `benign_admin_role` now investigates a new ordinary user, `helpdesk.agent@contoso.com`, who is in no other scenario and is not in `ADMIN_UPNS`. The role add is initiated by `sec.admin` and cites ticket `HD-1042`; `expected_mitre` stays `["T1098.003"]`.
  - `it.admin` remains only the privilege-escalation initiator, so it no longer appears in any benign user's window.
  - New tests: `test_benign_admin_role_target_is_an_ordinary_unique_user` and `test_no_cross_scenario_contamination` (no scenario user is initiator or target of another scenario's planted audit).
  - Same seed ⇒ byte-identical for all six files (SHA-256 verified); pip-audit: **No known vulnerabilities found**.

## Microsoft Graph Schema Sources

Field names in `itdr_agent/data_generator.py` follow these published shapes:

| Resource | Fields used | Source |
|----------|-------------|--------|
| `signIn` (v1.0) | `riskEventTypes_v2`, `riskDetail`, `riskLevelAggregated`, `riskLevelDuringSignIn`, `riskState`, `status`, `deviceDetail`, `location`, `clientAppUsed`, `conditionalAccessStatus`, `correlationId` | https://learn.microsoft.com/en-us/graph/api/resources/signin?view=graph-rest-1.0 |
| `mfaDetail` (beta) | `authMethod`, `authDetail` | https://learn.microsoft.com/en-us/graph/api/resources/mfadetail?view=graph-rest-beta |
| `directoryAudit` (v1.0) | `activityDateTime`, `activityDisplayName`, `category`, `correlationId`, `initiatedBy`, `targetResources`, `result`, `resultReason`, `loggedByService` | https://learn.microsoft.com/en-us/graph/api/resources/directoryaudit?view=graph-rest-1.0 |
| `signInLocation` (v1.0) | `city`, `state`, `countryOrRegion`, `geoCoordinates` | https://learn.microsoft.com/en-us/graph/api/resources/signinlocation?view=graph-rest-1.0 |
| `deviceDetail` (v1.0) | `deviceId`, `displayName`, `operatingSystem`, `browser`, `isCompliant`, `isManaged`, `trustType` | https://learn.microsoft.com/en-us/graph/api/resources/devicedetail?view=graph-rest-1.0 |
| `user` (v1.0) | `id`, `userPrincipalName`, `displayName`, `department`, `jobTitle`, `manager`, `hireDate`, `accountEnabled` | https://learn.microsoft.com/en-us/graph/api/resources/user?view=graph-rest-1.0 |
| `riskyUser` (v1.0) | `id`, `userDisplayName`, `userPrincipalName`, `riskLevel`, `riskState`, `riskDetail`, `riskLastUpdatedDateTime`, `isDeleted`, `isProcessing` | https://learn.microsoft.com/en-us/graph/api/resources/riskyuser?view=graph-rest-1.0 |
| `networkLocationDetails` (beta `signIn` field) | `networkNames`, `networkType` (`intranet`, `extranet`, `namedNetwork`, `trusted`, `unknownFutureValue`) | https://learn.microsoft.com/en-us/graph/api/resources/networklocationdetail?view=graph-rest-beta |

Notes verified against the live docs page:
- `riskEventTypes` is **deprecated**; we emit `riskEventTypes_v2`.
- Valid `riskEventTypes_v2` values include `unlikelyTravel`, `anonymizedIPAddress`, `unfamiliarFeatures`.
- Anonymous IP is therefore `riskEventTypes_v2 == ["anonymizedIPAddress"]`, **not** a `riskEventType` scalar.
- `riskyUser` does **not** have `riskEventTypes_v2`; that field is on `signIn`. The `riskyUser` fields we use are confirmed on the `riskyUser` page above.
- `networkLocationDetails` is **beta-only** on `signIn` (v1.0 does not have it), so it is marked beta. `networkType` values confirmed on the `networkLocationDetail` page: `intranet`, `extranet`, `namedNetwork`, `trusted`, `unknownFutureValue`. We use `namedNetwork` + `networkNames` to mark the company VPN.

## MITRE ATT&CK Checklist

| Planted attack | Technique | Evidence in data | Test |
|----------------|-----------|------------------|------|
| Impossible travel | **T1078** | two `unlikelyTravel` sign-ins (US → RU) 25 min apart | `test_impossible_travel_pattern` |
| MFA fatigue | **T1621** | ≥3 MFA-denied sign-ins followed by a success | `test_mfa_fatigue_pattern` |
| Anonymous IP | **T1090.003** | `riskEventTypes_v2` contains `anonymizedIPAddress`, high risk | `test_anonymous_ip_pattern` |
| App consent after foreign sign-in | **T1528** | `unfamiliarFeatures` sign-in → `Consent to application` audit | `test_app_consent_after_foreign_signin_pattern` |
| Privilege escalation | **T1098.003** | `Add member to role` → Global Administrator audit | `test_privilege_escalation_pattern` |

Each pattern test finds the behaviour in the generated data **and** asserts
`SCENARIO_TECHNIQUES[scenario]` equals the expected technique ID.

## Fixture Decision

**Commit the fixtures.** They are fake, small, and deterministic, so they are
tracked in git under `data/fixtures/` (not gitignored). Tests may also
regenerate them from a seed via `data_generator.write_fixtures(tmp_path, seed=...)`.

## What's Next

**Checkpoint 1b — complete (red `d49281d`, green `3e70589`; review fix red `18a74d0`, green `49edfdc`; overlap fix red `72418ed`, green `0438e4c`; 106 tests). Checkpoint 4 task 8 — complete (red `377d586`, green `5dd360d`; 112 tests).**

**Next: Checkpoint 5 — Adjudicator agent (structured reasoning):**
1. Verify a free OpenRouter model exists and document it (open item).
2. Write failing `tests/test_adjudicator.py` (red commit first).
3. Build `itdr_agent/adjudicator.py`: single-shot structured output over the dossier.
4. Apply confidence coercion; require rollback on every containment step.
5. Skill alignment (`T1078.004`; T1621 3-in-30; T1528 after a risky sign-in; Adjudicator MITRE guard).
6. Green commit, then commit PROGRESS.md.

## Mistakes & Lessons

Institutional log so future sessions do not repeat these. Each row is a real
mistake made in this project, its root cause, and the rule that prevents it.

| Mistake | Root cause | Prevention rule | Fixed in |
|---------|------------|-----------------|----------|
| Wrong MITRE IDs (T1090/T1550.001/T1098) | Wrote from memory instead of checking ATT&CK | Verify every technique ID against the ATT&CK source before coding | `9f2d832` / `188a293` |
| Invented Graph fields (`riskEventTypes`, `riskLevel`) | Trusted PLAN prose over the real schema | Check every field on Microsoft Learn; use `riskEventTypes_v2`, `riskLevelAggregated`, `riskLevelDuringSignIn` | `9f2d832` / `188a293` |
| Wrong risk enum value `impossibleTravel` | Did not read the documented enum | Use the documented value (`unlikelyTravel`) | `188a293` |
| Alerts pointed at benign baseline sign-ins | Generic "first match" source selection | Each trigger/alert must reference the sign-in that demonstrates its pattern | `86976df` / `d5cdcec` |
| `directory_audits` attribute shadowed its method | Same name used for data and accessor | Name accessors `get_*` so they cannot collide with data attributes | `1e53f2d` (caught pre-commit) |
| Stray parentheses in `test_sim_api.py` | Hand-written test, no compile check | Run `py_compile` (or import) on new test files before committing | `9922656` (fixed pre-commit) |
| Landed first Checkpoint 1 without a red/green split | Did not follow the review process initially | Commit failing tests first (`red`), then code (`green`) | `9f2d832` / `188a293` |
| Started Checkpoint 2 before Checkpoint 1 fixes | Advanced without waiting for review | AGENTS.md rule 9: stop after each checkpoint, show evidence, wait | AGENTS.md rule 9 |
| Mapped `T1098.003` from role adds the user merely initiated, with no time window | `_derive` treated any role add the user touched as escalation | Check direction (user must be the target) and confine to the investigation window; tie each technique to evidence ids | `541047f` / `2d9a680` |
| Tool-data wrapper could be broken out of with `</microsoft_graph_data>` | `json.dumps` leaves `<`/`>` unescaped | Escape `<`/`>` to `\u003c`/`\u003e` so the closing tag appears exactly once | `541047f` / `2d9a680` |
| Emitted `riskEventTypes_v2` on a `riskyUser` record | Copied a `signIn` field onto the `riskyUser` shape | Use the graph-field-check allowlist per resource; a field on one Graph resource is not valid on another | `3e70589` |

Standing prevention rules distilled from the above:
1. Verify external facts (schemas, enum values, technique IDs) against the
   primary source before writing code — never from memory or prose.
2. Every test file must compile/import before it is committed.
3. Watch for attribute/method name collisions; accessors use a `get_` prefix.
4. Synthetic triggers must point at the evidence that proves their pattern.
5. Red-green from the first commit; stop and wait after each checkpoint.

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
| Fixtures: commit them | Fake, small, deterministic JSONL. Tests can also regenerate from seed. |
| `get_risky_user_report` | Dropped from Investigator tool registry. The agent already infers risk from sign-in history and directory audits. Keeps tool count lean. |
| `riskEventTypes_v2`, not the deprecated `riskEventTypes` | Matches current Graph; anonymous IP surfaces here as `anonymizedIPAddress`. |
| Impossible travel value is `unlikelyTravel` | That is the real `riskEventTypes_v2` value; "impossibleTravel" does not exist in the enum. |
| MITRE IDs corrected | anonymous IP `T1090.003`, app consent `T1528`, privilege escalation `T1098.003` (review feedback). |
| Deterministic IDs via seeded RNG, not Faker | `uuid.UUID(int=rng.getrandbits(128))` keeps IDs stable across code changes that alter Faker call order. |
| Alerts fixture included in Checkpoint 1 | The architecture and CLI need alert IDs; generating them alongside sign-ins keeps the simulator self-contained. |
| Scenario UPNs exposed as `SCENARIO_UPNS` | Tests and later tools need a stable way to locate the 5 planted attack patterns. |
| `is_critical_gap` enforced by a model validator | Callers cannot claim no critical gap when profile or sign-in history is missing. |
| Confidence guardrail as a plain function | Pydantic validators run on construction and would block honest low-confidence reports. The orchestrator applies policy explicitly. |
| `Verdict` as `str, Enum` | Serializes cleanly to JSON and compares naturally with plain strings in tests. |
| Red-green commits from Checkpoint 1 onward | Review requirement: failing tests are committed first (`checkpoint-1: red`), then the code (`checkpoint-1: green`). |
| Scenario-aware alert selection | Each alert's `riskEventTypes_v2`/`status` must point at the sign-in that demonstrates its pattern, or the downstream Investigator gets a meaningless trigger. |
| Simulated Graph errors raise `SimulatedGraphError` | Mirrors real Graph HTTP failures so the Investigator's retry logic can be exercised via `injected_error`; `status_code` carries 429/500. |
| Fixture store "now" = newest synthetic event | Makes `hours` windowing deterministic without a wall clock, keeping tests reproducible. |
| `get_directory_audits` method name (not `directory_audits`) | Avoids shadowing the store's `directory_audits` list attribute. |
| **Custom ReAct loop, not smolagents** | Review requires every attempt (including retries) to count toward an exact 8-call cap, retry-once, and data-gap recording. A custom loop makes those semantics explicit and the LLM fully mockable with no network, no extra dependency, no license/pip-audit churn. |
| **Register `get_risky_user_report` as the 5th tool** | Reverses the earlier "drop it" call: it is the strongest single risk signal and feeds `risk_indicators` and MITRE mapping directly, so keeping it improves the dossier. |
| Tool output wrapped in `<microsoft_graph_data untrusted="true">` | Tool output is data, not instructions. Prompt-injection text inside a log is serialized and delimited, and the system prompt forbids following it. Tested. |
| Dossier facts assembled from verbatim tool output | Prevents hallucination: the LLM only chooses which tools to call; sign-in/audit records must match fixtures by id. Risk/MITRE are derived in code. |
| Retry-once then `data_gaps`; attempts count toward cap | Matches review: persistent 429/500 is retried once, recorded, and investigation continues; persistent failures consume 2 of the 8 calls. |
| MITRE derivation is windowed and direction-aware | Only in-window events count; `T1098.003` requires the investigated user to be the **target** of the role add. Being the initiator yields indicator "user granted a role to another account" and no escalation claim. |
| Each technique stores evidence ids (`mitre_attack_evidence`) | The Adjudicator can verify every MITRE claim against the exact sign-in/audit record it came from. |
| Tool wrapper escapes `<`/`>` | A log field containing `</microsoft_graph_data>` cannot break out of the untrusted-data block. |
| Background role changes only by `ADMIN_UPNS` | Ordinary staff (e.g. Sales) initiating role changes must not look like an attack; role adds are IT-admin noise, and baseline role targets exclude scenario users. |
| Ground truth in `data/fixtures/ground_truth.jsonl` | Labels (`scenario`, `expected_verdict`, `expected_mitre`, `is_benign`) must never reach the model. Tests and `scripts/evaluate.py` are the only readers; `alerts.jsonl` stays Graph-shaped via `ALERT_FIELD_ALLOWLIST`. |
| `benign_admin_role` keeps `T1098.003` in `expected_mitre` | The role-add pattern is real; deciding it is legitimate (helpdesk ticket) is the analyst's/Adjudicator's job, not the mapper's. |
| Three benign + thin-data + unknown alerts | False-positive control and the low-confidence `ask_user` path need ground-truth cases. |
| graph-field-check allowlist test per resource | Catches invented/renamed fields; it caught `riskyUser.riskEventTypes_v2`. |
| `user_context.jsonl` (home city, known devices, stable IPs) | Realistic baseline noise; lets tests prove benign cases are physically plausible without putting project fields in Graph records. |
| `benign_vpn` uses beta `networkLocationDetails` | The agent cannot know `198.51.100.x` is the company VPN from the IP alone; a trusted named network is the Graph-native explanation. |
| Alert is allowlisted + wrapped like tool output | The full alert record (including `scenario`) must never reach the model; `build_alert_prompt` applies `ALERT_FIELD_ALLOWLIST` and the untrusted-data wrapper. |

## Free OpenRouter Model (Checkpoint 5)

Verified against `https://openrouter.ai/api/v1/models` and the model page
`https://openrouter.ai/google/gemma-4-31b-it:free` (HTTP 200) in the pre-code
check; no live tokens spent.

| Field | Value |
|---|---|
| Model id | `google/gemma-4-31b-it:free` |
| Name | Google: Gemma 4 31B (free) |
| Pricing (prompt / completion) | `0` / `0` (free tier) |
| Context length | 262,144 tokens |
| Page | https://openrouter.ai/google/gemma-4-31b-it:free |

`EVAL_MODEL` and the adjudicator integration script default to this id. The
live script (`scripts/run_adjudicator_live.py`) is **not** run until Joe says go.

## Open Problems

1. ~~**Which free OpenRouter model?**~~ **Resolved (Checkpoint 5):** `google/gemma-4-31b-it:free`, confirmed free with a 262,144-token context on the OpenRouter models API and model page.
2. ~~**Framework choice for Investigator.**~~ **Resolved (Checkpoint 4):** lightweight custom ReAct loop (exact cap, retry-once, fully mockable).

## Commit History

- `f186259` — checkpoint-0: skeleton, venv, pinned deps, pip-audit clean, red-green TDD
- `5528d5e` — checkpoint-0: update PROGRESS.md
- `cf443c5` — checkpoint-1: synthetic data generator with 5 MITRE ATT&CK patterns
- `495f9eb` — checkpoint-1: update PROGRESS.md
- `d445d00` — checkpoint-2: pydantic schemas, critical-gap rule, confidence guardrail
- `703d310` — checkpoint-2: update PROGRESS.md
- `19ec859` — checkpoint-0-fix: bump openai to 3.26.1, harden timeout test against real .env
- `9f2d832` — checkpoint-1: red — real Graph field names, corrected MITRE IDs, byte-stable and synthetic-domain tests
- `188a293` — checkpoint-1: green — Graph-accurate fields, corrected MITRE IDs, byte-identical fixtures
- `9d2a539` — checkpoint-1: update PROGRESS.md with Graph sources, MITRE checklist, red/green commits
- `86976df` — checkpoint-1-fix: red — alerts must reference their planted pattern evidence
- `d5cdcec` — checkpoint-1-fix: green — scenario-aware alert selection points at real pattern evidence
- `5de4076` — checkpoint-1-fix: docs — AGENTS.md stop-and-wait rule, update PROGRESS.md
- `d022092` — checkpoint-0-fix: skip venv test on a fresh clone instead of failing
- `9922656` — checkpoint-3: red — simulated Graph layer endpoint and error-injection tests
- `1e53f2d` — checkpoint-3: green — simulated Graph layer with fixture store and deterministic error injection
- `54ae871` — checkpoint-3: update PROGRESS.md
- `747ce5c` — governance: add Mistakes & Lessons log to PROGRESS.md
- `47e17ec` — checkpoint-4: red — Investigator loop, cap, retry, no-hallucination, prompt-safety tests
- `5121f03` — checkpoint-4: green — custom ReAct Investigator with 5 tools, retry-once, cap, data-wrapped output
- `f5f7ed3` — checkpoint-4: update PROGRESS.md with agent-loop and tool decisions
- `541047f` — checkpoint-4-fix: red — MITRE direction/window/evidence tests and wrapper-breakout test
- `2d9a680` — checkpoint-4-fix: green — direction/time-aware MITRE with evidence ids, escaped wrapper, admin-only role noise
- `139ffea` — plan: rubric additions, ground-truth split, 3 approved project skills
- `d49281d` — checkpoint-1b: red — benign/thin/unknown alerts, ground-truth split, graph field allowlist, riskyUser fix
- `3e70589` — checkpoint-1b: green — benign/thin/unknown alerts, ground-truth split, field allowlist, riskyUser fix
- `18a74d0` — checkpoint-1b-fix: red — home-city/known-device/IP baseline, real-flight travel, named-network VPN, admin-only audits, benign plausibility
- `49edfdc` — checkpoint-1b-fix: green — home-city/known-device/IP baseline, real-flight travel, named-network VPN, admin-only audits
- `72418ed` — checkpoint-1b-fix2: red — benign role target must be unique; no cross-scenario contamination
- `0438e4c` — checkpoint-1b-fix2: green — unique ordinary helpdesk target for benign role add
- `377d586` — checkpoint-4-task8: red — alert allowlist + untrusted-data wrapper tests
- `5dd360d` — checkpoint-4-task8: green — allowlist + untrusted-data wrapper for the alert
