# Progress Diary — ITDR Identity Incident Builder

**Where this lives:** `~/itdr-agent` (private GitHub `ghost1226/itdr-agent`) since 2026-10-12. The copy inside `~/ai-agents-class` is frozen.

Updated 2026-10-14: Joe's half of the live evaluation is complete (15/15, `a7f74fb`); README.md written. Partner's 15 runs still pending. Output-token cap added (`MAX_OUTPUT_TOKENS`, `7fefa50`); OpenRouter key swapped in `.env`. Problem #22 fixed: `CliReviewer` no longer approves by default (`30d2503`/`2d56034`). GUI batch 1 done (verdict shown before decisions, alert summaries + incident note, incident queue). 336 tests.

---

## Current Checkpoint

**Checkpoint 7 — live evaluation running (split 15/15 with Joe's partner). Joe's half: 15 of 15 runs done (day 1 `7990b79`, day 2 `3c65367`, day 3 `a7f74fb`). Partner's half pending, then `--combine eval eval/partner`. Fixes 2 and 3 landed mid-eval; see below for which runs came before them. README.md done (Final Step); refresh its eval section after the combine.**

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
- ✅ Checkpoint 5: Adjudicator agent + MITRE mapping skill alignment.
  - **Pre-code:** verified free model `google/gemma-4-31b-it:free` (262,144-token context, `0`/`0` pricing) against the OpenRouter models API and page (`230b571`); no live tokens spent.
  - **Red:** `a2ed3f5` — tests only; `pytest` → **22 failed, 119 passed** (141 tests).
  - **Green:** `cdac646` — **141 passed**.
  - `itdr_agent/adjudicator.py`: single-shot structured call; the dossier is wrapped as `<microsoft_graph_data tool="dossier" untrusted="true">` with `<`/`>` escaped; parse (strips code fences) → confidence coercion → MITRE guard.
  - `invalid_mitre_claims` / `assert_mitre_claims_supported`: any technique absent from `dossier.mitre_attack_evidence` is rejected in code (`UnsupportedMitreClaimError`), never trusted.
  - MITRE alignment: `T1078.004` everywhere; `T1621` only for 3+ MFA denials in 30 minutes (1–2 → indicator only); `T1528` only when a risky sign-in precedes the consent in-window.
  - `scripts/run_adjudicator_live.py` added (manual only; not run).
  - Four tests per technique: in-window / outside-window / wrong-direction-or-benign / below-threshold.
- ✅ Checkpoint 5 fix (review): prompt guidance + faithful sample mocks.
  - **Red:** `2e6a950` — tests only; `pytest` → **5 failed, 141 passed** (146 tests).
  - **Green:** `221a907` — **146 passed**.
  - Adjudicator prompt now says `mitre_techniques_observed` lists **every** evidence-backed technique pattern, **even when the verdict is FALSE_POSITIVE** (explain the benign reason in the narrative), and shows `T#### or T####.###`, instructing the model to use the **exact IDs** from `mitre_attack_evidence` (sub-technique example `T1078.004`).
  - New `itdr_agent/samples.py` (later moved to `scripts/samples.py` in fix 2) builds deterministic, offline mocked sample reports whose narrative is composed from the real dossier, so it cannot invent evidence.
  - New `tests/test_mitre_ids.py` guard: no bare `T1078` in `itdr_agent/` or `scripts/`; fixed the stale `(T1078)` comment in `data_generator.py`.
- ✅ Checkpoint 5 fix 2 (review): samples moved to scripts, evidence-derived, verdict-specific.
  - **Red:** `01212d6` — tests only; `pytest` → **6 failed, 144 passed** (150 tests).
  - **Green:** `c6d7132` — **150 passed**.
  - `itdr_agent/samples.py` deleted; `scripts/samples.py` reads `ground_truth.jsonl` (scripts/tests only). New test asserts nothing under `itdr_agent/` references ground truth (`data_generator.py` is the producer).
  - Each benign narrative comes from that alert's own evidence: travel = same known device + the real NY→London 8.2 h leg; role add = the `HD-1042` ticket in `resultReason`; VPN = the trusted named network `Contoso Corporate VPN`.
  - Verdict-specific output: `FALSE_POSITIVE` → "no containment required; continue monitoring"; `INSUFFICIENT_DATA` → no containment steps and recommends gathering sign-ins/audits then re-adjudicating; only compromised/suspicious keep the account-disable step.
  - New tests cover all 10 alerts: every claimed technique must be in that alert's `mitre_attack_evidence`, and benign/insufficient samples never contain "disable".
- ✅ Checkpoint 5 fix 3 (review): attack "expected" wording + empty benign containment + fact test.
  - **Red:** `45ebedd` — tests only; `pytest` → **2 failed, 151 passed** (153 tests).
  - **Green:** `8e8912c` — **153 passed**.
  - `_role_note` says "expected" only for a `FALSE_POSITIVE` whose `resultReason` cites a ticket (`HD-\d+`); attack role adds read "an in-window role add".
  - `FALSE_POSITIVE` samples return `containment_steps == []`; "continue monitoring" moves to `recommended_actions`.
  - New test checks every narrative fact (cities, ISO times, device names, ticket ids, network/role names) against that alert's dossier, and "expected" only in FALSE_POSITIVE narratives.
- ✅ Checkpoint 6: Orchestration + Governance + Human Oversight (HITL).
  - **Red:** `efe5d05` — tests only; `pytest` → **12 failed, 153 passed** (165 tests).
  - **Green:** `b6d266d` — **165 passed**; pip-audit clean.
  - `itdr_agent/orchestrator.py`: anonymization gate → Investigator → critical-gap short-circuit (no LLM) → Adjudicator (coercion + MITRE guard) → one `ask_user` question if `INSUFFICIENT_DATA` or confidence < 0.7 → at most one re-adjudication → approve/edit/reject each containment step → `logs/audit.jsonl`.
  - `itdr_agent/human.py`: frozen `ask_user` contract (`cancelled` is exactly "no decision has been supplied"), `ContainmentDecision`, `ScriptedReviewer`/`CliReviewer`.
  - Analyst answers are wrapped in `<analyst_input untrusted="true">` (escaped), never inside the dossier block; the dossier gains `InvestigatorOutput.analyst_context`.
  - `python -m itdr_agent --alert-id ALERT_001` (live) and `python scripts/demo_orchestrator.py` (offline, no tokens).
  - **Review: passed.** The reviewer ran the offline demo in a clean copy; the approve/edit/reject audit lines, the analyst-input breakout probe, and the ALERT_010 short-circuit all check out.
- ✅ Checkpoint 7 fix 1 (Pi): `run_id` on every audit line (`run`, `containment_decision`, `ask_user`, `re_adjudication`, `mitre_rejection`).
  - One commit `70217a0` (tests + code together, no separate red). Red verified afterwards: the new tests run against `0bd0f18` code → **3 failed, 6 passed**; at `70217a0` they pass.
- ✅ Checkpoint 7: evaluation harness (Pi's run stopped when its own OpenRouter key hit its spending cap, 2026-10-12; finished in a separate session). Pi's uncommitted draft was replaced; see Mistakes & Lessons for its gaps.
  - **Red:** `7e847f4` — tests + a stub `evaluate.py`; `pytest tests/test_evaluate.py` → **29 failed**, rest of suite 167 passed.
  - **Green:** `22dd74d` — **30 passed** (one live-wiring test added in green; proven by mutation: switching off request counting in `_chat` makes it fail). Full suite **197 passed**; pip-audit: **No known vulnerabilities found**.
  - `scripts/evaluate.py --live` runs every alert through the **real orchestrator** (`EVAL_MODEL`, default `google/gemma-4-31b-it:free`); `--dry-run` uses offline stand-ins (no key, no network) and writes only `eval/dry_run/`. No flag → refuses (exit 2).
  - **Budget:** `RequestBudget` counts every request before it is sent (failed runs count), spaces requests 3.1 s apart (≤ 20 in any 60 s), and a run starts only if its worst case (`MAX_REQUESTS_PER_RUN = 10`: 8 tool turns + the cap/final turn + 1 Adjudicator) still fits under the daily budget (default 45 < free cap 50). OpenAI SDK retries are off (`max_retries=0`).
  - **Resume:** `eval/raw.jsonl` (one line per finished run) is the resume point; `eval/state.json` holds the UTC day + requests used. A 429, the budget, or a 401/402/403 stops the session and leaves that run pending (`eval/interruptions.jsonl`); it is retried next session. MITRE rejection, invalid JSON, timeouts, other API errors → a failed run record, never a crash.
  - **Metrics:** exact verdict accuracy (failed runs count as wrong; also shown over scored runs), majority-of-3, attack-vs-benign detection over the 8 labeled attack/benign alerts, false positives, MITRE precision/recall (n/a when nothing predicted), multi-run agreement (errors are an outcome), tokens/seconds/requests totals and means, per-alert and per-run tables, failure table (wrong verdict with the model's own notes; missing technique says Investigator vs Adjudicator; unexpected technique; errors), interrupted attempts, caveats.
  - **Review fixes (separate review pass):** red `f34b67e` (**4 failed**), green `f6cd9af` — **201 passed**. (1) 400/404 (wrong model id, unsupported `response_format`) now **stop** instead of recording 30 failed runs; (2) 5xx and connection errors **skip** the run (logged in `interruptions.jsonl`, retried next session) instead of scoring infrastructure as model failure; (3) `--alerts` limits only what runs — `results.md` and "Runs still pending" always cover all 10 alerts × 3, so a smoke test reads "1 of 30", not "all runs complete".
  - **Split between two people (2026-10-12):** red `1ffb60f` (5 failing), green `55cddaa` — **206 passed**. Each person runs their own alerts on their own free account (`--alerts ...`, partner uses `--eval-dir eval/partner`); the run prints "Your alerts: X of Y runs done". `--combine eval eval/partner` merges both into `eval/final/` (raw + results, each run tagged with its source; refuses a run that appears twice; keeps only the chosen model). Split: Joe ALERT_001, 002, 003, 006, 009; partner ALERT_004, 005, 007, 008, 010. Budget spacing is now read at run time.
  - **Dry run:** 30 runs, 207 requests (6–7 per run with the offline tool script) → **about 5 days at 45/day; worst case 8**.
- ✅ Checkpoint 7 fix 2 (Joe: "fix now", 2026-10-13, mid-evaluation): total timeout + action-claim guard.
  - **Red:** `ccb1b61` — tests only; `pytest` → **31 failed, 206 passed** (237 tests).
  - **Green:** `d0d6b15` — **237 passed**. Dry run unchanged (207 requests); offline demo unchanged; 0 action claims flagged on the canned sample reports.
  - **Total timeout enforced:** `Orchestrator(timeout_seconds=None → config.TIMEOUT_SECONDS, default 120, clock=time.monotonic)`. The Investigator checks the deadline before each model turn (`InvestigationTimeoutError`), the orchestrator before the Adjudicator and before a re-adjudication. Analyst think time (the one `ask_user`) is added back to the deadline, so a person is never timed out. Overrun → `timeout` audit line (`stage`: investigation / adjudication / re_adjudication) and `OrchestrationTimeoutError` (a `TimeoutError`, so the eval records it as a failed `timeout` run).
  - **Eval wiring bug fixed:** `make_live_runner` was passing the 90 s per-request cap as the orchestrator's total; it now passes `TIMEOUT_SECONDS` (120) via `total_timeout`.
  - **Action-claim guard (flag, never reject):** `find_action_claims` scans narrative, audit notes, recommended actions, and steps for claims that containment/remediation was executed/applied/performed/completed, or first-person "I/we disabled/reset/revoked…"; negated sentences ("No containment steps were executed") and evidence ("the sign-in was blocked", "Helpdesk reset the password") are not flagged. `apply_action_claim_guard` sets `AdjudicatorOutput.action_claims` (code-owned; a model-supplied value is replaced) and appends an audit note; the verdict is untouched. The orchestrator logs an `action_claim` audit line. System prompt: "You only recommend… never say that any step was executed… a human must approve."
  - **Mid-eval effect:** Joe's runs from 2026-10-12 (ALERT_001 x3, ALERT_002 x3) and 2026-10-13 (ALERT_003 x3, ALERT_006 x3) ran **before** this fix; ALERT_009 and any partner run after `git pull` run with it. Before the fix there was no total time cap (observed runs 26–73 s, so 120 s would not have cut any of them). The prompt rule may change wording in later runs; verdict scoring is unaffected.
- ✅ Checkpoint 7 fix 3 (Joe: "fix now 1", 2026-10-13 night, mid-evaluation): unsafe-rollback guard.
  - Found in Joe's live CLI run (ALERT_001, Nemotron): step 0's rollback said "temporarily revert the password to its previous value". You can't restore an old Entra password, and going back to the password the attacker used undoes the fix. The schema only required a non-empty rollback.
  - **Red:** `658dbb1` — tests only; `pytest` → **16 failed, 238 passed** (one new guard test, no warning on a safe rollback, passes on the old code by design).
  - **Green:** `1a83ccb` — **254 passed**. Dry run unchanged; offline demo unchanged; 0 unsafe-rollback flags on the canned sample reports.
  - `find_unsafe_rollbacks` flags a rollback that reverts/restores/reinstates/rolls back to a previous/old/original/prior password, credential, MFA setup, or authentication method (either word order); "restore the user's previous access rights" and "issue a new temporary password" are not flagged. `apply_unsafe_rollback_guard` sets `AdjudicatorOutput.unsafe_rollbacks` (step indexes; code-owned, a model value is replaced) and appends an audit note; nothing is removed and the verdict is untouched. The orchestrator logs an `unsafe_rollback` audit line, passes `warning=` to `review_step` for that step (the CLI prints `WARNING: ...`; `Reviewer.review_step` gained an optional `warning` argument), and recomputes the indexes after review. Prompt rule: never restore an old password or previous MFA setup; issue a new temporary password / re-register MFA instead.
  - **Mid-eval effect:** one more prompt sentence before ALERT_009 and the partner's runs; same note as fix 2.
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
- ✅ Checkpoint 1b fix 2 (review): benign target is no longer shared with the privilege-escalation attack.
  - **Red:** `72418ed` — tests only; `pytest` → **2 failed, 104 passed** (106 tests). The failure named the overlap exactly: `it.admin@contoso.com initiates privilege_escalation's planted audit`.
  - **Green:** `0438e4c` — **106 passed**; fixtures regenerated (users 30, sign-ins 133, audits 53, alerts 10, ground_truth 10, user_context 30).
  - `benign_admin_role` now investigates a new ordinary user, `helpdesk.agent@contoso.com`, who is in no other scenario and is not in `ADMIN_UPNS`. The role add is initiated by `sec.admin` and cites ticket `HD-1042`; `expected_mitre` stays `["T1098.003"]`.
  - `it.admin` remains only the privilege-escalation initiator, so it no longer appears in any benign user's window.
  - New tests: `test_benign_admin_role_target_is_an_ordinary_unique_user` and `test_no_cross_scenario_contamination` (no scenario user is initiator or target of another scenario's planted audit).
  - Same seed ⇒ byte-identical for all six files (SHA-256 verified); pip-audit: **No known vulnerabilities found**.
- ✅ Output-token cap (2026-10-14, Joe's go):
  - **Why:** no call set `max_tokens`, so OpenRouter reserves the model's whole context (~234k tokens) per request. Free models cost $0 so it never showed, but any key with credits or a spending limit gets 402 before the model runs (same error Pi hit on Kimi K2.6).
  - **Red:** `8642520` — `tests/test_max_tokens.py`, **3 failed**. Parses (never imports) the 4 live-call files and requires every `chat.completions.create` to pass `max_tokens=config.MAX_OUTPUT_TOKENS` (exactly 5 calls), plus a fake-client check on `evaluate._chat`.
  - **Green:** `7fefa50` — `config.MAX_OUTPUT_TOKENS = 8192` on all 5 calls; **293 passed**.
  - OpenRouter key replaced in `.env` the same day (value never written anywhere else; Joe to rotate it since it was pasted in a chat).
- ✅ Prompt rule removed (problem #33, 2026-10-16, Joe agreed): red `d96de9f` → green `972ee9a` (387 passed). The after-fix eval showed the "Missing evidence is not evidence of benign activity" prompt line made the model answer INSUFFICIENT_DATA 0.55 on ALERT_006 and ALERT_008 (benign, real history; FALSE_POSITIVE 3/3 before). The code guard (`apply_thin_evidence_guard`, fewer than 3 sign-ins and no audits) fires only on ALERT_009 in this data and caught its FALSE_POSITIVE alone, so it stays as the only thin-data check. `test_prompt_says_missing_evidence_is_not_benign` became `test_prompt_leaves_thin_data_to_the_code_guard`. ALERT_006/008/009 after-fix numbers were measured with the rule; see open problem 19.
- ✅ Edit can change the rollback (problem #32, 2026-10-16, Joe: "go ahead"): red `1b3fab2` (8 failed) → green `2606755` (387 passed). `ContainmentDecision.edited_rollback`; Edit takes a new step and/or a new rollback (blank keeps each; changing neither is an error / re-asks in the CLI); the edited rollback is re-checked (`is_unsafe_rollback`) and stays flagged if still unsafe; audit adds `final_rollback` + `final_unsafe_rollback`; GUI has a "New rollback" box; warning now says "Edit the rollback before approving, or reject the step." Two CLI tests got one extra input (the rollback prompt): `test_cli_reviewer_valid_edit`, `test_cli_reviewer_blank_edit_text_asks_again`.
- ✅ Audit line records the rollback (problem #31, 2026-10-16, Joe: "go ahead"): red `02812a4` → green `9049423` (379 passed). Each `containment_decision` line now has `rollback` and `unsafe_rollback`. Only one rollback field: Edit changes the step text and keeps the original rollback, so the rollback cannot differ (see open problem 18).
- ✅ One default model (problems #11 + #30, 2026-10-16, Joe: "yes"):
  - **Why:** the GUI and CLI still defaulted to Gemma 4 31B; Joe's first live GUI test hit Gemma's upstream 429 again. The eval has used Nemotron since 2026-10-12.
  - **Red:** `49fb1c3` (7 failed) → **Green:** `f7a0c62` (378 passed). `adjudicator.DEFAULT_MODEL` = `nvidia/nemotron-3-super-120b-a12b:free`; `evaluate.EVAL_DEFAULT_MODEL` imports it; `run_investigator_live.pick_model()` = OPENROUTER_MODEL → EVAL_MODEL → default (no longer refuses to run); `.env.example` has `EVAL_MODEL=…`; README updated. EVAL_MODEL still overrides everywhere.
- ✅ Verdict box in Joe's ticket format (2026-10-16, Joe: "approve"):
  - **Why:** Joe wanted the pre-decision box to keep the model's narrative and add his incident-note format plus a short summary on top.
  - **Red:** `9bdc723` (9 failed, 360 passed) → **Green:** `e8a5c6e` (369 passed).
  - `summary.found` (alert risk detections + techniques the evidence proved, so MFA fatigue no longer reads "Sign-in flagged with no risk detection"), `what_happened` (one code-built sentence: sign-in counts, alerted sign-in, techniques found, conclusion), `ticket_lines` (Alert / What / User / Analysis / Action, Action marked "Proposed" before review). The GUI box shows: What happened → verdict + narrative (unchanged) → MITRE evidence → ticket. The final incident note uses the found What when a dossier exists. No IP (Joe, 2026-10-14) and no answer key, both tested.
  - **Moved (Joe: "move this to the top right below" the alert line):** red `015db23` → green `b6e7aba` (371 passed). "What happened" now sits right below the alert line on the question, review, and report screens, once; the page waits for the run's status first so an instantly finished run still shows it.
- ✅ Thin-evidence guard (problem #14) + investigator token cut (2026-10-16, Joe: "go ahead"):
  - **Fix 1 (#14):** red `d068a4a` (6 failed, 347 passed) → green `d12a110` (353 passed). `MIN_BASELINE_SIGN_INS = 3`; `is_thin_evidence` = fewer than 3 sign-ins AND no directory audits; `apply_thin_evidence_guard` turns a FALSE_POSITIVE on thin evidence into INSUFFICIENT_DATA (sets `thin_evidence`, audit note, `thin_evidence` audit line), which triggers the one analyst question; skipped once an analyst has answered. Prompt rule: "Missing evidence is not evidence of benign activity." In the fixtures only ALERT_009 is thin (ALERT_004 has an audit; ALERT_010 short-circuits). `test_show_report_not_called_when_there_is_nothing_to_review` given 3 sign-ins (its 1-sign-in dossier is now thin; intent unchanged).
  - **Fix 2 (token cut):** red `695c8f0` (6 failed) → green `b6d5a5a` (360 passed). `summarize_tool_result`: the Investigator's model gets a sign-in summary (count, first/last, device ids, countries, IPs, apps, failures, risk events/levels) instead of raw records; the dossier and the Adjudicator still get every raw record. `wrap_tool_output` uses compact JSON separators. pip-audit: no known vulnerabilities.
  - **offline prompt size** (fixed 6-call tool sequence per alert, ~4 chars/token): average input ~8,515 → ~5,400 tokens per alert (-37%); ALERT_002 15,619 → 6,986 (-55%). Estimate only; the after-fix eval measures the real numbers.
  - **Next:** after-fix eval in `eval/after-fix/` (all 10 alerts x1 + ALERT_009 x3 = 12 runs), separate from the locked final eval.
- ✅ Token counter (2026-10-16, Joe: "i want to add a token counter ... so we know how much token is being spent"; CLI + GUI + audit log):
  - **Why:** only `scripts/evaluate.py` counted tokens; a normal CLI or GUI run spent tokens with no record.
  - **Red:** `bf41698` — `tests/test_token_meter.py`, **11 failed, 336 passed**.
  - **Green:** `3f9bf8a` — new `itdr_agent/usage.py` (`TokenMeter`, `format_tokens`); both OpenRouter wrappers record each reply's `usage` (before parsing, so a bad reply still counts); `Orchestrator(token_meter=...)` resets it per run and writes `tokens_in`, `tokens_out`, `llm_requests`, `requests_without_usage` into the `run` and `timeout` audit lines (null when no meter, never a fake 0); `OrchestrationResult.tokens`; CLI prints `Tokens: … in / … out across N model calls`; GUI report shows the same line (offline mocks → "no model calls"). **347 passed.** The eval harness keeps its own counter; finished eval numbers unchanged.
  - **Live check:** CLI on ALERT_002 (Nemotron free) → COMPROMISED; printed `Tokens: 12,727 in / 2,168 out across 6 model calls`, and the audit `run` line matched exactly.
- ✅ Problem #22: CLI reviewer approved by default (2026-10-14).
  - **Why:** `CliReviewer.review_step` returned `approve` for anything that was not exactly `edit`/`reject`, so a blank line or a typo approved a containment step with no human decision.
  - **Red:** `30d2503` — 8 new cases in `tests/test_human.py`; `pytest` → **5 failed, 296 passed** (301 tests).
  - **Green:** `2d56034` — **301 passed**.
  - `CliReviewer.review_step` now accepts only `approve` / `edit` / `reject` (case- and space-insensitive). Anything else, including blank, prints `Please type approve, edit, or reject.` and re-asks; a blank edited step re-asks too. `EOFError` raises `ReviewAbortedError(RuntimeError, EOFError)` (never an approve) and stops the run.
  - `ScriptedReviewer` and the GUI reviewer (`gui_run.py`) are unchanged.

- ✅ GUI batch 1 (2026-10-14; built by Pi, reviewed by Jessica; spec in the vault's GUI UX audit #1, #10, #11):
  - **Alert summaries** (`itdr_agent/summary.py`, pure, allowlisted fields only, no IPs, no answer key): red `3395db6` / green `9ab4e11`. `what`, `stage` (Attempted / Blocked / Successful; never Compromised before a verdict), `severity` bars, `short_summary`, `incident_note` in Joe's What / User / Analysis / Conclusion / Action layout.
  - **Verdict before decisions:** red `4b52e3e` / green `fa37ffe`. Orchestrator calls an optional `reviewer.show_report(report, dossier)` before the question and before the first containment step (refreshed after re-adjudication); `GuiRun` and `CliReviewer` implement it, `ScriptedReviewer` doesn't, so the eval path is unchanged.
  - **Incident queue home:** red `ecbf6b4` / green `bd1416c` (Pi wrote it; its session stopped on OpenRouter credits before committing; Jessica committed it unchanged after review). Table of all alerts with search, severity/status filters, row select, status (Not started / Waiting on you / Closed: VERDICT), Back to queue.
  - **Fix found in review:** `SUSPICIOUS` had no conclusion line. Red `3331ca2` / green `71143b7` (+ a test that every `Verdict` has one). **336 passed.**
  - Review: frozen eval files 0-line diff, `ScriptedReviewer` byte-identical; 0 IP / answer-key leaks across all 10 alerts x 4 verdicts; offline Chrome click-through (queue → search → open → verdict above step → approve → incident note → Closed).
  - Open: Back to queue while a run waits on the analyst drops that run (thread stays blocked, status stuck at "Waiting on you").

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

Confirmed on attack.mitre.org (all pages HTTP 200) and used by the mapper:

| Planted attack | Technique | ATT&CK page | Evidence required (skill rules) | Tests |
|----------------|-----------|-------------|------------------------------|------|
| Impossible travel | **T1078.004** — Valid Accounts: Cloud Accounts | https://attack.mitre.org/techniques/T1078/004/ | `unlikelyTravel` sign-in **in the window** | `test_impossible_travel_pattern`, `test_t1078_004_*` |
| MFA fatigue | **T1621** — Multi-Factor Authentication Request Generation | https://attack.mitre.org/techniques/T1621/ | **3+ MFA denials in 30 minutes** for the same user, in the window | `test_mfa_fatigue_pattern`, `test_t1621_*` |
| Anonymous IP | **T1090.003** — Proxy: Multi-hop Proxy | https://attack.mitre.org/techniques/T1090/003/ | `anonymizedIPAddress` sign-in in the window | `test_anonymous_ip_pattern`, `test_t1090_003_*` |
| Consent after a risky sign-in | **T1528** — Steal Application Access Token | https://attack.mitre.org/techniques/T1528/ | a risky sign-in (`unlikelyTravel`/`anonymizedIPAddress`/`unfamiliarFeatures`) **precedes** `Consent to application` in the window | `test_app_consent_after_foreign_signin_pattern`, `test_t1528_*` |
| Privilege escalation | **T1098.003** — Account Manipulation: Additional Cloud Roles | https://attack.mitre.org/techniques/T1098/003/ | `Add member to role` with the user as **TARGET**, in the window | `test_privilege_escalation_pattern`, `test_role_add_*`, `test_t1098_003_*` |

Each pattern test finds the behaviour in the generated data **and** asserts
`SCENARIO_TECHNIQUES[scenario]` equals the expected technique ID. The
Adjudicator may only output IDs present in `mitre_attack_evidence`
(`assert_mitre_claims_supported`); anything else is rejected in code.

## Fixture Decision

**Commit the fixtures.** They are fake, small, and deterministic, so they are
tracked in git under `data/fixtures/` (not gitignored). Tests may also
regenerate them from a seed via `data_generator.write_fixtures(tmp_path, seed=...)`.

## What's Next

**Checkpoint 1b — complete ...; 106 tests). Checkpoint 4 task 8 — complete (`377d586`/`5dd360d`; 112 tests). Checkpoint 5 — complete (`a2ed3f5`/`cdac646`, then `2e6a950`/`221a907`, `01212d6`/`c6d7132`, `45ebedd`/`8e8912c`; 153 tests). Checkpoint 6 — complete (`efe5d05`/`b6d266d`; 165 tests).**

**Eval model switched (Joe, 2026-10-12): `nvidia/nemotron-3-super-120b-a12b:free`.** `google/gemma-4-31b-it:free` returned 429 "temporarily rate-limited upstream" on both smoke attempts (2 requests spent; both logged in `eval/interruptions.jsonl`, no runs scored). Nemotron verified on the OpenRouter models API + page (HTTP 200): NVIDIA Nemotron 3 Super (free), 120B hybrid MoE (12B active), 262,144-token context, `0`/`0` pricing, supports `response_format`, `temperature`. It is now `EVAL_DEFAULT_MODEL` in `scripts/evaluate.py` (override with `--model` or `EVAL_MODEL`); the CLI demo keeps Gemma; every scored run uses this one model. **Smoke test PASSED:** ALERT_001 run 1 → COMPROMISED, 0.92, `T1078.004`, 8 requests, 11,942/3,028 tokens, 53 s. Finding: its `audit_notes` said "Containment steps executed as per playbook" — false, the agent executes nothing (same overclaim as HW4); added to the results caveats.

**Next: the live evaluation — only on Joe's go.** Joe's key is in `.env` (free tier, 50 requests/day; Joe chose to stay free, 2026-10-12).
1. ~~Smoke test first~~ DONE (passed on Nemotron): `python scripts/evaluate.py --live --alerts ALERT_001 --runs 1` (≤ 10 requests). Check `eval/results.md`, `eval/raw.jsonl`, and that the free model accepts `response_format=json_object`.
2. Then `python scripts/evaluate.py --live` once per UTC day until `Runs still pending: 0` (about 5 days). Each session stops on its own before the cap.
3. Commit `eval/results.md`, `eval/raw.jsonl`, `eval/interruptions.jsonl` after each day.
**Evaluation DONE 2026-10-16:** the partner's 15 runs came in as PR #1 (`partner-eval`, only `eval/partner/`), merged by Joe (`33c00f8`); `--combine eval eval/partner` → `eval/final/` (`0924fc3`): 30/30, 0 failed, exact 80.0%, majority-of-3 80% (misses ALERT_004 app consent, ALERT_009 thin data), detection 100%, 0 of 9 benign flagged, MITRE P 100% / R 83.3%, agreement 93.3%. README eval section refreshed.
4. Then PROJECT_BRIEF.md (needs Joe's manual baseline numbers) and the README. **Started 2026-10-13:** `PROJECT_BRIEF.md` has section 7 (Limits and risks, approved by Joe, every claim cited, Claims-to-verify table); sections 1-6 and 9 added 2026-10-13 (approved by Joe; Microsoft comparison checked on Microsoft Learn: Entra ID Protection, Identity Risk Management Agent (preview; PLAN's "Risk Management agent"), Purview DLP Triage Agent); only 8 left, blocked on Joe's baseline. Refresh section 7's numbers when the eval finishes. **Done 2026-10-16 (Joe: "approve"): section 7 refreshed to the final 30-run numbers** (at least 18 runs predate `d0d6b15`; the `7fefa50` output cap added as a mid-eval change; ALERT_004 and ALERT_009 misses; new citations P9, P10). **PROJECT_BRIEF section 8 written 2026-10-16 (Joe: "approve"):** Joe's manual baseline is 30 to 60 minutes per identity alert (his estimate, not timed) vs 44.3 s of agent machine time plus unmeasured analyst review; citations B1, C5. The brief is complete.

~~Open: the orchestrator's total timeout was never enforced.~~ **Fixed 2026-10-13** (`ccb1b61`/`d0d6b15`).

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
| Pi's Checkpoint 7 draft: live mode was a placeholder; failed runs were never written to raw output; a run could start with only 1 request of budget left and overshoot the cap; previous days' results were dropped on resume; a 429 marked the run as done; the request estimate was a hard-coded 6 | Draft written before the tests, and the tests never ran | Write the tests first and include the live path (fake client); count requests where they are sent; reserve the worst case before a run starts; resume from the raw file, not memory | `7e847f4` / `22dd74d` |
| Checkpoint 7 fix 1 landed without a separate red commit | Tests and code committed together | Red-green holds for fixes too; red verified after the fact against the parent commit | `70217a0` |
| Eval passed the 90 s per-request cap as the orchestrator's 120 s total | One `timeout` variable reused for two different limits | Name limits by what they cap (`timeout` per request, `total_timeout` per run) and test the wiring | `ccb1b61` / `d0d6b15` |
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
| `MAX_OUTPUT_TOKENS = 8192` on every call | Uncapped requests reserve ~234k tokens and 402 on any key with a limit; 8192 covers the JSON reply plus Nemotron's reasoning (smoke run used ~3k output over 8 calls). |
| Timeout default 120s | Free models are slow. Configurable via `.env`. |
| Commit inside existing repo | `~/ai-agents-class` is already a git repo with a private GitHub remote. (Superseded 2026-10-12, see below.) |
| Own repo: `~/itdr-agent` → private `ghost1226/itdr-agent` (2026-10-12) | Joe's partner runs half the evaluation and a review group will read the code; they get just this project. Full history kept (red/green commits are evidence). The old `~/ai-agents-class/itdr-agent` copy is frozen so the two never drift. |
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
| Evaluation needs `--live` explicitly | A bare `python scripts/evaluate.py` must never spend the free daily requests by accident. |
| Budget reserves the worst case before each run | A run cut off mid-way wastes its requests; starting only with 10 requests of room keeps a session at or under 45 (free cap 50). |
| UTC day for the request counter | Assumed to match the free tier's daily window; a 429 stops the session anyway, so a mismatch costs a retry, not an overrun. |
| SDK retries off (`max_retries=0`) | The OpenAI SDK retries twice by default, which would spend extra requests unseen. |
| 429 / budget / auth stops leave the run pending | A rate limit says nothing about the model, so it is not scored; the run is redone next session and the stop is logged in `interruptions.jsonl`. |
| Failed runs count as wrong in the headline accuracy | Otherwise a model that crashes on hard alerts would look more accurate. The accuracy over scored runs is shown beside it. |
| Detection accuracy excludes the 2 INSUFFICIENT_DATA alerts | They are neither attack nor benign; exact accuracy already scores them. |
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
3. **Eval model ≠ Checkpoint 5 model.** Gemma 4 31B (free) was rate-limited upstream; the evaluation runs on Nemotron 3 Super (free). Free models can change or vanish, so results may not reproduce later. Say so in PROJECT_BRIEF "Limits and risks".
4. ~~**Model overclaims actions.**~~ **Fixed 2026-10-13** (`d0d6b15`): recommend-only prompt rule + action-claim guard that flags (does not reject) and logs `action_claim`. Runs before the fix are not re-scored.
5. ~~**Orchestrator total timeout not enforced.**~~ **Fixed 2026-10-13** (`d0d6b15`), including the eval passing 90 s instead of 120 s.
8. **Mid-eval code change.** 12 of Joe's runs predate fixes 2 and 3; say so in PROJECT_BRIEF.
10. **Confidently wrong on thin data (2026-10-14). Guard added 2026-10-16 (`d12a110`); after-fix eval pending.** ALERT_009 (expected INSUFFICIENT_DATA) came back FALSE_POSITIVE at 0.90-0.92 in all 3 runs: missing evidence read as benign, so the 0.7 guardrail and the one question never fired. No code change mid-eval (Joe, 2026-10-14); any fix comes after the eval, with ALERT_009 re-run as a separate after-fix row. Say so in PROJECT_BRIEF.
11. ~~**Model selection is inconsistent.**~~ **Fixed 2026-10-16** (`f7a0c62`): one default (Nemotron), EVAL_MODEL everywhere. The CLI and eval read `EVAL_MODEL`, `scripts/run_investigator_live.py` requires `OPENROUTER_MODEL` (not in `.env.example`), `scripts/run_adjudicator_live.py` takes an argument. README documents each as is; unifying them is Joe's call.
9. ~~**Unsafe rollbacks.**~~ **Fixed 2026-10-13** (fix 3): flagged, warned, logged; still pattern-based, so a reworded unsafe rollback can slip through.
6. **Scoring never tests the human-help path.** The scripted reviewer cancels every question, so the one-question re-adjudication is unmeasured.
7. **Free tier makes the eval slow:** ~8 requests/run, 45/day with worst-case reservation → ~6 days for 30 runs ($10 of credits would make it one day).

12. **Thin-data threshold picked knowing the test data (2026-10-16).** `MIN_BASELINE_SIGN_INS = 3` matches the generator's thin_data (1-2 sign-ins); ALERT_006 has exactly 3. Judgment call, not measured.
13. **Whole conversation resent every call (2026-10-16).** ~12k tokens/alert, mostly raw sign-ins resent on each investigator turn. Fix 2 in progress.
14. **Investigator skips needed tools (2026-10-16).** ALERT_004 runs 1-2 never fetched directory audits → missed T1528. Not fixed; watch in the after-fix eval.
15. **Shared test dossier is thin (2026-10-16).** 1 sign-in, no audits; one test adjusted to 3 sign-ins in `d12a110`.
16. **Output tokens not fully explained (2026-10-16).** Likely hidden reasoning; unverified.
17. **Eval records have no code version (2026-10-16).** `raw.jsonl` lacks a commit hash.
18. ~~**Edit can't fix an unsafe rollback (2026-10-16).**~~ **Fixed 2026-10-16** (`2606755`). `ContainmentDecision` carries only `edited_step`; an edit keeps the original rollback. The unsafe-rollback warning says "Edit it before approving", which the analyst can't actually do, so the only safe choice today is Reject.
19. **After-fix eval partly stale (2026-10-16).** `eval/after-fix` ALERT_006, ALERT_008 and ALERT_009 ran with the prompt rule removed in problem #33. Re-run them on the current prompt before quoting after-fix accuracy.

Full discussion list (incl. Pi's draft gaps and the build-agent budget stall): Joe's vault, "ITDR Agent — Build Journal", "Problems to talk about".

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
- `f2fa5c9` — checkpoint-4-task8: update PROGRESS.md (wrapper, commits, next)
- `230b571` — checkpoint-5: record free OpenRouter model (google/gemma-4-31b-it:free)
- `a2ed3f5` — checkpoint-5: red — adjudicator, T1078.004, T1621 30-min, T1528 prior risky sign-in, MITRE guard
- `cdac646` — checkpoint-5: green — Adjudicator, T1078.004, T1621 30-min burst, T1528 prior risky sign-in, MITRE guard
- `2e6a950` — checkpoint-5-fix: red — prompt FALSE_POSITIVE/sub-technique guidance, faithful sample mocks, no bare T1078
- `221a907` — checkpoint-5-fix: green — prompt guidance, faithful sample mocks, T1078.004 comment
- `01212d6` — checkpoint-5-fix2: red — move samples to scripts, no ground truth in package, verdict-specific containment, all 10 alerts
- `c6d7132` — checkpoint-5-fix2: green — samples under scripts, evidence-derived benign narratives, verdict-specific containment
- `45ebedd` — checkpoint-5-fix3: red — expected only for ticket-backed FALSE_POSITIVE, no pseudo containment step, all-narrative-facts test
- `8e8912c` — checkpoint-5-fix3: green — expected only for ticket-backed FALSE_POSITIVE, benign containment steps empty
- `efe5d05` — checkpoint-6: red — orchestrator, HITL approve/edit/reject, one ask/re-adjudication, MITRE guard, short-circuit, anonymization
- `b6d266d` — checkpoint-6: green — orchestrator, governance, HITL ask/review, MITRE guard wiring, CLI + offline demo
- `70217a0` — checkpoint-7-fix1: add run_id to every audit line in orchestrator
- `7e847f4` — checkpoint-7: red — evaluation harness tests (budget, resume, failure rows, metrics, dry run)
- `22dd74d` — checkpoint-7: green — evaluation harness: real orchestrator runs, request budget + pacing, resume, failure rows, metrics, dry run
- `f34b67e` — checkpoint-7-fix: red — 400/404 stop, 5xx/connection errors skip and retry, subset runs report against the full plan
- `f6cd9af` — checkpoint-7-fix: green — same
- `1ffb60f` — checkpoint-7-split: red — per-person progress line and combining two people's results
- `55cddaa` — checkpoint-7-split: green — per-person progress line and --combine for two people's results
- `7990b79` — Eval day 1 (2026-10-12, Joe's half): ALERT_001 x3, ALERT_002 x3 on Nemotron
- `3c65367` — Eval day 2 (2026-10-13, Joe's half): ALERT_003 x3, ALERT_006 x3 on Nemotron
- `ccb1b61` — checkpoint-7-fix2: red — total timeout + action-claim tests
- `d0d6b15` — checkpoint-7-fix2: green — total timeout enforced, action-claim guard, recommend-only prompt
- `658dbb1` — checkpoint-7-fix3: red — unsafe-rollback tests
- `1a83ccb` — checkpoint-7-fix3: green — unsafe-rollback guard, reviewer warning, audit line, prompt rule
- `a7f74fb` — Eval day 3 (2026-10-14, Joe's half): ALERT_009 x3 on Nemotron
- `8642520` — max-tokens: red — every model call must cap output tokens
- `7fefa50` — max-tokens: green — config.MAX_OUTPUT_TOKENS=8192 on all 5 calls
- `30d2503` — problem-22: red — CliReviewer must reject blank/typo, re-ask blank edit, and abort on EOF
- `2d56034` — problem-22: green — CliReviewer accepts only approve/edit/reject, re-asks on blank/typo, aborts on EOF
- `ada82b9` — max-tokens: update PROGRESS.md
- `3395db6` — gui-batch1-summary: red — pure alert summaries
- `9ab4e11` — gui-batch1-summary: green — pure alert summaries and shared report-summary lines
- `4b52e3e` — gui-batch1-showverdict: red — show the report summary before the question and each review step
- `fa37ffe` — gui-batch1-showverdict: green — optional show_report hook; verdict summary on question/review
- `ecbf6b4` — gui-batch1-queue: red — incident queue home
- `bd1416c` — gui-batch1-queue: green — incident queue home (written by Pi, committed by Jessica)
- `3331ca2` — gui-batch1-summary-fix: red — SUSPICIOUS verdict has no conclusion
- `71143b7` — gui-batch1-summary-fix: green — SUSPICIOUS conclusion in the incident note
- `33c00f8` — Merge PR #1: partner evaluation results (ALERT_004, 005, 007, 008, 010 x3)
- `0924fc3` — Combined evaluation: 30 of 30 runs
- `bf41698` — token-meter: red — per-run token totals in the CLI, GUI, and audit log
- `3f9bf8a` — token-meter: green — TokenMeter per run; CLI, GUI, audit log
- `d068a4a` — problem-14: red — thin evidence cannot support a FALSE_POSITIVE
- `d12a110` — problem-14: green — thin-evidence guard, prompt rule, audit line
- `695c8f0` — token-cut: red — investigator sees sign-in summaries, compact JSON
- `b6d5a5a` — token-cut: green — sign-in summary for the investigator model; compact JSON
- `e8a5c6e` — verdict-box: green — what-happened summary, Joe's ticket format, found-What in the incident note
- `b6e7aba` — verdict-box-top: green — What happened right below the alert line
- `49fb1c3` — default-model: red — one default model everywhere
- `f7a0c62` — default-model: green — Nemotron is the default; EVAL_MODEL overrides
- `02812a4` — problem-31: red — audit line records the rollback
- `9049423` — problem-31: green — rollback + unsafe_rollback in containment_decision
- `1b3fab2` — problem-32: red — Edit can change the rollback
- `2606755` — problem-32: green — editable rollback, re-checked, logged
- `d96de9f` — problem-33: red — prompt no longer carries the thin-data rule
- `972ee9a` — problem-33: green — prompt rule removed; code guard only
