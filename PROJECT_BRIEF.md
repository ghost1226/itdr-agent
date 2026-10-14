# PROJECT_BRIEF: ITDR Identity Incident Builder

**Status (2026-10-13): in progress.** Section 7 is written; the other sections follow PLAN.md ("PROJECT_BRIEF.md (After Checkpoint 7)"). Evaluation numbers are partial (12 of 30 runs) and will be refreshed from `eval/results.md` when the evaluation finishes.

## 1. Problem

_To be written._

## 2. Target users

_To be written._

## 3. Why this is an agentic AI problem

_To be written._

## 4. Definition of Done

_To be written._

## 5. Flow diagram

_To be written. Required shape: `Alert → Understand goal → Gather context (tools) → Plan → Evaluate results → Ask the analyst if needed → Draft containment + rollback → Analyst approves → Report`._

## 6. Comparison: Microsoft Entra ID Protection, Security Copilot Risk Management agent, Purview DLP triage agent

_To be written._

## 7. Limits and risks

The numbers below come from a partial evaluation: 12 of 30 runs, as of October 13, 2026 [E1]. They will be replaced with the final numbers when all 30 runs are done.

### 7.1 Synthetic data, no real tenant

- **Everything is synthetic.** The corpus is 10 alerts (5 attacks, 3 benign look-alikes, 1 thin-data, 1 unknown user), 30 users, 133 sign-ins, and 53 directory audits, generated from a fixed seed [F1]. No real logs, users, or tenant data were used at any point [A1].
- **Microsoft Graph is simulated.** The agent calls a local stand-in for Graph [C1]. Field names were checked against Microsoft Learn and are locked by an allowlist test [T1], and one field we rely on (`networkLocationDetails`) exists only in the Graph beta API [P1]. A real tenant adds things this project never exercised: paging, throttling, missing or renamed fields, and far more noise.
- **The same team wrote the data and the detection logic.** The MITRE mapping in code was built against the same five attack patterns the generator plants [P2]. That risks measuring how well the agent matches its own data. What we did: the answer key (`ground_truth.jsonl`) never reaches the model [T2], each attack has a benign look-alike, and every technique must point to the exact sign-in or audit record that proves it [T3]. It is still not an independent test set.

### 7.2 Free-model variability and reproducibility

- **The same alert can get a different answer.** At temperature 0, ALERT_006 (benign travel) came back INSUFFICIENT_DATA (confidence 0.55), then FALSE_POSITIVE (0.90), then FALSE_POSITIVE (0.70). Multi-run agreement is 91.7% so far [E1].
- **The evaluated model is not the one first verified.** Checkpoint 5 was verified on Gemma 4 31B (free). Gemma was rate-limited by its provider on both smoke-test attempts, so the evaluation runs on Nemotron 3 Super (free) [P3]. OpenRouter documents that a 429 can come from the upstream provider [X1]. Free models can change or disappear, so these results may not be reproducible later.
- **One model only.** No other model was evaluated, so there is no comparison across models.
- **The code changed during the evaluation.** After 12 of Joe's 15 runs, a total timeout and an action-claim guard were added (commit `d0d6b15`) [P4]. Those 12 runs used the earlier code; the remaining runs use the new code. Neither change alters how a verdict is decided, but two things differ: a run that passes 120 seconds is now scored as failed (none of the first 12 took longer than 73 seconds [E1]), and the prompt gained one sentence ("You only recommend…"), which could change the model's wording in later runs [C2].

### 7.3 Prompt injection

- **What's in place.** The alert, every tool result, the dossier, and the analyst's answers are wrapped as untrusted data, with `<` and `>` escaped so a record cannot close its own data block. Tests try to break out of the wrapper and to slip instructions into the data [T4]. MITRE technique claims are checked in code against the evidence, not trusted from the model [T5].
- **What's not.** Wrapping and escaping lower the risk; they don't remove it. A model can still be misled by text inside the data, and the project has no red-team testing beyond the probes in the test suite.

### 7.4 False positives and missed attacks

- **So far:** 0 of 3 benign runs were called COMPROMISED or SUSPICIOUS, and all 9 attack runs were caught with the correct MITRE technique [E1]. One benign run fell back to INSUFFICIENT_DATA instead of FALSE_POSITIVE [E1].
- **Why that fallback happens.** Any verdict below 0.70 confidence is turned into INSUFFICIENT_DATA in code [C3]. That sends uncertain cases to the analyst instead of making a wrong call, but it costs analyst time.
- **Small sample.** Ten alerts, three runs each. Joe's half covers one of the three benign alerts (ALERT_006); the other two (ALERT_007, ALERT_008) are in the partner's half [P5]. The false-positive rate on real alert volume is unknown.

### 7.5 Human oversight: what the numbers don't show

- **The ask-the-analyst path is never measured.** During scoring, a scripted reviewer approves every containment step and cancels every question, so the one-question re-check never runs. The numbers show the agent alone [E2].
- **The model claimed actions it never took.** In the first live run, the model wrote "Containment steps executed as per playbook" [P3]. The agent executes nothing: it recommends steps, and a person approves them. Since `d0d6b15`, the prompt forbids that wording and a code check flags it in the report and the audit log [T6]. The check matches patterns, so it can miss a reworded claim. An analyst still has to read the report.

### 7.6 Cost and latency

- **Model cost: $0.** The evaluation uses a free model on OpenRouter. Free models are limited to 20 requests a minute and 50 a day, or 1,000 a day after buying at least 10 credits [X1].
- **Per run (so far):** 42.8 seconds on average (26.4 to 72.6), about 6.7 model requests (80 over 12 runs), and about 10,900 tokens in and 3,000 out [E1].
- **The free tier makes evaluation slow.** With a 45-request daily budget and room for a 10-request worst case reserved before every run, 30 runs take about six days [P6]. The dry run estimated five days, worst case eight [P6].
- **A run has 120 seconds of machine time.** Runs that go over are stopped and scored as failed; time an analyst spends answering does not count [C4].
- **No paid-model estimate.** Cost on a paid model was not measured.
- **Time saved versus a person:** see section 8, which needs Joe's manual baseline.

### Citations (section 7)

- **[E1]** `eval/results.md` (Headline metrics, Per alert, Per run, Failure table), commit `3c65367`.
- **[E2]** `eval/results.md`, Method: "a scripted reviewer approves every containment step and cancels every `ask_user` question."
- **[F1]** `data/fixtures/` (`alerts.jsonl` 10, `users.jsonl` 30, `sign_ins.jsonl` 133, `directory_audits.jsonl` 53, `ground_truth.jsonl` 10); `itdr_agent/data_generator.py`.
- **[A1]** `AGENTS.md`, Standing Rule 1 ("Synthetic data only").
- **[C1]** `itdr_agent/sim_api.py`, `itdr_agent/fixture_store.py`.
- **[C2]** `itdr_agent/adjudicator.py` (`SYSTEM_PROMPT`, `apply_action_claim_guard`); `git diff 3c65367 d0d6b15`.
- **[C3]** `itdr_agent/schemas.py`, `apply_confidence_guardrail` (`CONFIDENCE_THRESHOLD = 0.7`).
- **[C4]** `itdr_agent/orchestrator.py` (total timeout, analyst time excluded); `itdr_agent/config.py` (`TIMEOUT_SECONDS`, default 120).
- **[T1]** `tests/test_graph_fields.py`.
- **[T2]** `tests/test_investigator.py::test_no_answer_key_in_any_alert_prompt`; PROGRESS.md decision "Ground truth in `data/fixtures/ground_truth.jsonl`".
- **[T3]** `mitre_attack_evidence` in `itdr_agent/investigator.py`; MITRE checklist in PROGRESS.md.
- **[T4]** `tests/test_investigator.py` (`test_tool_output_is_wrapped_as_untrusted_data`, `test_wrapper_cannot_be_broken_out_of`, `test_alert_wrapper_breakout_probe`, `test_alert_instruction_probe_stays_inside_wrapper`); `tests/test_adjudicator.py` (`test_dossier_is_wrapped_and_escaped`, `test_dossier_breakout_probe`); `tests/test_human.py::test_wrap_analyst_input_wraps_and_escapes`.
- **[T5]** `itdr_agent/adjudicator.py`, `assert_mitre_claims_supported`; `tests/test_adjudicator.py::test_mitre_claims_must_be_supported`.
- **[T6]** `tests/test_adjudicator.py` (action-claim tests), `tests/test_orchestrator.py::test_action_claim_is_logged_with_run_id`; commits `ccb1b61` / `d0d6b15`.
- **[P1]** PROGRESS.md, "Microsoft Graph Schema Sources" (`networkLocationDetails` beta-only).
- **[P2]** PROGRESS.md, "MITRE ATT&CK Checklist".
- **[P3]** PROGRESS.md, "Eval model switched" and Open Problem 3; `eval/interruptions.jsonl`.
- **[P4]** PROGRESS.md, "Checkpoint 7 fix 2" (mid-eval effect).
- **[P5]** PROGRESS.md, Checkpoint 7 split (Joe: ALERT_001, 002, 003, 006, 009; partner: 004, 005, 007, 008, 010).
- **[P6]** PROGRESS.md, Checkpoint 7 (budget, dry run) and Open Problem 7.
- **[X1]** OpenRouter, API rate limits: https://openrouter.ai/docs/api/reference/limits (checked 2026-10-13).

### Claims to verify (section 7)

| Claim | Citation |
|---|---|
| 12 of 30 runs complete as of 2026-10-13 | E1 |
| Corpus: 10 alerts, 30 users, 133 sign-ins, 53 audits | F1 |
| No real data used | A1 |
| Graph is simulated | C1 |
| Field names locked by an allowlist test | T1 |
| `networkLocationDetails` is beta-only | P1 |
| Answer key never reaches the model | T2 |
| Each technique points to its evidence record | T3 |
| ALERT_006 outcomes 0.55 / 0.90 / 0.70; agreement 91.7% | E1 |
| Gemma rate-limited upstream; eval on Nemotron | P3 |
| 429s can come from the upstream provider | X1 |
| 12 of Joe's runs predate `d0d6b15` | P4 |
| Wrapper escaping and breakout/instruction probes | T4 |
| MITRE claims checked in code | T5 |
| 0 of 3 benign runs flagged; 9 of 9 attack runs caught with correct technique | E1 |
| Below 0.70 becomes INSUFFICIENT_DATA | C3 |
| Joe's half has 1 of 3 benign alerts | P5 |
| Scripted reviewer cancels every question | E2 |
| Model wrote "Containment steps executed as per playbook" | P3 |
| Action-claim guard flags the wording | T6 |
| Free models: 20/min, 50/day, 1,000/day with 10+ credits | X1 |
| 42.8 s average (26.4-72.6), 80 requests / 12 runs, ~10.9k in / 3.0k out tokens | E1 |
| ~6 days for 30 runs; dry run 5, worst case 8 | P6 |
| 120 s machine time per run, analyst time excluded | C4 |

## 8. Practical value

_To be written. Needs Joe's manual baseline numbers._

## 9. Citations and Claims to verify

_To be written. Sections 1-6 and 8 add their citations here; section 7's are above._

