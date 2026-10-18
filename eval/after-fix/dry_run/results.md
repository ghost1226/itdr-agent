# ITDR Evaluation Results

> **DRY RUN.** Offline stand-ins replaced the model: the Adjudicator stand-in answers with the ground-truth verdict, so these scores test the harness, not a model. No API key, no network.

> **PARTIAL:** 3 of 30 runs complete. The evaluation resumes where it stopped; numbers will change.

## Method

- **Model:** none (offline stand-ins; see the note above).
- **Alerts:** 10 synthetic Entra ID alerts (5 attacks, 3 benign, 1 thin-data, 1 unknown user), 3 runs each, through the full orchestrator.
- **Reviewer:** a scripted reviewer approves every containment step and cancels every `ask_user` question. No human is in the loop during scoring, so the one-question re-adjudication path is never exercised.
- **Labels:** `data/fixtures/ground_truth.jsonl`, read only by this script and the tests; the agents never see it.
- **Limits:** none applied in a dry run (no requests are sent).
- **Run days (UTC):** 2026-10-17.

## Headline metrics

| Metric | Value |
|---|---|
| Runs complete | 3 of 30 (0 failed) |
| Exact verdict accuracy (primary; failed runs count as wrong) | 100.0% |
| Exact verdict accuracy, runs that returned a verdict | 100.0% |
| Majority-of-3 verdict accuracy (per alert) | 100.0% |
| Attack-vs-benign detection (8 labeled alerts) | 100.0% (2 runs) |
| False positives (benign runs called COMPROMISED/SUSPICIOUS) | 0 of 2 |
| MITRE precision | n/a (TP 0, FP 0) |
| MITRE recall | n/a (FN 0) |
| Multi-run agreement | n/a |
| Model requests | 21 total |
| Tokens in / out | 0 / 0 total; 0.0 / 0.0 per run |
| Seconds | 0.0 total; 0.0 per run |

## Per alert

| Alert | Scenario | Expected | Run outcomes | Majority | Correct |
|---|---|---|---|---|---|
| ALERT_006 | benign_travel | FALSE_POSITIVE | FALSE_POSITIVE | FALSE_POSITIVE | yes |
| ALERT_008 | benign_vpn | FALSE_POSITIVE | FALSE_POSITIVE | FALSE_POSITIVE | yes |
| ALERT_009 | thin_data | INSUFFICIENT_DATA | INSUFFICIENT_DATA | INSUFFICIENT_DATA | yes |

## Per run

| Alert | Run | Verdict | Confidence | Techniques | Requests | Tokens in/out | Seconds | Error |
|---|---|---|---|---|---|---|---|---|
| ALERT_006 | 1 | FALSE_POSITIVE | 0.88 | - | 7 | 0/0 | 0.0 | - |
| ALERT_008 | 1 | FALSE_POSITIVE | 0.88 | - | 7 | 0/0 | 0.0 | - |
| ALERT_009 | 1 | INSUFFICIENT_DATA | 0.40 | - | 7 | 0/0 | 0.0 | - |

## Failure table

No failures.

## Interrupted attempts (retried in a later session)

None.

## Caveats

- Synthetic data only; no real tenant. Ten alerts is a small sample.
- A free model can change or be rate-limited between days; runs are spread over several UTC days.
- Labels come from the data generator. `benign_admin_role` keeps T1098.003 as expected because the role-add pattern is real; deciding it is legitimate is the verdict's job.
- Questions are always cancelled, so these numbers show the agent without analyst help.
- Check the model's `audit_notes` before quoting them: in the first live run the model wrote "Containment steps executed as per playbook", but the agent executes nothing; steps are recommendations an analyst approves.
