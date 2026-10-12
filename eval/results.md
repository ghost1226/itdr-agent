# ITDR Evaluation Results

> **PARTIAL:** 1 of 30 runs complete. The evaluation resumes where it stopped; numbers will change.

## Method

- **Model:** `nvidia/nemotron-3-super-120b-a12b:free` via OpenRouter (free tier), temperature 0.
- **Alerts:** 10 synthetic Entra ID alerts (5 attacks, 3 benign, 1 thin-data, 1 unknown user), 3 runs each, through the full orchestrator.
- **Reviewer:** a scripted reviewer approves every containment step and cancels every `ask_user` question. No human is in the loop during scoring, so the one-question re-adjudication path is never exercised.
- **Labels:** `data/fixtures/ground_truth.jsonl`, read only by this script and the tests; the agents never see it.
- **Limits:** at most 20 requests/minute and 45 requests/UTC day (free cap 50); a run starts only with room for its worst case (10 requests).
- **Run days (UTC):** 2026-10-12.

## Headline metrics

| Metric | Value |
|---|---|
| Runs complete | 1 of 30 (0 failed) |
| Exact verdict accuracy (primary; failed runs count as wrong) | 100.0% |
| Exact verdict accuracy, runs that returned a verdict | 100.0% |
| Majority-of-3 verdict accuracy (per alert) | 100.0% |
| Attack-vs-benign detection (8 labeled alerts) | 100.0% (1 runs) |
| False positives (benign runs called COMPROMISED/SUSPICIOUS) | 0 of 0 |
| MITRE precision | 100.0% (TP 1, FP 0) |
| MITRE recall | 100.0% (FN 0) |
| Multi-run agreement | n/a |
| Model requests | 8 total |
| Tokens in / out | 11942 / 3028 total; 11942.0 / 3028.0 per run |
| Seconds | 53.3 total; 53.3 per run |

## Per alert

| Alert | Scenario | Expected | Run outcomes | Majority | Correct |
|---|---|---|---|---|---|
| ALERT_001 | impossible_travel | COMPROMISED | COMPROMISED | COMPROMISED | yes |

## Per run

| Alert | Run | Verdict | Confidence | Techniques | Requests | Tokens in/out | Seconds | Error |
|---|---|---|---|---|---|---|---|---|
| ALERT_001 | 1 | COMPROMISED | 0.92 | T1078.004 | 8 | 11942/3028 | 53.3 | - |

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
