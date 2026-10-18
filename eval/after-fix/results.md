# ITDR Evaluation Results

> **PARTIAL:** 10 of 30 runs complete. The evaluation resumes where it stopped; numbers will change.

## Method

- **Model:** `nvidia/nemotron-3-super-120b-a12b:free` via OpenRouter (free tier), temperature 0.
- **Alerts:** 10 synthetic Entra ID alerts (5 attacks, 3 benign, 1 thin-data, 1 unknown user), 3 runs each, through the full orchestrator.
- **Reviewer:** a scripted reviewer approves every containment step and cancels every `ask_user` question. No human is in the loop during scoring, so the one-question re-adjudication path is never exercised.
- **Labels:** `data/fixtures/ground_truth.jsonl`, read only by this script and the tests; the agents never see it.
- **Limits:** at most 20 requests/minute and 45 requests/UTC day (free cap 50); a run starts only with room for its worst case (10 requests).
- **Run days (UTC):** 2026-10-16, 2026-10-17, 2026-10-18.

## Headline metrics

| Metric | Value |
|---|---|
| Runs complete | 10 of 30 (0 failed) |
| Exact verdict accuracy (primary; failed runs count as wrong) | 100.0% |
| Exact verdict accuracy, runs that returned a verdict | 100.0% |
| Majority-of-3 verdict accuracy (per alert) | 100.0% |
| Attack-vs-benign detection (8 labeled alerts) | 100.0% (8 runs) |
| False positives (benign runs called COMPROMISED/SUSPICIOUS) | 0 of 3 |
| MITRE precision | 100.0% (TP 6, FP 0) |
| MITRE recall | 100.0% (FN 0) |
| Multi-run agreement | n/a |
| Model requests | 66 total |
| Tokens in / out | 67380 / 25836 total; 6738.0 / 2583.6 per run |
| Seconds | 688.9 total; 68.9 per run |

## Per alert

| Alert | Scenario | Expected | Run outcomes | Majority | Correct |
|---|---|---|---|---|---|
| ALERT_001 | impossible_travel | COMPROMISED | COMPROMISED | COMPROMISED | yes |
| ALERT_002 | mfa_fatigue | COMPROMISED | COMPROMISED | COMPROMISED | yes |
| ALERT_003 | anonymous_ip | COMPROMISED | COMPROMISED | COMPROMISED | yes |
| ALERT_004 | app_consent | COMPROMISED | COMPROMISED | COMPROMISED | yes |
| ALERT_005 | privilege_escalation | COMPROMISED | COMPROMISED | COMPROMISED | yes |
| ALERT_006 | benign_travel | FALSE_POSITIVE | FALSE_POSITIVE | FALSE_POSITIVE | yes |
| ALERT_007 | benign_admin_role | FALSE_POSITIVE | FALSE_POSITIVE | FALSE_POSITIVE | yes |
| ALERT_008 | benign_vpn | FALSE_POSITIVE | FALSE_POSITIVE | FALSE_POSITIVE | yes |
| ALERT_009 | thin_data | INSUFFICIENT_DATA | INSUFFICIENT_DATA | INSUFFICIENT_DATA | yes |
| ALERT_010 | unknown | INSUFFICIENT_DATA | INSUFFICIENT_DATA | INSUFFICIENT_DATA | yes |

## Per run

| Alert | Run | Verdict | Confidence | Techniques | Requests | Tokens in/out | Seconds | Error |
|---|---|---|---|---|---|---|---|---|
| ALERT_001 | 1 | COMPROMISED | 0.92 | T1078.004 | 8 | 8683/2450 | 55.1 | - |
| ALERT_002 | 1 | COMPROMISED | 0.86 | T1621 | 6 | 6958/1836 | 52.0 | - |
| ALERT_003 | 1 | COMPROMISED | 0.88 | T1090.003 | 8 | 8372/4043 | 89.4 | - |
| ALERT_004 | 1 | COMPROMISED | 0.85 | T1528 | 6 | 6542/3390 | 87.1 | - |
| ALERT_005 | 1 | COMPROMISED | 0.85 | T1098.003 | 6 | 6448/1750 | 52.8 | - |
| ALERT_006 | 1 | FALSE_POSITIVE | 0.85 | - | 7 | 7106/2475 | 94.3 | - |
| ALERT_007 | 1 | FALSE_POSITIVE | 0.90 | T1098.003 | 7 | 8608/3592 | 79.3 | - |
| ALERT_008 | 1 | FALSE_POSITIVE | 0.92 | - | 7 | 6774/2890 | 78.9 | - |
| ALERT_009 | 1 | INSUFFICIENT_DATA | 0.88 | - | 6 | 5144/2566 | 75.9 | - |
| ALERT_010 | 1 | INSUFFICIENT_DATA | 0.00 | - | 5 | 2745/844 | 24.2 | - |

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
