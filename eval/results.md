# ITDR Evaluation Results

> **PARTIAL:** 15 of 30 runs complete. The evaluation resumes where it stopped; numbers will change.

## Method

- **Model:** `nvidia/nemotron-3-super-120b-a12b:free` via OpenRouter (free tier), temperature 0.
- **Alerts:** 10 synthetic Entra ID alerts (5 attacks, 3 benign, 1 thin-data, 1 unknown user), 3 runs each, through the full orchestrator.
- **Reviewer:** a scripted reviewer approves every containment step and cancels every `ask_user` question. No human is in the loop during scoring, so the one-question re-adjudication path is never exercised.
- **Labels:** `data/fixtures/ground_truth.jsonl`, read only by this script and the tests; the agents never see it.
- **Limits:** at most 20 requests/minute and 45 requests/UTC day (free cap 50); a run starts only with room for its worst case (10 requests).
- **Run days (UTC):** 2026-10-12, 2026-10-13, 2026-10-14.

## Headline metrics

| Metric | Value |
|---|---|
| Runs complete | 15 of 30 (0 failed) |
| Exact verdict accuracy (primary; failed runs count as wrong) | 73.3% |
| Exact verdict accuracy, runs that returned a verdict | 73.3% |
| Majority-of-3 verdict accuracy (per alert) | 80.0% |
| Attack-vs-benign detection (8 labeled alerts) | 100.0% (12 runs) |
| False positives (benign runs called COMPROMISED/SUSPICIOUS) | 0 of 3 |
| MITRE precision | 100.0% (TP 9, FP 0) |
| MITRE recall | 100.0% (FN 0) |
| Multi-run agreement | 93.3% |
| Model requests | 98 total |
| Tokens in / out | 153562 / 42629 total; 10237.5 / 2841.9 per run |
| Seconds | 625.1 total; 41.7 per run |

## Per alert

| Alert | Scenario | Expected | Run outcomes | Majority | Correct |
|---|---|---|---|---|---|
| ALERT_001 | impossible_travel | COMPROMISED | COMPROMISED, COMPROMISED, COMPROMISED | COMPROMISED | yes |
| ALERT_002 | mfa_fatigue | COMPROMISED | COMPROMISED, COMPROMISED, COMPROMISED | COMPROMISED | yes |
| ALERT_003 | anonymous_ip | COMPROMISED | COMPROMISED, COMPROMISED, COMPROMISED | COMPROMISED | yes |
| ALERT_006 | benign_travel | FALSE_POSITIVE | INSUFFICIENT_DATA, FALSE_POSITIVE, FALSE_POSITIVE | FALSE_POSITIVE | yes |
| ALERT_009 | thin_data | INSUFFICIENT_DATA | FALSE_POSITIVE, FALSE_POSITIVE, FALSE_POSITIVE | FALSE_POSITIVE | no |

## Per run

| Alert | Run | Verdict | Confidence | Techniques | Requests | Tokens in/out | Seconds | Error |
|---|---|---|---|---|---|---|---|---|
| ALERT_001 | 1 | COMPROMISED | 0.92 | T1078.004 | 8 | 11942/3028 | 53.3 | - |
| ALERT_001 | 2 | COMPROMISED | 0.86 | T1078.004 | 6 | 7700/2431 | 28.4 | - |
| ALERT_001 | 3 | COMPROMISED | 0.88 | T1078.004 | 7 | 9461/3319 | 43.7 | - |
| ALERT_002 | 1 | COMPROMISED | 0.92 | T1621 | 5 | 9678/2252 | 26.5 | - |
| ALERT_002 | 2 | COMPROMISED | 0.92 | T1621 | 7 | 16114/3131 | 40.5 | - |
| ALERT_002 | 3 | COMPROMISED | 0.88 | T1621 | 5 | 9540/1274 | 26.4 | - |
| ALERT_003 | 1 | COMPROMISED | 0.86 | T1090.003 | 7 | 9531/2959 | 46.1 | - |
| ALERT_003 | 2 | COMPROMISED | 0.85 | T1090.003 | 7 | 9531/2868 | 43.5 | - |
| ALERT_003 | 3 | COMPROMISED | 0.88 | T1090.003 | 7 | 9531/3360 | 40.3 | - |
| ALERT_006 | 1 | INSUFFICIENT_DATA | 0.55 | - | 6 | 9143/2715 | 42.0 | - |
| ALERT_006 | 2 | FALSE_POSITIVE | 0.90 | - | 7 | 11503/3316 | 50.7 | - |
| ALERT_006 | 3 | FALSE_POSITIVE | 0.70 | - | 8 | 17505/5056 | 72.6 | - |
| ALERT_009 | 1 | FALSE_POSITIVE | 0.90 | - | 6 | 7269/2762 | 44.7 | - |
| ALERT_009 | 2 | FALSE_POSITIVE | 0.92 | - | 6 | 7557/1862 | 35.9 | - |
| ALERT_009 | 3 | FALSE_POSITIVE | 0.92 | - | 6 | 7557/2296 | 30.5 | - |

## Failure table

| Alert | Run | What went wrong | Why |
|---|---|---|---|
| ALERT_006 | 1 | expected FALSE_POSITIVE, got INSUFFICIENT_DATA | Alert ALERT_006 generated; no MITRE technique evidence present; data gaps none. Sign-in history shows normal activity from a managed, compliant device with no risk flags; the observed location change from New York to London is consistent with legitimate travel and there are no indicators of compr... |
| ALERT_009 | 1 | expected INSUFFICIENT_DATA, got FALSE_POSITIVE | Verdict based on lack of risk indicators, normal sign‑in patterns, and empty MITRE attack evidence in the dossier. The sign-in history shows two successful authentications for user05@contoso.com from a compliant, managed macOS device in New York, with no risk detections, no anomalous IP or locati... |
| ALERT_009 | 2 | expected INSUFFICIENT_DATA, got FALSE_POSITIVE | Alert ALERT_009 triggered but evidence lacks any compromise indicators; treated as false positive. The sign-in history shows two successful authentications from known, compliant devices in New York with no risk detections, MFA not required but no anomalous indicators. No directory changes, no ris... |
| ALERT_009 | 3 | expected INSUFFICIENT_DATA, got FALSE_POSITIVE | Alert ALERT_009 triggered but evidence shows normal sign‑ins from New York on a compliant macOS device with no risk indicators; no MITRE techniques observed. The sign-in history shows two successful authentications from known corporate locations and a compliant, managed device. No risk events, MF... |

## Interrupted attempts (retried in a later session)

None.

## Caveats

- Synthetic data only; no real tenant. Ten alerts is a small sample.
- A free model can change or be rate-limited between days; runs are spread over several UTC days.
- Labels come from the data generator. `benign_admin_role` keeps T1098.003 as expected because the role-add pattern is real; deciding it is legitimate is the verdict's job.
- Questions are always cancelled, so these numbers show the agent without analyst help.
- Check the model's `audit_notes` before quoting them: in the first live run the model wrote "Containment steps executed as per playbook", but the agent executes nothing; steps are recommendations an analyst approves.
