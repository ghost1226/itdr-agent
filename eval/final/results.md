# ITDR Evaluation Results

## Method

- **Model:** `nvidia/nemotron-3-super-120b-a12b:free` via OpenRouter (free tier), temperature 0.
- **Alerts:** 10 synthetic Entra ID alerts (5 attacks, 3 benign, 1 thin-data, 1 unknown user), 3 runs each, through the full orchestrator.
- **Reviewer:** a scripted reviewer approves every containment step and cancels every `ask_user` question. No human is in the loop during scoring, so the one-question re-adjudication path is never exercised.
- **Labels:** `data/fixtures/ground_truth.jsonl`, read only by this script and the tests; the agents never see it.
- **Limits:** at most 20 requests/minute and 45 requests/UTC day (free cap 50); a run starts only with room for its worst case (10 requests).
- **Run days (UTC):** 2026-10-12, 2026-10-13, 2026-10-14, 2026-10-15.
- **Sources (one free account each, same code and model):** eval: 15 runs, partner: 15 runs.

## Headline metrics

| Metric | Value |
|---|---|
| Runs complete | 30 of 30 (0 failed) |
| Exact verdict accuracy (primary; failed runs count as wrong) | 80.0% |
| Exact verdict accuracy, runs that returned a verdict | 80.0% |
| Majority-of-3 verdict accuracy (per alert) | 80.0% |
| Attack-vs-benign detection (8 labeled alerts) | 100.0% (24 runs) |
| False positives (benign runs called COMPROMISED/SUSPICIOUS) | 0 of 9 |
| MITRE precision | 100.0% (TP 15, FP 0) |
| MITRE recall | 83.3% (FN 3) |
| Multi-run agreement | 93.3% |
| Model requests | 192 total |
| Tokens in / out | 286894 / 77454 total; 9563.1 / 2581.8 per run |
| Seconds | 1330.1 total; 44.3 per run |

## Per alert

| Alert | Scenario | Expected | Run outcomes | Majority | Correct |
|---|---|---|---|---|---|
| ALERT_001 | impossible_travel | COMPROMISED | COMPROMISED, COMPROMISED, COMPROMISED | COMPROMISED | yes |
| ALERT_002 | mfa_fatigue | COMPROMISED | COMPROMISED, COMPROMISED, COMPROMISED | COMPROMISED | yes |
| ALERT_003 | anonymous_ip | COMPROMISED | COMPROMISED, COMPROMISED, COMPROMISED | COMPROMISED | yes |
| ALERT_004 | app_consent | COMPROMISED | SUSPICIOUS, SUSPICIOUS, COMPROMISED | SUSPICIOUS | no |
| ALERT_005 | privilege_escalation | COMPROMISED | COMPROMISED, COMPROMISED, COMPROMISED | COMPROMISED | yes |
| ALERT_006 | benign_travel | FALSE_POSITIVE | INSUFFICIENT_DATA, FALSE_POSITIVE, FALSE_POSITIVE | FALSE_POSITIVE | yes |
| ALERT_007 | benign_admin_role | FALSE_POSITIVE | FALSE_POSITIVE, FALSE_POSITIVE, FALSE_POSITIVE | FALSE_POSITIVE | yes |
| ALERT_008 | benign_vpn | FALSE_POSITIVE | FALSE_POSITIVE, FALSE_POSITIVE, FALSE_POSITIVE | FALSE_POSITIVE | yes |
| ALERT_009 | thin_data | INSUFFICIENT_DATA | FALSE_POSITIVE, FALSE_POSITIVE, FALSE_POSITIVE | FALSE_POSITIVE | no |
| ALERT_010 | unknown | INSUFFICIENT_DATA | INSUFFICIENT_DATA, INSUFFICIENT_DATA, INSUFFICIENT_DATA | INSUFFICIENT_DATA | yes |

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
| ALERT_004 | 1 | SUSPICIOUS | 0.78 | - | 6 | 7640/2969 | 40.7 | - |
| ALERT_004 | 2 | SUSPICIOUS | 0.72 | - | 6 | 7640/2038 | 30.0 | - |
| ALERT_004 | 3 | COMPROMISED | 0.88 | T1528 | 7 | 10470/3069 | 52.1 | - |
| ALERT_005 | 1 | COMPROMISED | 0.92 | T1098.003 | 7 | 10336/2124 | 34.9 | - |
| ALERT_005 | 2 | COMPROMISED | 0.85 | T1098.003 | 7 | 10612/2792 | 43.2 | - |
| ALERT_005 | 3 | COMPROMISED | 0.86 | T1098.003 | 7 | 10910/2855 | 41.2 | - |
| ALERT_006 | 1 | INSUFFICIENT_DATA | 0.55 | - | 6 | 9143/2715 | 42.0 | - |
| ALERT_006 | 2 | FALSE_POSITIVE | 0.90 | - | 7 | 11503/3316 | 50.7 | - |
| ALERT_006 | 3 | FALSE_POSITIVE | 0.70 | - | 8 | 17505/5056 | 72.6 | - |
| ALERT_007 | 1 | FALSE_POSITIVE | 0.92 | T1098.003 | 7 | 17101/4024 | 82.1 | - |
| ALERT_007 | 2 | FALSE_POSITIVE | 0.86 | T1098.003 | 7 | 14339/3215 | 53.8 | - |
| ALERT_007 | 3 | FALSE_POSITIVE | 0.96 | - | 6 | 10715/2076 | 41.0 | - |
| ALERT_008 | 1 | FALSE_POSITIVE | 0.95 | - | 6 | 7722/2261 | 64.4 | - |
| ALERT_008 | 2 | FALSE_POSITIVE | 0.92 | - | 6 | 7710/2041 | 50.8 | - |
| ALERT_008 | 3 | FALSE_POSITIVE | 0.95 | - | 7 | 9497/2440 | 46.4 | - |
| ALERT_009 | 1 | FALSE_POSITIVE | 0.90 | - | 6 | 7269/2762 | 44.7 | - |
| ALERT_009 | 2 | FALSE_POSITIVE | 0.92 | - | 6 | 7557/1862 | 35.9 | - |
| ALERT_009 | 3 | FALSE_POSITIVE | 0.92 | - | 6 | 7557/2296 | 30.5 | - |
| ALERT_010 | 1 | INSUFFICIENT_DATA | 0.00 | - | 5 | 2880/746 | 28.8 | - |
| ALERT_010 | 2 | INSUFFICIENT_DATA | 0.00 | - | 5 | 2880/1084 | 44.9 | - |
| ALERT_010 | 3 | INSUFFICIENT_DATA | 0.00 | - | 5 | 2880/1091 | 50.7 | - |

## Failure table

| Alert | Run | What went wrong | Why |
|---|---|---|---|
| ALERT_004 | 1 | expected COMPROMISED, got SUSPICIOUS | Verdict based on high-risk unfamiliarFeatures sign-in from unmanaged device; no MITRE techniques observed in evidence; further investigation needed to confirm compromise. The user Dave Consent exhibited a high-risk sign-in from an unfamiliar location (Lagos, NG) using an unmanaged, non-compliant ... |
| ALERT_004 | 1 | missing technique T1528 | not in the dossier's evidence: the Investigator did not gather the records that show it |
| ALERT_004 | 2 | expected COMPROMISED, got SUSPICIOUS | Verdict based on sign‑in history showing high‑risk unfamiliar location, unmanaged non‑compliant device, conditional access failure, and risk indicators. No MITRE techniques were present in the evidence dossier, so none are reported. The user Dave Consent exhibited a high-risk sign-in from an unfa... |
| ALERT_004 | 2 | missing technique T1528 | not in the dossier's evidence: the Investigator did not gather the records that show it |
| ALERT_006 | 1 | expected FALSE_POSITIVE, got INSUFFICIENT_DATA | Alert ALERT_006 generated; no MITRE technique evidence present; data gaps none. Sign-in history shows normal activity from a managed, compliant device with no risk flags; the observed location change from New York to London is consistent with legitimate travel and there are no indicators of compr... |
| ALERT_007 | 3 | missing technique T1098.003 | not in the dossier's evidence: the Investigator did not gather the records that show it |
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
