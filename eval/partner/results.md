# ITDR Evaluation Results

> **PARTIAL:** 6 of 30 runs complete. The evaluation resumes where it stopped; numbers will change.

## Method

- **Model:** `nvidia/nemotron-3-super-120b-a12b:free` via OpenRouter (free tier), temperature 0.
- **Alerts:** 10 synthetic Entra ID alerts (5 attacks, 3 benign, 1 thin-data, 1 unknown user), 3 runs each, through the full orchestrator.
- **Reviewer:** a scripted reviewer approves every containment step and cancels every `ask_user` question. No human is in the loop during scoring, so the one-question re-adjudication path is never exercised.
- **Labels:** `data/fixtures/ground_truth.jsonl`, read only by this script and the tests; the agents never see it.
- **Limits:** at most 20 requests/minute and 45 requests/UTC day (free cap 50); a run starts only with room for its worst case (10 requests).
- **Run days (UTC):** 2026-10-13.

## Headline metrics

| Metric | Value |
|---|---|
| Runs complete | 6 of 30 (0 failed) |
| Exact verdict accuracy (primary; failed runs count as wrong) | 66.7% |
| Exact verdict accuracy, runs that returned a verdict | 66.7% |
| Majority-of-3 verdict accuracy (per alert) | 50.0% |
| Attack-vs-benign detection (8 labeled alerts) | 100.0% (6 runs) |
| False positives (benign runs called COMPROMISED/SUSPICIOUS) | 0 of 0 |
| MITRE precision | 100.0% (TP 4, FP 0) |
| MITRE recall | 66.7% (FN 2) |
| Multi-run agreement | 83.3% |
| Model requests | 40 total |
| Tokens in / out | 57608 / 15847 total; 9601.3 / 2641.2 per run |
| Seconds | 242.2 total; 40.4 per run |

## Per alert

| Alert | Scenario | Expected | Run outcomes | Majority | Correct |
|---|---|---|---|---|---|
| ALERT_004 | app_consent | COMPROMISED | SUSPICIOUS, SUSPICIOUS, COMPROMISED | SUSPICIOUS | no |
| ALERT_005 | privilege_escalation | COMPROMISED | COMPROMISED, COMPROMISED, COMPROMISED | COMPROMISED | yes |

## Per run

| Alert | Run | Verdict | Confidence | Techniques | Requests | Tokens in/out | Seconds | Error |
|---|---|---|---|---|---|---|---|---|
| ALERT_004 | 1 | SUSPICIOUS | 0.78 | - | 6 | 7640/2969 | 40.7 | - |
| ALERT_004 | 2 | SUSPICIOUS | 0.72 | - | 6 | 7640/2038 | 30.0 | - |
| ALERT_004 | 3 | COMPROMISED | 0.88 | T1528 | 7 | 10470/3069 | 52.1 | - |
| ALERT_005 | 1 | COMPROMISED | 0.92 | T1098.003 | 7 | 10336/2124 | 34.9 | - |
| ALERT_005 | 2 | COMPROMISED | 0.85 | T1098.003 | 7 | 10612/2792 | 43.2 | - |
| ALERT_005 | 3 | COMPROMISED | 0.86 | T1098.003 | 7 | 10910/2855 | 41.2 | - |

## Failure table

| Alert | Run | What went wrong | Why |
|---|---|---|---|
| ALERT_004 | 1 | expected COMPROMISED, got SUSPICIOUS | Verdict based on high-risk unfamiliarFeatures sign-in from unmanaged device; no MITRE techniques observed in evidence; further investigation needed to confirm compromise. The user Dave Consent exhibited a high-risk sign-in from an unfamiliar location (Lagos, NG) using an unmanaged, non-compliant ... |
| ALERT_004 | 1 | missing technique T1528 | not in the dossier's evidence: the Investigator did not gather the records that show it |
| ALERT_004 | 2 | expected COMPROMISED, got SUSPICIOUS | Verdict based on sign‑in history showing high‑risk unfamiliar location, unmanaged non‑compliant device, conditional access failure, and risk indicators. No MITRE techniques were present in the evidence dossier, so none are reported. The user Dave Consent exhibited a high-risk sign-in from an unfa... |
| ALERT_004 | 2 | missing technique T1528 | not in the dossier's evidence: the Investigator did not gather the records that show it |

## Interrupted attempts (retried in a later session)

None.

## Caveats

- Synthetic data only; no real tenant. Ten alerts is a small sample.
- A free model can change or be rate-limited between days; runs are spread over several UTC days.
- Labels come from the data generator. `benign_admin_role` keeps T1098.003 as expected because the role-add pattern is real; deciding it is legitimate is the verdict's job.
- Questions are always cancelled, so these numbers show the agent without analyst help.
- Check the model's `audit_notes` before quoting them: in the first live run the model wrote "Containment steps executed as per playbook", but the agent executes nothing; steps are recommendations an analyst approves.
