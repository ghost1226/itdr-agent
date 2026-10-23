# ITDR Evaluation Results

> **PARTIAL:** 0 of 30 runs complete. The evaluation resumes where it stopped; numbers will change.

## Method

- **Model:** `nvidia/nemotron-3-super-120b-a12b:free` via OpenRouter (free tier), temperature 0.
- **Alerts:** 10 synthetic Entra ID alerts (5 attacks, 3 benign, 1 thin-data, 1 unknown user), 3 runs each, through the full orchestrator.
- **Reviewer:** a scripted reviewer approves every containment step and cancels every `ask_user` question. No human is in the loop during scoring, so the one-question re-adjudication path is never exercised.
- **Labels:** `data/fixtures/ground_truth.jsonl`, read only by this script and the tests; the agents never see it.
- **Limits:** at most 20 requests/minute and 45 requests/UTC day (free cap 50); a run starts only with room for its worst case (10 requests).
- **Run days (UTC):** none yet.

## Headline metrics

| Metric | Value |
|---|---|
| Runs complete | 0 of 30 (0 failed) |
| Exact verdict accuracy (primary; failed runs count as wrong) | n/a |
| Exact verdict accuracy, runs that returned a verdict | n/a |
| Majority-of-3 verdict accuracy (per alert) | n/a |
| Attack-vs-benign detection (8 labeled alerts) | n/a (0 runs) |
| False positives (benign runs called COMPROMISED/SUSPICIOUS) | 0 of 0 |
| MITRE precision | n/a (TP 0, FP 0) |
| MITRE recall | n/a (FN 0) |
| Multi-run agreement | n/a |
| Model requests | 0 total |
| Tokens in / out | 0 / 0 total; n/a / n/a per run |
| Seconds | 0.0 total; n/a per run |

## Per alert

| Alert | Scenario | Expected | Run outcomes | Majority | Correct |
|---|---|---|---|---|---|

## Per run

| Alert | Run | Verdict | Confidence | Techniques | Requests | Tokens in/out | Seconds | Error |
|---|---|---|---|---|---|---|---|---|

## Failure table

No failures.

## Interrupted attempts (retried in a later session)

| Alert | Run | Stop reason | Detail | Requests spent |
|---|---|---|---|---|
| ALERT_004 | 1 | fatal:404 | Error code: 404 - {'error': {'message': 'Provider returned error', 'code': 404, 'metadata': {'raw': '{"status":404,"title":"Not Found","detail":"Function \'ac74040f-9fc9-4c5e-ac74-279ba5161d69\': Not found for account \'sxpm0VR-knE2_K2__i14ZbzmXEludXpJbFGRvrvc08w\'"}', 'provider_name': 'Nvidia', ... | 1 |

## Caveats

- Synthetic data only; no real tenant. Ten alerts is a small sample.
- A free model can change or be rate-limited between days; runs are spread over several UTC days.
- Labels come from the data generator. `benign_admin_role` keeps T1098.003 as expected because the role-add pattern is real; deciding it is legitimate is the verdict's job.
- Questions are always cancelled, so these numbers show the agent without analyst help.
- Check the model's `audit_notes` before quoting them: in the first live run the model wrote "Containment steps executed as per playbook", but the agent executes nothing; steps are recommendations an analyst approves.
