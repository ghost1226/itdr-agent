# ITDR Identity Incident Builder

An AI agent that investigates an identity alert (for example, a risky Microsoft Entra ID sign-in) the way a SOC analyst would. It pulls the user's profile, sign-ins, device trust, directory audits, and risk report. It turns that evidence into a dossier, gives a verdict (COMPROMISED, SUSPICIOUS, FALSE_POSITIVE, or INSUFFICIENT_DATA) with a confidence score and MITRE ATT&CK techniques, and recommends containment steps. **It executes nothing.** A human approves, edits, or rejects every step.

It runs on synthetic Entra ID data (fake `@contoso.com` tenant), not a real tenant. The why, the users, and the limits are in [`PROJECT_BRIEF.md`](PROJECT_BRIEF.md).

## What it does

1. **Investigator agent** (tool-calling loop): decides which of 5 simulated Microsoft Graph tools to call, up to 8 calls, retries a failed call once, then records the gap and keeps going. Dossier facts are copied from tool output, never written by the model. Risk indicators and MITRE techniques are derived in code, each tied to the evidence record it came from.
2. **Adjudicator agent** (one structured call): reads the dossier and returns the verdict, confidence, narrative, MITRE techniques, and containment steps with rollbacks.
3. **Orchestrator**: runs the two agents with the guardrails below and puts a human in charge of the outcome.

## Setup

Built and tested on Python 3.14.

```bash
git clone https://github.com/ghost1226/itdr-agent.git
cd itdr-agent
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Configure `.env`

```bash
cp .env.example .env
```

Then edit `.env`:

```
OPENROUTER_API_KEY=sk-or-v1-your-key-here
TIMEOUT_SECONDS=120
```

- `OPENROUTER_API_KEY`: your own key from openrouter.ai (a free account works). `.env` is gitignored. Never commit it or paste it anywhere.
- `TIMEOUT_SECONDS`: total time limit per investigation (default 120). Time a person spends answering the agent's question is not counted.
- `EVAL_MODEL`: the model for the CLI, the GUI, the evaluation, and both live scripts. The default is `nvidia/nemotron-3-super-120b-a12b:free`; change it here to try another model. (`OPENROUTER_MODEL`, an older setting, still works for `scripts/run_investigator_live.py`.)

## Generate the synthetic data

The fixtures are already committed in `data/fixtures/`. To regenerate them:

```bash
python -m itdr_agent.data_generator
```

Same seed, byte-identical files: users, sign-ins, directory audits, 10 alerts, user context, and `ground_truth.jsonl`. The ground truth (expected verdict and techniques) is read only by the tests and the evaluation script. The agents never see it.

The 10 alerts: 5 attacks (impossible travel, MFA fatigue, anonymous IP, app consent after a risky sign-in, privilege escalation), 3 benign look-alikes (real travel, a ticket-backed role add, the company VPN), 1 thin-data case, and 1 unknown user.

## Run the tests

```bash
pytest
```

254 tests, no network, no API key needed. The model is mocked in every unit test.

## Run the demo

**Offline (no key, no tokens):**

```bash
python scripts/demo_orchestrator.py
```

**Live, with a real model and you as the reviewer:**

```bash
python -m itdr_agent --alert-id ALERT_001
```

The agent investigates, may ask you one question if it is unsure, then shows each containment step for you to approve, edit, or reject. Every decision is written to `logs/audit.jsonl`. Alert ids are `ALERT_001` to `ALERT_010`.

## Run the GUI

A local web page for the same agent: pick an alert from the queue, watch the investigation, answer its question, and approve, edit, or reject each containment step. It runs on your own computer with your own key; nothing is hosted.

```bash
pip install -r requirements-gui.txt
python -m streamlit run app.py
```

It opens at http://localhost:8501. Pick a mode in the sidebar:

- **Offline demo:** no key, no model, no requests used. Scripted tool calls and a canned verdict, for trying the screens.
- **Live:** the real model with the key in your `.env` (never shown on the page). Each alert uses about 6 to 8 of a free account's 50 daily requests.

The Report shows the verdict, the MITRE techniques with the evidence behind each one, the steps you kept, a ready-to-paste incident note, the token use (`Tokens: … in / … out across N model calls`), and this run's lines from `logs/audit.jsonl`. The CLI prints the same token line after its report.

Found a problem? Open an issue on the repo with what you clicked, what you expected, and what happened.

## Integration runs with a real model

Unit tests never call a model. These scripts do, so they spend free-tier requests. Run them by hand only:

```bash
# Investigator only: prints the dossier as JSON (uses EVAL_MODEL)
python scripts/run_investigator_live.py ALERT_001 > dossier.json

# Adjudicator only, on that dossier (model is optional)
python scripts/run_adjudicator_live.py dossier.json [model-id]
```

The full pipeline is `python -m itdr_agent` (above) or the evaluation (below).

## Architecture

```
 alert (allowlisted fields, wrapped as untrusted data)
   |
   v
 anonymization gate  -- stops if any email domain isn't the synthetic tenant's
   |
   v
 INVESTIGATOR (tool loop, max 8 calls, retry once)
   |  tools: get_user_profile, get_sign_in_history, get_device_trust,
   |         get_directory_audits, get_risky_user_report
   |  -> dossier: facts from tool output, MITRE derived in code with evidence ids
   v
 critical gap? (no profile or no sign-ins) --yes--> INSUFFICIENT_DATA, no model call
   | no
   v
 ADJUDICATOR (one structured call)
   |  -> verdict, confidence, narrative, MITRE, containment steps + rollbacks
   v
 code guards: confidence coercion, MITRE claim check, action-claim flag,
              unsafe-rollback flag
   |
   v
 INSUFFICIENT_DATA or confidence < 0.7? --yes--> ask the analyst ONE question
   |                                             -> at most one re-adjudication
   v
 HUMAN REVIEW: approve / edit / reject each containment step
   |
   v
 report + logs/audit.jsonl (every step, with a run id)
```

## Governance guardrails

- **Human in charge.** The agent only recommends. Every containment step needs a person's approve, edit, or reject, and the decision is logged.
- **Untrusted data stays data.** The alert, tool output, and analyst answers are wrapped in tagged blocks with `<` and `>` escaped, so a log field can't break out and give the model instructions. Tested with breakout probes.
- **No answer key in the model's path.** Alerts pass through a field allowlist; labels live in a separate file the agents never read.
- **No invented evidence.** Dossier facts come from tool output. Any MITRE technique the Adjudicator claims that isn't backed by evidence in the dossier is rejected in code.
- **No fake certainty.** Any verdict below 0.7 confidence is changed to INSUFFICIENT_DATA in code, and the analyst gets one question.
- **Hard limits.** 8 tool calls, retry once, a 90-second cap per request, and a 120-second total per investigation.
- **Flags, never silent fixes.** Wording that claims a step was already executed, and rollbacks that would restore an old password or MFA setup, are flagged, shown as a warning to the reviewer, and logged. The verdict is left alone.
- **Synthetic data only.** No real tenant, users, or credentials.

## Free model check

Both models were verified as free (prompt and completion price 0) on OpenRouter's models API and model page before any live use:

| Use | Model | Context | Checked |
|---|---|---|---|
| Checkpoint 5 (first live checks) | `google/gemma-4-31b-it:free` | 262,144 tokens | checkpoint 5 (`230b571`) |
| Evaluation, and the default everywhere since 2026-10-16 | `nvidia/nemotron-3-super-120b-a12b:free` | 262,144 tokens | 2026-10-12 |

The evaluation switched to Nemotron because Gemma was rate-limited by its provider; on 2026-10-16 Nemotron became the default for the CLI and GUI too, after a GUI run hit the same Gemma limit. Free models can change or disappear, so results may not reproduce later. Free accounts get about 50 requests a day.

## Dependency audit

```bash
pip-audit -r requirements.txt
```

Result on 2026-10-14: **No known vulnerabilities found.** Dependencies are pinned in `requirements.txt` (pytest, pydantic, faker, python-dotenv, httpx, openai, tenacity, pip-audit).

## How we evaluated it

Full results: [`eval/final/results.md`](eval/final/results.md) (both halves combined). Raw runs: `eval/final/raw.jsonl`. Each person's half is in `eval/` and `eval/partner/`.

- **Model:** `nvidia/nemotron-3-super-120b-a12b:free`, temperature 0.
- **Runs:** all 10 alerts x 3 runs each = 30 runs, each through the full orchestrator, split across two people's free accounts.
- **Scoring:** a scripted reviewer approves every step and cancels every question, so the numbers show the agent without analyst help.
- **Metrics:** exact verdict accuracy (failed runs count as wrong), majority-of-3 per alert, attack-vs-benign detection, false positives, MITRE precision and recall, run-to-run agreement, and tokens, seconds, and requests per run.

**Results: 30 of 30 runs, 0 failed.** Exact verdict accuracy 80.0%, majority-of-3 80% (8 of 10 alerts), attack-vs-benign detection 100%, 0 of 9 benign runs flagged, MITRE precision 100% and recall 83.3%, agreement 93.3%, about 44 seconds per run. Two alerts were wrong by majority. On the thin-data alert, the model said FALSE_POSITIVE at 0.90+ confidence in all 3 runs instead of INSUFFICIENT_DATA; it treated missing evidence as proof that nothing happened. On the app-consent alert, it said SUSPICIOUS in 2 of 3 runs because the Investigator didn't pull the consent record. The full write-up is in the brief.

### Reproduce it

```bash
python scripts/evaluate.py --dry-run                 # offline, no key, writes eval/dry_run/
python scripts/evaluate.py --live                    # real model; run once per day until 0 pending
python scripts/evaluate.py --live --alerts ALERT_001 ALERT_002   # only some alerts
python scripts/evaluate.py --live --eval-dir eval/partner        # a second person's half
python scripts/evaluate.py --combine eval eval/partner           # merge into eval/final/
```

A bare `python scripts/evaluate.py` refuses to run, so free requests are never spent by accident. Each session stays under 45 requests (worst case reserved before each run), and stops cleanly on a rate limit. The next session picks up where it stopped.

## More

- [`PROJECT_BRIEF.md`](PROJECT_BRIEF.md): the problem, users, why an agent, comparison with Microsoft's own tools, limits and risks.
- [`PLAN.md`](PLAN.md): the build plan, checkpoint by checkpoint.
- [`PROGRESS.md`](PROGRESS.md): what was built, commit by commit, and the mistakes log.
