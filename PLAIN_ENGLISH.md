# ITDR Agent — Plain English Reference

This doc explains the plan in normal human terms.

---

## What the agent actually does

**"Drafts an ITDR incident narrative with containment and rollback recommendations"**

- **ITDR** = Identity Threat Detection and Response. It's the security practice of catching when someone's identity (account, password, login) is being attacked or misused, then responding to it.
- **Incident narrative** = the written story of what happened. Think of it like a police report: "On Tuesday at 3pm, user Alice logged in from Russia 20 minutes after logging in from New York. Then her account approved a new app called 'EvilSync.' This suggests her account was compromised."
- **Containment** = what you do right now to stop the damage. Examples: disable the account, revoke app consent, force a password reset, block the IP.
- **Rollback** = how you undo the containment if you got it wrong. Example: if you disabled Alice's account and it turns out she was on a VPN, rollback is "re-enable the account and restore her sessions."

---

## "No real tenant, no M365 developer sandbox"

- **Real tenant** = a live Microsoft 365 / Entra ID environment with real user accounts, real emails, real company data. We are **not** touching yours.
- **M365 developer sandbox** = Microsoft's free program that gives developers a fake tenant to play with. We don't qualify for it.
- **So what we do instead:** Build our own fake Microsoft environment inside Python. The accounts, logins, and alerts are computer-generated nonsense that *look* real but aren't connected to any actual company.

---

## The fake API tools the agent calls

These simulate what a real analyst would pull from Microsoft's Graph API. We build fake versions because we have no real Microsoft environment.

| Function | Plain English | What it returns in our fake world |
|----------|---------------|-----------------------------------|
| `get_user_profile(upn)` | "Who is this person?" | Fake name, department, manager, hire date. |
| `get_sign_in_history(upn, hours)` | "Where and when did they log in recently?" | Fake list of recent logins: time, city, IP, success/fail, MFA used or not. |
| `get_device_trust(device_id)` | "Is their laptop/phone managed by the company?" | Fake status: is it joined to the company? Does it pass compliance checks? |
| `get_directory_audits(upn, hours)` | "What admin changes happened on their account?" | Fake logs: password reset? Added to an admin group? Approved a suspicious app? |
| `get_risky_user_report(upn)` | "Does Microsoft think this user is suspicious?" | Fake risk score: low, medium, high. Reasons like "impossible travel" or "anonymous IP." |

### The two agents

| Agent | Role | Uses |
|-------|------|------|
| **Investigator** | Detective | The 5 fake API tools above. Pulls records, builds an evidence dossier. |
| **Adjudicator** | Judge + report writer | Reads the dossier, decides if it's an attack, and writes the incident report with containment/rollback steps. |

---

## The five attack patterns we plant in fake data

We intentionally create fake scenarios that match real hacker techniques (called MITRE ATT&CK patterns):

1. **Impossible travel** — User logs in from New York and Moscow 10 minutes apart. Physically impossible.
2. **MFA fatigue** — Attacker spams login prompts until the user clicks "approve" just to make it stop.
3. **Anonymous IP / proxy** — Login comes from a known VPN or Tor node used to hide location.
4. **App consent after foreign sign-in** — Right after a suspicious login, the account approves a new app to access email/files.
5. **Privilege escalation** — Attacker adds the compromised account to an admin group (like Global Administrator) to gain more power.

Each of these maps to a real MITRE ATT&CK technique ID so the agent's report speaks the same language real security teams use.

---

## Key rules in plain English

| Rule | What it means |
|------|---------------|
| **Synthetic data only** | Everything is fake. No real coworkers. No real logins. |
| **Local virtual environment** | Python packages install inside the project folder, not system-wide. |
| **`.env` for secrets** | API keys live in a file that git ignores. Never typed into code. |
| **Red-green TDD** | Write a failing test first. Then write code to make it pass. |
| **Mocked LLM in unit tests** | Tests run fast and offline. Real AI calls happen only in separate "try it for real" scripts. |
| **Injected errors, not random** | If we test retry logic, we tell the fake API "return a 429 right now." No dice rolls. |
| **pip-audit** | Scan for known vulnerabilities in our dependencies before we build on them. |
| **Timeout = 120s** | Free models on OpenRouter can be slow. Default patience is 2 minutes, not 30 seconds. |
| **Confidence < 0.7 → INSUFFICIENT_DATA** | If the AI isn't pretty sure, we don't let it guess. It admits "I don't have enough info." |
| **Critical gaps only short-circuit** | If we don't even know who the user is, we stop. But missing audit logs alone doesn't kill the investigation. |
| **Rollback with every containment step** | Every "do this now" action has an "undo it if we're wrong" paired with it. |
