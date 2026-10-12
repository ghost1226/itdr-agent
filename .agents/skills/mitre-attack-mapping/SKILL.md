---
name: mitre-attack-mapping
description: How to map identity evidence (Entra sign-ins, directory audits, risky-user reports) to MITRE ATT&CK technique IDs in the ITDR agent, for the Investigator's mitre_attack_evidence and the Adjudicator's verdict. Use whenever code or a prompt assigns, checks, or explains an ATT&CK ID, or when adding a new attack pattern or mapping rule. Every ID must be tied to real evidence ids, inside the time window, with the right direction.
---

# MITRE ATT&CK mapping

A wrong technique ID is worse than none: an analyst acts on it. In checkpoint 4 this project mapped T1098.003 (privilege escalation) onto an impossible-travel alert because of a role change the user made to SOMEONE ELSE, 6 days earlier. Every record was real; the conclusion was false.

## The five rules

1. **No evidence id, no technique.** Every ID in `mitre_attack_evidence` lists the record ids (sign-in or audit `id`) that produced it. The Adjudicator may only use IDs that appear there; anything else gets rejected in code, not by trusting the model.
2. **Inside the window only.** Count only events inside `INVESTIGATION_WINDOW_HOURS` around the alert time. Older or later events can go in the dossier as context, never as technique evidence.
3. **Check direction.** For every audit event, ask: is the investigated user the target (it happened TO them) or the initiator (they DID it)? Map the escalation technique only to the target. If the user is the initiator, record an indicator ("user granted a role to another account"), not a technique for them.
4. **A pattern, not one event.** Map a technique only when the pattern in its definition is there:
   - MFA fatigue (T1621) = repeated MFA denials for the same user in a short span (3+ in 30 minutes), usually followed by a success. One failed MFA is an indicator, not T1621.
   - App consent (T1528) = consent granted in the window after a risky sign-in (unlikelyTravel, anonymizedIPAddress, unfamiliarFeatures). A routine consent with no risky sign-in before it is an indicator only.
5. **Most specific ID, checked at the source.** Use the sub-technique when one fits, and confirm the ID and name on attack.mitre.org before adding a mapping. Write the page URL in PROGRESS.md.

## This project's mappings

| Pattern | ID | Name | Evidence that must be present |
|---|---|---|---|
| Impossible travel | T1078.004 | Valid Accounts: Cloud Accounts | Sign-in with `unlikelyTravel` in the window |
| MFA fatigue | T1621 | Multi-Factor Authentication Request Generation | 3+ MFA denials in 30 min for the user |
| Anonymous IP | T1090.003 | Proxy: Multi-hop Proxy | Sign-in with `anonymizedIPAddress` in the window |
| Consent after a risky sign-in | T1528 | Steal Application Access Token | Risky sign-in, then "Consent to application" in the window |
| Privilege escalation | T1098.003 | Account Manipulation: Additional Cloud Roles | "Add member to role" with the user as TARGET, in the window |

Use T1078.004, not plain T1078: these are Microsoft Entra cloud accounts, and MITRE's Cloud Accounts page lists Entra ID compromises as examples.

## Indicator or technique?

When the evidence is suspicious but doesn't meet the pattern, record it as an indicator in `risk_indicators` and leave the ID out. The Adjudicator weighs indicators; it doesn't get handed a technique the evidence can't support.

## Tests for every mapping rule (red first)

For each technique, write four tests before the code:
1. Pattern present, in the window, right direction → mapped, with the right evidence ids.
2. Same event outside the window → not mapped.
3. Wrong direction (the user is the initiator) → indicator only, no technique.
4. Below the threshold (one MFA failure; a consent with no risky sign-in) → indicator only.
Plus one test that the Adjudicator's output can't contain an ID missing from `mitre_attack_evidence`.
