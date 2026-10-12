---
name: graph-field-check
description: "Check every Microsoft Graph field name and value against Microsoft Learn before using it in the ITDR agent's synthetic data, simulated Graph layer, schemas, or prompts. Use whenever code adds, renames, or reads a field on a Graph-shaped record (signIn, directoryAudit, user, riskyUser, device), or adds a new enum value such as a risk event type."
---

# Graph field check

This project simulates Microsoft Graph, so its records have to look like real Graph records. In checkpoint 1 the data used `riskEventTypes` (deprecated), `riskLevel` (not a signIn property), and `impossibleTravel` (not a real value). They came from the plan's wording, not the schema. All tests passed anyway, because the tests were written from the same wrong names.

## The rules

1. **Look it up before you type it.** Before adding or renaming a field on a Graph-shaped record, open the resource page on Microsoft Learn (v1.0 first) and confirm the exact name, its type, and where it sits (top level or nested, e.g. `deviceDetail.isCompliant`).
2. **Values too, not just names.** Enum values (risk event types, risk levels, risk states, audit activity names) must come from the docs. `unlikelyTravel`, not `impossibleTravel`.
3. **v1.0 over beta.** Use a beta-only field only when v1.0 doesn't have it, and mark it beta in the sources table.
4. **Write it down.** Add every new field and its Learn URL to the "Microsoft Graph Schema Sources" table in PROGRESS.md in the same commit.
5. **Project fields are not Graph fields.** Anything this project invents (`scenario`, `expected_verdict`, `expected_mitre`, `is_benign`, ground truth of any kind) never goes inside a Graph-shaped record. Ground truth lives in its own file, keyed by alert id (see the untrusted-data-wrapping skill).
6. **Not in the docs? Don't use it.** If you can't find a field on Learn, say so in your reply and leave it out. Don't guess a name that sounds right.

## Pages to check

| Resource | Microsoft Learn page |
|---|---|
| signIn | https://learn.microsoft.com/en-us/graph/api/resources/signin?view=graph-rest-1.0 |
| directoryAudit | https://learn.microsoft.com/en-us/graph/api/resources/directoryaudit?view=graph-rest-1.0 |
| riskyUser | https://learn.microsoft.com/en-us/graph/api/resources/riskyuser?view=graph-rest-1.0 |
| user | https://learn.microsoft.com/en-us/graph/api/resources/user?view=graph-rest-1.0 |
| mfaDetail (beta) | https://learn.microsoft.com/en-us/graph/api/resources/mfadetail?view=graph-rest-beta |

## Mistakes already made here

| Wrong | Right |
|---|---|
| `riskEventTypes` | `riskEventTypes_v2` |
| `riskLevel` on a signIn | `riskLevelAggregated`, `riskLevelDuringSignIn` |
| `impossibleTravel` | `unlikelyTravel` |

## Test (red first)

Keep one schema test per resource: an allowlist of the field names this project uses, each one confirmed on Learn. The test fails if a fixture record has a key that isn't on the list. Adding a field means adding it to the allowlist and to the PROGRESS.md sources table in the same commit.
