---
name: st
description: Sonatype IQ Server CLI (`st`) reference. Use for any Sonatype / IQ Server / Lifecycle question — vulnerable dependencies, CVE details, policy violations, which version fixes a component. To actually upgrade vulnerable dependencies and open a PR, use the st-upgrade skill.
---

`st` reads Sonatype IQ Server (Lifecycle): applications, their latest scan reports, security policy violations, vulnerability details and IQ's remediation (which version to upgrade to). It never edits files and changes nothing on the server, except `st waive` (see below). Run `st <cmd> --help` when unsure; help texts are written for agents.

Auth is preconfigured. `st auth status` checks it; exit code 4 anywhere = not authenticated → stop and tell the user, never attempt login.

## Conventions

- Application: `-A PUBLIC_ID`, else `ST_APP`, else matched from the git remote of the current checkout (the IQ application's source control repository URL). If matching fails, find it with `st app list -S <name>` and pass `-A`.
- Report: the build stage's latest by default, else the most recent; `--stage release` etc. to pick another. Results are only as fresh as the last scan (`st app view` shows when).
- Prefer `--json <fields> [--jq <expr>]` for anything you parse. `--json` alone lists fields.
- Output is plain and prompt-free when piped. Exit codes: 0 ok, 1 error, 4 auth, 9 some components have no remediation (`st fix`). Errors print to stderr, often followed by a `hint:` line — read it.
- Components are named by package URL (`pkg:maven/g/a@1.0`), or by name: `group:artifact` for Maven, the package name elsewhere.

## Commands

| Need | Command |
|---|---|
| Which app / when scanned | `st app view [--json publicId,repositoryUrl,reports]` |
| Find an app | `st app list -S text` |
| Vulnerable components | `st vuln list [--min-threat 8] [--direct\|--transitive] [--cve ID] [--json name,version,purl,dependency,parents,threatLevel,cves,violations]` |
| What is already waived | `st vuln list --include-waived --json name,version,waived` |
| Is the app affected by a CVE? | `st vuln list --cve CVE-2022-42003` |
| What a vulnerability is | `st vuln view CVE-… [--json description,recommendation,vulnerableVersionRanges,score,kev]` |
| Which version fixes it | `st fix [PURL\|NAME\|CVE] --json name,current,target,strategy,complete,breaking,dependency,parents,manifestHint,resolves` |
| Accept a risk (only when the user asks) | `st waive PURL --comment "why" [--expires 14d] [--policy NAME] [--all-versions] [--dry-run]` |
| All apps at a glance | `st status [-S text] [--min-threat 8] [--json application,threatLevel,components,direct,error]` |
| Anything else | `st api <path> [--jq expr]` (paths are relative to `api/v2/`; `{app}`/`{appId}` placeholders) |

## Reading `st fix`

- `target` is the version of the vulnerable component itself; `strategy` is IQ's remediation type it came from. `recommended-non-breaking*` is Sonatype's "golden version".
- `complete: false` → the version only stops the stage failing; lower-threat violations remain. Say so when reporting.
- `breaking: true` → major version change; expect API changes. `null` → unknown.
- `dependency: transitive` → don't add the component directly unless there is no other way. If `parents[].target` is set, bump that parent to that version. Otherwise follow `manifestHint` (find the path, bump the parent, or pin via the ecosystem's override mechanism).
- `available: false` (and exit 9) → IQ knows no fixed version (`error` says if the request failed). Report it; never guess a version.

## Waivers

`st waive` hides a real vulnerability from IQ's reports. Never run it on your own initiative, and never as a substitute for an upgrade you could not make. Only when the user explicitly asks to waive a specific component:

1. Run it with `--dry-run` first and show the user what would be waived (policy, threat level, version scope, expiry).
2. Put the user's reason into `--comment`, in their words; don't invent one.
3. Keep `--expires` as short as the reason allows (default 7d, max 90d; `30d`, `4w` or `YYYY-MM-DD`). Waivers cannot be permanent.
4. Waive only the exact version unless the user asks for `--all-versions`; use `--policy` if they want only one policy's violation waived.

It waives exactly one component; an ambiguous name fails and lists the matching package URLs — pass one of those. HTTP 403 → the user lacks IQ's "Waive Policy Violations" permission; say so and stop. Never retry a failed waive blindly: check `st vuln list --include-waived` first so you don't create a duplicate.

## Troubleshooting

- `st` already retries rate limiting (429) and server errors (5xx) with backoff, so a failure that reaches you is persistent: report it rather than looping.
- HTTP 404 → the application, report or endpoint doesn't exist (or this IQ version lacks it). Check `st app view`, then rerun the command with `ST_DEBUG=1` to see every request URL and status on stderr, and include that in your report.
- `st status` keeps going when one application fails; look at its `error` field instead of treating the whole run as failed.
