---
name: st-upgrade
description: Upgrade dependencies that Sonatype IQ Server reports as vulnerable, verify the build, and open a pull request. Use when asked to fix vulnerabilities, remediate Sonatype / IQ findings, or bump vulnerable dependencies in a repository.
---

Loop: find what's vulnerable → get IQ's target versions → edit the manifests → build and test → commit → open a PR → report. `st` only reads IQ Server here; you make the changes. See the `st` skill for command details.

## 1. Scope

Run in the repository's checkout, on an up-to-date default branch.

```sh
st app view --json publicId,repositoryUrl,reports
st fix --json name,purl,current,target,strategy,complete,breaking,dependency,parents,manifestHint,resolves,available,error,threatLevel
```

Check the report's `evaluationDate`: if it predates recent dependency changes on the branch, the findings may be stale — mention it. Exit code 9 means some components have no remediation; keep going with the rest. If the user named a CVE or a component, pass it to `st fix` instead of fixing everything. Large batches: start with `--min-threat 8`.

Group the work: components that share a parent bump (same `parents[].name`) are one change; so are artifacts of one library family (e.g. all `com.fasterxml.jackson.*`) — upgrade them together to a consistent version.

## 2. Plan each change

For each component with `available: true`:

- `dependency: direct` → change its version in the manifest. The version may live in a property, a BOM, `dependencyManagement`, a version catalog (`gradle/libs.versions.toml`) or a workspace root — find where it is actually set (`grep -rn '<current version>'`).
- `dependency: transitive` with `parents[].target` → bump that parent to that version instead.
- `dependency: transitive` without a parent target → follow `manifestHint`: find the path (`mvn dependency:tree -Dincludes=…`, `npm why …`, `go mod why …`), prefer bumping the parent to a release that pulls the fixed version; pin/override only as a last resort and say so in the PR.
- `breaking: true` or `complete: false` → still do it, but flag it in the PR and in your report.

Never invent versions: use `target` / `parents[].target` only. For `available: false`, don't change anything; report it (with `error` if set). Never waive (`st waive`) instead of upgrading: list what couldn't be fixed and leave the decision to waive to the user (the `st` skill covers how).

## 3. Apply and verify

```sh
git switch -c fix/vulnerable-dependencies
```

Edit the manifests, regenerate lockfiles with the project's own tool (`npm install`, `mvn -q dependency:resolve`, `go mod tidy`, …), then run the project's build and tests. If an upgrade breaks compilation or tests, fix the code when the change is mechanical (renamed API, changed signature — check the library's changelog); otherwise revert that one upgrade, keep the rest, and report why.

Confirm the resolved version actually changed (`mvn dependency:tree -Dincludes=…`, `npm ls …`, `go list -m …`).

## 4. Commit and open the PR

One commit per logical change is easiest to review. Then push and open the PR — with `bb` on Bitbucket, `gh` on GitHub:

```sh
git push -u origin HEAD
bb pr create -t "Upgrade vulnerable dependencies" -F - <<'EOF'
Fixes security policy violations reported by Sonatype IQ Server (<app>, <stage> report of <date>).

| Component | From | To | Resolves | Notes |
|---|---|---|---|---|
| … | … | … | CVE-… | golden version / major bump / transitive via … |

Not fixed: … (no remediation known)

Build and tests: …
EOF
```

IQ re-evaluates when CI scans the branch; the findings disappear from `st vuln list` only after that scan — don't claim they're gone before.

## 5. Report

Tell the user: the PR link, what was upgraded (from → to, CVEs resolved), what was flagged (`breaking`, `complete: false`, overrides/pins), what couldn't be fixed and why, and the build/test result.
