# st — Sonatype IQ Server CLI for agents

Find vulnerable dependencies in Sonatype IQ Server (Lifecycle) and the versions that fix them. Same conventions as [`bb`](https://github.com/marcowarnke/bb) and `gh`: plain output when piped, `--json`/`--jq`/`--format`, no prompts, meaningful exit codes. It only reads IQ Server (except `st waive`, which creates time-limited waivers) and never edits files; making the upgrade is the agent's job (see the `st-upgrade` skill). Plain Python (3.10+, standard library plus truststore), shipped as a single zip app with launchers, so there is no binary for endpoint policies to flag.

## Install

Needs [uv](https://docs.astral.sh/uv/) (recommended: it also provides Python) or Python 3.10+. `--jq` needs the [jq](https://jqlang.org/download/) command; without it, use `--format`.

1. Download `st-v0.3.0.zip` from [Releases](https://github.com/marcowarnke/st/releases) and unpack it. The `st` folder holds:

   | File | What |
   |---|---|
   | `st.pyz` | The whole CLI as one Python zip app |
   | `st.cmd` | Launcher for cmd.exe (and PowerShell) on Windows |
   | `st.ps1` | Launcher for PowerShell on Windows |
   | `st` | Launcher for macOS/Linux shells and Git Bash |

2. Put the folder on your `PATH` and check with `st --version`:

   ```powershell
   # Windows (PowerShell), for the current user
   $dir = "$HOME\bin\st"   # where you unpacked it
   [Environment]::SetEnvironmentVariable("Path", [Environment]::GetEnvironmentVariable("Path", "User") + ";$dir", "User")
   ```

   ```sh
   # macOS/Linux
   ln -s "$PWD/st/st" ~/.local/bin/st
   ```

The launchers run `st.pyz` through `uv run` when uv is installed (uv finds or downloads a suitable Python), otherwise with `python3`/`python` (or `py -3` on Windows) from `PATH`. No executable is installed.

On Windows, PowerShell prefers `st.ps1` over `st.cmd`. If PowerShell says running scripts is disabled (execution policy), delete `st.ps1` and `st.cmd` takes over.

Alternatively, install it as a uv tool. On Windows this creates a small `st.exe` shim, which endpoint policies may block like the old binaries:

```sh
uv tool install git+https://github.com/marcowarnke/st@v0.3.0
```

TLS: `st` trusts the operating system's certificate store (through [truststore](https://github.com/sethmlarson/truststore)), so corporate TLS inspection works without setup; `SSL_CERT_FILE` overrides it. For uv itself (downloading Python behind such a proxy), set `UV_SYSTEM_CERTS=1`.

### Upgrading from the Go binaries

Delete the old `st` executable and install as above. Logins carry over: keyring entries and `config.json` are read and written exactly as before (CI checks the keyring format against go-keyring on every OS). Re-run `st skills install` afterwards.

The command line is unchanged, except that Go's `--template` is replaced by `--format`, a Python format string applied to each item (`--json name,version --format '{name}@{version}'`).

## Retries and errors

Requests that hit HTTP 429 or 503 are retried (any method), as are other 5xx responses and network errors for GET/PUT/DELETE: up to 3 retries with exponential backoff (0.5s, 1s, 2s + jitter), honoring `Retry-After`. POSTs are not retried on 500/502/504 since they may have taken effect. Errors for 403/404/429/5xx come with a hint; `ST_DEBUG=1` shows exactly which request failed.

## Auth

IQ Server uses HTTP Basic auth. Use a user token (user menu → User Token): a code/passcode pair. A username and password work the same way.

```sh
st auth login --hostname https://iq.example.com              # prompts for code and passcode
echo "$CODE:$PASSCODE" | st auth login -h https://iq.example.com:8070 --with-token
st auth status | token | logout
```

| Where | When |
|---|---|
| OS keyring (macOS Keychain, Windows Credential Manager, Linux Secret Service), service `st:<host>` | Default |
| `~/.config/st/config.json`, plain text, 0600 | `--insecure-storage`, or no keyring available — login warns |
| `ST_TOKEN` | Always wins; nothing stored. Use for CI/agent sandboxes |

| Env | Effect |
|---|---|
| `ST_TOKEN` | `code:passcode` (or just the passcode, with `ST_USER`); overrides stored credentials |
| `ST_HOST` | Host or base URL; needed when more than one host is configured |
| `ST_APP` | Default application public ID (same as `-A`) |
| `ST_CONFIG_DIR`, `XDG_CONFIG_HOME` | Config location |
| `ST_DEBUG` | Log every request (method, URL, status, duration) and retry to stderr |
| `NO_COLOR`, `BROWSER` | As in gh |

## Application resolution

`-A PUBLIC_ID` → `ST_APP` → the IQ application whose source control repository URL (`api/v2/sourceControl`) matches a git remote of the current checkout (`upstream` > `origin` > others). SSH and HTTPS URLs of the same repository match (`ssh://git@host:7999/proj/repo.git` = `https://host/scm/proj/repo.git`). Building the map costs one request per application, so it is cached in `~/.config/st/apps.json` and rebuilt when it misses.

## Commands

| Command | Notes |
|---|---|
| `vuln list` | Components with unwaived security policy violations in the latest report, highest threat first, with the CVE/sonatype IDs behind them, direct/transitive and the parents that pull them in. `--min-threat`, `--direct`, `--transitive`, `--cve`, `--include-waived`, `--stage`, `-L` |
| `vuln view <id>` | CVE or sonatype ID: CVSS, CWE, CISA KEV, vulnerable version ranges, Sonatype's explanation and recommendation |
| `fix [purl\|name\|id]` | IQ's remediation per component: target version, strategy, whether it's complete/breaking, the parent to bump for transitive deps, and a per-ecosystem `manifestHint`. Exit 9 when some components have no remediation |
| `waive <purl\|name>` | Waive one component's unwaived security violations. `--comment` required; always expires: 7 days by default, at most 90 (`--expires 30d\|4w\|YYYY-MM-DD`); this version only unless `--all-versions`; `--policy`, `--dry-run`. Needs the "Waive Policy Violations" permission |
| `app list` / `app view` | Applications; repository URL, base branch and latest report per stage. `view -w` opens the report |
| `status` | Dashboard across all applications: vulnerable component count and highest threat |
| `api` | Raw REST: `-X -f -F -H --input --jq -i`; paths are relative to `api/v2/`; `{app}` / `{appId}` placeholders |
| `skills install` / `list` | Agent skills, embedded in `st.pyz` |

Reports: the build stage by default, else the most recently evaluated; `--stage develop|source|build|stage-release|release|operate`. Findings are only as fresh as the last scan.

### How `st fix` picks a version

It calls `POST api/v2/components/remediation/application/{id}?stageId=…&includeParentRemediation=true` and takes the first strategy IQ offers, skipping any that would keep the current version:

1. `recommended-non-breaking-with-dependencies`: golden version, its dependencies clean too
2. `recommended-non-breaking`: golden version
3. `next-no-violations-with-dependencies`
4. `next-no-violations`
5. `next-non-failing-with-dependencies`: passes the stage, but may leave lower-threat violations (`complete: false`)
6. `next-non-failing`

`--strategy a,b` overrides the order. `breaking` is false for golden versions, true when the major version of what gets bumped changes (or a 0.x version moves), and null when unknown. For transitive dependencies, IQ names the direct parent and its target version where it can (Maven). Otherwise `parents` lists the current parents from the report and `manifestHint` explains how to find the dependency path or pin the version.

```sh
st fix --json name,current,target,strategy,complete,breaking,dependency,parents,manifestHint
st fix CVE-2022-42003
st fix pkg:maven/org.yaml/snakeyaml --strategy next-no-violations
```

## Agent usage

Non-TTY output is tab-separated/plain, without color or prompts. Prefer `--json` + `--jq` (`--jq` runs the `jq` command; without it use `--format '{name}\t{version}'`, a Python format string applied to each item); `--json` alone lists the available fields. Shell completion: `st completion bash|zsh|fish|powershell`. Exit codes: 0 ok, 1 error, 4 auth, 9 no remediation for some components.

| Skill | Loop |
|---|---|
| `st` | Command reference, conventions, how to read `st fix` |
| `st-upgrade` | `fix --json` → group changes → edit manifests (direct / parent bump / override) → regenerate lockfiles → build + test → commit → `bb pr create` (or `gh`) → report |

```sh
st skills install                                   # interactive (piped: ~/.claude/skills)
st skills install --agent copilot --scope project   # .github/skills
st skills install --dir path/to/skills
```

## API endpoints used

`api/v2/applications`, `api/v2/sourceControl/application/{id}`, `api/v2/reports/applications/{id}`, `api/v2/applications/{publicId}/reports/{reportId}/policy` and `/raw`, `api/v2/components/remediation/application/{id}`, `api/v2/vulnerabilities/{id}`; `st waive` also `POST api/v2/policyWaivers/application/{id}/{policyViolationId}`. The user needs view permission on the applications. Reading source control configuration may need more on some servers; if it fails, pass `-A`.

## Dev

```sh
uv sync                                     # environment with the dev tools
uv run st --help                            # run from the checkout
uv run pytest                               # tests (need jq)
uv run ruff check && uv run ruff format --check
uv run python scripts/build.py              # → dist/: st.pyz, st.cmd, st.ps1, st, st-vX.Y.Z.zip
uv run python scripts/verify_artifact.py    # run the built launchers against a fake server
```

CI (`.github/workflows/build.yml`) runs on every push: lint, tests on Linux, macOS and Windows with Python 3.10 and 3.13, a keyring check against go-keyring, the build, and the built launchers on every OS with and without uv. Pushing a `v*` tag that matches the version in `pyproject.toml` publishes a release with the files.
