"""Verify the built artifacts in dist/ end to end: every launcher this OS can
run, against an in-process fake IQ Server. Checks the version, output
(including non-ASCII), stdin, exit codes, argument quoting, the jq
integration and the skills embedded in the .pyz.

Usage: uv run python scripts/verify_artifact.py [--no-uv] [dist]

--no-uv hides uv from the launchers, so they fall back to the Python on PATH.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))
from fakes import FakeIQ  # noqa: E402

APP = "st"


def launchers(dist: Path) -> list[tuple[str, list[str], str]]:
    """(name, command prefix, mode) for every way this OS runs the CLI. Modes: argv
    (run the prefix with the arguments), cmd (typed at a cmd.exe prompt), ps (typed
    at a PowerShell prompt); the last two find the launcher on PATH."""
    out = []
    if os.name == "nt":
        out.append(("cmd (direct)", [str(dist / f"{APP}.cmd")], "argv"))
        out.append(("cmd (on PATH)", [], "cmd"))
        for ps in ("powershell", "pwsh"):
            exe = shutil.which(ps)
            if exe:
                out.append((f"{ps} (on PATH, .ps1)", [exe, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command"], "ps"))
        sh = shutil.which("sh")
        if sh:
            out.append(("sh (Git Bash)", [sh, str(dist / APP)], "argv"))
    else:
        out.append(("sh", [str(dist / APP)], "argv"))
    out.append(("pyz", [sys.executable, str(dist / f"{APP}.pyz")], "argv"))
    return out


def cmd_quote(a: str) -> str:
    """Quote one argument the way a person types it in cmd.exe."""
    if a and not re.search(r'[\s"&|<>^()]', a):
        return a
    return '"' + a.replace('"', '\\"') + '"'


def ps_quote(a: str) -> str:
    """Quote one argument the way a person types it in PowerShell (a,b stays unquoted)."""
    if re.fullmatch(r"[A-Za-z0-9_./:=,+-][A-Za-z0-9_./:@=,+-]*", a):
        return a
    return "'" + a.replace("'", "''") + "'"


class Runner:
    def __init__(self, prefix: list[str], mode: str, env: dict[str, str]):
        self.prefix, self.mode, self.env = prefix, mode, env
        self.results: list[tuple[str, bool, object]] = []

    def run(self, *args: str, stdin: str = "", extra: dict | None = None) -> tuple[str, str, int]:
        env = dict(self.env, **(extra or {}))
        if self.mode == "cmd":
            line = " ".join([APP, *(cmd_quote(a) for a in args)])
            p = subprocess.run(f'cmd /d /s /c "{line}"', input=stdin.encode(), capture_output=True, env=env)
        elif self.mode == "ps":  # stdin comes from a PowerShell pipeline, as a user would write it
            line = " ".join([APP, *(ps_quote(a) for a in args)])
            if stdin:
                line = "'" + stdin.rstrip("\n").replace("'", "''") + "' | " + line  # a string, never a command
            p = subprocess.run(self.prefix + [line + "; exit $LASTEXITCODE"], stdin=subprocess.DEVNULL, capture_output=True, env=env)
        else:
            p = subprocess.run(self.prefix + list(args), input=stdin.encode(), capture_output=True, env=env)

        def text(b: bytes) -> str:
            return b.decode("utf-8", "replace").replace("\r\n", "\n")

        return text(p.stdout), text(p.stderr), p.returncode

    def check(self, what: str, ok: bool, detail: object = "") -> None:
        self.results.append((what, ok, detail))


def verify(r: Runner, fake: FakeIQ, version: str, jq: bool) -> None:
    out, err, code = r.run("--version")
    r.check("version", code == 0 and out == f"{APP} version {version}\n", (out, err, code))
    out, err, code = r.run("app", "list")
    r.check("plain output", code == 0 and out == "my-service\tMy Service\ta1\nother\tOther\ta2\n", (out, err))
    out, err, code = r.run("fix", "-A", "my-service")
    r.check("exit code 9 + non-ASCII output", code == 9 and "2.7.0 → 3.0.0" in out, (out, err, code))
    logged_out = {"ST_TOKEN": "", "ST_HOST": ""}
    out, err, code = r.run("auth", "login", "-h", fake.url, "--with-token", "--insecure-storage", stdin="code:pass\n", extra=logged_out)
    r.check("stdin", code == 0 and "Logged in to 127.0.0.1 as code" in err, (out, err))
    out, err, code = r.run("auth", "token", extra=logged_out)
    r.check("stored credentials", code == 0 and out == "code:pass\n", (out, err))
    fmt = "{threatLevel} {name}@{version} (ok)"
    out, err, code = r.run("vuln", "list", "-A", "my-service", "--json", "name,version,threatLevel", "--format", fmt)
    r.check("argument quoting", code == 0 and out.startswith("9 com.fasterxml.jackson.core:jackson-databind@2.9.10.1 (ok)\n"), (out, err))
    if jq:
        expr = '.[0] | "\\(.threatLevel): \\(.name)"'
        out, err, code = r.run("vuln", "list", "-A", "my-service", "--json", "name,threatLevel", "--jq", expr)
        r.check("--jq with quotes", code == 0 and out == "9: com.fasterxml.jackson.core:jackson-databind\n", (out, err))
    _, err, code = r.run("nope")
    r.check("exit code 1", code == 1 and 'unknown command "nope"' in err, (err, code))
    _, err, code = r.run("app", "list", extra={"ST_TOKEN": "code:wrong"})
    r.check("exit code 4 (auth)", code == 4 and "HTTP 401" in err, (err, code))
    out, err, code = r.run("skills", "list")
    r.check("embedded skills", code == 0 and out.count("\n") == 2 and out.startswith("st\t"), (out, err))


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # Windows pipes default to cp1252
    ap = argparse.ArgumentParser()
    ap.add_argument("dist", nargs="?", default=str(ROOT / "dist"))
    ap.add_argument("--no-uv", action="store_true")
    opts = ap.parse_args()
    dist = Path(opts.dist).resolve()
    version = re.search(r'^version = "(.+)"$', (ROOT / "pyproject.toml").read_text(encoding="utf-8"), re.M).group(1)
    if os.name != "nt":
        (dist / APP).chmod(0o755)
    env = {k: v for k, v in os.environ.items() if not k.startswith("ST_") and k != "NO_COLOR"}
    path = env.get("PATH", "")
    if opts.no_uv:
        uv = "uv.exe" if os.name == "nt" else "uv"
        path = os.pathsep.join(d for d in path.split(os.pathsep) if not (Path(d) / uv).exists())
    env["PATH"] = str(dist) + os.pathsep + path
    jq = shutil.which("jq", path=env["PATH"]) is not None

    failures = 0
    for name, prefix, mode in launchers(dist):
        fake = FakeIQ()
        tmp = tempfile.mkdtemp()
        r = Runner(prefix, mode, dict(env, ST_CONFIG_DIR=tmp, ST_HOST=fake.url, ST_TOKEN="code:pass", HOME=tmp, USERPROFILE=tmp))
        verify(r, fake, version, jq)
        if mode == "ps":
            # The PowerShell completion script, through the launcher on PATH.
            matches = f"(TabExpansion2 -inputScript '{APP} vu' -cursorColumn 5).CompletionMatches"
            script = f"{APP} completion powershell | Out-String | Invoke-Expression; {matches} | ForEach-Object {{ $_.CompletionText }}"
            p = subprocess.run([prefix[0], "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script], capture_output=True, env=r.env)
            out = p.stdout.decode("utf-8", "replace").split()
            r.check("powershell completion", out == ["vuln"], (out, p.stderr.decode("utf-8", "replace")[-300:]))
        fake.close()
        shutil.rmtree(tmp, ignore_errors=True)
        bad = [c for c in r.results if not c[1]]
        failures += len(bad)
        print(f"{name}: {len(r.results) - len(bad)}/{len(r.results)} checks passed")
        for what, _, detail in bad:
            print(f"  FAIL {what}: {detail!r}")
    print("OK" if failures == 0 else f"{failures} check(s) failed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
