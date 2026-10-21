"""Build the release artifacts into dist/:

  <app>.pyz      the whole CLI as one zipapp (truststore vendored), runs on Python 3.10+
  <app>.cmd      Windows launcher (cmd.exe)
  <app>.ps1      Windows launcher (PowerShell)
  <app>          macOS/Linux launcher (sh)
  <app>-v<version>.zip  all four, to unpack into a folder on PATH

The launchers run the .pyz next to them through `uv run` when uv is
installed (uv picks or installs a suitable Python), else with the Python on
PATH (python3/python, or the py launcher on Windows).

Usage: uv run python scripts/build.py
"""

from __future__ import annotations

import importlib.metadata
import re
import shutil
import stat
import sys
import zipapp
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DIST = ROOT / "dist"

MAIN = """import sys

if sys.version_info < (3, 10):
    sys.exit("{app} needs Python 3.10 or newer; this is Python %d.%d" % sys.version_info[:2])

from {app}.commands.root import main

main()
"""

CMD = """@echo off
rem {app} launcher: runs {app}.pyz from this folder with Python 3.10+ (through uv when it is installed).
setlocal
set "PYZ=%~dp0{app}.pyz"
where uv >nul 2>nul || goto python
uv run --quiet --no-project --python ">=3.10" python "%PYZ%" %*
exit /b %ERRORLEVEL%
:python
where python >nul 2>nul || goto py
python "%PYZ%" %*
exit /b %ERRORLEVEL%
:py
py -3 "%PYZ%" %*
exit /b %ERRORLEVEL%
"""

PS1 = """# {app} launcher: runs {app}.pyz from this folder with Python 3.10+ (through uv when it is installed).
$pyz = Join-Path $PSScriptRoot '{app}.pyz'
if (Get-Command uv -ErrorAction SilentlyContinue) {{
    $exe = 'uv'
    $pre = @('run', '--quiet', '--no-project', '--python', '>=3.10', 'python', $pyz)
}} elseif (Get-Command python -ErrorAction SilentlyContinue) {{
    $exe = 'python'
    $pre = @($pyz)
}} else {{
    $exe = 'py'
    $pre = @('-3', $pyz)
}}
if ($MyInvocation.ExpectingInput) {{ $input | & $exe @pre @args }} else {{ & $exe @pre @args }}
exit $LASTEXITCODE
"""

SH = """#!/bin/sh
# {app} launcher: runs {app}.pyz next to this script with Python 3.10+ (through uv when it is installed).
self=$0
while [ -L "$self" ]; do
    link=$(readlink "$self")
    case $link in
        /*) self=$link ;;
        *) self=$(dirname "$self")/$link ;;
    esac
done
pyz=$(dirname "$self")/{app}.pyz
if command -v uv >/dev/null 2>&1; then
    exec uv run --quiet --no-project --python '>=3.10' python "$pyz" "$@"
fi
for py in python3 python; do
    if command -v "$py" >/dev/null 2>&1; then
        exec "$py" "$pyz" "$@"
    fi
done
echo "{app}: needs uv or Python 3.10+ on PATH" >&2
exit 127
"""


def vendor(dist_name: str, dest: Path) -> None:
    """Copy an installed pure-Python distribution (package and metadata, for its license) into dest."""
    d = importlib.metadata.distribution(dist_name)
    for f in d.files or []:
        src = Path(d.locate_file(f))
        if f.suffix == ".pyc" or "__pycache__" in f.parts or not src.is_file():
            continue
        target = dest / f
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, target)


def main() -> int:
    project = (ROOT / "pyproject.toml").read_text()
    app = re.search(r'^name = "(.+)"$', project, re.M).group(1)
    version = re.search(r'^version = "(.+)"$', project, re.M).group(1)
    sys.path.insert(0, str(ROOT / "src"))
    pkg_version = __import__(app).__version__
    if pkg_version != version:
        sys.exit(f"version mismatch: pyproject.toml has {version}, src/{app}/__init__.py has {pkg_version}")

    shutil.rmtree(DIST, ignore_errors=True)
    stage = DIST / "stage"
    shutil.copytree(ROOT / "src" / app, stage / app, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    vendor("truststore", stage)
    (stage / "__main__.py").write_text(MAIN.format(app=app))
    pyz = DIST / f"{app}.pyz"
    zipapp.create_archive(stage, pyz, interpreter="/usr/bin/env python3", compressed=True)
    shutil.rmtree(stage)

    (DIST / f"{app}.cmd").write_bytes(CMD.format(app=app).replace("\n", "\r\n").encode())
    (DIST / f"{app}.ps1").write_bytes(PS1.format(app=app).replace("\n", "\r\n").encode())
    sh = DIST / app
    sh.write_text(SH.format(app=app), newline="\n")
    sh.chmod(sh.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    bundle = DIST / f"{app}-v{version}.zip"
    with zipfile.ZipFile(bundle, "w", zipfile.ZIP_DEFLATED) as z:
        for name in (f"{app}.pyz", f"{app}.cmd", f"{app}.ps1", app):
            info = zipfile.ZipInfo.from_file(DIST / name, f"{app}/{name}")
            info.external_attr = (0o755 if name in (app, f"{app}.pyz") else 0o644) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, (DIST / name).read_bytes())
    for f in sorted(DIST.iterdir()):
        print(f"{f.relative_to(ROOT)}\t{f.stat().st_size} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
