"""Test harness: the fake server fixture and a runner that captures output."""

from __future__ import annotations

import io
import os
import shutil
import subprocess
from typing import Any

import pytest
from fakes import FakeIQ

from st import credstore, output
from st.commands import root


@pytest.fixture
def fake(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> Any:
    credstore.backend = credstore.Mock()  # never touch the real OS keyring from tests
    f = FakeIQ()
    monkeypatch.setenv("ST_CONFIG_DIR", str(tmp_path / "config"))
    monkeypatch.setenv("ST_HOST", f.url)
    monkeypatch.setenv("ST_TOKEN", "code:pass")
    for k in ("ST_USER", "ST_APP", "ST_DEBUG", "NO_COLOR"):
        monkeypatch.delenv(k, raising=False)
    yield f
    f.close()
    credstore.backend = None


def run(*args: str, stdin: str = "", tty: bool = False) -> tuple[str, str, int]:
    """Run st in-process; returns (stdout, stderr, exit code)."""
    o, e = io.StringIO(), io.StringIO()
    old = (output.io.stdin, output.io.stdout, output.io.stderr, output.io.tty)
    output.io.stdin, output.io.stdout, output.io.stderr, output.io.tty = io.StringIO(stdin), o, e, tty
    try:
        code = root.run(list(args))
    finally:
        output.io.stdin, output.io.stdout, output.io.stderr, output.io.tty = old
    return o.getvalue(), e.getvalue(), code


def run_tty(*args: str, stdin: str = "") -> tuple[str, str, int]:
    """Run as if attached to a terminal (prompts enabled; no color in tests)."""
    os.environ["NO_COLOR"] = "1"
    try:
        return run(*args, stdin=stdin, tty=True)
    finally:
        del os.environ["NO_COLOR"]


def jq(data: str, expr: str) -> str:
    return subprocess.run(["jq", "-r", expr], input=data, capture_output=True, text=True, check=True).stdout.strip()


def pytest_collection_modifyitems(config: Any, items: list) -> None:
    if shutil.which("jq") is None and not os.environ.get("CI"):
        skip = pytest.mark.skip(reason="needs the jq command")
        for item in items:
            if "jq" in item.keywords:
                item.add_marker(skip)


def pytest_configure(config: Any) -> None:
    config.addinivalue_line("markers", "jq: needs the jq command (always required in CI)")
