"""Check that the OS keyring entries are compatible with the Go releases, so
logins made with them keep working: a go-keyring helper (built in CI, see
.github/workflows/build.yml) and this package write and read each other's
entries.

Usage: uv run python scripts/keyring_compat.py <path to the go-keyring helper>
The helper takes: set SERVICE USER SECRET | get SERVICE USER | delete SERVICE USER
"""

from __future__ import annotations

import subprocess
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from st import credstore  # noqa: E402


def main() -> int:
    helper = sys.argv[1]
    service, user = f"st:compat-{uuid.uuid4().hex[:8]}.example", "code"

    def go(*args: str) -> subprocess.CompletedProcess:
        return subprocess.run([helper, *args], capture_output=True, text=True, timeout=30)

    try:
        p = go("set", service, user, "secret-from-go ✓")
        assert p.returncode == 0, p.stderr
        got = credstore.get(service, user)
        assert got == "secret-from-go ✓", f"Python read {got!r}"
        print("go-keyring → Python: ok")

        credstore.set(service, user, "secret-from-python ✓")
        p = go("get", service, user)
        assert p.returncode == 0 and p.stdout == "secret-from-python ✓", (p.stdout, p.stderr)
        print("Python → go-keyring: ok")

        credstore.delete(service, user)
        p = go("get", service, user)
        assert p.returncode != 0 and "not found" in p.stderr, (p.stdout, p.stderr)
        print("Python delete seen by go-keyring: ok")
    finally:
        go("delete", service, user)
    return 0


if __name__ == "__main__":
    sys.exit(main())
