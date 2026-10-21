from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone

import pytest
from conftest import run
from fakes import sec_violation

from st import config, credstore
from st.commands import waive
from st.commands.fix import Fix, breaking, major
from st.commands.root import EXIT_AUTH
from st.commands.vuln import Finding, purl_base, purl_name, purl_version

pytestmark = pytest.mark.jq


def config_file() -> str:
    return config.path().read_text(encoding="utf-8")


def test_auth_login_keyring(fake, monkeypatch):
    monkeypatch.setenv("ST_TOKEN", "")
    monkeypatch.setenv("ST_HOST", "")
    _, err, code = run("auth", "login", "--hostname", fake.url, "--with-token", stdin="code:pass\n")
    assert code == 0 and "Logged in to 127.0.0.1 as code (token stored in keyring)" in err, err
    assert "pass" not in config_file()
    assert credstore.get("st:127.0.0.1", "code") == "pass"
    out, err, code = run("app", "list", "--json", "publicId", "--jq", ".[0].publicId")
    assert code == 0 and out == "my-service\n", err
    out, _, _ = run("auth", "status")
    assert "as code (keyring)" in out and "pass" not in out
    out, _, _ = run("auth", "token")
    assert out == "code:pass\n"
    _, err, code = run("auth", "logout")
    assert code == 0, err
    with pytest.raises(credstore.NotFound):
        credstore.get("st:127.0.0.1", "code")


def test_auth_login_rejects_bad_token(fake, monkeypatch):
    monkeypatch.setenv("ST_TOKEN", "")
    _, err, code = run("auth", "login", "-h", fake.url, "--with-token", stdin="code:nope")
    assert code == EXIT_AUTH and "HTTP 401" in err
    _, err, code = run("auth", "login", "-h", fake.url, "--with-token", stdin="justapasscode")
    assert code == 1 and 'expected "code:passcode"' in err


def test_auth_login_keyring_unavailable(fake, monkeypatch):
    credstore.backend = credstore.Mock(OSError("no secret service"))
    monkeypatch.setenv("ST_TOKEN", "")
    _, err, code = run("auth", "login", "--hostname", fake.url, "--with-token", stdin="code:pass")
    assert code == 0 and "storing it in plain text" in err
    assert '"token": "pass"' in config_file()
    out, err, code = run("app", "list")
    assert code == 0 and out.startswith("my-service"), err


def test_config_compatible_with_go(fake, monkeypatch):
    # A config.json written by the Go version (host key keeps its case).
    monkeypatch.setenv("ST_TOKEN", "")
    monkeypatch.setenv("ST_HOST", "")
    config.config_dir().mkdir(parents=True)
    config.path().write_text(json.dumps({"hosts": {"127.0.0.1": {"base_url": fake.url, "user": "code"}}}), encoding="utf-8")
    credstore.set("st:127.0.0.1", "code", "pass")
    out, err, code = run("app", "list")
    assert code == 0 and out.startswith("my-service"), err
    assert config.normalize_host("https://IQ.Corp:8070/ctx/") == ("IQ.Corp", "https://IQ.Corp:8070/ctx")


def test_token_env_with_user(fake, monkeypatch):
    monkeypatch.setenv("ST_TOKEN", "pass")
    monkeypatch.setenv("ST_USER", "code")
    out, err, code = run("app", "list")
    assert code == 0 and out.startswith("my-service"), err
    monkeypatch.setenv("ST_USER", "")
    _, err, code = run("app", "list")
    assert code == EXIT_AUTH and "ST_TOKEN must be" in err


def in_repo(tmp_path, monkeypatch, origin: str) -> None:
    d = tmp_path / "repo"
    d.mkdir(exist_ok=True)
    monkeypatch.chdir(d)
    subprocess.run(["git", "init", "-q"], check=True)
    subprocess.run(["git", "remote", "remove", "origin"], capture_output=True)
    if origin:
        subprocess.run(["git", "remote", "add", "origin", origin], check=True)


def test_app_from_git_remote(fake, tmp_path, monkeypatch):
    in_repo(tmp_path, monkeypatch, "ssh://git@bitbucket.corp:7999/proj/my-service.git")
    out, err, code = run("vuln", "list", "--json", "application", "--jq", ".[0].application")
    assert code == 0 and out == "my-service\n", err
    assert fake.count("GET /api/v2/sourceControl/") == 2  # one lookup per app
    assert '"proj/my-service": "my-service"' in (config.config_dir() / "apps.json").read_text(encoding="utf-8")
    # Second run uses the cache.
    assert run("app", "view", "--json", "publicId")[2] == 0
    assert fake.count("GET /api/v2/sourceControl/") == 3  # +1 from app view's own repository lookup
    # ST_APP and -A win over the remote.
    monkeypatch.setenv("ST_APP", "other")
    out, _, _ = run("app", "view", "--json", "publicId", "--jq", ".publicId")
    assert out == "other\n"


def test_app_resolution_errors(fake, tmp_path, monkeypatch):
    in_repo(tmp_path, monkeypatch, "https://github.com/someone/unrelated.git")
    _, err, code = run("vuln", "list")
    assert code == 1 and "no IQ application has a repository URL matching someone/unrelated" in err
    in_repo(tmp_path, monkeypatch, "")
    _, err, _ = run("fix")
    assert "not in a git repository with a remote" in err
    _, err, _ = run("vuln", "list", "-A", "nope")
    assert 'no application with public ID "nope"' in err


@pytest.mark.parametrize(
    "p,name,version,base",
    [
        ("pkg:maven/org.yaml/snakeyaml@1.26?type=jar", "org.yaml:snakeyaml", "1.26", "pkg:maven/org.yaml/snakeyaml"),
        ("pkg:npm/%40babel/core@7.0.0", "@babel/core", "7.0.0", "pkg:npm/%40babel/core"),
        ("pkg:golang/golang.org/x/net@v0.17.0", "golang.org/x/net", "v0.17.0", "pkg:golang/golang.org/x/net"),
        ("pkg:pypi/django@4.2", "django", "4.2", "pkg:pypi/django"),
    ],
)
def test_purl_helpers(p, name, version, base):
    assert (purl_name(p), purl_version(p), purl_base(p)) == (name, version, base)


def test_versions():
    for v, want in {"2.9.10.1": 2, "v1.2.3": 1, "10": 10, "3.0.0-RC1": 3}.items():
        assert major(v) == want
    assert major("latest") is None
    for cur, tgt, want in [
        ("1.2.0", "1.9.0", False),
        ("1.2.0", "2.0.0", True),
        ("0.3.1", "0.3.9", False),
        ("0.3.1", "0.4.0", True),
        ("v0.17.0", "v0.23.0", True),
    ]:
        assert breaking(Fix(f=Finding(version=cur), target=tgt, strategy="next-no-violations")) is want


@pytest.fixture
def fixed_now(monkeypatch):
    monkeypatch.setattr(waive, "now", lambda: datetime(2026, 10, 20, 12, 0, 0, tzinfo=timezone.utc))


def test_waive(fake, fixed_now):
    _, err, code = run("waive", "-A", "my-service", "lodash")
    assert code == 1 and "--comment is required" in err
    for bad in ["0d", "91d", "never", "2026-10-01", "2027-06-01"]:
        _, err, code = run("waive", "-A", "my-service", "lodash", "-m", "x", "--expires", bad)
        assert code == 1 and "--expires" in err, bad
    assert fake.count("POST") == 0

    out, err, code = run(
        "waive", "-A", "my-service", "lodash", "-m", "not reachable", "--dry-run", "--json", "violationId,expiresAt,scope,dryRun"
    )
    assert code == 0, err
    rows = json.loads(out)
    assert rows == [
        {"violationId": "pv-Security-Medium-7", "expiresAt": "2026-10-27T12:00:00.000+0000", "scope": "EXACT_COMPONENT", "dryRun": True}
    ]
    assert fake.count("POST") == 0

    _, err, code = run(
        "waive", "-A", "my-service", "pkg:maven/org.yaml/snakeyaml", "-m", "  SafeConstructor only ", "--expires", "2w", "--all-versions"
    )
    assert (
        code == 0 and "Waived Security-High violation (threat 8) of org.yaml:snakeyaml (all versions) in my-service until 2026-11-03" in err
    ), err
    body = json.loads(fake.bodies["POST /api/v2/policyWaivers/application/a1/pv-Security-High-8"])
    assert body == {"comment": "SafeConstructor only", "expiryTime": "2026-11-03T12:00:00.000+0000", "matcherStrategy": "ALL_VERSIONS"}

    _, err, code = run("waive", "-A", "my-service", "lodash", "-m", "x", "--policy", "Security-High")
    assert code == 1 and "no unwaived Security-High violation" in err
    _, err, code = run("waive", "-A", "my-service", "commons-io:commons-io", "-m", "x")
    assert code == 1 and "no unwaived security violations" in err
    _, err, code = run("waive", "-A", "my-service", "lodash", "-m", "x", "--expires", "2026-10-25", "--dry-run", "--json", "expiresAt")
    assert code == 0 and "2026-10-25T23:59:59.999+0000" in _


def test_waive_partial_failure(fake, fixed_now):
    """A failure after some waivers were created must name them, also with --json."""
    fake.extra_violations = {
        "h2": [sec_violation("Security-Medium", 5, False, "Found security vulnerability CVE-2022-38749 with severity 6.5.")]
    }
    fake.fail_waivers = {"pv-Security-Medium-5"}
    out, err, code = run("waive", "-A", "my-service", "org.yaml:snakeyaml", "-m", "x", "--json", "violationId", "--jq", ".[].violationId")
    assert code == 1 and out == "pv-Security-High-8\n", err
    assert "waiving Security-Medium violation of org.yaml:snakeyaml: HTTP 403" in err
    assert "1 of 2 waivers were created before this failure (Security-High); don't create them again" in err

    # Text mode: the created waiver is printed, then the same error.
    _, err, _ = run("waive", "-A", "my-service", "org.yaml:snakeyaml", "-m", "x")
    assert "Waived Security-High violation (threat 8)" in err and "1 of 2 waivers were created" in err

    # Nothing created yet: plain error, and the 403 hint still applies.
    fake.fail_waivers.add("pv-Security-High-8")
    _, err, code = run("waive", "-A", "my-service", "org.yaml:snakeyaml", "-m", "x")
    assert code == 1 and "were created" not in err and "hint: the user lacks permission" in err


def test_vuln_list_violations(fake):
    out, _, _ = run("vuln", "list", "-A", "my-service", "--json", "name,violations", "--jq", ".[0].violations[0].id")
    assert out == "pv-Security-High-9\n"
