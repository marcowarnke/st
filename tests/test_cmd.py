from __future__ import annotations

import json

import pytest
from conftest import run, run_tty
from fakes import JACKSON_PURL, LODASH_PURL, STARTER_PURL, YAML_PURL

from st.commands.root import EXIT_AUTH, EXIT_NO_REMEDIATION, error_hint
from st.iq import APIError

pytestmark = pytest.mark.jq


def test_vuln_list(fake):
    out, err, code = run("vuln", "list", "-A", "my-service")
    assert code == 0, err
    assert out == (
        f"9\t{JACKSON_PURL}\tdirect\tCVE-2020-36518,CVE-2022-42003\tSecurity-High\n"
        f"8\t{YAML_PURL}\ttransitive\tCVE-2022-1471\tSecurity-High\n"
        f"7\t{LODASH_PURL}\ttransitive\tsonatype-2020-0001\tSecurity-Medium\n"
    )

    out, _, _ = run("vuln", "list", "-A", "my-service", "--transitive", "--json", "name,parents,cves,stage,reportUrl")
    rows = json.loads(out)
    assert len(rows) == 2 and rows[0]["name"] == "org.yaml:snakeyaml" and rows[0]["stage"] == "build"
    assert rows[0]["parents"] == [STARTER_PURL]
    c = rows[0]["cves"][0]
    assert c["id"] == "CVE-2022-1471" and c["url"] == "https://nvd/CVE-2022-1471"
    assert rows[0]["reportUrl"].endswith("/ui/links/application/my-service/report/r1")

    out, _, _ = run("vuln", "list", "-A", "my-service", "--cve", "cve-2022-42003", "--json", "name", "--jq", ".[].name")
    assert out == "com.fasterxml.jackson.core:jackson-databind\n"
    out, _, _ = run("vuln", "list", "-A", "my-service", "--min-threat", "8", "--direct", "--json", "name", "--jq", "length")
    assert out == "1\n"
    out, _, _ = run(
        "vuln", "list", "-A", "my-service", "--include-waived", "--json", "name,waived", "--jq", ".[] | select(.waived) | .name"
    )
    assert out == "commons-io:commons-io\n"
    out, _, _ = run("vuln", "list", "-A", "my-service", "--stage", "release", "--json", "stage", "--jq", ".[0].stage")
    assert out == "release\n"
    _, err, code = run("vuln", "list", "-A", "my-service", "--stage", "operate")
    assert code == 1 and "no operate report; available stages: build, release" in err
    _, err, code = run("vuln", "list", "-A", "other")
    assert code == 1 and "not been evaluated" in err
    _, err, code = run("vuln", "list", "-A", "my-service", "--json", "nope")
    assert code != 0 and "Unknown JSON field" in err


def test_vuln_list_format(fake):
    out, err, code = run(
        "vuln",
        "list",
        "-A",
        "my-service",
        "--json",
        "name,version,threatLevel,policies",
        "--format",
        "{threatLevel}\\t{name}@{version}\\t{policies}",
    )
    assert code == 0, err
    assert out.splitlines()[0] == "9\tcom.fasterxml.jackson.core:jackson-databind@2.9.10.1\tSecurity-High"
    _, err, code = run("vuln", "list", "-A", "my-service", "--json", "name", "--format", "{version}")
    assert code == 1 and "unknown field 'version'" in err
    _, err, code = run("vuln", "list", "-A", "my-service", "--format", "{name}")
    assert code == 1 and "without specifying `--json`" in err


def test_vuln_list_tty(fake):
    out, err, code = run_tty("vuln", "list", "-A", "my-service")
    assert code == 0, err
    for want in [
        "Showing 3 vulnerable components in my-service (build",
        "THREAT",
        "com.fasterxml.jackson.core:jackson-databind",
        "CVE-2020-36518 CVE-2022-42003",
        "/report/r1",
    ]:
        assert want in out


def test_fix(fake):
    out, err, code = run(
        "fix",
        "-A",
        "my-service",
        "--json",
        "name,current,target,strategy,complete,breaking,dependency,parents,available,resolves,manifestHint",
    )
    assert code == EXIT_NO_REMEDIATION and "1 of 3 components have no remediation" in err
    j, y, lo = json.loads(out)
    # Golden version wins over next-no-violations; the current version is ignored.
    assert (j["target"], j["strategy"], j["breaking"], j["complete"], j["dependency"]) == (
        "2.12.7.1",
        "recommended-non-breaking",
        False,
        True,
        "direct",
    )
    assert len(j["resolves"]) == 2
    # Transitive: bump the parent; its major changes.
    p = y["parents"][0]
    assert y["dependency"] == "transitive" and p["name"] == "org.springframework.boot:spring-boot-starter"
    assert p["current"] == "2.7.0" and p["target"] == "3.0.0" and y["breaking"] is True
    assert "bump the parent" in y["manifestHint"]
    assert lo["available"] is False and lo["target"] == "" and lo["resolves"] == [] and "npm why lodash" in lo["manifestHint"]
    assert fake.count("POST /api/v2/components/remediation/application/a1?includeParentRemediation=true&stageId=build") == 3

    # Narrowing by name, purl without version, or CVE; exit 0 when all are fixable.
    for arg in [
        "com.fasterxml.jackson.core:jackson-databind",
        "pkg:maven/com.fasterxml.jackson.core/jackson-databind",
        JACKSON_PURL,
        "CVE-2022-42003",
    ]:
        out, err, code = run("fix", arg, "-A", "my-service", "--json", "target", "--jq", ".[].target")
        assert code == 0 and out == "2.12.7.1\n", (arg, err)
    out, _, code = run(
        "fix",
        "com.fasterxml.jackson.core:jackson-databind",
        "-A",
        "my-service",
        "--strategy",
        "next-no-violations",
        "--json",
        "target,complete,breaking",
        "--jq",
        ".[] | [.target, .complete, .breaking] | @tsv",
    )
    assert code == 0 and out == "2.13.4.2\ttrue\tfalse\n"
    _, err, code = run("fix", "pkg:npm/left-pad", "-A", "my-service")
    assert code == 1 and "has no security violations" in err
    _, err, code = run("fix", "-A", "my-service", "--strategy", "best")
    assert code == 1 and "invalid --strategy" in err

    out, _, code = run("fix", "-A", "my-service")
    assert code == EXIT_NO_REMEDIATION
    assert out.startswith(JACKSON_PURL + "\t2.9.10.1\t2.12.7.1\tdirect\trecommended-non-breaking\t")
    assert "via org.springframework.boot:spring-boot-starter 2.7.0 → 3.0.0" in out
    assert LODASH_PURL + "\t4.17.15\t\tno remediation" in out
    out, _, _ = run_tty("fix", "-A", "my-service")
    assert "⚠ major bump" in out and "2.9.10.1 → 2.12.7.1" in out


def test_vuln_view(fake):
    out, err, code = run("vuln", "view", "CVE-2022-42003")
    assert code == 0, err
    for want in [
        "CVE-2022-42003",
        "Severity:   7.5 CVSS:3.1",
        "Weakness:   CWE-502",
        "Exploited:  yes",
        "Vulnerable: [2.4.0-rc1,2.12.7.1) [2.13.0,2.13.4.1)",
        "Recommendation\nUpgrade to 2.13.4.1",
    ]:
        assert want in out
    out, _, _ = run("vuln", "view", "CVE-2022-42003", "--json", "score,cwes,kev", "--jq", "[.score, .cwes[0], .kev] | @tsv")
    assert out == "7.5\tCWE-502\ttrue\n"
    _, err, code = run("vuln", "view", "CVE-0000-0000")
    assert code == 1 and "HTTP 404" in err and "hint:" in err


def test_app_list_view_and_api(fake):
    out, _, _ = run("app", "list")
    assert out == "my-service\tMy Service\ta1\nother\tOther\ta2\n"
    out, _, _ = run("app", "list", "-S", "OTH", "--json", "publicId", "--jq", ".[].publicId")
    assert out == "other\n"
    out, _, _ = run(
        "app",
        "view",
        "my-service",
        "--json",
        "repositoryUrl,reports",
        "--jq",
        '[.repositoryUrl, (.reports | map(.stage) | join(","))] | @tsv',
    )
    assert out == "https://bitbucket.corp/scm/proj/my-service.git\tbuild,release\n"
    out, _, _ = run_tty("app", "view", "my-service")
    assert "My Service (my-service)" in out and "Repository: https://bitbucket.corp/scm/proj/my-service.git (main)" in out
    out, err, code = run("api", "reports/applications/{appId}", "-A", "my-service", "--jq", ".[].stage")
    assert code == 0 and out == "release\nbuild\n", err


def test_status(fake):
    out, err, code = run("status", "--json", "application,components,direct,threatLevel,error")
    assert code == 0, err
    rows = json.loads(out)
    assert len(rows) == 2 and rows[0]["application"] == "my-service"
    assert (rows[0]["components"], rows[0]["direct"], rows[0]["threatLevel"]) == (3, 1, 9)
    assert "not been evaluated" in rows[1]["error"]


@pytest.mark.parametrize("policy_deps", [False, True])
def test_status_skips_raw_report(fake, policy_deps):
    fake.policy_deps = policy_deps
    out, err, code = run("status", "--json", "application,components,direct,threatLevel")
    assert code == 0, err
    r = json.loads(out)[0]
    assert (r["components"], r["direct"], r["threatLevel"]) == (3, 1, 9)
    # The raw report is only needed for dependency data the policy report lacks.
    assert fake.count("GET /api/v2/applications/my-service/reports/r1/raw") == (0 if policy_deps else 1)


def test_auth_failure_exit_code(fake, monkeypatch):
    monkeypatch.setenv("ST_TOKEN", "code:wrong")
    _, err, code = run("vuln", "list", "-A", "my-service")
    assert code == EXIT_AUTH and "HTTP 401" in err
    monkeypatch.setenv("ST_TOKEN", "")
    monkeypatch.setenv("ST_HOST", "")
    assert run("vuln", "list")[2] == EXIT_AUTH


@pytest.mark.parametrize(
    "status,want", [(404, "ST_DEBUG=1"), (403, "permission"), (429, "try again later"), (503, "try again later"), (400, "")]
)
def test_error_hint(status, want):
    wrapped = Exception("wrapped")
    wrapped.__cause__ = APIError(status, "GET", "u")
    got = error_hint(wrapped)
    assert (got == "") if want == "" else (want in got)


def test_debug_logs_requests(fake, monkeypatch):
    monkeypatch.setenv("ST_DEBUG", "1")
    _, err, code = run("app", "list")
    assert code == 0 and f"st: GET {fake.url}/api/v2/applications -> 200" in err


def test_help_for_every_command():
    from st.commands.root import new_root

    n = 0

    def walk(c):
        nonlocal n
        for sub in c.commands:
            path = sub.path().split()[1:]
            out, err, code = run(*path, "--help")
            assert code == 0 and "Usage:" in out, (path, err)
            n += 1
            walk(sub)

    walk(new_root())
    assert n >= 15


def test_usage_errors(fake):
    _, err, code = run("vuln", "list", "--nope")
    assert code == 1 and "unknown flag: --nope" in err
    _, err, code = run("vuln", "view")
    assert code == 1 and "accepts 1 arg(s), received 0" in err
    _, err, code = run("vuln", "list", "--json")
    assert code == 1 and "Specify one or more comma-separated fields for `--json`:\n  application" in err
    _, err, code = run("nope")
    assert code == 1 and 'unknown command "nope" for "st"' in err
    out, _, code = run("vuln")
    assert code == 0 and "Available Commands:" in out
    out, _, code = run("--version")
    assert code == 0 and out.startswith("st version ")


def test_completion(fake):
    out, _, code = run("__complete", "vuln", "list", "-A", "")
    assert code == 0 and out == "my-service\tMy Service\nother\tOther\n:4\n"
    out, _, _ = run("__complete", "vuln", "list", "--stage", "")
    assert out.startswith("develop\nsource\nbuild\n") and out.endswith(":4\n")
    out, _, _ = run("__complete", "v")
    assert out == "vuln\tList and view vulnerabilities\n:4\n"
    out, _, _ = run("__complete", "fix", "--stra")
    assert out == "--strategy\tRemediation `strategies` to use, in order of preference\n:4\n"
    for shell in ("bash", "zsh", "fish", "powershell"):
        out, _, code = run("completion", shell)
        assert code == 0 and "__complete" in out
