"""In-process fake IQ Server, shared by the tests and scripts/verify_artifact.py."""

from __future__ import annotations

import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit

JACKSON_PURL = "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.10.1?type=jar"
YAML_PURL = "pkg:maven/org.yaml/snakeyaml@1.26?type=jar"
STARTER_PURL = "pkg:maven/org.springframework.boot/spring-boot-starter@2.7.0?type=jar"
LODASH_PURL = "pkg:npm/lodash@4.17.15"
WAIVED_PURL = "pkg:maven/commons-io/commons-io@2.4?type=jar"
LICENSE_PURL = "pkg:maven/org.gpl/thing@1.0?type=jar"


def maven_id(g: str, a: str, v: str) -> dict:
    return {"format": "maven", "coordinates": {"groupId": g, "artifactId": a, "version": v, "extension": "jar", "classifier": ""}}


def sec_violation(policy: str, level: int, waived: bool, *reasons: str) -> dict:
    conds = [{"conditionSummary": "Security Vulnerability Severity >= 7", "conditionReason": r} for r in reasons]
    return {
        "policyViolationId": f"pv-{policy}-{level}",
        "policyId": "p-" + policy,
        "policyName": policy,
        "policyThreatCategory": "SECURITY",
        "policyThreatLevel": level,
        "waived": waived,
        "grandfathered": False,
        "constraints": [{"constraintId": "c1", "constraintName": "cvss", "conditions": conds}],
    }


def policy_report() -> dict:
    lic = {"policyId": "lic", "policyName": "License-Banned", "policyThreatCategory": "LEGAL", "policyThreatLevel": 10, "waived": False}
    return {
        "reportTime": 1700000000000,
        "reportTitle": "Build Report",
        "initiator": "ci",
        "application": {"id": "a1", "publicId": "my-service", "name": "My Service", "organizationId": "o1"},
        "components": [
            {
                "hash": "h1",
                "packageUrl": JACKSON_PURL,
                "componentIdentifier": maven_id("com.fasterxml.jackson.core", "jackson-databind", "2.9.10.1"),
                "violations": [
                    sec_violation(
                        "Security-High",
                        9,
                        False,
                        "Found security vulnerability CVE-2020-36518 with severity 7.5.",
                        "Found security vulnerability CVE-2022-42003 with severity 7.5.",
                    ),
                    lic,
                ],
            },
            {
                "hash": "h2",
                "packageUrl": YAML_PURL,
                "componentIdentifier": maven_id("org.yaml", "snakeyaml", "1.26"),
                "violations": [sec_violation("Security-High", 8, False, "Found security vulnerability CVE-2022-1471 with severity 9.8.")],
            },
            {
                "hash": "h3",
                "packageUrl": LODASH_PURL,
                "componentIdentifier": {"format": "npm", "coordinates": {"packageId": "lodash", "version": "4.17.15"}},
                "violations": [
                    sec_violation("Security-Medium", 7, False, "Found security vulnerability sonatype-2020-0001 with severity 6.5.")
                ],
            },
            {
                "hash": "h4",
                "packageUrl": WAIVED_PURL,
                "componentIdentifier": maven_id("commons-io", "commons-io", "2.4"),
                "violations": [sec_violation("Security-High", 9, True, "Found security vulnerability CVE-2021-29425 with severity 9.1.")],
            },
            {"hash": "h5", "packageUrl": LICENSE_PURL, "violations": [lic]},
        ],
    }


def raw_report() -> dict:
    def issue(ref: str, sev: float) -> dict:
        return {
            "source": "cve",
            "reference": ref,
            "severity": sev,
            "status": "Open",
            "url": "https://nvd/" + ref,
            "threatCategory": "critical",
        }

    def dep(direct: bool, *parents: str) -> dict:
        return {"directDependency": direct, "innerSource": False, "parentComponentPurls": list(parents)}

    return {
        "components": [
            {
                "hash": "h1",
                "packageUrl": JACKSON_PURL,
                "dependencyData": dep(True),
                "securityData": {
                    "securityIssues": [issue("CVE-2020-36518", 7.5), issue("CVE-2022-42003", 7.5), issue("CVE-2019-0001", 3.1)]
                },
            },
            {
                "hash": "h2",
                "packageUrl": YAML_PURL,
                "dependencyData": dep(False, STARTER_PURL),
                "securityData": {"securityIssues": [issue("CVE-2022-1471", 9.8)]},
            },
            {
                "hash": "h3",
                "packageUrl": LODASH_PURL,
                "dependencyData": dep(False),
                "securityData": {"securityIssues": [issue("sonatype-2020-0001", 6.5)]},
            },
            {"hash": "h4", "packageUrl": WAIVED_PURL, "dependencyData": dep(True)},
        ]
    }


def with_policy_deps(p: dict, on: bool) -> dict:
    if not on:
        return p
    deps = {c["hash"]: c["dependencyData"] for c in raw_report()["components"]}
    for c in p["components"]:
        if c["hash"] in deps:
            c["dependencyData"] = deps[c["hash"]]
    return p


def change(typ: str, purl: str, cid: dict) -> dict:
    return {"type": typ, "data": {"component": {"packageUrl": purl, "componentIdentifier": cid}}}


def remediation(artifact: str) -> dict:
    changes: list[dict] = []
    if artifact == "jackson-databind":
        a = change(
            "recommended-non-breaking",
            "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.12.7.1?type=jar",
            maven_id("com.fasterxml.jackson.core", "jackson-databind", "2.12.7.1"),
        )
        b = change(
            "next-no-violations",
            "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.4.2?type=jar",
            maven_id("com.fasterxml.jackson.core", "jackson-databind", "2.13.4.2"),
        )
        # IQ may list the current version when it already satisfies a strategy.
        cur = change("next-non-failing", JACKSON_PURL, maven_id("com.fasterxml.jackson.core", "jackson-databind", "2.9.10.1"))
        a["directDependency"] = b["directDependency"] = True
        changes = [cur, b, a]
    elif artifact == "snakeyaml":
        c = change(
            "next-no-violations-with-dependencies", "pkg:maven/org.yaml/snakeyaml@2.0?type=jar", maven_id("org.yaml", "snakeyaml", "2.0")
        )
        c["directDependency"] = False
        c["directDependencyData"] = [
            {
                "component": {
                    "packageUrl": "pkg:maven/org.springframework.boot/spring-boot-starter@3.0.0?type=jar",
                    "hash": None,
                    "componentIdentifier": maven_id("org.springframework.boot", "spring-boot-starter", "3.0.0"),
                    "displayName": "org.springframework.boot : spring-boot-starter : 3.0.0",
                }
            }
        ]
        changes = [c]
    return {"remediation": {"versionChanges": changes}}


APPS = [
    {"id": "a1", "publicId": "my-service", "name": "My Service", "organizationId": "o1"},
    {"id": "a2", "publicId": "other", "name": "Other", "organizationId": "o1"},
]


class FakeIQ:
    """A tiny in-memory IQ Server with one evaluated application."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.requests: list[str] = []
        self.bodies: dict[str, str] = {}
        # policy_deps adds the raw report's dependency data to the policy report, as newer IQ versions do.
        self.policy_deps = False
        # extra_violations are appended to a component's violations in the policy report, by hash.
        self.extra_violations: dict[str, list] = {}
        # fail_waivers answers waiver requests for these violation IDs with HTTP 403.
        self.fail_waivers: set[str] = set()
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a: Any) -> None:
                pass

            def handle_any(self) -> None:
                fake.handle(self)

            do_GET = do_POST = do_PUT = do_DELETE = handle_any

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def count(self, prefix: str) -> int:
        with self.lock:
            return sum(1 for r in self.requests if r.startswith(prefix))

    def handle(self, h: BaseHTTPRequestHandler) -> None:
        def send(status: int, body: bytes = b"", ctype: str = "text/plain") -> None:
            h.send_response(status)
            h.send_header("Content-Type", ctype)
            h.send_header("Content-Length", str(len(body)))
            h.end_headers()
            h.wfile.write(body)

        auth = h.headers.get("Authorization", "")
        if auth != "Basic " + base64.b64encode(b"code:pass").decode():
            send(401, b"Unauthorized")
            return
        u = urlsplit(h.path)
        key = f"{h.command} {u.path}"
        body = h.rfile.read(int(h.headers.get("Content-Length") or 0))
        with self.lock:
            self.requests.append(key + "?" + u.query)
            self.bodies[key] = body.decode()
        if key.startswith("POST /api/v2/policyWaivers/application/a1/pv-"):
            if key.rsplit("/", 1)[1] in self.fail_waivers:
                send(403, b"Forbidden")
                return
            send(204)
            return
        q = parse_qs(u.query)
        out: Any
        if key == "GET /api/v2/applications":
            pid = q.get("publicId", [""])[0]
            out = {"applications": {"": APPS, "my-service": APPS[:1], "other": APPS[1:]}.get(pid, [])}
        elif key == "GET /api/v2/sourceControl/application/a1":
            out = {"repositoryUrl": "https://bitbucket.corp/scm/proj/my-service.git", "baseBranch": "main"}
        elif key == "GET /api/v2/reports/applications/a1":
            out = [
                {
                    "stage": "release",
                    "applicationId": "a1",
                    "evaluationDate": "2026-01-01T10:00:00.000-05:00",
                    "reportHtmlUrl": "ui/links/application/my-service/report/r2",
                    "latestReportHtmlUrl": "ui/links/application/my-service/latestReport/release",
                    "reportDataUrl": "api/v2/applications/my-service/reports/r2",
                },
                {
                    "stage": "build",
                    "applicationId": "a1",
                    "evaluationDate": "2026-02-01T10:00:00.000-05:00",
                    "reportHtmlUrl": "ui/links/application/my-service/report/r1",
                    "latestReportHtmlUrl": "ui/links/application/my-service/latestReport/build",
                    "reportDataUrl": "api/v2/applications/my-service/reports/r1/raw",
                },
            ]
        elif key == "GET /api/v2/reports/applications/a2":
            out = []
        elif key in ("GET /api/v2/applications/my-service/reports/r1/policy", "GET /api/v2/applications/my-service/reports/r2/policy"):
            p = with_policy_deps(policy_report(), self.policy_deps)
            for c in p["components"]:
                c["violations"] = c["violations"] + self.extra_violations.get(c["hash"], [])
            out = p
        elif key in ("GET /api/v2/applications/my-service/reports/r1/raw", "GET /api/v2/applications/my-service/reports/r2/raw"):
            out = raw_report()
        elif key == "POST /api/v2/components/remediation/application/a1":
            try:
                coords = json.loads(body)["componentIdentifier"]["coordinates"]
            except (ValueError, KeyError, TypeError):
                send(400)
                return
            out = remediation(coords.get("artifactId") or coords.get("packageId") or "")
        elif key == "GET /api/v2/vulnerabilities/CVE-2022-42003":
            out = {
                "identifier": "CVE-2022-42003",
                "vulnerabilityLink": "https://nvd/CVE-2022-42003",
                "source": {"shortName": "CVE", "longName": "National Vulnerability Database"},
                "mainSeverity": {"source": "cve_cvss_3", "score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"},
                "weakness": {"cweSource": "CVE", "cweIds": [{"id": "502", "uri": "https://cwe.mitre.org/data/definitions/502.html"}]},
                "description": "Deep wrapper array nesting causes resource exhaustion.",
                "recommendationMarkdown": "Upgrade to 2.13.4.1 or later.",
                "vulnerableVersionRanges": ["[2.4.0-rc1,2.12.7.1)", "[2.13.0,2.13.4.1)"],
                "kevData": {"isKev": True},
            }
        else:
            send(404, f"no route for {key}".encode())
            return
        send(200, json.dumps(out).encode(), "application/json")
