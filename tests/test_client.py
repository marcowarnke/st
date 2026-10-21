from __future__ import annotations

import io
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from st import git, iq
from st.cli import Error
from st.iq import Client, report_id


@pytest.fixture
def flaky(monkeypatch):
    """flaky(retry_after, *statuses): a server answering the first requests with
    those statuses, then 200 echoing the body; returns (client, counter, waits)."""
    servers = []

    def make(retry_after: str, *statuses: int):
        n = [0]

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def handle_any(self):
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                i = n[0]
                n[0] += 1
                if i < len(statuses):
                    self.send_response(statuses[i])
                    if retry_after:
                        self.send_header("Retry-After", retry_after)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                data = b'{"echo":' + (body or b"null") + b"}"
                self.send_response(200)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = handle_any

        srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        servers.append(srv)
        waits: list[float] = []
        monkeypatch.setattr(iq, "sleep", waits.append)
        return Client(f"http://127.0.0.1:{srv.server_address[1]}", "u", "p"), n, waits

    yield make
    for s in servers:
        s.shutdown()
        s.server_close()


def test_retry_then_succeed(flaky):
    c, n, waits = flaky("", 503, 502, 500)
    assert c.do("GET", "api/v2/applications") == {"echo": None}
    assert n[0] == 4 and len(waits) == 3
    for i, w in enumerate(waits):
        base = 0.5 * 2**i
        assert base <= w <= base * 1.5


def test_retry_gives_up(flaky):
    c, n, _ = flaky("", 500, 500, 500, 500, 500)
    with pytest.raises(Error) as e:
        c.do("GET", "api/v2/applications")
    assert n[0] == 4 and "HTTP 500" in str(e.value) and "gave up after 4 attempts" in str(e.value)


def test_retry_after_and_body_replay(flaky):
    c, n, waits = flaky("2", 429)
    out = c.do("POST", "api/v2/components/remediation/application/a1", None, {"x": 1})
    assert n[0] == 2 and waits == [2.0] and out["echo"] == {"x": 1}


def test_no_retry_for_post_server_error(flaky):
    c, n, _ = flaky("", 500)
    with pytest.raises(Error):
        c.do("POST", "api/v2/policyWaivers/application/a1/v1", None, {})
    assert n[0] == 1


def test_no_retry_for_client_errors(flaky):
    c, n, _ = flaky("", 404)
    with pytest.raises(iq.APIError) as e:
        c.do("GET", "api/v2/x")
    assert iq.is_not_found(e.value) and n[0] == 1 and "attempts" not in str(e.value)


def test_network_errors_are_retried(monkeypatch):
    waits: list[float] = []
    monkeypatch.setattr(iq, "sleep", waits.append)
    c = Client("http://127.0.0.1:9", "u", "p")  # discard port: connection refused
    with pytest.raises(Error) as e:
        c.do("GET", "api/v2/applications")
    assert len(waits) == 3 and 'Get "http://127.0.0.1:9/api/v2/applications"' in str(e.value)


def test_debug(flaky):
    c, _, _ = flaky("", 503)
    buf = io.StringIO()
    c.debug = buf
    c.do("GET", "api/v2/applications")
    out = buf.getvalue()
    for want in [f"GET {c.base_url}/api/v2/applications -> 503", "retrying in", "-> 200"]:
        assert want in out


@pytest.mark.parametrize(
    "data,html,want",
    [
        ("api/v2/applications/my-app/reports/abc123/raw", "", "abc123"),
        ("api/v2/applications/my-app/reports/abc123", "", "abc123"),
        ("api/v2/applications/my-app/reports/abc123/", "", "abc123"),
        ("https://iq.corp/api/v2/applications/my-app/reports/abc123/raw?x=1", "", "abc123"),
        ("", "ui/links/application/my-app/report/def456", "def456"),
        ("", "", ""),
    ],
)
def test_report_id(data, html, want):
    assert report_id({"reportDataUrl": data, "reportHtmlUrl": html}) == want


@pytest.mark.parametrize(
    "url,want",
    [
        ("https://bitbucket.corp/scm/proj/repo.git", "proj/repo"),
        ("https://bitbucket.corp/ctx/scm/PROJ/Repo.git", "proj/repo"),
        ("ssh://git@bitbucket.corp:7999/proj/repo.git", "proj/repo"),
        ("git@bitbucket.corp:proj/repo.git", "proj/repo"),
        ("https://bitbucket.corp/projects/PROJ/repos/repo/browse", "proj/repo"),
        ("https://bitbucket.corp/users/alice/repos/tool", "~alice/tool"),
        ("https://github.com/org/repo", "org/repo"),
        ("https://user@bitbucket.corp/scm/proj/repo.git", "proj/repo"),
        ("https://gitlab.corp/group/subgroup/repo.git", "subgroup/repo"),
        ("", None),
        ("not a url", None),
        ("https://host/", None),
    ],
)
def test_repo_key(url, want):
    assert git.repo_key(url) == want


def test_query_encoding_matches_go():
    c = Client("https://iq", "", "")
    assert (
        c.url("p", {"stageId": "build", "includeParentRemediation": "true"}) == "https://iq/p?includeParentRemediation=true&stageId=build"
    )
    assert iq.path_escape("a b/c:d@e") == "a%20b%2Fc:d@e"
    assert json.loads(json.dumps({"x": 1}))["x"] == 1
