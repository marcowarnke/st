"""A minimal Sonatype IQ Server (Lifecycle) REST client."""

from __future__ import annotations

import base64
import http.client
import json
import random
import ssl
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import HTTPSHandler, Request, build_opener

from .cli import Error

# Stages IQ Server evaluates in, in pipeline order.
STAGES = ["develop", "source", "build", "stage-release", "release", "operate"]

# sleep is swappable for tests.
sleep: Callable[[float], None] = time.sleep

STATUS_TEXT = {code: r.phrase for code, r in ((s.value, s) for s in http.HTTPStatus)}


def ssl_context() -> ssl.SSLContext:
    """TLS trusting the OS certificate store (corporate CAs included) via
    truststore when available; SSL_CERT_FILE still wins when set."""
    import os

    if not os.environ.get("SSL_CERT_FILE") and not os.environ.get("SSL_CERT_DIR"):
        try:
            import truststore

            return truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        except ImportError:
            pass
    return ssl.create_default_context()


def path_escape(s: str) -> str:
    """Go's url.PathEscape."""
    return quote(s, safe="$&+:=@")


def encode_query(query: dict[str, Any]) -> str:
    """Go's url.Values.Encode: sorted by key."""
    items = []
    for k in sorted(query):
        v = query[k]
        for x in v if isinstance(v, list) else [v]:
            items.append((k, str(x)))
    return urlencode(items)


class APIError(Error):
    def __init__(self, status: int, method: str, url: str, message: str = "", attempts: int = 1):
        self.status, self.method, self.url, self.message, self.attempts = status, method, url, message, attempts
        super().__init__(str(self))

    def __str__(self) -> str:
        msg = self.message or STATUS_TEXT.get(self.status, "")
        s = f"HTTP {self.status}: {msg} ({self.method} {self.url})"
        if self.attempts > 1:
            s += f", gave up after {self.attempts} attempts"
        return s


def is_not_found(e: BaseException | None) -> bool:
    return isinstance(e, APIError) and e.status == 404


@dataclass
class Response:
    status: int
    reason: str
    headers: list[tuple[str, str]]
    body: bytes
    version: str = "HTTP/1.1"

    def header(self, name: str) -> str:
        for k, v in self.headers:
            if k.lower() == name.lower():
                return v
        return ""


class Client:
    def __init__(self, base_url: str, user: str, password: str):
        self.base_url = base_url.rstrip("/")
        self.user, self.password = user, password
        self.timeout = 60.0
        # How often a request is retried after a 429, a 5xx or a network error (see retryable).
        self.max_retries = 3
        # If set, receives one line per request and retry.
        self.debug: Any = None
        self._opener = build_opener(HTTPSHandler(context=ssl_context()))

    def url(self, path: str, query: dict[str, Any] | None = None) -> str:
        u = self.base_url + "/" + path.lstrip("/")
        if query:
            u += ("&" if "?" in u else "?") + encode_query(query)
        return u

    def raw(
        self,
        method: str,
        path: str,
        query: dict[str, Any] | None = None,
        headers: list[tuple[str, str]] | None = None,
        body: bytes | None = None,
    ) -> Response:
        """Perform a request; non-2xx statuses raise APIError. Rate limiting,
        server errors and network errors are retried with backoff."""
        u = self.url(path, query)
        attempt = 1
        while True:
            start = time.monotonic()
            resp, err = None, None
            try:
                resp = self._send(method, u, headers or [], body)
            except Error as e:
                err = e
            status = resp.status if resp else 0
            took = round((time.monotonic() - start) * 1000)
            self._debugf(f"{method} {u} -> {err if err else status} ({took}ms)")
            if attempt <= self.max_retries and retryable(method, status, err):
                wait = backoff(attempt, resp)
                self._debugf(f"retrying in {round(wait * 1000)}ms (attempt {attempt + 1} of {self.max_retries + 1})")
                sleep(wait)
                attempt += 1
                continue
            if err is not None:
                raise err
            assert resp is not None
            if resp.status >= 300:
                raise parse_error(resp, method, u, attempt)
            return resp

    def _send(self, method: str, u: str, headers: list[tuple[str, str]], body: bytes | None) -> Response:
        req = Request(u, data=body, method=method)
        for k, v in headers:
            req.add_header(k, v)
        if not req.has_header("Accept"):
            req.add_header("Accept", "application/json")
        if body is not None and not req.has_header("Content-type"):
            req.add_header("Content-Type", "application/json")
        if self.user or self.password:
            cred = base64.b64encode(f"{self.user}:{self.password}".encode()).decode("ascii")
            req.add_header("Authorization", "Basic " + cred)
        try:
            with self._opener.open(req, timeout=self.timeout) as r:
                return Response(r.status, r.reason, list(r.headers.items()), r.read(), _version(r))
        except HTTPError as e:
            try:
                data = e.read()
            except Exception:
                data = b""
            return Response(e.code, e.reason or "", list(e.headers.items()) if e.headers else [], data)
        except URLError as e:
            raise Error(f'{method.title()} "{u}": {e.reason}') from e
        except (OSError, http.client.HTTPException) as e:
            raise Error(f'{method.title()} "{u}": {e}') from e

    def _debugf(self, msg: str) -> None:
        if self.debug is not None:
            self.debug.write("st: " + msg + "\n")

    def do(self, method: str, path: str, query: dict[str, Any] | None = None, body: Any = None) -> Any:
        """Send body (JSON-encoded if not None) and decode the JSON response."""
        data = json.dumps(body).encode("utf-8") if body is not None else None
        resp = self.raw(method, path, query, None, data)
        if resp.status == 204 or not resp.body.strip():
            return None
        try:
            return json.loads(resp.body)
        except ValueError as e:
            raise Error(f"decoding the response of {method} {self.url(path, query)}: {e}") from None

    # API

    def applications(self) -> list[dict]:
        out = self.do("GET", "api/v2/applications") or {}
        return out.get("applications") or []

    def application(self, public_id: str) -> dict:
        out = self.do("GET", "api/v2/applications", {"publicId": public_id}) or {}
        apps = out.get("applications") or []
        if not apps:
            raise Error(f"no application with public ID {json.dumps(public_id)} (or no permission to view it)")
        return apps[0]

    def source_control(self, app_id: str) -> dict | None:
        """The application's SCM configuration, None if none."""
        try:
            return self.do("GET", "api/v2/sourceControl/application/" + path_escape(app_id)) or {}
        except APIError as e:
            if e.status == 404:
                return None
            raise

    def reports(self, app_id: str) -> list[dict]:
        """The most recent report per stage, in pipeline order."""
        out = self.do("GET", "api/v2/reports/applications/" + path_escape(app_id)) or []
        rank = {s: i for i, s in enumerate(STAGES)}
        return sorted(out, key=lambda r: rank.get(r.get("stage", ""), len(STAGES)))

    def raw_report(self, public_id: str, report_id: str) -> list[dict]:
        out = self.do("GET", f"api/v2/applications/{path_escape(public_id)}/reports/{path_escape(report_id)}/raw") or {}
        return out.get("components") or []

    def policy_report(self, public_id: str, report_id: str) -> dict:
        return self.do("GET", f"api/v2/applications/{path_escape(public_id)}/reports/{path_escape(report_id)}/policy") or {}

    def remediation(self, app_id: str, stage: str, component_identifier: dict) -> list[dict]:
        """Which versions of a component would fix its policy violations in
        the application. stage is needed for the next-non-failing strategies."""
        q = {"includeParentRemediation": "true"}
        if stage:
            q["stageId"] = stage
        out = (
            self.do(
                "POST", "api/v2/components/remediation/application/" + path_escape(app_id), q, {"componentIdentifier": component_identifier}
            )
            or {}
        )
        return (out.get("remediation") or {}).get("versionChanges") or []

    def vulnerability(self, vid: str) -> dict:
        return self.do("GET", "api/v2/vulnerabilities/" + path_escape(vid)) or {}

    def create_waiver(self, app_id: str, violation_id: str, waiver: dict) -> None:
        self.do("POST", f"api/v2/policyWaivers/application/{path_escape(app_id)}/{path_escape(violation_id)}", None, waiver)


# Waiver matcher strategies: which components a waiver covers.
WAIVE_EXACT_COMPONENT = "EXACT_COMPONENT"  # this version only
WAIVE_ALL_VERSIONS = "ALL_VERSIONS"  # every version of the component


def _version(r: Any) -> str:
    v = getattr(r, "version", 11)
    return {10: "HTTP/1.0", 11: "HTTP/1.1"}.get(v, "HTTP/1.1")


def retryable(method: str, status: int, err: BaseException | None) -> bool:
    """429 and 503 mean the server did not handle the request, so any method
    is retried. Other 5xx and network errors are retried only for idempotent
    methods: a POST may have taken effect (e.g. a waiver was created)."""
    if status in (429, 503):
        return True
    if method in ("POST", "PATCH"):
        return False
    if err is not None:
        return True
    return status in (500, 502, 504)


def backoff(attempt: int, resp: Response | None) -> float:
    """Honor Retry-After (seconds, capped at 30s), else wait 0.5s, 1s, 2s, …
    with up to 50% jitter."""
    if resp is not None:
        ra = resp.header("Retry-After").strip()
        if ra.isdigit():
            return min(float(ra), 30.0)
    d = 0.5 * (2 ** (attempt - 1))
    return d + random.uniform(0, d / 2)


def parse_error(resp: Response, method: str, url: str, attempts: int) -> APIError:
    """Keep short plain-text or JSON bodies; IQ Server mostly answers errors
    with a plain-text message."""
    data = resp.body[: 1 << 20]
    message = ""
    try:
        payload = json.loads(data)
        if isinstance(payload, dict):
            msgs = []
            if isinstance(payload.get("message"), str) and payload["message"]:
                msgs.append(payload["message"])
            for m in payload.get("errors") or []:
                if isinstance(m, dict):
                    msgs.append(str(m.get("message", "")))
            message = "; ".join(msgs)
    except ValueError:
        pass
    if not message and 0 < len(data) < 500 and b"<html" not in data:
        message = data.decode("utf-8", "replace").strip()
    return APIError(resp.status, method, url, message, attempts)


# Report helpers


def report_id(r: dict) -> str:
    """The segment after "reports" in reportDataUrl (documented as
    "api/v2/applications/<publicId>/reports/<reportId>/raw", so the last
    segment is not the ID); falls back to reportHtmlUrl
    ("ui/links/application/<publicId>/report/<reportId>")."""
    return _segment_after(r.get("reportDataUrl") or "", "reports") or _segment_after(r.get("reportHtmlUrl") or "", "report")


def _segment_after(raw_url: str, key: str) -> str:
    try:
        p = urlsplit(raw_url).path
    except ValueError:
        p = raw_url
    segs = p.strip("/").split("/")
    for i in range(len(segs) - 2, -1, -1):
        if segs[i] == key and segs[i + 1]:
            return segs[i + 1]
    return ""


def identifier_version(ci: dict | None) -> str:
    """coordinates.version of a componentIdentifier, if any."""
    if not ci:
        return ""
    v = (ci.get("coordinates") or {}).get("version")
    return v if isinstance(v, str) else ""


def is_security(v: dict) -> bool:
    return str(v.get("policyThreatCategory", "")).upper() == "SECURITY"
