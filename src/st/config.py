"""Per-host credentials, modelled after gh's hosts.yml (same config.json as the Go version)."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from . import credstore
from .cli import Error


class NoHostError(Error):
    pass


def err_no_host() -> NoHostError:
    return NoHostError("no IQ Server host configured: run `st auth login --hostname <host>` or set ST_HOST and ST_TOKEN")


@dataclass
class Host:
    """An IQ Server login. IQ uses HTTP Basic auth: user is the user token
    code (or username), token the passcode (or password)."""

    base_url: str = ""
    user: str = ""
    token: str = ""
    # Where resolve found the token: "ST_TOKEN", "keyring" or the config path.
    token_source: str = ""

    def to_json(self) -> dict:
        d = {"base_url": self.base_url}
        if self.user:
            d["user"] = self.user
        if self.token:
            d["token"] = self.token
        return d


def config_dir() -> Path:
    if d := os.environ.get("ST_CONFIG_DIR"):
        return Path(d)
    if d := os.environ.get("XDG_CONFIG_HOME"):
        return Path(d) / "st"
    return Path.home() / ".config" / "st"


def path() -> Path:
    return config_dir() / "config.json"


def service(host: str) -> str:
    return "st:" + host


def keyring_get(host: str, user: str) -> str:
    return credstore.get(service(host), user)


def keyring_set(host: str, user: str, token: str) -> None:
    credstore.set(service(host), user, token)


def keyring_delete(host: str, user: str) -> None:
    credstore.delete(service(host), user)


def normalize_host(raw: str) -> tuple[str, str]:
    """Turn "iq.corp", "https://iq.corp:8070/ctx/" etc. into a host key
    ("iq.corp") and base URL ("https://iq.corp:8070/ctx")."""
    raw = raw.strip()
    if not raw:
        raise Error("empty hostname")
    if "://" not in raw:
        raw = "https://" + raw
    try:
        u = urlsplit(raw)
    except ValueError:
        raise Error(f"invalid hostname {json.dumps(raw)}") from None
    host = hostname(u.netloc)
    if not host:
        raise Error(f"invalid hostname {json.dumps(raw)}")
    return host, (u.scheme + "://" + u.netloc + u.path).rstrip("/")


def hostname(netloc: str) -> str:
    """The host of a URL's netloc without userinfo and port, case kept (Go's URL.Hostname)."""
    host = netloc.rpartition("@")[2]
    if host.startswith("["):
        return host[1 : host.find("]")] if "]" in host else ""
    return host.partition(":")[0]


class Config:
    def __init__(self, hosts: dict[str, Host], file: Path):
        self.hosts = hosts
        self.path = file

    @classmethod
    def load(cls) -> Config:
        p = path()
        try:
            data = p.read_text(encoding="utf-8")
        except FileNotFoundError:
            return cls({}, p)
        try:
            raw = json.loads(data)
        except ValueError as e:
            raise Error(f"parsing {p}: {e}") from None
        hosts = {}
        for k, v in (raw.get("hosts") or {}).items():
            hosts[k] = Host(base_url=v.get("base_url", ""), user=v.get("user", ""), token=v.get("token", ""))
        return cls(hosts, p)

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        data = json.dumps({"hosts": {k: self.hosts[k].to_json() for k in sorted(self.hosts)}}, indent=2) + "\n"
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(data)

    def host_names(self) -> list[str]:
        return sorted(self.hosts)

    def resolve(self, name: str) -> tuple[str, Host]:
        """Pick the host to use. Precedence: explicit name, ST_HOST, the only
        configured host. ST_TOKEN ("code:passcode", or a passcode with
        ST_USER) overrides the stored credentials."""
        key, h = self.resolve_host(name)
        t = os.environ.get("ST_TOKEN", "")
        if t:
            if ":" in t:
                h.user, h.token = t.split(":", 1)
            else:
                if u := os.environ.get("ST_USER", ""):
                    h.user = u
                h.token = t
            h.token_source = "ST_TOKEN"
            if not h.user:
                raise Error('ST_TOKEN must be "code:passcode" (or set ST_USER to the token code)')
        elif h.token:
            h.token_source = str(self.path)
        elif h.user:
            try:
                tok = keyring_get(key, h.user)
            except credstore.NotFound:
                tok = ""
            except Exception as e:
                raise Error(f"reading token for {key} from the OS keyring: {e}") from e
            h.token, h.token_source = tok, "keyring"
        if not h.token:
            raise Error(f"not logged in to {key}: run `st auth login --hostname {key}` or set ST_TOKEN")
        return key, h

    def resolve_host(self, name: str) -> tuple[str, Host]:
        if not name:
            name = os.environ.get("ST_HOST", "")
        if name:
            key, base = normalize_host(name)
            stored = self.hosts.get(key)
            h = Host(stored.base_url, stored.user, stored.token) if stored else Host(base_url=base)
            return key, h
        if not self.hosts:
            raise err_no_host()
        if len(self.hosts) > 1:
            raise Error(f"multiple hosts configured ({', '.join(self.host_names())}); set ST_HOST or pass --hostname")
        key = next(iter(self.hosts))
        stored = self.hosts[key]
        return key, Host(stored.base_url, stored.user, stored.token)
