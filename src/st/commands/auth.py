from __future__ import annotations

import getpass
import os
import sys

from .. import config, output
from ..cli import Command, Error, ExitError, Opts, no_args
from ..output import bold, green, red, success
from .resolve import Session, new_iq
from .root import EXIT_AUTH


def new_auth_cmd() -> Command:
    cmd = Command(
        "auth <command>",
        short="Authenticate st with an IQ Server",
        long="""Authenticate with a Sonatype IQ Server using a user token
(IQ Server → your user menu → User Token → Access user token). A token is a
code/passcode pair used as HTTP Basic credentials; a username and password
work the same way.

Alternatively set ST_HOST and ST_TOKEN ("code:passcode"); they take
precedence over stored credentials.""",
    )
    cmd.add(new_auth_login_cmd(), new_auth_status_cmd(), new_auth_logout_cmd(), new_auth_token_cmd())
    return cmd


def verify_login(c: Session) -> None:
    """A cheap authenticated request; IQ answers 401 for bad credentials and
    an empty list for an unknown public ID."""
    c.do("GET", "api/v2/applications", {"publicId": "st-auth-check"})


def prompt(label: str) -> str:
    output.io.stderr.write(label)
    output.io.stderr.flush()
    return output.io.stdin.readline().strip()


def read_password(label: str) -> str:
    """Read a secret without echoing it (when stdin is a terminal)."""
    if output.io.stdin is sys.stdin and sys.stdin.isatty():
        return getpass.getpass(label, stream=output.io.stderr)
    output.io.stderr.write(label)
    line = output.io.stdin.readline()
    output.io.stderr.write("\n")
    return line.rstrip("\n")


def new_auth_login_cmd() -> Command:
    def run(o: Opts) -> None:
        hostname = o.hostname or os.environ.get("ST_HOST", "")
        if not hostname:
            if not output.io.is_tty():
                raise Error("--hostname required when not running interactively")
            hostname = prompt("IQ Server URL (e.g. https://iq.example.com): ")
        key, base = config.normalize_host(hostname)
        if o.with_token:
            data = output.read_stdin().strip()
            if ":" not in data:
                raise Error('expected "code:passcode" on standard input')
            user, pw = data.split(":", 1)
        elif output.io.is_tty():
            output.err(f"Create a user token at {base} (user menu → User Token → Generate)")
            user = prompt("Token code (or username): ")
            pw = read_password("Token passcode (or password): ")
        else:
            raise Error("--with-token required when not running interactively")
        user, pw = user.strip(), pw.strip()
        if not user or not pw:
            raise Error("no token provided")
        try:
            verify_login(new_iq(base, user, pw))
        except Error as e:
            raise Error(f"validating token against {base}: {e}") from e
        cfg = config.Config.load()
        old = cfg.hosts.get(key)
        if old is not None and old.user:
            try:
                config.keyring_delete(key, old.user)
            except Exception:
                pass
        h = config.Host(base_url=base, user=user)
        storage = "keyring"
        insecure = o.insecure_storage
        if not insecure:
            try:
                config.keyring_set(key, user, pw)
            except Exception as e:
                output.err(f"warning: could not store token in the OS keyring ({e}); storing it in plain text in {config.path()}")
                insecure = True
        if insecure:
            h.token, storage = pw, str(config.path())
        cfg.hosts[key] = h
        cfg.save()
        success(f"Logged in to {key} as {bold(user)} (token stored in {storage})")

    cmd = Command(
        "login",
        short="Log in to an IQ Server",
        long="""Log in to a Sonatype IQ Server with a user token.

The passcode is stored in the OS credential store (macOS Keychain, Windows
Credential Manager, Linux Secret Service). If none is available, or with
--insecure-storage, it is stored in plain text in the config file.

With --with-token, standard input is read as "code:passcode".""",
        example="""  $ st auth login --hostname iq.example.com
  $ echo "$CODE:$PASSCODE" | st auth login --hostname https://iq.example.com:8070 --with-token""",
        args=no_args,
        run=run,
    )
    cmd.flag("hostname", "h", help="IQ Server host or base URL (include port and context path if any)")
    cmd.flag("with-token", kind="bool", help='Read "code:passcode" from standard input')
    cmd.flag("insecure-storage", kind="bool", help="Save the token in plain text instead of the OS credential store")
    return cmd


def new_auth_status_cmd() -> Command:
    def run(o: Opts) -> None:
        cfg = config.Config.load()
        names = cfg.host_names()
        if o.hostname:
            names = [o.hostname]
        elif h := os.environ.get("ST_HOST", ""):
            try:
                k, _ = config.normalize_host(h)
            except Error:
                k = ""
            if k not in names:
                names.append(h)
        if not names:
            raise ExitError(EXIT_AUTH, config.err_no_host())
        failed = False
        for n in names:
            try:
                key = config.normalize_host(n)[0]
            except Error:
                key = ""
            try:
                key, h = cfg.resolve(n)
            except Error as e:
                output.out(bold(key))
                output.out(f"  {red('X')} {e}")
                failed = True
                continue
            output.out(bold(key))
            try:
                verify_login(new_iq(h.base_url, h.user, h.token))
            except Error as e:
                output.out(f"  {red('X')} Failed to log in to {key} using token ({h.token_source}): {e}")
                failed = True
                continue
            output.out(f"  {green('✓')} Logged in to {key} as {bold(h.user)} ({h.token_source})")
            output.out(f"  - API base URL: {h.base_url}")
            tok = h.token
            if not o.show_token:
                tok = (tok[:4] if len(tok) > 8 else "") + "*" * 12
            output.out(f"  - Token: {tok}")
        if failed:
            raise ExitError(EXIT_AUTH)

    cmd = Command("status", short="Display authentication state", args=no_args, run=run)
    cmd.flag("hostname", "h", help="Check only a specific host")
    cmd.flag("show-token", "t", kind="bool", help="Display the auth token")
    return cmd


def new_auth_logout_cmd() -> Command:
    def run(o: Opts) -> None:
        cfg = config.Config.load()
        hostname = o.hostname
        if not hostname:
            if len(cfg.hosts) != 1:
                raise Error(f"--hostname required (logged in to {len(cfg.hosts)} hosts)")
            hostname = cfg.host_names()[0]
        key, _ = config.normalize_host(hostname)
        h = cfg.hosts.get(key)
        if h is None:
            raise Error(f"not logged in to {key}")
        try:
            config.keyring_delete(key, h.user)
        except Exception as e:
            raise Error(f"removing token from the OS keyring: {e}") from e
        del cfg.hosts[key]
        cfg.save()
        success(f"Logged out of {key} account {h.user}")

    cmd = Command("logout", short="Log out of an IQ Server", args=no_args, run=run)
    cmd.flag("hostname", "h", help="The host to log out of")
    return cmd


def new_auth_token_cmd() -> Command:
    def run(o: Opts) -> None:
        _, h = config.Config.load().resolve(o.hostname)
        output.out(h.user + ":" + h.token)

    cmd = Command("token", short='Print the credentials st uses, as "code:passcode"', args=no_args, run=run)
    cmd.flag("hostname", "h", help="The host to print the token for")
    return cmd
