"""OS credential store (macOS Keychain, Windows Credential Manager, Linux
Secret Service), storing entries exactly as go-keyring did so logins made
with the Go binaries keep working:

- Windows: generic credential "<service>:<user>", UTF-8 blob, local-machine persistence.
- macOS: generic password (-s service -a user), value "go-keyring-base64:<base64>".
- Linux: Secret Service item with attributes {service, username}, via secret-tool.
"""

from __future__ import annotations

import base64
import binascii
import os
import re
import shutil
import subprocess
import sys
import threading
from collections.abc import Callable
from typing import Any

TIMEOUT = 3.0  # a locked keyring may wait forever for an unlock prompt


class NotFound(Exception):
    pass


class Unavailable(Exception):
    pass


class KeyringTimeout(Exception):
    def __str__(self) -> str:
        return "timed out waiting for the OS keyring"


def _with_timeout(f: Callable[[], Any]) -> Any:
    result: dict[str, Any] = {}

    def run() -> None:
        try:
            result["v"] = f()
        except BaseException as e:  # noqa: BLE001 - re-raised in the caller
            result["e"] = e

    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(TIMEOUT)
    if t.is_alive():
        raise KeyringTimeout()
    if "e" in result:
        raise result["e"]
    return result.get("v")


class _Windows:
    CRED_TYPE_GENERIC = 1
    CRED_PERSIST_LOCAL_MACHINE = 2
    ERROR_NOT_FOUND = 1168

    def __init__(self) -> None:
        import ctypes
        from ctypes import wintypes

        class FILETIME(ctypes.Structure):
            _fields_ = [("dwLowDateTime", wintypes.DWORD), ("dwHighDateTime", wintypes.DWORD)]

        class CREDENTIAL(ctypes.Structure):
            _fields_ = [
                ("Flags", wintypes.DWORD),
                ("Type", wintypes.DWORD),
                ("TargetName", wintypes.LPWSTR),
                ("Comment", wintypes.LPWSTR),
                ("LastWritten", FILETIME),
                ("CredentialBlobSize", wintypes.DWORD),
                ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)),
                ("Persist", wintypes.DWORD),
                ("AttributeCount", wintypes.DWORD),
                ("Attributes", ctypes.c_void_p),
                ("TargetAlias", wintypes.LPWSTR),
                ("UserName", wintypes.LPWSTR),
            ]

        self.ctypes, self.CREDENTIAL = ctypes, CREDENTIAL
        adv = ctypes.WinDLL("advapi32", use_last_error=True)  # type: ignore[attr-defined]
        PCRED = ctypes.POINTER(CREDENTIAL)
        self.CredReadW = adv.CredReadW
        self.CredReadW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(PCRED)]
        self.CredReadW.restype = wintypes.BOOL
        self.CredWriteW = adv.CredWriteW
        self.CredWriteW.argtypes = [PCRED, wintypes.DWORD]
        self.CredWriteW.restype = wintypes.BOOL
        self.CredDeleteW = adv.CredDeleteW
        self.CredDeleteW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD]
        self.CredDeleteW.restype = wintypes.BOOL
        self.CredFree = adv.CredFree
        self.CredFree.argtypes = [ctypes.c_void_p]
        self.PCRED = PCRED

    def _error(self) -> Exception:
        code = self.ctypes.get_last_error()  # type: ignore[attr-defined]
        if code == self.ERROR_NOT_FOUND:
            return NotFound()
        return OSError(code, self.ctypes.FormatError(code))  # type: ignore[attr-defined]

    def get(self, service: str, user: str) -> str:
        p = self.PCRED()
        if not self.CredReadW(f"{service}:{user}", self.CRED_TYPE_GENERIC, 0, self.ctypes.byref(p)):
            raise self._error()
        try:
            c = p.contents
            return self.ctypes.string_at(c.CredentialBlob, c.CredentialBlobSize).decode("utf-8")
        finally:
            self.CredFree(p)

    def set(self, service: str, user: str, password: str) -> None:
        blob = password.encode("utf-8")
        if len(blob) > 2560:
            raise ValueError("data passed to Set was too big")
        buf = (self.ctypes.c_ubyte * len(blob)).from_buffer_copy(blob)
        c = self.CREDENTIAL()
        c.Type = self.CRED_TYPE_GENERIC
        c.TargetName = f"{service}:{user}"
        c.UserName = user
        c.CredentialBlobSize = len(blob)
        c.CredentialBlob = self.ctypes.cast(buf, self.ctypes.POINTER(self.ctypes.c_ubyte))
        c.Persist = self.CRED_PERSIST_LOCAL_MACHINE
        if not self.CredWriteW(self.ctypes.byref(c), 0):
            raise self._error()

    def delete(self, service: str, user: str) -> None:
        if not self.CredDeleteW(f"{service}:{user}", self.CRED_TYPE_GENERIC, 0):
            raise self._error()


_SAFE = re.compile(r"[^\w@%+=:,./-]", re.ASCII)


def _shellquote(s: str) -> str:
    if not s:
        return "''"
    if _SAFE.search(s):
        return "'" + s.replace("'", "'\"'\"'") + "'"
    return s


class _MacOS:
    SECURITY = "/usr/bin/security"
    B64 = "go-keyring-base64:"
    HEX = "go-keyring-encoded:"

    def get(self, service: str, user: str) -> str:
        p = subprocess.run(
            [self.SECURITY, "find-generic-password", "-s", service, "-wa", user], capture_output=True, text=True, encoding="utf-8"
        )
        if p.returncode != 0:
            if "could not be found" in p.stdout + p.stderr:
                raise NotFound()
            raise OSError((p.stderr or p.stdout).strip() or f"security exited with status {p.returncode}")
        v = p.stdout.strip()
        if v.startswith(self.HEX):
            return binascii.unhexlify(v[len(self.HEX) :]).decode("utf-8")
        if v.startswith(self.B64):
            return base64.b64decode(v[len(self.B64) :]).decode("utf-8")
        return v

    def set(self, service: str, user: str, password: str) -> None:
        value = self.B64 + base64.b64encode(password.encode("utf-8")).decode("ascii")
        command = f"add-generic-password -U -s {_shellquote(service)} -a {_shellquote(user)} -w {_shellquote(value)}\n"
        if len(command) > 4096:
            raise ValueError("data passed to Set was too big")
        # -i reads the command from stdin, so the secret never shows up in the process list.
        p = subprocess.run([self.SECURITY, "-i"], input=command, capture_output=True, text=True, encoding="utf-8")
        if p.returncode != 0:
            raise OSError((p.stderr or p.stdout).strip() or f"security exited with status {p.returncode}")

    def delete(self, service: str, user: str) -> None:
        p = subprocess.run(
            [self.SECURITY, "delete-generic-password", "-s", service, "-a", user], capture_output=True, text=True, encoding="utf-8"
        )
        if "could not be found" in p.stdout + p.stderr:
            raise NotFound()
        if p.returncode != 0:
            raise OSError((p.stderr or p.stdout).strip() or f"security exited with status {p.returncode}")


class _SecretService:
    def _tool(self) -> str:
        tool = shutil.which("secret-tool")
        if tool is None:
            raise Unavailable("secret-tool not found (install libsecret-tools for the Secret Service)")
        return tool

    def get(self, service: str, user: str) -> str:
        p = subprocess.run([self._tool(), "lookup", "username", user, "service", service], capture_output=True)
        if p.returncode != 0 or not p.stdout:
            if p.stderr.strip():
                raise OSError(p.stderr.decode("utf-8", "replace").strip())
            raise NotFound()
        return p.stdout.decode("utf-8")

    def set(self, service: str, user: str, password: str) -> None:
        p = subprocess.run(
            [self._tool(), "store", f"--label=Password for '{user}' on '{service}'", "username", user, "service", service],
            input=password.encode("utf-8"),
            capture_output=True,
        )
        if p.returncode != 0:
            raise OSError(p.stderr.decode("utf-8", "replace").strip() or f"secret-tool exited with status {p.returncode}")

    def delete(self, service: str, user: str) -> None:
        self.get(service, user)  # NotFound if missing; secret-tool clear doesn't say
        p = subprocess.run([self._tool(), "clear", "username", user, "service", service], capture_output=True)
        if p.returncode != 0:
            raise OSError(p.stderr.decode("utf-8", "replace").strip() or f"secret-tool exited with status {p.returncode}")


class Mock:
    """In-memory store for tests; err makes every call fail."""

    def __init__(self, err: Exception | None = None):
        self.items: dict[tuple[str, str], str] = {}
        self.err = err

    def get(self, service: str, user: str) -> str:
        if self.err:
            raise self.err
        try:
            return self.items[(service, user)]
        except KeyError:
            raise NotFound() from None

    def set(self, service: str, user: str, password: str) -> None:
        if self.err:
            raise self.err
        self.items[(service, user)] = password

    def delete(self, service: str, user: str) -> None:
        if self.err:
            raise self.err
        if self.items.pop((service, user), None) is None:
            raise NotFound()


backend: Any = None


def _backend() -> Any:
    global backend
    if backend is None:
        if os.name == "nt":
            backend = _Windows()
        elif sys.platform == "darwin":
            backend = _MacOS()
        else:
            backend = _SecretService()
    return backend


def get(service: str, user: str) -> str:
    b = _backend()
    return _with_timeout(lambda: b.get(service, user))


def set(service: str, user: str, password: str) -> None:  # noqa: A001 - mirrors keyring.Set
    b = _backend()
    _with_timeout(lambda: b.set(service, user, password))


def delete(service: str, user: str) -> None:
    """Remove an entry; a missing one is not an error."""
    b = _backend()
    try:
        _with_timeout(lambda: b.delete(service, user))
    except NotFound:
        pass
