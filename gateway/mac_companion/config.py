"""Device-local Companion credential loading.

The public JSON configuration contains only opaque Keychain references. Secret
values are resolved in memory and fail closed when the login Keychain cannot be
used. The subprocess backend is injectable so tests never touch a real
Keychain.
"""

from __future__ import annotations

import re
import subprocess
import sys
from typing import Dict, Mapping, Optional, Protocol


SERVICE = "com.claudian.remote"
REFERENCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
SECRET_FIELDS = ("relay_token", "adapter_token", "payload_secret")


class KeychainError(RuntimeError):
    pass


class Keychain(Protocol):
    def get(self, reference: str) -> str:
        ...


class InMemoryKeychain:
    def __init__(self, values: Optional[Mapping[str, str]] = None) -> None:
        self.values = dict(values or {})

    def get(self, reference: str) -> str:
        value = self.values.get(reference, "")
        if not value:
            raise KeychainError("missing secret reference")
        return value

    def set(self, reference: str, value: str) -> None:
        if not value:
            raise KeychainError("empty credential")
        self.values[reference] = value

    def delete(self, reference: str) -> None:
        self.values.pop(reference, None)


class MacOSKeychain:
    def __init__(self, *, runner=subprocess.run, service: str = SERVICE) -> None:
        self.runner = runner
        self.service = service

    def _validate(self, reference: str) -> str:
        if not REFERENCE_RE.fullmatch(str(reference or "")):
            raise KeychainError("invalid secret reference")
        return str(reference)

    def _run(self, arguments, *, input_text: Optional[str] = None) -> subprocess.CompletedProcess:
        if sys.platform != "darwin":
            raise KeychainError("macOS Keychain unavailable")
        try:
            return self.runner(
                ["/usr/bin/security", *arguments],
                input=input_text,
                text=True,
                capture_output=True,
                check=False,
            )
        except OSError as exc:
            raise KeychainError("macOS Keychain unavailable") from exc

    def get(self, reference: str) -> str:
        account = self._validate(reference)
        result = self._run(["find-generic-password", "-s", self.service, "-a", account, "-w"])
        value = result.stdout.rstrip("\n") if result.returncode == 0 else ""
        if not value:
            raise KeychainError("missing secret reference")
        return value

    def set(self, reference: str, value: str) -> None:
        account = self._validate(reference)
        if not value:
            raise KeychainError("empty credential")
        # A trailing -w prompts security to read the password from stdin, so the
        # credential never appears in argv or a process listing.
        result = self._run(
            ["add-generic-password", "-U", "-s", self.service, "-a", account, "-w"],
            input_text=value + "\n",
        )
        if result.returncode != 0:
            raise KeychainError("unable to store credential")

    def delete(self, reference: str) -> None:
        account = self._validate(reference)
        result = self._run(["delete-generic-password", "-s", self.service, "-a", account])
        if result.returncode not in (0, 44):
            raise KeychainError("unable to delete credential")


def load_secret_fields(data: Mapping[str, object], keychain: Keychain) -> Dict[str, str]:
    for field in SECRET_FIELDS:
        if data.get(field):
            raise KeychainError("plaintext credential is forbidden in public config")
    resolved: Dict[str, str] = {}
    for field in ("relay_token", "adapter_token"):
        reference = str(data.get(field + "_ref") or "")
        if not reference:
            raise KeychainError("missing secret reference")
        resolved[field] = keychain.get(reference)
    payload_reference = str(data.get("payload_secret_ref") or "")
    resolved["payload_secret"] = keychain.get(payload_reference) if payload_reference else ""
    return resolved
