"""Lifecycle-owned macOS Keychain adapter.

The installer bundle must be able to start before Companion is installed, so
its bootstrap credential adapter cannot import from the gateway package.
"""

from __future__ import annotations

import re
import subprocess
import sys
from typing import Callable, Protocol


SERVICE = "com.claudian.remote"
REFERENCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class KeychainError(RuntimeError):
    pass


class Keychain(Protocol):
    def get(self, reference: str) -> str: ...

    def set(self, reference: str, value: str) -> None: ...

    def delete(self, reference: str) -> None: ...


class MacOSKeychain:
    def __init__(
        self,
        *,
        runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
        service: str = SERVICE,
    ) -> None:
        self.runner = runner
        self.service = service

    @staticmethod
    def _validate(reference: str) -> str:
        if not REFERENCE_RE.fullmatch(str(reference or "")):
            raise KeychainError("invalid_secret_reference")
        return str(reference)

    def _run(self, arguments: list[str], *, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
        if sys.platform != "darwin":
            raise KeychainError("macos_keychain_unavailable")
        try:
            return self.runner(
                ["/usr/bin/security", *arguments],
                input=input_text,
                text=True,
                capture_output=True,
                check=False,
            )
        except OSError as exc:
            raise KeychainError("macos_keychain_unavailable") from exc

    def get(self, reference: str) -> str:
        account = self._validate(reference)
        result = self._run(["find-generic-password", "-s", self.service, "-a", account, "-w"])
        value = result.stdout.rstrip("\n") if result.returncode == 0 else ""
        if not value:
            raise KeychainError("missing_secret_reference")
        return value

    def set(self, reference: str, value: str) -> None:
        account = self._validate(reference)
        if not value:
            raise KeychainError("empty_credential")
        result = self._run(
            ["add-generic-password", "-U", "-s", self.service, "-a", account, "-w"],
            input_text=value + "\n",
        )
        if result.returncode != 0:
            raise KeychainError("unable_to_store_credential")

    def delete(self, reference: str) -> None:
        account = self._validate(reference)
        result = self._run(["delete-generic-password", "-s", self.service, "-a", account])
        if result.returncode not in (0, 44):
            raise KeychainError("unable_to_delete_credential")
