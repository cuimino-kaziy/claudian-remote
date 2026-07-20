"""Authoritative, device-local connection profile contract.

The lifecycle manager owns the only ``LifecycleAuthority`` accepted by a
``ConnectionProfileStore``. Runtime components receive the resulting immutable
profile and never select a fallback endpoint themselves.
"""

from __future__ import annotations

import json
import os
import secrets
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit


CONNECTION_MODES = frozenset({"local_tailscale", "local_lan", "remote_vps"})


class ProfileError(ValueError):
    pass


class LifecycleAuthority:
    def __init__(self, marker: str) -> None:
        self._marker = marker

    @classmethod
    def create(cls) -> "LifecycleAuthority":
        return cls(secrets.token_urlsafe(32))


@dataclass(frozen=True)
class ConnectionProfile:
    schema_version: int
    mode: str
    installation_id: str
    vault_id: str
    endpoint: str
    endpoint_audience: str
    companion_credential_ref: str
    mobile_credential_ref: str
    cursor: int
    epoch: str

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ConnectionProfile":
        profile = cls(
            schema_version=int(value.get("schema_version", 0)),
            mode=str(value.get("mode") or ""),
            installation_id=str(value.get("installation_id") or ""),
            vault_id=str(value.get("vault_id") or ""),
            endpoint=str(value.get("endpoint") or "").rstrip("/"),
            endpoint_audience=str(value.get("endpoint_audience") or ""),
            companion_credential_ref=str(value.get("companion_credential_ref") or ""),
            mobile_credential_ref=str(value.get("mobile_credential_ref") or ""),
            cursor=int(value.get("cursor", 0)),
            epoch=str(value.get("epoch") or ""),
        )
        profile.validate()
        return profile

    def validate(self) -> None:
        if self.schema_version != 1:
            raise ProfileError("unsupported_connection_profile_schema")
        if self.mode not in CONNECTION_MODES:
            raise ProfileError("unsupported_connection_mode")
        if not self.installation_id or not self.vault_id or not self.epoch or self.cursor < 0:
            raise ProfileError("incomplete_connection_profile")
        parsed = urlsplit(self.endpoint)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise ProfileError("local_relay_endpoint_must_be_https" if self.mode != "remote_vps" else "remote_relay_endpoint_must_be_https")
        expected_audience = f"claudian-remote:{self.mode}:{self.installation_id}"
        if self.endpoint_audience != expected_audience:
            raise ProfileError("profile_audience_mismatch")
        expected_companion_ref = f"{self.installation_id}:{self.mode}:companion"
        expected_mobile_ref = f"{self.installation_id}:{self.mode}:mobile"
        if (
            self.companion_credential_ref != expected_companion_ref
            or self.mobile_credential_ref != expected_mobile_ref
        ):
            raise ProfileError("profile_credential_binding_mismatch")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ConnectionProfileStore:
    def __init__(self, path: Path, authority: LifecycleAuthority) -> None:
        self.path = Path(path)
        self._authority_marker = authority._marker

    def read(self) -> ConnectionProfile:
        return ConnectionProfile.from_dict(json.loads(self.path.read_text(encoding="utf-8")))

    def write(self, profile: ConnectionProfile, *, authority: LifecycleAuthority) -> None:
        if not secrets.compare_digest(self._authority_marker, getattr(authority, "_marker", "")):
            raise PermissionError("lifecycle_authority_required")
        profile.validate()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(self.path.parent, 0o700)
        descriptor, temporary = tempfile.mkstemp(prefix=self.path.name + ".", dir=self.path.parent)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(profile.to_dict(), handle, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, self.path)
            directory = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            Path(temporary).unlink(missing_ok=True)
