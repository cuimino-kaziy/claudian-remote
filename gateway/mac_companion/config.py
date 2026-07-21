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
import json
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Mapping, Optional, Protocol


SERVICE = "com.claudian.remote"
REFERENCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
SECRET_FIELDS = (
    "relay_token",
    "bridge_credential",
    "pairing_admin_credential",
    "adapter_token",
    "payload_secret",
)


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
    for field in ("relay_token", "bridge_credential"):
        reference = str(data.get(field + "_ref") or "")
        if not reference:
            raise KeychainError("missing secret reference")
        resolved[field] = keychain.get(reference)
    payload_reference = str(data.get("payload_secret_ref") or "")
    resolved["payload_secret"] = keychain.get(payload_reference) if payload_reference else ""
    pairing_admin_reference = str(data.get("pairing_admin_credential_ref") or "")
    if pairing_admin_reference:
        resolved["pairing_admin_credential"] = keychain.get(pairing_admin_reference)
    return resolved


@dataclass
class CompanionRuntimeConfig:
    relay_base_url: str
    relay_token: str
    pairing_id: str
    bridge_credential: str
    connection_mode: str = ""
    installation_id: str = ""
    vault_id: str = ""
    endpoint_audience: str = ""
    bridge_credential_id: str = "installation-bridge"
    bridge_bootstrap_ack_path: str = ""
    bootstrap_generation: str = ""
    bridge_host: str = "127.0.0.1"
    bridge_port: int = 27124
    relay_ws_url: str = ""
    payload_secret: str = ""
    pairing_admin_credential: str = ""
    request_timeout_seconds: float = 30.0
    v2_state_path: str = ""
    bridge_command_path: str = "command.execute"
    bridge_bind_path: str = "transport.bind"
    bridge_invalidate_path: str = "transport.invalidate"
    bridge_keyframe_path: str = "keyframe.request"
    bridge_import_path: str = "upload.import"
    upload_temp_dir: str = ""
    upload_stream_bytes: int = 64 * 1024
    outbound_max_events: int = 256
    outbound_max_bytes: int = 2 * 1024 * 1024
    relay_heartbeat_seconds: float = 20.0
    reconnect_min_seconds: float = 0.25
    reconnect_max_seconds: float = 10.0

    @classmethod
    def from_file(cls, path: Path, keychain: Optional[Keychain] = None) -> "CompanionRuntimeConfig":
        data = json.loads(path.read_text(encoding="utf-8"))
        profile = None
        profile_path = str(data.get("connection_profile_path") or "")
        if profile_path:
            from installer.claudian_remote_lifecycle.connection_profile import ConnectionProfile

            selected = Path(profile_path)
            if not selected.is_absolute():
                selected = path.parent / selected
            profile = ConnectionProfile.from_dict(json.loads(selected.read_text(encoding="utf-8")))
            if str(data.get("relay_token_ref") or "") != profile.companion_credential_ref:
                raise KeychainError("profile_credential_binding_mismatch")
        values = load_secret_fields(data, keychain or MacOSKeychain())
        return cls(
            relay_base_url=(profile.endpoint if profile else str(data.get("relay_base_url") or "").rstrip("/")),
            relay_token=values["relay_token"],
            pairing_id=str(data.get("pairing_id") or ""),
            bridge_credential=values["bridge_credential"],
            connection_mode=profile.mode if profile else "",
            installation_id=profile.installation_id if profile else "",
            vault_id=profile.vault_id if profile else "",
            endpoint_audience=profile.endpoint_audience if profile else "",
            bridge_credential_id=str(data.get("bridge_credential_id") or "installation-bridge"),
            bridge_bootstrap_ack_path=str(data.get("bridge_bootstrap_ack_path") or ""),
            bootstrap_generation=str(data.get("bootstrap_generation") or ""),
            bridge_host=str(data.get("bridge_host") or "127.0.0.1"),
            bridge_port=int(data.get("bridge_port") or 27124),
            relay_ws_url=str(data.get("relay_ws_url") or ""),
            payload_secret=values["payload_secret"],
            pairing_admin_credential=values.get("pairing_admin_credential", ""),
            request_timeout_seconds=float(data.get("request_timeout_seconds") or 30),
            v2_state_path=str(data.get("v2_state_path") or path.with_name("companion_state_v2.json")),
            upload_temp_dir=str(data.get("upload_temp_dir") or path.with_name("upload_temp")),
            upload_stream_bytes=min(64 * 1024, max(4096, int(data.get("upload_stream_bytes") or 64 * 1024))),
            outbound_max_events=max(16, int(data.get("outbound_max_events") or 256)),
            outbound_max_bytes=max(64 * 1024, int(data.get("outbound_max_bytes") or 2 * 1024 * 1024)),
            relay_heartbeat_seconds=float(data.get("relay_heartbeat_seconds") or 20),
            reconnect_min_seconds=max(0.05, float(data.get("reconnect_min_seconds") or 0.25)),
            reconnect_max_seconds=max(0.25, float(data.get("reconnect_max_seconds") or 10)),
        )

    def validate(self) -> None:
        if not self.relay_base_url or not self.relay_token or not self.pairing_id or not self.bridge_credential:
            raise KeychainError("missing companion runtime configuration")
        if self.bridge_host != "127.0.0.1" or self.bridge_port != 27124:
            raise KeychainError("invalid loopback Bridge configuration")
        if self.connection_mode and (
            not self.bridge_bootstrap_ack_path
            or not Path(self.bridge_bootstrap_ack_path).is_absolute()
            or not re.fullmatch(r"bootstrap-[A-Za-z0-9_-]{16,128}", self.bootstrap_generation)
        ):
            raise KeychainError("invalid_bridge_bootstrap_ack_configuration")
        if self.connection_mode and self.connection_mode not in {"local_tailscale", "local_lan", "remote_vps"}:
            raise KeychainError("unsupported_connection_mode")
        if self.connection_mode and (
            not self.installation_id
            or not self.vault_id
            or self.endpoint_audience != f"claudian-remote:{self.connection_mode}:{self.installation_id}"
        ):
            raise KeychainError("connection_profile_binding_mismatch")

    def resolved_relay_ws_url(self) -> str:
        if self.relay_ws_url:
            return self.relay_ws_url
        parsed = urllib.parse.urlsplit(self.relay_base_url)
        scheme = "wss" if parsed.scheme == "https" else "ws"
        return urllib.parse.urlunsplit((scheme, parsed.netloc, "/api/v2/ws/mac", "", ""))
