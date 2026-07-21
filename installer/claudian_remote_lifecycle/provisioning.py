"""OS-backed local credential provisioning with one-use input support."""

from __future__ import annotations

import json
import os
import secrets
import stat
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Mapping

from .connection_profile import ConnectionProfile, ConnectionProfileStore, LifecycleAuthority
from .keychain import Keychain
from .private_io import write_private_json
from .runtime import RuntimeLayout


def verify_secure_provisioning(
    layout: RuntimeLayout,
    keychain: Keychain,
    *,
    expected_provisioning_ref: str | None = None,
) -> bool:
    """Verify reference-only public state and every required Keychain item."""

    try:
        state = json.loads(layout.secure_provisioning.read_text(encoding="utf-8"))
        companion = json.loads(layout.companion_config.read_text(encoding="utf-8"))
        relay = json.loads(layout.relay_config.read_text(encoding="utf-8"))
        if not all(isinstance(value, Mapping) for value in (state, companion, relay)):
            return False
        provisioning_ref = str(state.get("provisioning_ref") or "")
        if not provisioning_ref or (
            expected_provisioning_ref is not None
            and provisioning_ref != expected_provisioning_ref
        ):
            return False
        references = {
            field: str(companion.get(field) or "")
            for field in (
                "pairing_admin_credential_ref",
                "bridge_credential_ref",
                "relay_token_ref",
            )
        }
        if (
            state.get("pairing_admin_credential_ref") != references["pairing_admin_credential_ref"]
            or state.get("bridge_credential_ref") != references["bridge_credential_ref"]
        ):
            return False
        if any(not reference or not keychain.get(reference) for reference in references.values()):
            return False
        tokens = relay.get("tokens")
        if not isinstance(tokens, list) or not tokens:
            return False
        if any(
            not isinstance(item, Mapping)
            or item.get("token")
            or not item.get("token_ref")
            for item in tokens
        ):
            return False
        return True
    except Exception:
        return False


def verify_bridge_bootstrap_ack(layout: RuntimeLayout) -> bool:
    """Prove that the selected desktop plugin authenticated to Companion."""

    try:
        state = json.loads(layout.secure_provisioning.read_text(encoding="utf-8"))
        ack = json.loads(layout.bridge_bootstrap_ack.read_text(encoding="utf-8"))
        if not isinstance(state, Mapping) or not isinstance(ack, Mapping):
            return False
        return (
            ack.get("ack_schema") == "claudian-remote.bridge-bootstrap-ack/v1"
            and ack.get("bootstrap_generation") == state.get("bootstrap_generation")
            and ack.get("installation_id") == state.get("installation_id")
            and ack.get("vault_id") == state.get("vault_id")
            and ack.get("bridge_credential_id") == state.get("bridge_credential_id")
        )
    except Exception:
        return False


class SecureInputFile:
    """A lifecycle-owned 0600 secret envelope consumed exactly once."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    @classmethod
    def create(cls, path: Path, value: Mapping[str, Any]) -> "SecureInputFile":
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(dict(value), handle, ensure_ascii=False, separators=(",", ":"))
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, path)
        finally:
            Path(temporary).unlink(missing_ok=True)
        return cls(path)

    def consume(self, consumer: Callable[[Mapping[str, Any]], Any] | None = None) -> Any:
        descriptor: int | None = None
        try:
            flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(self.path, flags)
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077:
                raise PermissionError("secure_input_permissions_invalid")
            with os.fdopen(os.dup(descriptor), "r", encoding="utf-8") as handle:
                value = json.load(handle)
            if not isinstance(value, Mapping):
                raise ValueError("secure_input_invalid")
            return consumer(value) if consumer else dict(value)
        finally:
            try:
                if descriptor is not None:
                    size = os.fstat(descriptor).st_size
                    os.lseek(descriptor, 0, os.SEEK_SET)
                    chunk = b"\0" * min(64 * 1024, max(1, size))
                    remaining = size
                    while remaining:
                        written = os.write(descriptor, chunk[:remaining])
                        remaining -= written
                    os.fsync(descriptor)
            finally:
                if descriptor is not None:
                    os.close(descriptor)
                self.path.unlink(missing_ok=True)


class PairingAdminProvisioner:
    """Own Pairing Admin/Companion/Bridge identities in macOS Keychain.

    Public configuration contains references only.  The Obsidian plugin is not
    given the Pairing Admin credential; management calls are proxied by the
    authenticated Companion Bridge.
    """

    def __init__(self, layout: RuntimeLayout, keychain: Keychain) -> None:
        self.layout = layout
        self.keychain = keychain

    def provision(
        self,
        *,
        installation_id: str,
        vault_id: str,
        endpoint: str,
        endpoint_audience: str,
    ) -> dict[str, Any]:
        self.layout.ensure()
        refs = {
            "pairing_admin": f"{installation_id}:local_tailscale:pairing-admin",
            "companion": f"{installation_id}:local_tailscale:companion",
            "bridge": f"{installation_id}:local:bridge",
        }
        credential_values: dict[str, str] = {}
        for name, reference in refs.items():
            try:
                credential_values[name] = self.keychain.get(reference)
            except Exception as exc:
                # The bootstrap Keychain protocol is intentionally shared
                # with an independently packaged Companion implementation.
                # Both use the same stable missing-reference meaning even
                # though their concrete exception classes cannot be shared.
                if str(exc).strip().lower().replace(" ", "_") != "missing_secret_reference":
                    raise
                credential_values[name] = secrets.token_urlsafe(48)
                self.keychain.set(reference, credential_values[name])

        bootstrap_generation = "bootstrap-" + secrets.token_urlsafe(24)
        self.layout.bridge_bootstrap_ack.unlink(missing_ok=True)
        profile = ConnectionProfile(
            schema_version=1,
            mode="local_tailscale",
            installation_id=installation_id,
            vault_id=vault_id,
            endpoint=endpoint,
            endpoint_audience=endpoint_audience,
            companion_credential_ref=f"{installation_id}:local_tailscale:companion",
            mobile_credential_ref=f"{installation_id}:local_tailscale:mobile",
            cursor=0,
            epoch="epoch-" + secrets.token_urlsafe(18),
        )
        authority = LifecycleAuthority.create()
        ConnectionProfileStore(self.layout.connection_profile, authority).write(profile, authority=authority)

        common = {
            "installation_id": installation_id,
            "vault_id": vault_id,
            "endpoint_audience": endpoint_audience,
            "pairing_id": installation_id,
        }
        relay = {
            "host": "127.0.0.1",
            "port": 8787,
            "public_base_url": endpoint,
            **common,
            "database_path": str(self.layout.state / "relay-v2.db"),
            "pairing_database_path": str(self.layout.state / "pairing.db"),
            "upload_root": str(self.layout.state / "uploads"),
            "allowed_origins": ["app://obsidian.md", "capacitor://localhost"],
            "tokens": [
                {
                    "name": "pairing-admin",
                    "role": "pairing_admin",
                    "pairing_id": installation_id,
                    "installation_id": installation_id,
                    "vault_id": vault_id,
                    "device_id": "mac-pairing-admin",
                    "endpoint_audience": endpoint_audience,
                    "token_ref": refs["pairing_admin"],
                },
                {
                    "name": "mac-primary",
                    "role": "mac",
                    "pairing_id": installation_id,
                    "installation_id": installation_id,
                    "vault_id": vault_id,
                    "device_id": "mac-companion",
                    "endpoint_audience": endpoint_audience,
                    "token_ref": refs["companion"],
                },
            ],
        }
        companion = {
            **common,
            "connection_profile_path": str(self.layout.connection_profile),
            "relay_token_ref": refs["companion"],
            "bridge_credential_ref": refs["bridge"],
            "bridge_credential_id": f"{installation_id}:bridge",
            "bridge_bootstrap_ack_path": str(self.layout.bridge_bootstrap_ack),
            "bootstrap_generation": bootstrap_generation,
            "pairing_admin_credential_ref": refs["pairing_admin"],
            "v2_state_path": str(self.layout.state / "companion-v2.json"),
            "upload_temp_dir": str(self.layout.state / "upload-temp"),
        }
        # `tokens` is the Relay's historical name for role descriptors. Each
        # descriptor contains only a Keychain `token_ref`, never token bytes,
        # so this typed config uses its own schema/test validation rather than
        # the checkpoint key-name heuristic.
        write_private_json(self.layout.relay_config, relay, validate_secret_free=False)
        write_private_json(self.layout.companion_config, companion)
        provisioning_ref = f"{installation_id}:secure-provisioning"
        write_private_json(
            self.layout.secure_provisioning,
            {
                "schema_version": 1,
                "provisioning_ref": provisioning_ref,
                "installation_id": installation_id,
                "vault_id": vault_id,
                "pairing_admin_credential_ref": refs["pairing_admin"],
                "bridge_credential_ref": refs["bridge"],
                "bridge_credential_id": f"{installation_id}:bridge",
                "bootstrap_generation": bootstrap_generation,
            },
        )
        SecureInputFile.create(
            self.layout.bridge_bootstrap_for(vault_id),
            {
                "bootstrap_schema": "claudian-remote.bridge-bootstrap/v1",
                "installation_id": installation_id,
                "vault_id": vault_id,
                "endpoint": endpoint,
                "endpoint_audience": endpoint_audience,
                "bridge_credential_id": f"{installation_id}:bridge",
                "bridge_secret": credential_values["bridge"],
                "bootstrap_generation": bootstrap_generation,
                "expires_at": int(time.time()) + 600,
            },
        )
        return {
            "secure_provisioning_available": self.probe(provisioning_ref),
            "provisioning_ref": provisioning_ref,
            "bridge_bootstrap_pending": True,
            "credential_refs": {key: "<secure-reference>" for key in refs},
        }

    def probe(self, provisioning_ref: str) -> bool:
        return verify_secure_provisioning(
            self.layout,
            self.keychain,
            expected_provisioning_ref=provisioning_ref,
        )
