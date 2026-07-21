"""Allowlisted, local-only lifecycle diagnostics.

The diagnostic service deliberately does not serialize arbitrary runtime
objects.  Callers provide structured observations, but only stable codes,
versions, booleans, and counters cross the Agent/export boundary.  This keeps
paths, endpoints, credentials, content, argv/environment, stacks, and pairing
state out of both the short summary and the optional bundle.
"""

from __future__ import annotations

import json
import os
import platform
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping


DIAGNOSTIC_SCHEMA = "claudian-remote.diagnostics/v1"
SEMVER = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
LIFECYCLE_STATES = frozenset({"ready", "prepared", "blocked", "rolled_back", "recovery_required"})
LIFECYCLE_PHASES = frozenset({
    "inspection", "created", "install_prepared", "update_prepared", "before_staging",
    "before_legacy_migration", "before_activation", "after_activation", "await_pairing",
    "awaiting_purge_confirmation", "awaiting_diagnostic_export_confirmation", "verify", "ready",
    "rolled_back", "recovery_required",
})
REASON_CODES = frozenset({
    "unsupported_desktop_os", "unsupported_claudian_version", "claudian_not_enabled",
    "secure_provisioning_missing", "vault_not_found", "vault_selection_required",
    "tailscale_install_required", "tailscale_login_required", "tailscale_update_required",
    "tailscale_https_consent_required", "pairing_approval_required",
    "trusted_lan_not_release_eligible", "environment_drift", "owned_resource_modified",
    "device_revocation_unavailable", "device_revocation_unverified",
    "relay_offline",
})
CONNECTION_MODES = frozenset({"local_tailscale", "remote_vps", "local_lan"})
TRANSPORT_STATES = frozenset({"connected", "disconnected"})
MAC_STATES = frozenset({"online", "offline"})
COMPATIBILITY_STATES = frozenset({"compatible", "blocked"})
ARCHITECTURES = frozenset({"arm64", "aarch64", "x86_64"})


def _enum(value: Any, allowed: frozenset[str], fallback: str = "unknown") -> str:
    candidate = str(value or "").strip().lower()
    return candidate if candidate in allowed else fallback


def _version(key: str, value: Any) -> str:
    candidate = str(value or "").strip()
    if key == "protocol":
        return candidate if candidate == "claudian.remote.v2" else "unknown"
    return candidate if SEMVER.fullmatch(candidate) else "unknown"


def _count(value: Any) -> int:
    try:
        return max(0, min(int(value), 1_000_000_000))
    except (TypeError, ValueError):
        return 0


class DiagnosticService:
    """Build and optionally export a non-sensitive diagnostic projection."""

    EXPORT_FIELDS = (
        "schema",
        "created_at",
        "system",
        "components",
        "lifecycle",
        "connection",
        "counters",
    )

    def __init__(self, *, clock: Any | None = None) -> None:
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def _projection(self, observation: Mapping[str, Any]) -> dict[str, Any]:
        components = observation.get("components") if isinstance(observation.get("components"), Mapping) else {}
        lifecycle = observation.get("lifecycle") if isinstance(observation.get("lifecycle"), Mapping) else {}
        connection = observation.get("connection") if isinstance(observation.get("connection"), Mapping) else {}
        counters = observation.get("counters") if isinstance(observation.get("counters"), Mapping) else {}
        reasons = observation.get("reason_codes") if isinstance(observation.get("reason_codes"), (list, tuple)) else []
        return {
            "schema": DIAGNOSTIC_SCHEMA,
            "created_at": self.clock().astimezone(timezone.utc).isoformat(),
            "system": {
                "platform": "macos" if platform.system() == "Darwin" else "unsupported",
                "architecture": _enum(platform.machine(), ARCHITECTURES),
            },
            "components": {
                key: _version(key, components.get(key))
                for key in ("plugin", "companion", "relay", "protocol", "claudian")
            },
            "lifecycle": {
                "state": _enum(lifecycle.get("state"), LIFECYCLE_STATES),
                "phase": _enum(lifecycle.get("phase"), LIFECYCLE_PHASES),
                "reason_codes": [_enum(item, REASON_CODES) for item in reasons[:32]],
                "ownership_receipt_present": lifecycle.get("ownership_receipt_present") is True,
            },
            "connection": {
                "mode": _enum(connection.get("mode"), CONNECTION_MODES),
                "transport_status": _enum(connection.get("transport_status"), TRANSPORT_STATES),
                "mac_status": _enum(connection.get("mac_status"), MAC_STATES),
                "compatibility_status": _enum(connection.get("compatibility_status"), COMPATIBILITY_STATES),
            },
            "counters": {
                key: _count(counters.get(key))
                for key in ("pending_operations", "failed_checks", "owned_resources")
            },
        }

    def agent_safe_summary(self, observation: Mapping[str, Any]) -> dict[str, Any]:
        projection = self._projection(observation)
        return {
            "summary_schema": "claudian-remote.agent-safe-summary/v1",
            "state": projection["lifecycle"]["state"],
            "phase": projection["lifecycle"]["phase"],
            "reason_codes": projection["lifecycle"]["reason_codes"],
            "connection": projection["connection"],
            "components": projection["components"],
            "counters": projection["counters"],
        }

    def preview_export(self) -> dict[str, Any]:
        return {
            "preview_schema": "claudian-remote.diagnostic-preview/v1",
            "fields": list(self.EXPORT_FIELDS),
            "excluded": [
                "credentials", "pairing_state", "content", "paths", "urls",
                "network_identity", "argv", "environment", "stacks",
            ],
            "uploaded": False,
        }

    def export(
        self,
        observation: Mapping[str, Any],
        destination: Path,
        *,
        confirmation_verified: bool,
    ) -> dict[str, Any]:
        if confirmation_verified is not True:
            return {
                "state": "blocked",
                "code": "diagnostic_export_confirmation_required",
                "mutation_performed": False,
                "preview": self.preview_export(),
            }
        destination = Path(destination)
        if not destination.is_absolute() or destination.suffix.lower() != ".json":
            return {
                "state": "blocked",
                "code": "diagnostic_export_destination_invalid",
                "mutation_performed": False,
            }
        destination.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(prefix=destination.name + ".", dir=destination.parent)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(self._projection(observation), handle, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, destination)
        finally:
            Path(temporary).unlink(missing_ok=True)
        return {
            "state": "ready",
            "code": "diagnostic_export_ready",
            "mutation_performed": True,
            "uploaded": False,
            "field_names": list(self.EXPORT_FIELDS),
        }

    @staticmethod
    def delete_export(path: Path) -> bool:
        path = Path(path)
        if not path.is_file():
            return False
        path.unlink()
        return True
