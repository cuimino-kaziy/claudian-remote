"""Non-secret migration steps used by the lifecycle transaction engine."""

from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Callable, Dict, Mapping, MutableMapping


MIGRATION_ID = "legacy_shared_token_v1"
VAULT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")


def _sync_preferences(value: Mapping[str, Any]) -> Dict[str, Any]:
    mode = str(value.get("connection_mode") or "")
    vault_id = str(value.get("vault_id") or "")
    if mode not in ("", "local_tailscale", "local_lan", "remote_vps"):
        mode = ""
    return {
        "schema_version": 2,
        "vault_id": vault_id if VAULT_ID.fullmatch(vault_id) else "",
        "connection_mode": mode,
        "notifications_enabled": value.get("notifications_enabled") if isinstance(value.get("notifications_enabled"), bool) else True,
        "haptics_enabled": value.get("haptics_enabled") if isinstance(value.get("haptics_enabled"), bool) else True,
    }


def migrate_legacy_shared_token(
    synchronized: Mapping[str, Any],
    state: MutableMapping[str, Any],
    revoke: Callable[[str], None],
    *,
    purge: bool = False,
) -> Dict[str, Any]:
    """Revoke a synchronized legacy token exactly once and emit no secret journal data."""
    migrations = state.setdefault("migrations", {})
    marker = migrations.get(MIGRATION_ID)
    if marker and marker.get("completed") is True:
        result = {
            "migration_id": MIGRATION_ID,
            "already_completed": True,
            "re_pair_required": bool(marker.get("re_pair_required")),
            "synchronized": _sync_preferences(synchronized),
            "remove_device_cache": bool(purge),
        }
        if purge:
            state["device_cache_present"] = False
        return result

    credential = str(synchronized.get("mobile_token") or synchronized.get("relayToken") or "")
    if credential:
        revoke(credential)
    marker = {"completed": True, "re_pair_required": bool(credential)}
    migrations[MIGRATION_ID] = marker
    if purge:
        state["device_cache_present"] = False
    return {
        "migration_id": MIGRATION_ID,
        "already_completed": False,
        "re_pair_required": bool(credential),
        "synchronized": _sync_preferences(synchronized),
        "remove_device_cache": bool(purge),
    }


def _read_mapping(path: Path) -> Dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("legacy_plugin_state_invalid") from exc
    if not isinstance(value, Mapping):
        raise ValueError("legacy_plugin_state_invalid")
    return dict(value)


def _read_enabled(path: Path) -> list[str]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return []
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("community_plugin_state_invalid") from exc
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError("community_plugin_state_invalid")
    return list(dict.fromkeys(value))


def _write_json(path: Path, value: Any, *, private: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600 if private else 0o644)
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def write_sync_preferences(
    path: Path,
    value: Mapping[str, Any],
    *,
    vault_id: str,
    connection_mode: str,
) -> None:
    preferences = _sync_preferences(value)
    preferences["vault_id"] = vault_id
    preferences["connection_mode"] = connection_mode
    _write_json(Path(path), preferences)


class LegacyPluginMigration:
    """One-operation migration from the private plugin ID.

    The journal stores only the allowlisted synchronized projection. The old
    credential is retired before any plugin directory or enabled-plugin list
    changes, and rollback deliberately restores only sanitized data.
    """

    LEGACY_ID = "whale-agent-bridge"
    CURRENT_ID = "claudian-remote"

    def __init__(
        self,
        vault: Path,
        state_directory: Path,
        revoke_legacy_credential: Callable[[str], Any],
        *,
        target_vault_id: str,
        target_mode: str,
        interruption_probe: Callable[[str], None] | None = None,
    ) -> None:
        self.vault = Path(vault)
        self.state_directory = Path(state_directory)
        self.revoke_legacy_credential = revoke_legacy_credential
        if not VAULT_ID.fullmatch(target_vault_id):
            raise ValueError("invalid_vault_id")
        if target_mode not in {"local_tailscale", "local_lan", "remote_vps"}:
            raise ValueError("invalid_connection_mode")
        self.target_vault_id = target_vault_id
        self.target_mode = target_mode
        self.interruption_probe = interruption_probe or (lambda _phase: None)
        self.plugins = self.vault / ".obsidian" / "plugins"
        self.enabled_path = self.vault / ".obsidian" / "community-plugins.json"

    def _state_path(self, operation_id: str) -> Path:
        if not re.fullmatch(r"op-[A-Za-z0-9_-]{16,128}", operation_id):
            raise ValueError("invalid_operation_id")
        return self.state_directory / f"{operation_id}.legacy-plugin.json"

    def quarantine_path(self, operation_id: str) -> Path:
        self._state_path(operation_id)
        return self.state_directory.parent / "backups" / operation_id / self.LEGACY_ID

    def _load_state(self, operation_id: str) -> Dict[str, Any] | None:
        path = self._state_path(operation_id)
        if not path.exists():
            return None
        value = _read_mapping(path)
        if value.get("migration_schema") != "claudian-remote.legacy-plugin/v1":
            raise ValueError("legacy_plugin_migration_invalid")
        return value

    def _save_state(self, operation_id: str, value: Mapping[str, Any]) -> None:
        self.state_directory.mkdir(parents=True, exist_ok=True)
        os.chmod(self.state_directory, 0o700)
        _write_json(self._state_path(operation_id), dict(value), private=True)

    @staticmethod
    def _require_within(path: Path, root: Path, code: str) -> None:
        if path.is_symlink():
            raise ValueError(code)
        try:
            path.resolve(strict=path.exists()).relative_to(root.resolve())
        except (OSError, ValueError) as exc:
            raise ValueError(code) from exc

    def _validate_paths(self, operation_id: str) -> None:
        vault_root = self.vault.resolve()
        for path in (
            self.vault / ".obsidian",
            self.plugins,
            self.enabled_path,
            self.plugins / self.LEGACY_ID,
            self.plugins / self.LEGACY_ID / "manifest.json",
            self.plugins / self.LEGACY_ID / "data.json",
            self.plugins / self.CURRENT_ID,
            self.plugins / self.CURRENT_ID / "manifest.json",
            self.plugins / self.CURRENT_ID / "data.json",
        ):
            self._require_within(path, vault_root, "legacy_plugin_unsafe_path")
        lifecycle_root = self.state_directory.parent.resolve()
        for path in (
            self.state_directory,
            self.state_directory.parent / "backups",
            self.state_directory.parent / "backups" / operation_id,
            self.quarantine_path(operation_id),
        ):
            self._require_within(path, lifecycle_root, "legacy_plugin_unsafe_state_path")

    @staticmethod
    def _validate_manifest(directory: Path, expected_id: str) -> None:
        manifest = _read_mapping(directory / "manifest.json")
        if manifest.get("id") != expected_id:
            raise ValueError("legacy_plugin_manifest_invalid")

    def _preferences(self, raw: Mapping[str, Any]) -> Dict[str, Any]:
        preferences = _sync_preferences(raw)
        preferences["vault_id"] = self.target_vault_id
        preferences["connection_mode"] = self.target_mode
        return preferences

    @staticmethod
    def _revocation_verified(outcome: Any) -> bool:
        if outcome is True:
            return True
        return isinstance(outcome, Mapping) and outcome.get("verified") is True

    def validate_coexistence(self) -> None:
        enabled = _read_enabled(self.enabled_path)
        if self.LEGACY_ID in enabled and self.CURRENT_ID in enabled:
            raise ValueError("legacy_and_current_plugin_enabled")

    def is_clean(self) -> bool:
        self.validate_coexistence()
        legacy = self.plugins / self.LEGACY_ID
        if legacy.is_symlink():
            return False
        enabled = _read_enabled(self.enabled_path)
        return not legacy.exists() and self.LEGACY_ID not in enabled and self.CURRENT_ID in enabled

    def requires_migration(self) -> bool:
        self.validate_coexistence()
        legacy = self.plugins / self.LEGACY_ID
        if legacy.is_symlink():
            raise ValueError("legacy_plugin_unsafe_path")
        return legacy.exists() or self.LEGACY_ID in _read_enabled(self.enabled_path)

    def prepare(self, *, operation_id: str) -> Dict[str, Any]:
        self.validate_coexistence()
        self._validate_paths(operation_id)
        existing = self._load_state(operation_id)
        enabled = _read_enabled(self.enabled_path)
        legacy = self.plugins / self.LEGACY_ID
        quarantine = self.quarantine_path(operation_id)
        if existing is None:
            if not legacy.exists():
                return {"legacy_present": False, "already_completed": False, "re_pair_required": False}
            if not legacy.is_dir():
                raise ValueError("legacy_plugin_state_invalid")
            self._validate_manifest(legacy, self.LEGACY_ID)
            raw = _read_mapping(legacy / "data.json")
            credential = str(raw.get("mobile_token") or raw.get("relayToken") or "")
            existing = {
                "migration_schema": "claudian-remote.legacy-plugin/v1",
                "phase": "pending_revocation",
                "legacy_present": True,
                "legacy_was_enabled": self.LEGACY_ID in enabled,
                "current_was_enabled": self.CURRENT_ID in enabled,
                "re_pair_required": bool(credential),
                "synchronized": self._preferences(raw),
            }
            self._save_state(operation_id, existing)

        state = existing
        phase = str(state.get("phase") or "")
        if phase == "pending_revocation":
            if not legacy.is_dir():
                raise ValueError("legacy_plugin_migration_incomplete")
            raw = _read_mapping(legacy / "data.json")
            credential = str(raw.get("mobile_token") or raw.get("relayToken") or "")
            if state.get("re_pair_required") is True:
                if not credential or not self._revocation_verified(self.revoke_legacy_credential(credential)):
                    raise ValueError("legacy_credential_revocation_unverified")
            state["phase"] = "credential_revoked"
            self._save_state(operation_id, state)
            self.interruption_probe("after_credential_revoked")
            phase = "credential_revoked"

        if phase == "credential_revoked":
            if legacy.is_dir():
                _write_json(legacy / "data.json", dict(state.get("synchronized") or {}))
            elif not quarantine.is_dir():
                raise ValueError("legacy_plugin_migration_incomplete")
            state["phase"] = "sanitized"
            self._save_state(operation_id, state)
            self.interruption_probe("after_legacy_sanitized")
            phase = "sanitized"

        if phase == "sanitized":
            if legacy.is_dir():
                quarantine.parent.mkdir(parents=True, exist_ok=True)
                if quarantine.exists():
                    raise ValueError("legacy_plugin_quarantine_conflict")
                legacy.replace(quarantine)
            elif not quarantine.is_dir():
                raise ValueError("legacy_plugin_migration_incomplete")
            state["phase"] = "isolated"
            self._save_state(operation_id, state)
            self.interruption_probe("after_legacy_isolated")
            phase = "isolated"

        if phase == "isolated":
            current_enabled = _read_enabled(self.enabled_path)
            _write_json(self.enabled_path, [item for item in current_enabled if item != self.LEGACY_ID])
            state["phase"] = "prepared"
            self._save_state(operation_id, state)
            phase = "prepared"

        if phase not in {"prepared", "activated", "committed"}:
            raise ValueError("legacy_plugin_migration_invalid")
        return {
            "legacy_present": state.get("legacy_present") is True,
            "already_completed": phase == "committed",
            "re_pair_required": state.get("re_pair_required") is True,
        }

    def activate_new(self, *, operation_id: str, destination: Path) -> None:
        state = self._load_state(operation_id)
        if state is not None and state.get("phase") not in {"prepared", "activated"}:
            raise ValueError("legacy_plugin_migration_not_prepared")
        destination = Path(destination)
        if destination != self.plugins / self.CURRENT_ID or not destination.is_dir():
            raise ValueError("current_plugin_destination_invalid")
        if state is not None:
            _write_json(destination / "data.json", dict(state.get("synchronized") or {}))
        enabled = _read_enabled(self.enabled_path)
        enabled = [item for item in enabled if item != self.LEGACY_ID]
        if self.CURRENT_ID not in enabled:
            enabled.append(self.CURRENT_ID)
        _write_json(self.enabled_path, enabled)
        if state is not None:
            state["phase"] = "activated"
            self._save_state(operation_id, state)

    def commit(self, *, operation_id: str) -> None:
        state = self._load_state(operation_id)
        if state is None:
            return
        state["phase"] = "committed"
        self._save_state(operation_id, state)

    def rollback(self, *, operation_id: str) -> None:
        state = self._load_state(operation_id)
        if state is None:
            return
        legacy = self.plugins / self.LEGACY_ID
        quarantine = self.quarantine_path(operation_id)
        if state.get("legacy_present") is True and quarantine.exists():
            if legacy.exists():
                raise ValueError("legacy_plugin_restore_conflict")
            quarantine.replace(legacy)
        if state.get("legacy_present") is True and legacy.is_dir():
            _write_json(legacy / "data.json", dict(state.get("synchronized") or {}))
        enabled = _read_enabled(self.enabled_path)
        enabled = [item for item in enabled if item not in {self.LEGACY_ID, self.CURRENT_ID}]
        if state.get("legacy_was_enabled") is True and legacy.is_dir():
            enabled.append(self.LEGACY_ID)
        if state.get("current_was_enabled") is True:
            enabled.append(self.CURRENT_ID)
        _write_json(self.enabled_path, enabled)
        state["phase"] = "rolled_back"
        self._save_state(operation_id, state)
