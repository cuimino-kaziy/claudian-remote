"""Non-secret migration steps used by the lifecycle transaction engine."""

from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Callable, Dict, Mapping, MutableMapping

from .legacy_authority import (
    CredentialHandle,
    LegacyCredentialRetirementService,
    LegacyRetirementOutcomeUnknown,
    RetirementReconciliationResult,
    RetirementCommit,
)
from .private_io import write_private_json


MIGRATION_ID = "legacy_shared_token_v1"
VAULT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_MIGRATION_PHASES = frozenset(
    {
        "pending_revocation",
        "retirement_outcome_unknown",
        "retirement_not_applied",
        "retirement_inconclusive",
        "credential_revoked",
        "sanitized",
        "isolated",
        "prepared",
        "activated",
        "committed",
        "rolled_back",
    }
)
_POST_RETIREMENT_PHASES = _MIGRATION_PHASES - {
    "pending_revocation",
    "retirement_outcome_unknown",
    "retirement_not_applied",
    "retirement_inconclusive",
    "rolled_back",
}
_MIGRATION_FIELDS = frozenset(
    {
        "migration_schema",
        "operation_id",
        "plan_id",
        "installation_id",
        "vault_id",
        "connection_mode",
        "phase",
        "legacy_present",
        "legacy_was_enabled",
        "current_was_enabled",
        "re_pair_required",
        "synchronized",
    }
)


def _legacy_credential(value: Mapping[str, Any]) -> str:
    return str(value.get("mobile_token") or value.get("relayToken") or "")


class LegacyCredentialRetirementError(ValueError):
    """Stable lifecycle error for retirement failures callers must classify."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def inspect_legacy_retirement_journal(
    path: Path,
    *,
    operation_id: str,
    plan_id: str,
) -> str:
    """Classify a bound migration companion without touching the Vault."""

    value = _read_mapping(Path(path))
    fields = frozenset(value)
    if fields not in {_MIGRATION_FIELDS, _MIGRATION_FIELDS | {"retirement_commit"}}:
        raise ValueError("legacy_plugin_migration_invalid")
    if (
        value.get("migration_schema") != "claudian-remote.legacy-plugin/v2"
        or value.get("operation_id") != operation_id
        or value.get("plan_id") != plan_id
        or value.get("phase") not in _MIGRATION_PHASES
    ):
        raise ValueError("legacy_plugin_migration_binding_mismatch")
    commit_raw = value.get("retirement_commit")
    if value.get("phase") == "retirement_outcome_unknown":
        if commit_raw is not None:
            raise ValueError("legacy_plugin_migration_invalid")
        return "retirement_outcome_unknown"
    if value.get("phase") == "retirement_not_applied":
        if commit_raw is not None:
            raise ValueError("legacy_plugin_migration_invalid")
        return "not_applied"
    if value.get("phase") == "retirement_inconclusive":
        if commit_raw is not None:
            raise ValueError("legacy_plugin_migration_invalid")
        return "inconclusive"
    if commit_raw is None:
        return "not_dispatched"
    commit = RetirementCommit.from_mapping(commit_raw)
    if commit.operation_id != operation_id or commit.plan_id != plan_id:
        raise ValueError("legacy_plugin_retirement_commit_binding_mismatch")
    return "retired"


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
    retirement_service: LegacyCredentialRetirementService | None,
    *,
    operation_id: str = "",
    plan_id: str = "",
    target_installation_id: str = "",
    target_vault_id: str = "",
    purge: bool = False,
) -> Dict[str, Any]:
    """Retire a synchronized legacy token exactly once without journaling it."""
    migrations = state.setdefault("migrations", {})
    if not isinstance(migrations, MutableMapping):
        raise ValueError("legacy_migration_state_invalid")
    marker = migrations.get(MIGRATION_ID)
    if marker is not None:
        if not isinstance(marker, Mapping) or marker.get("completed") is not True:
            raise ValueError("legacy_migration_marker_invalid")
        marker_fields = set(marker)
        if marker_fields not in (
            {"completed", "re_pair_required"},
            {"completed", "re_pair_required", "retirement_commit"},
        ) or not isinstance(marker.get("re_pair_required"), bool):
            raise ValueError("legacy_migration_marker_invalid")
        commit_raw = marker.get("retirement_commit")
        commit = (
            RetirementCommit.from_mapping(commit_raw)
            if commit_raw is not None
            else None
        )
        if marker["re_pair_required"] is True and commit is None:
            raise ValueError("legacy_migration_retirement_commit_required")
        if marker["re_pair_required"] is False and commit is not None:
            raise ValueError("legacy_migration_marker_invalid")
        if commit is not None and (
            commit.operation_id != operation_id
            or commit.plan_id != plan_id
            or commit.installation_id != target_installation_id
            or commit.vault_id != target_vault_id
            or commit.role != "mobile"
        ):
            raise ValueError("legacy_migration_retirement_commit_binding_mismatch")
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

    credential = _legacy_credential(synchronized)
    if credential:
        commit = _retire_credential(
            credential,
            retirement_service,
            operation_id=operation_id,
            plan_id=plan_id,
            installation_id=target_installation_id,
            vault_id=target_vault_id,
            role="mobile",
        )
    else:
        commit = None
    marker = {
        "completed": True,
        "re_pair_required": bool(credential),
        **({"retirement_commit": commit.to_mapping()} if commit is not None else {}),
    }
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


def _retire_credential(
    credential: str,
    service: LegacyCredentialRetirementService | None,
    *,
    operation_id: str,
    plan_id: str,
    installation_id: str,
    vault_id: str,
    role: str,
    lock_held: bool = False,
) -> RetirementCommit:
    if not isinstance(service, LegacyCredentialRetirementService):
        raise LegacyCredentialRetirementError(
            "legacy_credential_retirement_service_unavailable"
        )
    handle = CredentialHandle.from_memory(credential)
    try:
        try:
            retire_kwargs = {
                "credential": handle,
                "operation_id": operation_id,
                "plan_id": plan_id,
                "installation_id": installation_id,
                "vault_id": vault_id,
                "role": role,
            }
            # Keep compatibility with pre-U5 adapters.  The production U5
            # adapter is configured with ``lock_held_by_caller``; the explicit
            # keyword is only needed by callers that deliberately opt in.
            if lock_held:
                retire_kwargs["lock_held"] = True
            outcome = service.retire(**retire_kwargs)
        except LegacyRetirementOutcomeUnknown:
            raise LegacyCredentialRetirementError(
                "legacy_credential_retirement_outcome_unknown"
            ) from None
        except Exception:
            # Authority adapters receive secret material by capability.  Their
            # exception strings are never allowed to cross into lifecycle
            # output or diagnostics because they may echo that material.
            raise LegacyCredentialRetirementError(
                "legacy_credential_retirement_failed"
            ) from None
    finally:
        handle.destroy()
    if not isinstance(outcome, RetirementCommit):
        raise LegacyCredentialRetirementError(
            "legacy_credential_revocation_unverified"
        )
    if (
        outcome.operation_id != operation_id
        or outcome.plan_id != plan_id
        or outcome.installation_id != installation_id
        or outcome.vault_id != vault_id
        or outcome.role != role
    ):
        raise LegacyCredentialRetirementError(
            "legacy_credential_retirement_binding_mismatch"
        )
    return outcome


def _reconcile_credential(
    credential: str,
    service: LegacyCredentialRetirementService | None,
    *,
    operation_id: str,
    plan_id: str,
    installation_id: str,
    vault_id: str,
    role: str,
    lock_held: bool = False,
) -> RetirementReconciliationResult:
    if not isinstance(service, LegacyCredentialRetirementService):
        raise LegacyCredentialRetirementError(
            "legacy_credential_retirement_service_unavailable"
        )
    handle = CredentialHandle.from_memory(credential)
    try:
        try:
            outcome = service.reconcile(
                credential=handle,
                operation_id=operation_id,
                plan_id=plan_id,
                installation_id=installation_id,
                vault_id=vault_id,
                role=role,
                lock_held=lock_held,
            )
        except Exception:
            raise LegacyCredentialRetirementError(
                "legacy_credential_retirement_inconclusive"
            ) from None
    finally:
        handle.destroy()
    if not isinstance(outcome, RetirementReconciliationResult):
        raise LegacyCredentialRetirementError(
            "legacy_credential_retirement_inconclusive"
        )
    return outcome


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
        retirement_service: LegacyCredentialRetirementService | None,
        *,
        target_plan_id: str = "",
        target_installation_id: str = "",
        target_vault_id: str,
        target_mode: str,
        interruption_probe: Callable[[str], None] | None = None,
        operation_lock_held: bool = False,
    ) -> None:
        self.vault = Path(vault)
        self.state_directory = Path(state_directory)
        if retirement_service is not None and not isinstance(
            retirement_service, LegacyCredentialRetirementService
        ):
            raise TypeError("legacy_credential_retirement_service_invalid")
        self.retirement_service = retirement_service
        self.target_plan_id = target_plan_id
        self.target_installation_id = target_installation_id
        if not VAULT_ID.fullmatch(target_vault_id):
            raise ValueError("invalid_vault_id")
        if target_mode not in {"local_tailscale", "local_lan", "remote_vps"}:
            raise ValueError("invalid_connection_mode")
        self.target_vault_id = target_vault_id
        self.target_mode = target_mode
        self.interruption_probe = interruption_probe or (lambda _phase: None)
        self.operation_lock_held = bool(operation_lock_held)
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
        if value.get("migration_schema") != "claudian-remote.legacy-plugin/v2":
            raise ValueError("legacy_plugin_migration_invalid")
        fields = frozenset(value)
        if fields not in {_MIGRATION_FIELDS, _MIGRATION_FIELDS | {"retirement_commit"}}:
            raise ValueError("legacy_plugin_migration_invalid")
        phase = value.get("phase")
        if phase not in _MIGRATION_PHASES:
            raise ValueError("legacy_plugin_migration_invalid")
        if (
            value.get("operation_id") != operation_id
            or value.get("plan_id") != self.target_plan_id
            or value.get("installation_id") != self.target_installation_id
            or value.get("vault_id") != self.target_vault_id
            or value.get("connection_mode") != self.target_mode
        ):
            raise ValueError("legacy_plugin_migration_binding_mismatch")
        for field in (
            "legacy_present",
            "legacy_was_enabled",
            "current_was_enabled",
            "re_pair_required",
        ):
            if not isinstance(value.get(field), bool):
                raise ValueError("legacy_plugin_migration_invalid")
        synchronized = value.get("synchronized")
        if not isinstance(synchronized, Mapping):
            raise ValueError("legacy_plugin_migration_invalid")
        normalized = _sync_preferences(synchronized)
        if (
            dict(synchronized) != normalized
            or normalized["vault_id"] != self.target_vault_id
            or normalized["connection_mode"] != self.target_mode
        ):
            raise ValueError("legacy_plugin_migration_invalid")
        commit_raw = value.get("retirement_commit")
        commit = (
            RetirementCommit.from_mapping(commit_raw)
            if commit_raw is not None
            else None
        )
        requires_commit = value["re_pair_required"] is True and phase in _POST_RETIREMENT_PHASES
        if requires_commit and commit is None:
            raise ValueError("legacy_plugin_retirement_commit_required")
        if phase in {
            "pending_revocation",
            "retirement_outcome_unknown",
            "retirement_not_applied",
            "retirement_inconclusive",
        } and commit is not None:
            raise ValueError("legacy_plugin_migration_invalid")
        if value["re_pair_required"] is False and commit is not None:
            raise ValueError("legacy_plugin_migration_invalid")
        if commit is not None and (
            commit.operation_id != operation_id
            or commit.plan_id != self.target_plan_id
            or commit.installation_id != self.target_installation_id
            or commit.vault_id != self.target_vault_id
            or commit.role != "mobile"
        ):
            raise ValueError("legacy_plugin_retirement_commit_binding_mismatch")
        return value

    def _save_state(self, operation_id: str, value: Mapping[str, Any]) -> None:
        write_private_json(self._state_path(operation_id), dict(value))

    def journal_present(self, operation_id: str) -> bool:
        """Return whether a valid journal exists without exposing its contents."""

        return self._load_state(operation_id) is not None

    def retirement_state(self, operation_id: str) -> str:
        """Return the fail-closed retirement boundary for this operation.

        The migration journal never contains the credential itself.  A bound
        commit proves the irreversible boundary; an outcome-unknown phase
        proves only that rollback/cancel are unsafe until reconciliation.
        """

        state = self._load_state(operation_id)
        if state is None or state.get("re_pair_required") is not True:
            return "not_dispatched"
        if state.get("phase") == "retirement_outcome_unknown":
            return "retirement_outcome_unknown"
        if state.get("phase") == "retirement_not_applied":
            return "not_applied"
        if state.get("phase") == "retirement_inconclusive":
            return "inconclusive"
        if state.get("retirement_commit") is not None:
            RetirementCommit.from_mapping(state["retirement_commit"])
            return "retired"
        return "not_dispatched"

    def retirement_commit(self, operation_id: str) -> Dict[str, Any] | None:
        state = self._load_state(operation_id)
        if state is None or state.get("retirement_commit") is None:
            return None
        return RetirementCommit.from_mapping(state["retirement_commit"]).to_mapping()

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

    def credential_revocation_required(self) -> bool:
        """Inspect whether migration needs an authoritative credential revoker.

        This is deliberately read-only so an unavailable revocation capability
        can block before staging or lifecycle journal creation mutates product
        resources.
        """

        self.validate_coexistence()
        legacy = self.plugins / self.LEGACY_ID
        if legacy.is_symlink():
            raise ValueError("legacy_plugin_unsafe_path")
        if not legacy.exists():
            return False
        if not legacy.is_dir():
            raise ValueError("legacy_plugin_state_invalid")
        self._validate_manifest(legacy, self.LEGACY_ID)
        raw = _read_mapping(legacy / "data.json")
        return bool(_legacy_credential(raw))

    def reconcile_retirement(
        self, *, operation_id: str
    ) -> RetirementReconciliationResult:
        """Reconcile only the already-dispatched authority request.

        This method may promote the secret-free migration journal, but it never
        sanitizes, moves, enables, or disables an Obsidian plugin.  Forward
        mutation therefore remains behind a later, freshly validated resume.
        """

        self.validate_coexistence()
        self._validate_paths(operation_id)
        state = self._load_state(operation_id)
        if state is None or state.get("phase") != "retirement_outcome_unknown":
            raise LegacyCredentialRetirementError(
                "legacy_credential_retirement_reconciliation_not_required"
            )
        legacy = self.plugins / self.LEGACY_ID
        if not legacy.is_dir():
            raise ValueError("legacy_plugin_migration_incomplete")
        raw = _read_mapping(legacy / "data.json")
        credential = _legacy_credential(raw)
        if not credential:
            raise LegacyCredentialRetirementError(
                "legacy_credential_retirement_inconclusive"
            )
        outcome = _reconcile_credential(
            credential,
            self.retirement_service,
            operation_id=operation_id,
            plan_id=self.target_plan_id,
            installation_id=self.target_installation_id,
            vault_id=self.target_vault_id,
            role="mobile",
            lock_held=self.operation_lock_held,
        )
        if outcome.outcome == "retired":
            if outcome.commit is None:
                raise LegacyCredentialRetirementError(
                    "legacy_credential_retirement_inconclusive"
                )
            state["retirement_commit"] = outcome.commit.to_mapping()
            state["phase"] = "credential_revoked"
            self._save_state(operation_id, state)
            self.interruption_probe("after_credential_revoked")
        elif outcome.outcome == "not_applied":
            state["phase"] = "retirement_not_applied"
            self._save_state(operation_id, state)
        else:
            state["phase"] = "retirement_inconclusive"
            self._save_state(operation_id, state)
        return outcome

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
            credential = _legacy_credential(raw)
            existing = {
                "migration_schema": "claudian-remote.legacy-plugin/v2",
                "operation_id": operation_id,
                "plan_id": self.target_plan_id,
                "installation_id": self.target_installation_id,
                "vault_id": self.target_vault_id,
                "connection_mode": self.target_mode,
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
            credential = _legacy_credential(raw)
            if state.get("re_pair_required") is True:
                if not credential:
                    raise LegacyCredentialRetirementError(
                        "legacy_credential_revocation_unverified"
                    )
                # Persist the conservative dispatch boundary before handing
                # the credential capability to an authority adapter.  A
                # typed pre-dispatch failure below may restore this marker;
                # a crash or uncertain response may not.
                state["phase"] = "retirement_outcome_unknown"
                self._save_state(operation_id, state)
                try:
                    commit = _retire_credential(
                        credential,
                        self.retirement_service,
                        operation_id=operation_id,
                        plan_id=self.target_plan_id,
                        installation_id=self.target_installation_id,
                        vault_id=self.target_vault_id,
                        role="mobile",
                        lock_held=self.operation_lock_held,
                    )
                    # The authority proof may already be durably consumed in
                    # the lifecycle checkpoint while this migration journal
                    # still says ``retirement_outcome_unknown``.  A restart in
                    # this exact window must reconcile the authority again;
                    # it may not infer current runtime health from the local
                    # commit alone.
                    self.interruption_probe("after_retirement_commit_consumed")
                except LegacyCredentialRetirementError as exc:
                    if exc.code == "legacy_credential_retirement_outcome_unknown":
                        pass
                    else:
                        state["phase"] = "pending_revocation"
                    self._save_state(operation_id, state)
                    raise
                state["retirement_commit"] = commit.to_mapping()
            state["phase"] = "credential_revoked"
            self._save_state(operation_id, state)
            self.interruption_probe("after_credential_revoked")
            phase = "credential_revoked"

        if phase == "retirement_outcome_unknown":
            outcome = self.reconcile_retirement(operation_id=operation_id)
            if outcome.outcome == "retired":
                phase = "credential_revoked"
            elif outcome.outcome == "not_applied":
                raise LegacyCredentialRetirementError(
                    "legacy_credential_retirement_not_applied"
                )
            else:
                raise LegacyCredentialRetirementError(
                    "legacy_credential_retirement_inconclusive"
                )

        if phase == "retirement_not_applied":
            raise LegacyCredentialRetirementError(
                "legacy_credential_retirement_not_applied"
            )
        if phase == "retirement_inconclusive":
            raise LegacyCredentialRetirementError(
                "legacy_credential_retirement_inconclusive"
            )

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
        phase = str(state.get("phase") or "")
        if phase == "rolled_back":
            return
        retirement_state = self.retirement_state(operation_id)
        if retirement_state == "retirement_outcome_unknown":
            raise LegacyCredentialRetirementError(
                "legacy_credential_retirement_outcome_unknown"
            )
        if retirement_state == "inconclusive":
            raise LegacyCredentialRetirementError(
                "legacy_credential_retirement_inconclusive"
            )
        if retirement_state == "retired":
            raise LegacyCredentialRetirementError(
                "legacy_credential_already_retired"
            )
        if phase in {"pending_revocation", "retirement_not_applied"}:
            # No authoritative revocation was verified, so the legacy
            # credential is still active.  At this boundary rollback is
            # metadata-only: touching data.json would orphan an active server
            # credential while falsely claiming a clean rollback.
            state["phase"] = "rolled_back"
            self._save_state(operation_id, state)
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
