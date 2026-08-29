"""Atomic, resumable Mac-local installation transaction."""

from __future__ import annotations

import json
import errno
import os
import shutil
import socket
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from .availability import validate_bound_vault_name
from .launchd import LaunchAgentManager
from .legacy_authority import LegacyCredentialRetirementService
from .migrations import (
    LegacyCredentialRetirementError,
    LegacyPluginMigration,
    inspect_legacy_retirement_journal,
    write_sync_preferences,
)
from .pairing import PairingIdentityTransition
from .private_io import tree_digest, write_private_json
from .provisioning import PairingAdminProvisioner
from .runtime import ReleaseSource, RuntimeLayout, StagedRelease


class LifecycleInterrupted(RuntimeError):
    pass


def _loopback_listener_absent(port: int) -> bool:
    try:
        connection = socket.create_connection(("127.0.0.1", int(port)), timeout=0.25)
    except OSError as exc:
        return exc.errno == errno.ECONNREFUSED
    else:
        connection.close()
        return False


@dataclass
class TransactionDependencies:
    layout: RuntimeLayout
    release_source: ReleaseSource
    launchd: LaunchAgentManager
    tailscale: Any
    keychain: Any
    vault_path: Callable[[str], Path]
    health_probe: Callable[[], bool]
    pairing_probe: Callable[[], bool]
    legacy_credential_revoker: LegacyCredentialRetirementService | None
    bridge_ready_probe: Callable[[], bool] = lambda: True
    migration_safe_probe: Callable[[], bool] = lambda: True
    interruption_probe: Callable[[str], bool] = lambda _phase: False
    readiness_attempts: int = 20
    readiness_delay_seconds: float = 0.25
    sleep: Callable[[float], None] = time.sleep
    local_listener_absent_probe: Callable[[int], bool] = _loopback_listener_absent
    active_pairing_device_ids: Callable[[], object] | None = None
    revoke_pairing_device: Callable[[str, str], Mapping[str, Any]] | None = None


class LocalTailscaleTransaction:
    def __init__(self, dependencies: TransactionDependencies) -> None:
        self.dependencies = dependencies

    def _interrupt(self, phase: str) -> None:
        if self.dependencies.interruption_probe(phase):
            raise LifecycleInterrupted(phase)

    def _pairing_identity_transition(self) -> PairingIdentityTransition | None:
        active = self.dependencies.active_pairing_device_ids
        revoke = self.dependencies.revoke_pairing_device
        if active is None:
            return None
        return PairingIdentityTransition(
            self.dependencies.layout.state,
            active_device_ids=active,
            revoke_device=revoke,
            interruption_probe=self._interrupt,
        )

    def _wait_until(self, probe: Callable[[], bool]) -> bool:
        attempts = max(1, min(int(self.dependencies.readiness_attempts), 120))
        delay = max(0.0, min(float(self.dependencies.readiness_delay_seconds), 5.0))
        for attempt in range(attempts):
            if probe():
                return True
            if attempt + 1 < attempts and delay:
                self.dependencies.sleep(delay)
        return False

    def _wait_ready(self, endpoint: str) -> bool:
        return self._wait_until(
            lambda: self.dependencies.tailscale.verify(endpoint)
            and self.dependencies.health_probe()
        )

    def _wait_bridge_ready(self) -> bool:
        return self._wait_until(self.dependencies.bridge_ready_probe)

    @staticmethod
    def _supports_availability(target: Path | None) -> bool:
        return bool(target) and (
            target / "installer" / "installer" / "claudian_remote_lifecycle" / "availability.py"
        ).is_file()

    @staticmethod
    def _journal_availability_binding(
        path: Path,
        *,
        operation_id: str,
        plan_id: str,
    ) -> tuple[bool, str | None]:
        """Read the pre-activation Vault binding from a matching journal."""

        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return False, None
        if (
            not isinstance(value, Mapping)
            or value.get("transaction_schema") != "claudian-remote.local-transaction/v1"
            or value.get("operation_id") != operation_id
            or value.get("plan_id") != plan_id
            or "prior_availability_vault" not in value
        ):
            return False, None
        binding = value.get("prior_availability_vault")
        if binding is None:
            return True, None
        try:
            return True, validate_bound_vault_name(binding)
        except ValueError:
            return False, None

    def _journal_rollback_context(
        self,
        path: Path,
        *,
        operation_id: str,
        plan_id: str,
    ) -> tuple[bool, Path | None, bool, bool]:
        """Read the rollback boundary owned by one matching operation."""

        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return False, None, False, False
        if (
            not isinstance(value, Mapping)
            or value.get("transaction_schema") != "claudian-remote.local-transaction/v1"
            or value.get("operation_id") != operation_id
            or value.get("plan_id") != plan_id
            or "prior_release_id" not in value
            or not isinstance(value.get("activation_started"), bool)
            or not isinstance(value.get("plugin_activated"), bool)
        ):
            return False, None, False, False
        prior_release_id = value.get("prior_release_id")
        if prior_release_id is None:
            prior_target = None
        elif isinstance(prior_release_id, str):
            try:
                prior_target = self.dependencies.layout.release_path(prior_release_id)
            except ValueError:
                return False, None, False, False
            if not prior_target.is_dir():
                return False, None, False, False
        else:
            return False, None, False, False
        return (
            True,
            prior_target,
            value["activation_started"],
            value["plugin_activated"],
        )

    def _profile_matches(self, plan: Mapping[str, Any], endpoint: str) -> bool:
        try:
            profile = json.loads(self.dependencies.layout.connection_profile.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return False
        installation_id = str(plan.get("installation_id") or "")
        mode = str(plan.get("topology", {}).get("mode") or "")
        expected = {
            "mode": mode,
            "installation_id": installation_id,
            "vault_id": str(plan.get("vault_id") or ""),
            "endpoint": endpoint,
            "endpoint_audience": f"claudian-remote:{mode}:{installation_id}",
            "companion_credential_ref": f"{installation_id}:{mode}:companion",
            "mobile_credential_ref": f"{installation_id}:{mode}:mobile",
        }
        return isinstance(profile, dict) and all(profile.get(key) == value for key, value in expected.items())

    def completed_phases(self, operation_id: str) -> list[str]:
        """Return validated, secret-free progress from the local journal."""

        path = self.dependencies.layout.state / f"{operation_id}.transaction.json"
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return []
        completed = value.get("completed_phases") if isinstance(value, Mapping) else None
        allowed = {
            "staging",
            "legacy_plugin_migration",
            "secure_provisioning",
            "plugin_activation",
            "launchd",
            "tailscale_serve",
            "verified",
            "paired",
        }
        if (
            value.get("transaction_schema") != "claudian-remote.local-transaction/v1"
            or value.get("operation_id") != operation_id
            or not isinstance(completed, list)
            or not all(isinstance(item, str) and item in allowed for item in completed)
            or len(completed) != len(set(completed))
        ):
            return []
        return list(completed)

    def recovery_action(self, operation_id: str, plan_id: str) -> str:
        """Return an executable recovery action only for a valid owned journal."""

        path = self.dependencies.layout.state / f"{operation_id}.transaction.json"
        pairing_transition = self._pairing_identity_transition()
        if pairing_transition is not None:
            try:
                if pairing_transition.operation_rotation_committed(
                    operation_id=operation_id,
                    plan_id=plan_id,
                ):
                    return "resume"
            except ValueError:
                return "manual_recovery_required"
        migration_path = (
            self.dependencies.layout.state / f"{operation_id}.legacy-plugin.json"
        )
        if migration_path.is_file():
            try:
                retirement = inspect_legacy_retirement_journal(
                    migration_path,
                    operation_id=operation_id,
                    plan_id=plan_id,
                )
            except ValueError:
                return "manual_recovery_required"
            if retirement == "retired":
                return "finish_forward"
            if retirement == "retirement_outcome_unknown":
                return "reconcile_retirement_outcome"
            if retirement == "inconclusive":
                return "manual_recovery_required"
            if retirement == "not_applied":
                return "rollback"
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return "manual_recovery_required"
        found, _prior, _activation_started, _plugin_activated = (
            self._journal_rollback_context(
                path,
                operation_id=operation_id,
                plan_id=plan_id,
            )
        )
        if found and isinstance(value, Mapping) and value.get("phase") == "recovery_required":
            return "rollback"
        return "manual_recovery_required"

    def reconcile_legacy_retirement(
        self, plan: Mapping[str, Any], *, operation_id: str
    ) -> dict[str, Any]:
        """Reconcile an ambiguous retirement without continuing installation."""

        if plan.get("topology", {}).get("mode") != "local_tailscale":
            return {
                "state": "blocked",
                "code": "connection_mode_not_implemented",
                "mutation_performed": False,
            }
        plan_id = str(plan.get("plan_id") or "")
        installation_id = str(plan.get("installation_id") or "")
        vault_id = str(plan.get("vault_id") or "")
        if not plan_id or not installation_id or not vault_id:
            raise ValueError("incomplete_install_plan")
        migration = self._legacy_migration(
            vault_id,
            "local_tailscale",
            plan_id=plan_id,
            installation_id=installation_id,
        )
        try:
            outcome = migration.reconcile_retirement(operation_id=operation_id)
        except LegacyCredentialRetirementError as exc:
            if exc.code == "legacy_credential_retirement_inconclusive":
                return {
                    "state": "recovery_required",
                    "code": "legacy_retirement_reconciliation_inconclusive",
                    "mutation_performed": True,
                    "recovery_action": "manual_recovery_required",
                }
            raise
        if outcome.outcome == "retired":
            return {
                "state": "recovery_required",
                "code": "post_retirement_finish_forward_required",
                "mutation_performed": True,
                "recovery_action": "finish_forward",
                "retirement_commit": migration.retirement_commit(operation_id),
            }
        if outcome.outcome == "not_applied":
            return self.rollback(plan, operation_id=operation_id)
        return {
            "state": "recovery_required",
            "code": "legacy_retirement_reconciliation_inconclusive",
            "mutation_performed": True,
            "recovery_action": "manual_recovery_required",
        }

    @staticmethod
    def _bound_plugin_directory(path: Path, plugin_id: str) -> bool:
        if path.is_symlink() or not path.is_dir():
            return False
        manifest = path / "manifest.json"
        if manifest.is_symlink() or not manifest.is_file():
            return False
        try:
            value = json.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return False
        return isinstance(value, Mapping) and value.get("id") == plugin_id

    @staticmethod
    def _private_owned_directory(path: Path) -> bool:
        """Prove a lifecycle directory is local, owned, and peer read-only."""

        if path.is_symlink() or not path.is_dir():
            return False
        try:
            metadata = path.stat()
        except OSError:
            return False
        return (
            metadata.st_uid == os.getuid()
            and not (metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH))
        )

    def verify_supported_v1_staging_only_recovery(
        self,
        plan: Mapping[str, Any],
        *,
        operation_id: str,
        closed: bool = False,
        _journal_phase: str | None = None,
        _require_staging_absent: bool | None = None,
    ) -> bool:
        """Prove the one Beta 4 recovery shape that Beta 5 may close.

        This is intentionally narrower than ordinary transaction recovery.
        It binds the old journal to a live host state in which only an inert,
        operation-owned staging directory exists.  Any contradictory or
        unavailable probe leaves the original operation untouched for manual
        recovery.
        """

        layout = self.dependencies.layout
        plan_id = str(plan.get("plan_id") or "")
        compatibility_set_id = str(plan.get("compatibility_set_id") or "")
        vault_id = str(plan.get("vault_id") or "")
        if (
            not operation_id
            or not plan_id
            or not compatibility_set_id
            or not vault_id
            or plan.get("topology", {}).get("mode") != "local_tailscale"
        ):
            return False
        if not all(
            self._private_owned_directory(path)
            for path in (layout.base, layout.state, layout.staging)
        ):
            return False

        operation_file = layout.state / f"{operation_id}.transaction.json"
        try:
            journal = json.loads(operation_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return False
        expected_fields = {
            "transaction_schema",
            "operation_id",
            "plan_id",
            "phase",
            "completed_phases",
            "prior_availability_vault",
            "prior_release_id",
            "activation_started",
            "plugin_activated",
        }
        if (
            not isinstance(journal, Mapping)
            or set(journal) != expected_fields
            or journal.get("transaction_schema")
            != "claudian-remote.local-transaction/v1"
            or journal.get("operation_id") != operation_id
            or journal.get("plan_id") != plan_id
            or journal.get("phase")
            != (
                _journal_phase
                if _journal_phase is not None
                else ("rolled_back" if closed else "recovery_required")
            )
            or journal.get("completed_phases") != ["staging"]
            or journal.get("prior_availability_vault") is not None
            or journal.get("prior_release_id") is not None
            or journal.get("activation_started") is not False
            or journal.get("plugin_activated") is not False
        ):
            return False

        partial = layout.staging / f"{operation_id}.partial"
        require_staging_absent = (
            closed
            if _require_staging_absent is None
            else _require_staging_absent
        )
        if require_staging_absent:
            if partial.exists() or partial.is_symlink():
                return False
        elif partial.is_symlink() or (partial.exists() and not partial.is_dir()):
            return False

        forbidden_paths = (
            layout.release_path(compatibility_set_id),
            layout.current,
            layout.previous,
            layout.ownership_receipt,
            layout.backups / operation_id,
            layout.state / f"{operation_id}.legacy-plugin.json",
            layout.connection_profile,
            layout.relay_config,
            layout.companion_config,
            layout.secure_provisioning,
            layout.bridge_bootstrap,
            layout.bridge_bootstrap_ack,
        )
        if any(path.exists() or path.is_symlink() for path in forbidden_paths):
            return False
        if not self.dependencies.launchd.managed_agents_absent():
            return False
        serve_absent = getattr(
            self.dependencies.tailscale,
            "owned_serve_absent",
            None,
        )
        if not callable(serve_absent) or serve_absent(8787) is not True:
            return False
        try:
            listener_absent = self.dependencies.local_listener_absent_probe(8787)
        except Exception:
            return False
        if listener_absent is not True:
            return False

        try:
            vault = Path(self.dependencies.vault_path(vault_id))
        except Exception:
            return False
        if not vault.is_absolute() or vault.is_symlink() or not vault.is_dir():
            return False
        plugins = vault / ".obsidian" / "plugins"
        legacy = plugins / "whale-agent-bridge"
        current = plugins / "claudian-remote"
        if not self._bound_plugin_directory(legacy, "whale-agent-bridge"):
            return False
        legacy_data = legacy / "data.json"
        if legacy_data.is_symlink() or not legacy_data.is_file():
            return False
        if current.exists() or current.is_symlink():
            if not self._bound_plugin_directory(current, "claudian-remote"):
                return False
        enabled_path = vault / ".obsidian" / "community-plugins.json"
        if enabled_path.is_symlink() or not enabled_path.is_file():
            return False
        try:
            enabled = json.loads(enabled_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return False
        if (
            not isinstance(enabled, list)
            or not all(isinstance(item, str) for item in enabled)
            or "whale-agent-bridge" not in enabled
            or "claudian-remote" in enabled
        ):
            return False
        return True

    def rollback_supported_v1_staging_only(
        self,
        plan: Mapping[str, Any],
        *,
        operation_id: str,
    ) -> dict[str, Any]:
        """Close the exact Beta 4 staging-only crash shape.

        Unlike the ordinary rollback path, this method can only remove the
        operation-owned inert staging directory and close its transaction
        journal. It never mutates plugins, credentials, LaunchAgents, Serve,
        release pointers, or backups.
        """

        if self.verify_supported_v1_staging_only_recovery(
            plan,
            operation_id=operation_id,
            closed=True,
        ):
            return {
                "state": "rolled_back",
                "code": "rollback_already_completed",
                "mutation_performed": False,
                "restored_previous": False,
            }
        if not self.verify_supported_v1_staging_only_recovery(
            plan,
            operation_id=operation_id,
            closed=False,
        ):
            return {
                "state": "recovery_required",
                "code": "v1_recovery_effect_probe_failed",
                "mutation_performed": False,
                "restored_previous": False,
            }

        layout = self.dependencies.layout
        partial = layout.staging / f"{operation_id}.partial"
        operation_file = layout.state / f"{operation_id}.transaction.json"
        mutated = partial.exists()
        try:
            if mutated:
                shutil.rmtree(partial)
            if not self.verify_supported_v1_staging_only_recovery(
                plan,
                operation_id=operation_id,
                _journal_phase="recovery_required",
                _require_staging_absent=True,
            ):
                return {
                    "state": "recovery_required",
                    "code": "rollback_closure_unverified",
                    "mutation_performed": mutated,
                    "restored_previous": False,
                }
            journal = json.loads(operation_file.read_text(encoding="utf-8"))
            write_private_json(operation_file, {**journal, "phase": "rolled_back"})
        except (OSError, json.JSONDecodeError):
            return {
                "state": "recovery_required",
                "code": "rollback_closure_unverified",
                "mutation_performed": mutated,
                "restored_previous": False,
            }
        if not self.verify_supported_v1_staging_only_recovery(
            plan,
            operation_id=operation_id,
            closed=True,
        ):
            return {
                "state": "recovery_required",
                "code": "rollback_closure_unverified",
                "mutation_performed": True,
                "restored_previous": False,
            }
        return {
            "state": "rolled_back",
            "code": "rollback_completed",
            "mutation_performed": mutated,
            "restored_previous": False,
        }

    def cancel_pre_boundary(
        self,
        plan: Mapping[str, Any],
        *,
        operation_id: str,
    ) -> dict[str, Any]:
        """Cancel only an operation proven not to have begun activation.

        The only removable product artifact is the exact operation-owned
        staging directory.  A migration journal, backup, activated plugin, or
        unknown transaction shape makes cancellation unavailable.
        """

        layout = self.dependencies.layout
        plan_id = str(plan.get("plan_id") or "")
        operation_file = layout.state / f"{operation_id}.transaction.json"
        partial = layout.staging / f"{operation_id}.partial"
        migration_state = layout.state / f"{operation_id}.legacy-plugin.json"
        backup = layout.backups / operation_id
        if not plan_id or not operation_id:
            return {
                "state": "blocked",
                "code": "cancel_precondition_unverified",
                "mutation_performed": False,
            }

        try:
            journal = json.loads(operation_file.read_text(encoding="utf-8"))
        except FileNotFoundError:
            journal = None
        except (OSError, json.JSONDecodeError):
            journal = "invalid"

        if journal is None:
            if (
                partial.exists()
                or partial.is_symlink()
                or migration_state.exists()
                or migration_state.is_symlink()
                or backup.exists()
                or backup.is_symlink()
            ):
                return {
                    "state": "blocked",
                    "code": "cancel_precondition_unverified",
                    "mutation_performed": False,
                }
            return {
                "state": "rolled_back",
                "code": "operation_cancelled",
                "mutation_performed": False,
            }

        expected_fields = {
            "transaction_schema",
            "operation_id",
            "plan_id",
            "phase",
            "completed_phases",
            "prior_availability_vault",
            "prior_release_id",
            "activation_started",
            "plugin_activated",
        }
        if not isinstance(journal, Mapping) or set(journal) != expected_fields:
            valid = False
        else:
            phase = journal.get("phase")
            completed = journal.get("completed_phases")
            valid = (
                journal.get("transaction_schema")
                == "claudian-remote.local-transaction/v1"
                and journal.get("operation_id") == operation_id
                and journal.get("plan_id") == plan_id
                and journal.get("activation_started") is False
                and journal.get("plugin_activated") is False
                and (
                    (phase == "before_staging" and completed == [])
                    or (phase == "before_legacy_migration" and completed == ["staging"])
                    or (phase == "rolled_back" and completed in ([], ["staging"]))
                )
            )
        if (
            not valid
            or migration_state.exists()
            or migration_state.is_symlink()
            or backup.exists()
            or backup.is_symlink()
            or partial.is_symlink()
            or (partial.exists() and not self._private_owned_directory(partial))
        ):
            return {
                "state": "blocked",
                "code": "cancel_precondition_unverified",
                "mutation_performed": False,
            }
        if journal.get("phase") == "rolled_back":
            if partial.exists():
                return {
                    "state": "blocked",
                    "code": "cancel_precondition_unverified",
                    "mutation_performed": False,
                }
            return {
                "state": "rolled_back",
                "code": "operation_cancelled",
                "mutation_performed": False,
            }

        staged = partial.exists()
        try:
            if staged:
                shutil.rmtree(partial)
            if partial.exists() or partial.is_symlink():
                raise OSError("staging_cleanup_failed")
            write_private_json(operation_file, {**dict(journal), "phase": "rolled_back"})
        except OSError:
            return {
                "state": "recovery_required",
                "code": "cancel_cleanup_unverified",
                "mutation_performed": staged,
            }
        return {
            "state": "rolled_back",
            "code": "operation_cancelled",
            "mutation_performed": staged,
        }

    def _active_target(self) -> Path | None:
        current = self.dependencies.layout.current
        if not current.is_symlink():
            return None
        try:
            return current.resolve(strict=True)
        except OSError:
            return None

    def _activate(self, target: Path) -> None:
        current = self.dependencies.layout.current
        temporary = current.with_name(current.name + ".next")
        temporary.unlink(missing_ok=True)
        temporary.symlink_to(target)
        os.replace(temporary, current)

    def _set_previous(self, target: Path | None) -> None:
        previous = self.dependencies.layout.previous
        temporary = previous.with_name(previous.name + ".next")
        temporary.unlink(missing_ok=True)
        if target is None:
            previous.unlink(missing_ok=True)
            return
        temporary.symlink_to(target)
        os.replace(temporary, previous)

    def _plugin_destination(self, vault_id: str) -> Path:
        vault = Path(self.dependencies.vault_path(vault_id))
        if not vault.is_absolute():
            raise ValueError("vault_path_must_be_absolute")
        return vault / ".obsidian" / "plugins" / "claudian-remote"

    def _legacy_migration(
        self,
        vault_id: str,
        mode: str = "local_tailscale",
        *,
        plan_id: str = "",
        installation_id: str = "",
    ) -> LegacyPluginMigration:
        vault = Path(self.dependencies.vault_path(vault_id))
        if not vault.is_absolute():
            raise ValueError("vault_path_must_be_absolute")
        return LegacyPluginMigration(
            vault,
            self.dependencies.layout.state,
            self.dependencies.legacy_credential_revoker,
            target_plan_id=plan_id,
            target_installation_id=installation_id,
            target_vault_id=vault_id,
            target_mode=mode,
            interruption_probe=self._interrupt,
        )

    @staticmethod
    def _validate_plugin_binding(destination: Path, vault_id: str) -> None:
        data = destination / "data.json"
        if not data.is_file():
            return
        try:
            value = json.loads(data.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError("plugin_sync_preferences_invalid") from exc
        if not isinstance(value, Mapping):
            raise ValueError("plugin_sync_preferences_invalid")
        bound_vault = str(value.get("vault_id") or "")
        if bound_vault and bound_vault != vault_id:
            raise ValueError("plugin_vault_binding_mismatch")

    def _activate_plugin(
        self,
        source: Path,
        destination: Path,
        operation_id: str,
        *,
        vault_id: str,
        connection_mode: str,
    ) -> Path | None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        backup = self.dependencies.layout.backups / operation_id / "plugin"
        backup.parent.mkdir(parents=True, exist_ok=True)
        preferences: dict[str, Any] = {}
        existing_data = (backup if backup.exists() else destination) / "data.json"
        if existing_data.is_file():
            try:
                value = json.loads(existing_data.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise ValueError("plugin_sync_preferences_invalid") from exc
            if not isinstance(value, Mapping):
                raise ValueError("plugin_sync_preferences_invalid")
            bound_vault = str(value.get("vault_id") or "")
            if bound_vault and bound_vault != vault_id:
                raise ValueError("plugin_vault_binding_mismatch")
            preferences = dict(value)
        moved_original = not backup.exists() and destination.exists()
        if moved_original:
            destination.replace(backup)
        elif backup.exists():
            # A crash may occur after the original plugin was backed up but
            # before the activation checkpoint. Preserve that one rollback
            # boundary instead of replacing it with the staged plugin.
            shutil.rmtree(destination, ignore_errors=True)
        staging = destination.parent / f".{destination.name}.{operation_id}.next"
        shutil.rmtree(staging, ignore_errors=True)
        try:
            shutil.copytree(source, staging)
            write_sync_preferences(
                staging / "data.json",
                preferences,
                vault_id=vault_id,
                connection_mode=connection_mode,
            )
            staging.replace(destination)
        except Exception:
            shutil.rmtree(staging, ignore_errors=True)
            if moved_original and backup.exists() and not destination.exists():
                backup.replace(destination)
            raise
        return backup if backup.exists() else None

    @staticmethod
    def _restore_plugin(destination: Path, backup: Path | None) -> None:
        shutil.rmtree(destination, ignore_errors=True)
        if backup and backup.exists():
            backup.replace(destination)

    def _record_receipt(
        self,
        *,
        operation_id: str,
        compatibility_set_id: str,
        release_target: Path,
        plugin: Path,
        vault_id: str,
    ) -> None:
        layout = self.dependencies.layout
        resources = [
            ("managed_runtime", layout.runtime),
            ("managed_release_store", layout.releases),
            ("active_release_pointer", layout.current),
            ("previous_release_pointer", layout.previous),
            ("active_release", release_target),
            ("relay_launch_agent", layout.relay_launch_agent),
            ("companion_launch_agent", layout.companion_launch_agent),
            ("availability_launch_agent", layout.availability_launch_agent),
            ("availability_config", layout.availability_config),
            ("connection_profile", layout.connection_profile),
            ("relay_config", layout.relay_config),
            ("companion_config", layout.companion_config),
            ("secure_provisioning", layout.secure_provisioning),
            ("bridge_bootstrap", layout.bridge_bootstrap_for(vault_id)),
            ("bridge_bootstrap_ack", layout.bridge_bootstrap_ack),
        ]
        entries = [
            {
                "resource_id": resource_id,
                "path": str(path),
                "kind": "symlink" if path.is_symlink() else "directory" if path.is_dir() else "file",
                "digest": tree_digest(path),
                "owned": True,
            }
            for resource_id, path in resources
            if path.exists() or path.is_symlink()
        ]
        # The plugin directory may gain normal device-local state such as
        # data.json after activation. Record shipped files independently so a
        # later uninstall can remove exact owned code without treating user
        # settings as package tampering.
        entries.append({
            "resource_id": "plugin_directory",
            "path": str(plugin),
            "kind": "directory",
            "owned": True,
            "removal_policy": "remove_if_empty_after_shipped_files",
        })
        for source in sorted((release_target / "plugin").rglob("*")):
            if not source.is_file() or source.is_symlink():
                continue
            relative = source.relative_to(release_target / "plugin")
            destination = plugin / relative
            entries.append({
                "resource_id": "plugin_shipped_file:" + relative.as_posix(),
                "path": str(destination),
                "kind": "file",
                "digest": tree_digest(destination),
                "owned": True,
                "conflict_policy": "preserve_and_report_if_modified",
            })
        receipt = {
            "receipt_schema": "claudian-remote.ownership/v1",
            "operation_id": operation_id,
            "compatibility_set_id": compatibility_set_id,
            "plugin_root": str(plugin),
            "resources": entries,
        }
        write_private_json(layout.ownership_receipt, receipt)

    def _already_ready(self, target: Path, plan: Mapping[str, Any]) -> bool:
        layout = self.dependencies.layout
        try:
            profile = json.loads(layout.connection_profile.read_text(encoding="utf-8"))
            endpoint = str(profile.get("endpoint") or "")
        except (OSError, ValueError, TypeError):
            endpoint = ""
        return (
            self._active_target() == target
            and layout.ownership_receipt.is_file()
            and self._legacy_migration(
                str(plan.get("vault_id") or ""),
                str(plan.get("topology", {}).get("mode") or "local_tailscale"),
            ).is_clean()
            and self.dependencies.launchd.status().get("ready") is True
            and bool(endpoint)
            and self._profile_matches(plan, endpoint)
            and self.dependencies.tailscale.verify(endpoint)
            and self.dependencies.health_probe()
            and self.dependencies.bridge_ready_probe()
            and self.dependencies.pairing_probe()
        )

    def verify(self, plan: Mapping[str, Any]) -> dict[str, Any]:
        self._legacy_migration(
            str(plan.get("vault_id") or ""),
            str(plan.get("topology", {}).get("mode") or "local_tailscale"),
        ).validate_coexistence()
        target = self.dependencies.layout.release_path(str(plan.get("compatibility_set_id") or ""))
        if self._already_ready(target, plan):
            return {"state": "ready", "code": "verification_ready", "mutation_performed": False}
        return {"state": "blocked", "code": "verification_failed", "mutation_performed": False}

    def rollback(self, plan: Mapping[str, Any], *, operation_id: str) -> dict[str, Any]:
        layout = self.dependencies.layout
        pairing_policy = str(plan.get("pairing_identity_policy") or "")
        pairing_transition = (
            self._pairing_identity_transition()
            if plan.get("journey") == "current_update"
            else None
        )
        if plan.get("journey") == "current_update" and pairing_policy == "rotate":
            if pairing_transition is None:
                return {
                    "state": "recovery_required",
                    "code": "pairing_identity_authority_unavailable",
                    "mutation_performed": False,
                    "recovery_action": "manual_recovery_required",
                }
            try:
                if pairing_transition.rotation_committed(
                    operation_id=operation_id,
                    plan_id=str(plan.get("plan_id") or ""),
                    policy=pairing_policy,
                ):
                    return {
                        "state": "blocked",
                        "code": "rollback_unavailable_after_pairing_rotation",
                        "mutation_performed": False,
                        "recovery_action": "resume",
                    }
            except ValueError:
                return {
                    "state": "recovery_required",
                    "code": "pairing_identity_journal_invalid",
                    "mutation_performed": False,
                    "recovery_action": "manual_recovery_required",
                }
        migration_path = layout.state / f"{operation_id}.legacy-plugin.json"
        if migration_path.is_file():
            try:
                retirement = inspect_legacy_retirement_journal(
                    migration_path,
                    operation_id=operation_id,
                    plan_id=str(plan.get("plan_id") or ""),
                )
            except ValueError:
                return {
                    "state": "recovery_required",
                    "code": "rollback_context_invalid",
                    "mutation_performed": False,
                    "recovery_action": "manual_recovery_required",
                }
            if retirement in {"retired", "retirement_outcome_unknown", "inconclusive"}:
                return {
                    "state": "blocked",
                    "code": (
                        "rollback_unavailable_after_retirement"
                        if retirement == "retired"
                        else (
                            "legacy_retirement_reconciliation_inconclusive"
                            if retirement == "inconclusive"
                            else "rollback_unavailable_after_dispatch"
                        )
                    ),
                    "mutation_performed": False,
                    "recovery_action": (
                        "finish_forward"
                        if retirement == "retired"
                        else (
                            "manual_recovery_required"
                            if retirement == "inconclusive"
                            else "reconcile_retirement_outcome"
                        )
                    ),
                }
        current = self._active_target()
        plugin = self._plugin_destination(str(plan.get("vault_id") or ""))
        backup = layout.backups / operation_id / "plugin"
        prior_availability_vault = self.dependencies.launchd.availability_vault_name()
        operation_file = layout.state / f"{operation_id}.transaction.json"
        found_context, prior_target, activation_started, plugin_activated = (
            self._journal_rollback_context(
                operation_file,
                operation_id=operation_id,
                plan_id=str(plan.get("plan_id") or ""),
            )
        )
        if not found_context:
            return {
                "state": "recovery_required",
                "code": "rollback_context_invalid",
                "mutation_performed": False,
                "restored_previous": False,
            }
        found_binding, journal_binding = self._journal_availability_binding(
            operation_file,
            operation_id=operation_id,
            plan_id=str(plan.get("plan_id") or ""),
        )
        if found_binding:
            prior_availability_vault = journal_binding
        planned_target = layout.release_path(str(plan.get("compatibility_set_id") or ""))
        release_activated = current == planned_target
        runtime_mutated = activation_started or plugin_activated or backup.exists() or release_activated
        if runtime_mutated:
            self.dependencies.launchd.remove_local_agents()
            self.dependencies.tailscale.remove_serve()
            if plugin_activated or backup.exists():
                self._restore_plugin(plugin, backup if backup.exists() else None)
            if prior_target:
                self._activate(prior_target)
                python = layout.environment_python(prior_target.name)
                if python.is_file():
                    self.dependencies.launchd.install_local_agents(
                        python,
                        vault_name=(
                            prior_availability_vault
                            if self._supports_availability(prior_target)
                            else None
                        ),
                    )
                self.dependencies.tailscale.activate_serve(8787)
            else:
                layout.current.unlink(missing_ok=True)
        self._legacy_migration(
            str(plan.get("vault_id") or ""),
            plan_id=str(plan.get("plan_id") or ""),
            installation_id=str(plan.get("installation_id") or ""),
        ).rollback(operation_id=operation_id)
        if pairing_transition is not None:
            try:
                if not pairing_transition.rollback(
                    operation_id=operation_id,
                    plan_id=str(plan.get("plan_id") or ""),
                    policy=pairing_policy,
                ):
                    return {
                        "state": "blocked",
                        "code": "rollback_unavailable_after_pairing_rotation",
                        "mutation_performed": runtime_mutated,
                        "recovery_action": "resume",
                    }
            except ValueError:
                return {
                    "state": "recovery_required",
                    "code": "pairing_identity_journal_invalid",
                    "mutation_performed": runtime_mutated,
                    "recovery_action": "manual_recovery_required",
                }
        shutil.rmtree(layout.staging / f"{operation_id}.partial", ignore_errors=True)
        try:
            journal = json.loads(operation_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            journal = None
        if (
            isinstance(journal, Mapping)
            and journal.get("transaction_schema") == "claudian-remote.local-transaction/v1"
            and journal.get("operation_id") == operation_id
            and journal.get("plan_id") == str(plan.get("plan_id") or "")
        ):
            write_private_json(operation_file, {**journal, "phase": "rolled_back"})
        return {
            "state": "rolled_back",
            "code": "rollback_completed",
            "mutation_performed": runtime_mutated,
            "restored_previous": runtime_mutated and prior_target is not None,
        }

    def install(self, plan: Mapping[str, Any], *, operation_id: str) -> dict[str, Any]:
        if plan.get("topology", {}).get("mode") != "local_tailscale":
            return {"state": "blocked", "code": "connection_mode_not_implemented", "mutation_performed": False}
        if plan.get("blockers"):
            return {"state": "blocked", "code": str(plan["blockers"][0]), "mutation_performed": False}
        if (
            plan.get("journey") == "legacy_upgrade"
            and plan.get("prior_operation_terminal") is not True
        ):
            return {
                "state": "blocked",
                "code": "prior_operation_not_terminal",
                "mutation_performed": False,
                "recovery_action": "reconcile_prior_operation",
            }
        compatibility_set_id = str(plan.get("compatibility_set_id") or "")
        installation_id = str(plan.get("installation_id") or "")
        vault_id = str(plan.get("vault_id") or "")
        plan_id = str(plan.get("plan_id") or "")
        journey = str(plan.get("journey") or "fresh_install")
        pairing_policy = str(plan.get("pairing_identity_policy") or "not_applicable")
        if not compatibility_set_id or not installation_id or not vault_id:
            raise ValueError("incomplete_install_plan")
        pairing_transition = self._pairing_identity_transition()
        if journey == "current_update":
            if pairing_policy not in {"preserve", "rotate"}:
                raise ValueError("current_update_pairing_identity_policy_invalid")
            if pairing_transition is None or (
                pairing_policy == "rotate"
                and self.dependencies.revoke_pairing_device is None
            ):
                return {
                    "state": "blocked",
                    "code": "pairing_identity_authority_unavailable",
                    "mutation_performed": False,
                }

        migration = self._legacy_migration(
            vault_id,
            "local_tailscale",
            plan_id=str(plan.get("plan_id") or ""),
            installation_id=installation_id,
        )
        migration.validate_coexistence()
        self._validate_plugin_binding(self._plugin_destination(vault_id), vault_id)
        if (
            migration.credential_revocation_required()
            and self.dependencies.legacy_credential_revoker is None
        ):
            return {
                "state": "blocked",
                "code": "legacy_credential_revocation_unavailable",
                "mutation_performed": False,
                "recovery_action": "retire_legacy_credential_and_retry",
            }
        if migration.requires_migration() and not self.dependencies.migration_safe_probe():
            return {
                "state": "blocked",
                "code": "obsidian_close_for_migration_required",
                "mutation_performed": False,
                "gate": {
                    "gate_type": "obsidian_close_for_migration_required",
                    "explanation": "The legacy plugin must be unloaded before its credential and files are migrated.",
                    "exact_action": "Close Obsidian completely on this Mac, then resume this operation.",
                    "verification_probe": "obsidian_closed_for_migration",
                    "resume_reference": operation_id,
                },
            }

        # Verify the signed-set handoff before creating any product resource.
        self.dependencies.release_source.verify(plan)
        preflight = dict(self.dependencies.tailscale.preflight())
        if preflight.get("state") != "ready":
            return {**preflight, "mutation_performed": False}
        endpoint = str(preflight.get("endpoint") or "")
        expected_audience = f"claudian-remote:local_tailscale:{installation_id}"
        target = self.dependencies.layout.release_path(compatibility_set_id)
        if target.exists() and self._already_ready(target, plan):
            identity_ready = True
            if pairing_transition is not None and journey == "current_update":
                try:
                    identity_ready = pairing_transition.ready(
                        operation_id=operation_id,
                        plan_id=plan_id,
                        policy=pairing_policy,
                    )
                except ValueError as exc:
                    return {
                        "state": "recovery_required",
                        "code": str(exc),
                        "mutation_performed": False,
                        "recovery_action": "manual_recovery_required",
                    }
            if identity_ready:
                return {"state": "ready", "code": "already_ready", "mutation_performed": False}

        layout = self.dependencies.layout
        layout.ensure()
        if pairing_transition is not None and journey == "current_update":
            try:
                pairing_transition.capture(
                    operation_id=operation_id,
                    plan_id=plan_id,
                    policy=pairing_policy,
                )
            except (ValueError, RuntimeError) as exc:
                return {
                    "state": "blocked",
                    "code": (
                        str(exc)
                        if isinstance(exc, ValueError)
                        else "pairing_device_inventory_unavailable"
                    ),
                    "mutation_performed": False,
                }
        operation_file = layout.state / f"{operation_id}.transaction.json"
        prior_availability_vault = self.dependencies.launchd.availability_vault_name()
        prior_target = self._active_target()
        activation_started = False
        plugin_activated = False

        pairing_rotation_committed = bool(
            pairing_transition is not None
            and journey == "current_update"
            and pairing_policy == "rotate"
            and pairing_transition.rotation_committed(
                operation_id=operation_id,
                plan_id=plan_id,
                policy=pairing_policy,
            )
        )
        resumed_after_activation = False
        prior_operation: dict[str, Any] = {}
        if operation_file.is_file():
            try:
                prior_operation = json.loads(operation_file.read_text(encoding="utf-8"))
                resumed_after_activation = (
                    prior_operation.get("operation_id") == operation_id
                    and prior_operation.get("plan_id") == plan.get("plan_id")
                    and prior_operation.get("phase") in {
                        "after_activation", "await_plugin_bootstrap", "await_pairing",
                        "recovery_required",
                    }
                    and (
                        prior_operation.get("phase") != "recovery_required"
                        or pairing_rotation_committed
                    )
                    and self._active_target() == target
                )
                found_context, journal_target, journal_activation, journal_plugin = (
                    self._journal_rollback_context(
                        operation_file,
                        operation_id=operation_id,
                        plan_id=str(plan.get("plan_id") or ""),
                    )
                )
                if found_context:
                    prior_target = journal_target
                    activation_started = journal_activation
                    plugin_activated = journal_plugin
            except (OSError, ValueError, TypeError):
                resumed_after_activation = False
        found_binding, journal_binding = self._journal_availability_binding(
            operation_file,
            operation_id=operation_id,
            plan_id=str(plan.get("plan_id") or ""),
        )
        if found_binding:
            prior_availability_vault = journal_binding

        def persist(name: str, completed: list[str]) -> None:
            write_private_json(
                operation_file,
                {
                    "transaction_schema": "claudian-remote.local-transaction/v1",
                    "operation_id": operation_id,
                    "plan_id": plan["plan_id"],
                    "phase": name,
                    "completed_phases": completed,
                    "prior_availability_vault": prior_availability_vault,
                    "prior_release_id": prior_target.name if prior_target else None,
                    "activation_started": activation_started,
                    "plugin_activated": plugin_activated,
                },
            )

        def phase(name: str, completed: list[str]) -> None:
            persist(name, completed)
            self._interrupt(name)

        plugin_destination = self._plugin_destination(vault_id)
        backup_candidate = layout.backups / operation_id / "plugin"
        plugin_backup: Path | None = backup_candidate if backup_candidate.exists() else None
        plugin_activated = plugin_activated or resumed_after_activation

        def compensate(code: str, completed: list[str]) -> dict[str, Any]:
            if pairing_rotation_committed:
                persist("recovery_required", completed)
                return {
                    "state": "recovery_required",
                    "code": "current_update_pairing_recovery_required",
                    "mutation_performed": True,
                    "recovery_action": "resume",
                    "re_pair_required": True,
                }
            retirement = migration.retirement_state(operation_id)
            if retirement in {"retired", "retirement_outcome_unknown", "inconclusive"}:
                persist("recovery_required", completed)
                return {
                    "state": "recovery_required",
                    "code": (
                        "post_retirement_finish_forward_required"
                        if retirement == "retired"
                        else (
                            "legacy_retirement_reconciliation_inconclusive"
                            if retirement == "inconclusive"
                            else "legacy_retirement_outcome_unknown"
                        )
                    ),
                    "mutation_performed": True,
                    "recovery_action": (
                        "finish_forward"
                        if retirement == "retired"
                        else (
                            "manual_recovery_required"
                            if retirement == "inconclusive"
                            else "reconcile_retirement_outcome"
                        )
                    ),
                    "retirement_commit": migration.retirement_commit(operation_id),
                }
            try:
                runtime_mutated = activation_started or plugin_activated
                if runtime_mutated:
                    self.dependencies.launchd.remove_local_agents()
                    self.dependencies.tailscale.remove_serve()
                    if plugin_activated:
                        self._restore_plugin(plugin_destination, plugin_backup)
                migration.rollback(operation_id=operation_id)
                if pairing_transition is not None and journey == "current_update":
                    if not pairing_transition.rollback(
                        operation_id=operation_id,
                        plan_id=plan_id,
                        policy=pairing_policy,
                    ):
                        raise RuntimeError("pairing_rotation_already_committed")
                if runtime_mutated:
                    if prior_target:
                        self._activate(prior_target)
                        prior_python = layout.environment_python(prior_target.name)
                        if prior_python.is_file():
                            self.dependencies.launchd.install_local_agents(
                                prior_python,
                                vault_name=(
                                    prior_availability_vault
                                    if self._supports_availability(prior_target)
                                    else None
                                ),
                            )
                        self.dependencies.tailscale.activate_serve(8787)
                    else:
                        layout.current.unlink(missing_ok=True)
                shutil.rmtree(layout.staging / f"{operation_id}.partial", ignore_errors=True)
                write_private_json(operation_file, {
                    "transaction_schema": "claudian-remote.local-transaction/v1",
                    "operation_id": operation_id,
                    "plan_id": plan["plan_id"],
                    "phase": "rolled_back",
                    "completed_phases": completed,
                    "prior_availability_vault": prior_availability_vault,
                    "prior_release_id": prior_target.name if prior_target else None,
                    "activation_started": activation_started,
                    "plugin_activated": plugin_activated,
                })
                return {"state": "rolled_back", "code": code, "mutation_performed": True}
            except Exception:
                write_private_json(operation_file, {
                    "transaction_schema": "claudian-remote.local-transaction/v1",
                    "operation_id": operation_id,
                    "plan_id": plan["plan_id"],
                    "phase": "recovery_required",
                    "completed_phases": completed,
                    "prior_availability_vault": prior_availability_vault,
                    "prior_release_id": prior_target.name if prior_target else None,
                    "activation_started": activation_started,
                    "plugin_activated": plugin_activated,
                })
                return {
                    "state": "recovery_required",
                    "code": "installation_compensation_failed",
                    "mutation_performed": True,
                }

        if resumed_after_activation:
            completed = list(prior_operation.get("completed_phases") or [])
        else:
            completed = []
            phase("before_staging", completed)
            partial = layout.staging / f"{operation_id}.partial"
            shutil.rmtree(partial, ignore_errors=True)
            staged: StagedRelease
            if target.exists():
                python = layout.environment_python(compatibility_set_id)
                if not python.is_file():
                    raise RuntimeError("runtime_environment_missing")
                uv = next((layout.runtime / "uv").glob("*/uv"))
                staged = StagedRelease(target, target / "plugin", python, uv, target.name)
            else:
                staged = self.dependencies.release_source.stage(plan, partial, layout.runtime)
            completed.append("staging")
            if migration.credential_revocation_required():
                revoker = self.dependencies.legacy_credential_revoker
                assert revoker is not None
                if not revoker.authorized(
                    operation_id=operation_id,
                    plan_id=str(plan.get("plan_id") or ""),
                ):
                    persist("before_legacy_migration", completed)
                    return {
                        "state": "blocked",
                        "code": "legacy_authority_authorization_required",
                        "mutation_performed": True,
                        "gate": {
                            "gate_type": "legacy_authority_authorization_required",
                            "explanation": (
                                "Retiring the legacy mobile credential will require "
                                "this installation to pair the iPhone again."
                            ),
                            "exact_action": (
                                "Review the bounded installation and authority identity, "
                                "then explicitly authorize retirement while resuming this "
                                "same operation."
                            ),
                            "verification_probe": "legacy_authority_available",
                            "resume_reference": operation_id,
                            "operator_options": (
                                {
                                    "id": "authorize_retirement",
                                    "label": "Authorize retirement",
                                    "instructions": (
                                        "Run resume for this operation with "
                                        "--authorize-legacy-retirement to open the native "
                                        "macOS confirmation. The user must review and "
                                        "approve the re-pairing impact in that dialog."
                                    ),
                                    "recommended": True,
                                },
                            ),
                        },
                    }
            phase("before_legacy_migration", completed)
            try:
                migration.prepare(operation_id=operation_id)
                completed.append("legacy_plugin_migration")
            except LifecycleInterrupted:
                raise
            except Exception as exc:
                # prepare can fail after an authoritative credential revoke;
                # reconcile through the migration rollback instead of claiming
                # that no mutation occurred.
                if not migration.journal_present(operation_id):
                    raise
                if (
                    isinstance(exc, LegacyCredentialRetirementError)
                    and exc.code == "legacy_credential_retirement_outcome_unknown"
                ):
                    return compensate(
                        "legacy_retirement_outcome_unknown", completed
                    )
                recovered = compensate("installation_failed_rolled_back", completed)
                if (
                    isinstance(exc, LegacyCredentialRetirementError)
                    and exc.code == "legacy_credential_revocation_unverified"
                    and recovered.get("state") == "rolled_back"
                ):
                    return {
                        "state": "blocked",
                        "code": "legacy_credential_revocation_required",
                        "mutation_performed": True,
                        "recovery_action": "retire_legacy_credential_and_retry",
                    }
                return recovered
            phase("before_activation", completed)

            try:
                activation_started = True
                persist("activation_started", completed)
                self._set_previous(prior_target)
                if not target.exists():
                    partial.replace(target)
                provisioner = PairingAdminProvisioner(layout, self.dependencies.keychain)
                provisioning = provisioner.provision(
                    installation_id=installation_id,
                    vault_id=vault_id,
                    endpoint=endpoint,
                    endpoint_audience=expected_audience,
                )
                if provisioning.get("secure_provisioning_available") is not True:
                    raise RuntimeError("secure_provisioning_failed")
                completed.append("secure_provisioning")
                plugin_backup = self._activate_plugin(
                    target / "plugin",
                    plugin_destination,
                    operation_id,
                    vault_id=vault_id,
                    connection_mode="local_tailscale",
                )
                plugin_activated = True
                persist("plugin_activated", completed)
                migration.activate_new(
                    operation_id=operation_id,
                    destination=plugin_destination,
                )
                self._activate(target)
                self.dependencies.launchd.install_local_agents(
                    staged.python_executable,
                    vault_name=Path(self.dependencies.vault_path(vault_id)).name,
                )
                self.dependencies.tailscale.activate_serve(8787)
                completed.extend(["plugin_activation", "launchd", "tailscale_serve"])
                phase("after_activation", completed)
            except LifecycleInterrupted:
                raise
            except Exception:
                return compensate("installation_failed_rolled_back", completed)

        # Verify exposure topology and application health exactly once each.
        if not self._profile_matches(plan, endpoint) or not self._wait_ready(endpoint):
            return compensate("post_activation_verification_failed", completed)

        # Once activation is healthy, record ownership before waiting on any
        # external gate. This keeps uninstall available even if the user never
        # opens Obsidian or finishes phone pairing.
        self._record_receipt(
            operation_id=operation_id,
            compatibility_set_id=compatibility_set_id,
            release_target=target,
            plugin=plugin_destination,
            vault_id=vault_id,
        )
        if not self._wait_bridge_ready():
            write_private_json(operation_file, {
                "transaction_schema": "claudian-remote.local-transaction/v1",
                "operation_id": operation_id,
                "plan_id": plan["plan_id"],
                "phase": "await_plugin_bootstrap",
                "completed_phases": completed,
                "prior_availability_vault": prior_availability_vault,
                "prior_release_id": prior_target.name if prior_target else None,
                "activation_started": activation_started,
                "plugin_activated": plugin_activated,
            })
            availability_state = str(
                self.dependencies.launchd.status().get("availability") or "launch_pending"
            )
            launch_failed = availability_state in {"launch_failed", "status_invalid"}
            return {
                "state": "blocked",
                "code": "desktop_plugin_bootstrap_required",
                "mutation_performed": True,
                "gate": {
                    "gate_type": "desktop_plugin_bootstrap_required",
                    "explanation": (
                        "Claudian Remote could not open the selected Obsidian Vault automatically."
                        if launch_failed
                        else "Claudian Remote requested the selected Obsidian Vault, but its plugin has not authenticated to the Companion Bridge yet."
                    ),
                    "exact_action": "Confirm Obsidian is installed and Claudian Remote is enabled in the selected Vault, then open or reload that Vault and resume this operation.",
                    "verification_probe": "desktop_plugin_authenticated",
                    "resume_reference": operation_id,
                },
            }

        # Re-record after authenticated bootstrap so the one-time ack is also
        # owned and ordinary uninstall can remove it.
        self._record_receipt(
            operation_id=operation_id,
            compatibility_set_id=compatibility_set_id,
            release_target=target,
            plugin=plugin_destination,
            vault_id=vault_id,
        )
        migration.commit(operation_id=operation_id)
        completed.append("verified")
        pairing_result: dict[str, Any]
        if journey == "current_update":
            assert pairing_transition is not None
            try:
                pairing_result = pairing_transition.finalize(
                    operation_id=operation_id,
                    plan_id=plan_id,
                    policy=pairing_policy,
                )
            except LifecycleInterrupted:
                raise
            except (ValueError, RuntimeError) as exc:
                persist("recovery_required", completed)
                return {
                    "state": "recovery_required",
                    "code": (
                        str(exc)
                        if isinstance(exc, ValueError)
                        else "pairing_device_inventory_unavailable"
                    ),
                    "mutation_performed": True,
                    "recovery_action": "manual_recovery_required",
                }
        else:
            pairing_ready = self.dependencies.pairing_probe()
            pairing_result = {
                "state": "ready" if pairing_ready else "blocked",
                "code": (
                    "pairing_ready"
                    if pairing_ready
                    else "pairing_approval_required"
                ),
                "re_pair_required": not pairing_ready,
            }
        if pairing_result.get("state") != "ready":
            if pairing_result.get("re_pair_required") is not True:
                persist("recovery_required", completed)
                return {
                    "state": "recovery_required",
                    "code": str(
                        pairing_result.get("code")
                        or "pairing_identity_transition_failed"
                    ),
                    "mutation_performed": True,
                    "recovery_action": "resume",
                    "re_pair_required": False,
                }
            write_private_json(operation_file, {
                "transaction_schema": "claudian-remote.local-transaction/v1",
                "operation_id": operation_id,
                "plan_id": plan["plan_id"],
                "phase": "await_pairing",
                "completed_phases": completed,
                "prior_availability_vault": prior_availability_vault,
                "prior_release_id": prior_target.name if prior_target else None,
                "activation_started": activation_started,
                "plugin_activated": plugin_activated,
            })
            return {
                "state": "blocked",
                "code": str(pairing_result.get("code") or "pairing_approval_required"),
                "mutation_performed": True,
                "re_pair_required": pairing_result.get("re_pair_required") is True,
                "gate": {
                    "gate_type": "pairing_approval_required",
                    "explanation": (
                        "The signed update requires a deliberate new phone pairing."
                        if pairing_policy == "rotate"
                        else (
                            "The update could not prove that the existing phone identity was preserved."
                            if pairing_result.get("code")
                            == "pairing_identity_preservation_failed"
                            else "Approve the phone shown by the Mac pairing UI."
                        )
                    ),
                    "exact_action": (
                        "Run a separately signed rotate update or restore the existing active phone identity."
                        if pairing_result.get("code")
                        == "pairing_identity_preservation_failed"
                        else "Redeem the one-time code on the phone and approve that device on the Mac."
                    ),
                    "verification_probe": "pairing_credential_active",
                    "resume_reference": operation_id,
                },
            }
        write_private_json(operation_file, {
            "transaction_schema": "claudian-remote.local-transaction/v1",
            "operation_id": operation_id,
            "plan_id": plan["plan_id"],
            "phase": "ready",
            "completed_phases": completed + ["paired"],
            "prior_availability_vault": prior_availability_vault,
            "prior_release_id": prior_target.name if prior_target else None,
            "activation_started": activation_started,
            "plugin_activated": plugin_activated,
        })
        return {"state": "ready", "code": "installation_ready", "mutation_performed": True}
