"""Atomic, resumable Mac-local installation transaction."""

from __future__ import annotations

import json
import os
import shutil
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from .launchd import LaunchAgentManager
from .migrations import LegacyPluginMigration, write_sync_preferences
from .private_io import tree_digest, write_private_json
from .provisioning import PairingAdminProvisioner
from .runtime import ReleaseSource, RuntimeLayout, StagedRelease


class LifecycleInterrupted(RuntimeError):
    pass


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
    legacy_credential_revoker: Callable[[str], Any]
    bridge_ready_probe: Callable[[], bool] = lambda: True
    migration_safe_probe: Callable[[], bool] = lambda: True
    interruption_probe: Callable[[str], bool] = lambda _phase: False
    readiness_attempts: int = 20
    readiness_delay_seconds: float = 0.25
    sleep: Callable[[float], None] = time.sleep


class LocalTailscaleTransaction:
    def __init__(self, dependencies: TransactionDependencies) -> None:
        self.dependencies = dependencies

    def _interrupt(self, phase: str) -> None:
        if self.dependencies.interruption_probe(phase):
            raise LifecycleInterrupted(phase)

    def _wait_ready(self, endpoint: str) -> bool:
        attempts = max(1, min(int(self.dependencies.readiness_attempts), 120))
        delay = max(0.0, min(float(self.dependencies.readiness_delay_seconds), 5.0))
        for attempt in range(attempts):
            if self.dependencies.tailscale.verify(endpoint) and self.dependencies.health_probe():
                return True
            if attempt + 1 < attempts and delay:
                self.dependencies.sleep(delay)
        return False

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

    def _legacy_migration(self, vault_id: str, mode: str = "local_tailscale") -> LegacyPluginMigration:
        vault = Path(self.dependencies.vault_path(vault_id))
        if not vault.is_absolute():
            raise ValueError("vault_path_must_be_absolute")
        return LegacyPluginMigration(
            vault,
            self.dependencies.layout.state,
            self.dependencies.legacy_credential_revoker,
            target_vault_id=vault_id,
            target_mode=mode,
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
        current = self._active_target()
        previous = layout.previous.resolve(strict=True) if layout.previous.is_symlink() else None
        plugin = self._plugin_destination(str(plan.get("vault_id") or ""))
        backup = layout.backups / operation_id / "plugin"
        self.dependencies.launchd.remove_local_agents()
        self.dependencies.tailscale.remove_serve()
        if backup.exists():
            self._restore_plugin(plugin, backup)
        elif current:
            shutil.rmtree(plugin, ignore_errors=True)
        if previous:
            self._activate(previous)
            python = layout.environment_python(previous.name)
            if python.is_file():
                self.dependencies.launchd.install_local_agents(python)
            self.dependencies.tailscale.activate_serve(8787)
        else:
            layout.current.unlink(missing_ok=True)
        self._legacy_migration(str(plan.get("vault_id") or "")).rollback(operation_id=operation_id)
        return {
            "state": "rolled_back",
            "code": "rollback_completed",
            "mutation_performed": True,
            "restored_previous": previous is not None,
        }

    def install(self, plan: Mapping[str, Any], *, operation_id: str) -> dict[str, Any]:
        if plan.get("topology", {}).get("mode") != "local_tailscale":
            return {"state": "blocked", "code": "connection_mode_not_implemented", "mutation_performed": False}
        if plan.get("blockers"):
            return {"state": "blocked", "code": str(plan["blockers"][0]), "mutation_performed": False}
        compatibility_set_id = str(plan.get("compatibility_set_id") or "")
        installation_id = str(plan.get("installation_id") or "")
        vault_id = str(plan.get("vault_id") or "")
        if not compatibility_set_id or not installation_id or not vault_id:
            raise ValueError("incomplete_install_plan")

        migration = self._legacy_migration(vault_id, "local_tailscale")
        migration.validate_coexistence()
        self._validate_plugin_binding(self._plugin_destination(vault_id), vault_id)
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
            return {"state": "ready", "code": "already_ready", "mutation_performed": False}

        layout = self.dependencies.layout
        layout.ensure()
        operation_file = layout.state / f"{operation_id}.transaction.json"

        resumed_after_activation = False
        prior_operation: dict[str, Any] = {}
        if operation_file.is_file():
            try:
                prior_operation = json.loads(operation_file.read_text(encoding="utf-8"))
                resumed_after_activation = (
                    prior_operation.get("operation_id") == operation_id
                    and prior_operation.get("plan_id") == plan.get("plan_id")
                    and prior_operation.get("phase") in {
                        "after_activation", "await_plugin_bootstrap", "await_pairing"
                    }
                    and self._active_target() == target
                )
            except (OSError, ValueError, TypeError):
                resumed_after_activation = False

        def phase(name: str, completed: list[str]) -> None:
            write_private_json(
                operation_file,
                {
                    "transaction_schema": "claudian-remote.local-transaction/v1",
                    "operation_id": operation_id,
                    "plan_id": plan["plan_id"],
                    "phase": name,
                    "completed_phases": completed,
                },
            )
            self._interrupt(name)

        plugin_destination = self._plugin_destination(vault_id)
        backup_candidate = layout.backups / operation_id / "plugin"
        plugin_backup: Path | None = backup_candidate if backup_candidate.exists() else None
        plugin_activated = resumed_after_activation
        prior_target = layout.previous.resolve(strict=True) if resumed_after_activation and layout.previous.is_symlink() else None

        def compensate(code: str, completed: list[str]) -> dict[str, Any]:
            try:
                self.dependencies.launchd.remove_local_agents()
                self.dependencies.tailscale.remove_serve()
                if plugin_activated:
                    self._restore_plugin(plugin_destination, plugin_backup)
                migration.rollback(operation_id=operation_id)
                if prior_target:
                    self._activate(prior_target)
                    prior_python = layout.environment_python(prior_target.name)
                    if prior_python.is_file():
                        self.dependencies.launchd.install_local_agents(prior_python)
                    self.dependencies.tailscale.activate_serve(8787)
                else:
                    layout.current.unlink(missing_ok=True)
                write_private_json(operation_file, {
                    "transaction_schema": "claudian-remote.local-transaction/v1",
                    "operation_id": operation_id,
                    "plan_id": plan["plan_id"],
                    "phase": "rolled_back",
                    "completed_phases": completed,
                })
                return {"state": "rolled_back", "code": code, "mutation_performed": True}
            except Exception:
                write_private_json(operation_file, {
                    "transaction_schema": "claudian-remote.local-transaction/v1",
                    "operation_id": operation_id,
                    "plan_id": plan["plan_id"],
                    "phase": "recovery_required",
                    "completed_phases": completed,
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
            phase("before_legacy_migration", completed)
            prior_target = self._active_target()
            try:
                migration.prepare(operation_id=operation_id)
                completed.append("legacy_plugin_migration")
            except LifecycleInterrupted:
                raise
            except Exception:
                # prepare can fail after an authoritative credential revoke;
                # reconcile through the migration rollback instead of claiming
                # that no mutation occurred.
                if migration._load_state(operation_id) is None:
                    raise
                return compensate("installation_failed_rolled_back", completed)
            phase("before_activation", completed)

            try:
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
                migration.activate_new(operation_id=operation_id, destination=plugin_destination)
                self._activate(target)
                self.dependencies.launchd.install_local_agents(staged.python_executable)
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
        if not self.dependencies.bridge_ready_probe():
            write_private_json(operation_file, {
                "transaction_schema": "claudian-remote.local-transaction/v1",
                "operation_id": operation_id,
                "plan_id": plan["plan_id"],
                "phase": "await_plugin_bootstrap",
                "completed_phases": completed,
            })
            return {
                "state": "blocked",
                "code": "desktop_plugin_bootstrap_required",
                "mutation_performed": True,
                "gate": {
                    "gate_type": "desktop_plugin_bootstrap_required",
                    "explanation": "The selected desktop Vault has not authenticated to the Companion Bridge yet.",
                    "exact_action": "Open or reload the selected Vault in Obsidian, wait for Claudian Remote to load, then resume this operation.",
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
        if not self.dependencies.pairing_probe():
            write_private_json(operation_file, {
                "transaction_schema": "claudian-remote.local-transaction/v1",
                "operation_id": operation_id,
                "plan_id": plan["plan_id"],
                "phase": "await_pairing",
                "completed_phases": completed,
            })
            return {
                "state": "blocked",
                "code": "pairing_approval_required",
                "mutation_performed": True,
                "gate": {
                    "gate_type": "pairing_approval_required",
                    "explanation": "Approve the phone shown by the Mac pairing UI.",
                    "exact_action": "Redeem the one-time code on the phone and approve that device on the Mac.",
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
        })
        return {"state": "ready", "code": "installation_ready", "mutation_performed": True}
