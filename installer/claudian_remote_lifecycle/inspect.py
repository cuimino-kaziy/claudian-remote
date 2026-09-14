"""Read-only, dependency-injected inspection for lifecycle planning."""

from __future__ import annotations

import hashlib
import json
import platform
import plistlib
import re
import shutil
import socket
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence

from .keychain import MacOSKeychain
from .journey import classify_journey
from .legacy_authority import legacy_authority_profile_status
from .model import (
    CHECKPOINT_SCHEMA,
    SNAPSHOT_SCHEMA,
    AmbiguityState,
    CredentialEffect,
    EffectDisposition,
    Journey,
    LifecyclePhase,
    PairingIdentityPolicy,
    RecoveryPolicy,
)
from .provisioning import verify_secure_provisioning
from .private_io import tree_digest
from .runtime import RuntimeLayout


SUPPORTED_CLAUDIAN_VERSION = "2.2.6"
SUPPORTED_CLAUDIAN_VERSIONS = frozenset({"2.0.4", "2.2.6", "2.2.7"})
SUPPORTED_LEGACY_PLUGIN_VERSIONS = frozenset({"recognized-dogfood-lineage"})
SUPPORTED_LEGACY_PLUGIN_BUILDS = {
    "0.2.0": "09e5e1f43b7db46636f12aace6117da579d0a50e322de2c8743ce42b5000de2f",
}


class InspectionProbe(Protocol):
    def macos(self) -> Mapping[str, Any]: ...

    def obsidian(self) -> Mapping[str, Any]: ...

    def claudian(self) -> Mapping[str, Any]: ...

    def vaults(self) -> Sequence[Mapping[str, Any]]: ...

    def installation(self) -> Mapping[str, Any]: ...

    def network(self) -> Mapping[str, Any]: ...


class LocalInspectionProbe:
    """Conservative host probe.

    It reads only Obsidian's registered Vaults and their plugin manifests. It
    neither crawls unrelated user directories nor starts applications.
    """

    def __init__(self, *, home: Path | None = None) -> None:
        self.home = Path(home or Path.home())
        self._vault_cache: list[dict[str, Any]] | None = None

    def macos(self) -> Mapping[str, Any]:
        return {
            "platform": platform.system(),
            "version": platform.mac_ver()[0],
            "architecture": platform.machine(),
        }

    def obsidian(self) -> Mapping[str, Any]:
        applications = (Path("/Applications/Obsidian.app"), self.home / "Applications" / "Obsidian.app")
        app = next((candidate for candidate in applications if candidate.is_dir()), applications[0])
        version = None
        info = app / "Contents" / "Info.plist"
        if info.is_file():
            try:
                with info.open("rb") as handle:
                    metadata = plistlib.load(handle)
                version = metadata.get("CFBundleShortVersionString")
            except (OSError, plistlib.InvalidFileException):
                version = None
        try:
            running = subprocess.run(
                ["pgrep", "-x", "Obsidian"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=2,
            ).returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            running = False
        return {"installed": app.is_dir(), "version": version, "running": running}

    def claudian(self) -> Mapping[str, Any]:
        vaults = self._discover_vaults()
        versions = sorted({str(vault["claudian_version"]) for vault in vaults if vault.get("claudian_version")})
        enabled = any(bool(vault.get("claudian_enabled")) for vault in vaults)
        return {
            "installed": bool(versions),
            "enabled": enabled,
            "version": versions[0] if len(versions) == 1 else None,
            "detected_versions": versions,
        }

    def vaults(self) -> Sequence[Mapping[str, Any]]:
        return [
            {key: value for key, value in vault.items() if not key.startswith("_")}
            for vault in self._discover_vaults()
        ]

    def installation(self) -> Mapping[str, Any]:
        manifests = []
        current = self._remote_plugin_summary("claudian-remote")
        legacy = self._remote_plugin_summary("whale-agent-bridge")
        for vault in self._discover_vaults():
            path = vault["_path"] / ".obsidian" / "plugins" / "claudian-remote" / "manifest.json"
            value = self._read_json(path)
            if isinstance(value, Mapping):
                manifests.append(value)
        versions = sorted({str(value.get("version")) for value in manifests if value.get("version")})
        provisioning = self._secure_provisioning_status()
        managed = self._managed_installation_status()
        authority = (
            legacy_authority_profile_status(
                self.home
                / "Library"
                / "Application Support"
                / "Claudian Remote"
                / "lifecycle"
                / "legacy-authority-profile.json"
            )
            if legacy["present"]
            else {"adapter": "not_applicable", "capability": "not_applicable"}
        )
        return {
            "installed": bool(manifests),
            "plugin_versions": versions,
            "plugin_lineage": {"current": current, "legacy": legacy},
            "legacy_authority_adapter": authority["adapter"],
            "legacy_authority_capability": authority["capability"],
            **managed,
            "operation_id": None,
            # A lifecycle process cannot safely provision an Obsidian WebView's
            # localStorage. This becomes true only when the signed Companion
            # secure-provisioning route and its OS-backed store are probed.
            **provisioning,
        }

    def _remote_plugin_summary(self, plugin_id: str) -> dict[str, Any]:
        present = False
        enabled = False
        recognized = True
        versions: set[str] = set()
        for vault in self._discover_vaults():
            plugin = vault["_path"] / ".obsidian" / "plugins" / plugin_id
            if not plugin.exists() and not plugin.is_symlink():
                continue
            present = True
            if plugin.is_symlink() or not plugin.is_dir():
                recognized = False
                continue
            manifest = self._read_json(plugin / "manifest.json")
            if not isinstance(manifest, Mapping) or manifest.get("id") != plugin_id:
                recognized = False
                continue
            version = manifest.get("version")
            if version is not None:
                versions.add(str(version))
            if (
                plugin_id == "whale-agent-bridge"
                and str(version or "") not in SUPPORTED_LEGACY_PLUGIN_VERSIONS
            ):
                main = plugin / "main.js"
                try:
                    build = hashlib.sha256(main.read_bytes()).hexdigest() if not main.is_symlink() else None
                except OSError:
                    build = None
                if build is None or SUPPORTED_LEGACY_PLUGIN_BUILDS.get(str(version)) != build:
                    recognized = False
            enabled_plugins = self._read_json(
                vault["_path"] / ".obsidian" / "community-plugins.json"
            )
            if isinstance(enabled_plugins, list) and plugin_id in enabled_plugins:
                enabled = True
        return {
            "present": present,
            "enabled": enabled,
            "recognized": recognized,
            "versions": sorted(versions),
        }

    def _managed_installation_status(self) -> Mapping[str, Any]:
        root = self.home / "Library" / "Application Support" / "Claudian Remote"
        layout = RuntimeLayout(root, self.home / "Library" / "LaunchAgents")
        current = root / "current"
        compatibility_set_id = None
        target = None
        if current.is_symlink():
            try:
                resolved = current.resolve(strict=True)
                releases = (root / "releases").resolve()
                if resolved.is_dir() and resolved.parent == releases and resolved.name.startswith("claudian-remote-"):
                    target = resolved
                    compatibility_set_id = target.name
            except (OSError, RuntimeError):
                compatibility_set_id = None

        profile_mode = None
        profile_generation_id = None
        profile = self._read_json(root / "config" / "connection-profile.json")
        if isinstance(profile, Mapping):
            mode = str(profile.get("mode") or "")
            if mode in {"local_tailscale", "remote_vps", "local_lan"}:
                profile_mode = mode
                generation = {
                    "mode": mode,
                    "installation_id": str(profile.get("installation_id") or ""),
                    "vault_id": str(profile.get("vault_id") or ""),
                    "endpoint": str(profile.get("endpoint") or ""),
                    "endpoint_audience": str(profile.get("endpoint_audience") or ""),
                    "epoch": str(profile.get("epoch") or ""),
                }
                profile_generation_id = content_id("profile-generation", generation)
        version = self._verified_managed_version(layout, target)
        receipt = self._read_json(layout.ownership_receipt)
        uninstalled = not layout.ownership_receipt.is_symlink() and isinstance(receipt, Mapping) and receipt.get("receipt_schema") == "claudian-remote.ownership/v1" and receipt.get("status") == "uninstalled" and receipt.get("resources") == []
        residue = any(path.exists() or path.is_symlink() for path in (
            layout.current, layout.previous,
            layout.connection_profile, layout.relay_config, layout.companion_config,
            layout.secure_provisioning, layout.availability_config,
            layout.relay_launch_agent, layout.companion_launch_agent, layout.availability_launch_agent,
        )) or any(path.is_symlink() for path in (layout.base, layout.config, layout.state)) or (not uninstalled and (layout.ownership_receipt.exists() or layout.ownership_receipt.is_symlink()))
        for directory in (layout.releases, layout.runtime):
            try:
                residue = residue or directory.is_symlink() or (directory.exists() and (not directory.is_dir() or next(directory.iterdir(), None) is not None))
            except OSError:
                residue = True
        return {
            "compatibility_set_id": compatibility_set_id,
            "managed_runtime_state": "verified" if version else "inconsistent" if residue else "absent",
            "managed_runtime_version": version,
            "profile_mode": profile_mode,
            "profile_generation_id": profile_generation_id,
        }

    def _verified_managed_version(self, layout: RuntimeLayout, target: Path | None) -> str | None:
        """Validate backend identity without hashing the market-owned Vault plugin."""
        if target is None:
            return None
        try:
            if any(path.is_symlink() for path in (layout.base, layout.releases, layout.config, layout.state, target, layout.ownership_receipt, layout.connection_profile, target / "plugin" / "manifest.json")):
                return None
            version = target.name.removeprefix("claudian-remote-")
            if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?", version) is None:
                return None
            if not layout.runtime.is_dir() or layout.runtime.is_symlink():
                return None
            if any(not (target / name).is_dir() or (target / name).is_symlink() for name in ("plugin", "companion", "relay", "installer")):
                return None
            receipt = self._read_json(layout.ownership_receipt)
            if not isinstance(receipt, Mapping) or receipt.get("receipt_schema") != "claudian-remote.ownership/v1" or receipt.get("compatibility_set_id") != target.name or receipt.get("status") == "uninstalled":
                return None
            operation = str(receipt.get("operation_id") or "")
            plan = str(receipt.get("plan_id") or "")
            if re.fullmatch(r"op-[0-9a-f]{32}", operation) is None or re.fullmatch(r"plan-[0-9a-f]{64}", plan) is None:
                return None
            journal_path = layout.state / f"{operation}.transaction.json"
            if journal_path.is_symlink():
                return None
            # Import lazily: the arbitration module also uses inspection via
            # planning. Its reader supports current journals as well as beta.
            from .operation_arbitration import _read_transaction_companion
            raw_journal = self._read_json(journal_path)
            completed = raw_journal.get("completed_phases") if isinstance(raw_journal, Mapping) else None
            if not isinstance(completed, list) or receipt.get("plugin_update_owner") not in {None, "obsidian"}:
                return None
            journey = "legacy_upgrade" if "legacy_plugin_migration" in completed else "current_update"
            journal = _read_transaction_companion(journal_path, operation_id=operation, plan_id=plan, journey=journey,
                plugin_update_owner="obsidian" if receipt.get("plugin_update_owner") == "obsidian" else "lifecycle_manager")
            if not isinstance(journal, Mapping) or any(journal.get(key) != value for key, value in {
                "transaction_schema": "claudian-remote.local-transaction/v1",
                "operation_id": operation, "plan_id": plan,
            }.items()):
                return None
            # Identity can be verified before the user finishes loading the
            # plugin or pairing. Operation arbitration still owns resumption.
            if journal.get("phase") not in {"ready", "after_activation", "await_plugin_bootstrap", "await_pairing"} or journal.get("activation_started") is not True:
                return None
            resources = receipt.get("resources")
            if not isinstance(resources, list):
                return None
            for resource_id, path in (("active_release", target), ("active_release_pointer", layout.current), ("connection_profile", layout.connection_profile)):
                matches = [item for item in resources if isinstance(item, Mapping) and item.get("resource_id") == resource_id]
                if len(matches) != 1:
                    return None
                item = matches[0]
                if item.get("owned") is not True or item.get("path") != str(path) or not path.exists() or item.get("digest") != tree_digest(path):
                    return None
            # This manifest belongs to the receipt-verified release, not the
            # independently updated plugin installed in the user's Vault.
            metadata = self._read_json(target / "plugin" / "manifest.json")
            if not isinstance(metadata, Mapping) or metadata.get("id") != "claudian-remote" or metadata.get("version") != version:
                return None
            return version
        except (OSError, ValueError, TypeError, RuntimeError):
            return None

    def _secure_provisioning_status(self) -> Mapping[str, Any]:
        root = self.home / "Library" / "Application Support" / "Claudian Remote"
        try:
            layout = RuntimeLayout(root, self.home / "Library" / "LaunchAgents")
            if not verify_secure_provisioning(layout, MacOSKeychain()):
                raise ValueError("secure_provisioning_missing")
            with socket.create_connection(("127.0.0.1", 27125), timeout=0.25):
                pass
            return {
                "secure_provisioning_available": True,
                "secure_provisioning_probe": "companion_route_and_keychain_verified",
            }
        except Exception:
            return {
                "secure_provisioning_available": False,
                "secure_provisioning_probe": "companion_route_unavailable",
            }

    def resolve_vault(self, vault_id: str) -> Path:
        matches = [item for item in self._discover_vaults() if str(vault_id) in {str(item.get("vault_id")), str(item.get("_registration_id"))}]
        if len(matches) == 1:
            return Path(matches[0]["_path"])
        if len(matches) > 1:
            raise ValueError("vault_identity_ambiguous")
        raise FileNotFoundError("vault_not_found")

    def network(self) -> Mapping[str, Any]:
        executable = shutil.which("tailscale")
        app_installed = Path("/Applications/Tailscale.app").is_dir()
        logged_in = False
        if executable:
            try:
                result = subprocess.run(
                    [executable, "status", "--json"],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=3,
                )
                if result.returncode == 0:
                    status = json.loads(result.stdout)
                    logged_in = status.get("BackendState") == "Running"
            except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
                logged_in = False
        return {"tailscale_installed": bool(executable or app_installed), "tailscale_logged_in": logged_in}

    @staticmethod
    def _read_json(path: Path) -> Any:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    def _discover_vaults(self) -> list[dict[str, Any]]:
        if self._vault_cache is not None:
            return self._vault_cache
        configuration = self._read_json(
            self.home / "Library" / "Application Support" / "obsidian" / "obsidian.json"
        )
        discovered: list[dict[str, Any]] = []
        values = configuration.get("vaults", {}) if isinstance(configuration, Mapping) else {}
        for vault_id, metadata in values.items():
            if not isinstance(metadata, Mapping) or not metadata.get("path"):
                continue
            path = Path(str(metadata["path"])).expanduser()
            if not path.is_dir():
                continue
            enabled_plugins = self._read_json(path / ".obsidian" / "community-plugins.json")
            enabled_ids = set(enabled_plugins) if isinstance(enabled_plugins, list) else set()
            remote_preferences = path / ".obsidian" / "plugins" / "claudian-remote" / "data.json"
            preferences = self._read_json(remote_preferences) if not remote_preferences.is_symlink() else None
            shared_id = preferences.get("vault_id") if isinstance(preferences, Mapping) else None
            shared_id_valid = isinstance(shared_id, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}", shared_id) is not None
            claudian_id = None
            claudian_version = None
            plugins_dir = path / ".obsidian" / "plugins"
            try:
                candidates = tuple(plugins_dir.iterdir()) if plugins_dir.is_dir() else ()
            except OSError:
                candidates = ()
            for plugin_dir in candidates:
                manifest = self._read_json(plugin_dir / "manifest.json")
                if not isinstance(manifest, Mapping):
                    continue
                plugin_id = str(manifest.get("id") or plugin_dir.name)
                plugin_name = str(manifest.get("name") or "")
                if plugin_id.lower() == "claudian" or plugin_name.lower() == "claudian":
                    claudian_id = plugin_id
                    claudian_version = manifest.get("version")
                    break
            discovered.append(
                {
                    "vault_id": shared_id if shared_id_valid else str(vault_id),
                    "remote_vault_id_ready": bool(shared_id_valid),
                    "display_name": path.name,
                    "open": bool(metadata.get("open")),
                    "claudian_version": claudian_version,
                    "claudian_enabled": bool(claudian_id and claudian_id in enabled_ids),
                    "_path": path,
                    "_registration_id": str(vault_id),
                }
            )
        discovered.sort(key=lambda item: item["vault_id"])
        counts: dict[str, int] = {}
        for item in discovered:
            counts[item["vault_id"]] = counts.get(item["vault_id"], 0) + 1
        for item in discovered:
            if counts[item["vault_id"]] > 1:
                item["remote_vault_id_ready"] = False
        self._vault_cache = discovered
        return discovered


def _normalize(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _normalize(value[key]) for key in sorted(value)}
    if isinstance(value, (list, tuple)):
        normalized = [_normalize(item) for item in value]
        if all(isinstance(item, Mapping) and "vault_id" in item for item in normalized):
            normalized.sort(key=lambda item: str(item["vault_id"]))
        return normalized
    return value


def canonical_json(value: Any) -> str:
    return json.dumps(_normalize(value), ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def content_id(prefix: str, value: Any) -> str:
    digest = hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()
    return f"{prefix}-{digest}"


def validate_snapshot(snapshot: Mapping[str, Any]) -> None:
    if snapshot.get("snapshot_schema") != SNAPSHOT_SCHEMA or not snapshot.get("snapshot_id"):
        raise ValueError("invalid_inspection_snapshot")
    signed_body = {key: value for key, value in snapshot.items() if key != "snapshot_id"}
    if snapshot.get("snapshot_id") != content_id("inspection", signed_body):
        raise ValueError("inspection_integrity_failed")


@dataclass(frozen=True)
class Inspector:
    probe: InspectionProbe

    def snapshot(
        self,
        *,
        operation_arbitration: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        body = {
            "snapshot_schema": SNAPSHOT_SCHEMA,
            "macos": dict(self.probe.macos()),
            "obsidian": dict(self.probe.obsidian()),
            "claudian": dict(self.probe.claudian()),
            "vaults": list(self.probe.vaults()),
            "installation": dict(self.probe.installation()),
            "network": dict(self.probe.network()),
        }
        body = _normalize(body)
        installation = body["installation"]
        lineage = installation.get("plugin_lineage")
        if not isinstance(lineage, Mapping):
            current_present = bool(installation.get("installed"))
            lineage = {
                "current": {
                    "present": current_present,
                    "enabled": current_present,
                    "recognized": True,
                },
                "legacy": {"present": False, "enabled": False, "recognized": True},
            }
        prior_operation = installation.get("existing_operation")
        prior_operation_terminal: bool | None = None
        if operation_arbitration is not None:
            arbitration = self._operation_arbitration(operation_arbitration)
            body["operation_arbitration"] = arbitration
            prior_operation_terminal = arbitration["prior_operation_terminal"]
            operation_id = arbitration.get("operation_id")
            if operation_id is not None:
                prior_operation = {
                    "operation_id": operation_id,
                    "terminal": prior_operation_terminal,
                    "recommended_action": arbitration.get("recommended_action"),
                }
        decision = classify_journey(
            {
                "current": {
                    key: bool(lineage.get("current", {}).get(key))
                    for key in ("present", "enabled", "recognized")
                },
                "legacy": {
                    key: bool(lineage.get("legacy", {}).get(key))
                    for key in ("present", "enabled", "recognized")
                },
                "legacy_authority_capability": installation.get(
                    "legacy_authority_capability", "not_applicable"
                ),
                "managed_runtime_state": installation.get("managed_runtime_state"),
            },
            prior_operation=prior_operation,
            prior_operation_terminal=prior_operation_terminal,
        )
        body["journey"] = decision.to_dict()
        body["read_only"] = True
        body["support"] = self._support(body)
        body["snapshot_id"] = content_id("inspection", body)
        return body

    @staticmethod
    def _operation_arbitration(value: Mapping[str, Any]) -> dict[str, Any]:
        base_fields = {
            "state",
            "reason_code",
            "prior_operation_terminal",
            "terminal_operation_ids",
            "operation_id",
            "recommended_action",
        }
        control_fields = {
            "operation_schema",
            "journey",
            "phase",
            "irreversible_boundary_crossed",
            "ambiguity_state",
            "recovery_policy",
            "effect_summary",
            "cancellation_available",
            "pairing_identity_policy",
        }
        if not isinstance(value, Mapping) or not set(value).issubset(
            base_fields | control_fields
        ):
            raise ValueError("invalid_operation_arbitration")
        present_controls = set(value) & control_fields
        if present_controls and present_controls != control_fields:
            raise ValueError("invalid_operation_arbitration")
        state = value.get("state")
        reason_code = value.get("reason_code")
        terminal = value.get("prior_operation_terminal")
        terminal_ids = value.get("terminal_operation_ids")
        if (
            state not in {"clear", "reconciliation_required", "blocked"}
            or not isinstance(reason_code, str)
            or not reason_code
            or not isinstance(terminal, bool)
            or not isinstance(terminal_ids, list)
            or any(
                not isinstance(item, str)
                or re.fullmatch(r"op-[0-9a-f]{32}", item) is None
                for item in terminal_ids
            )
        ):
            raise ValueError("invalid_operation_arbitration")
        operation_id = value.get("operation_id")
        if operation_id is not None and (
            not isinstance(operation_id, str)
            or re.fullmatch(r"op-[0-9a-f]{32}", operation_id) is None
        ):
            raise ValueError("invalid_operation_arbitration")
        action = value.get("recommended_action")
        if action is not None and action not in {
            "resume",
            "rollback",
            "finish_forward",
            "reconcile_retirement_outcome",
            "manual_recovery_required",
        }:
            raise ValueError("invalid_operation_arbitration")
        if terminal and state != "clear":
            raise ValueError("invalid_operation_arbitration")
        if not terminal and state == "clear":
            raise ValueError("invalid_operation_arbitration")
        projection = {
            "state": state,
            "reason_code": reason_code,
            "prior_operation_terminal": terminal,
            "terminal_operation_ids": list(terminal_ids),
            **({"operation_id": operation_id} if operation_id is not None else {}),
            **({"recommended_action": action} if action is not None else {}),
        }
        if present_controls:
            effect = value.get("effect_summary")
            if (
                value.get("operation_schema") != CHECKPOINT_SCHEMA
                or value.get("journey") not in {item.value for item in Journey}
                or value.get("phase") not in {item.value for item in LifecyclePhase}
                or not isinstance(value.get("irreversible_boundary_crossed"), bool)
                or value.get("ambiguity_state")
                not in {item.value for item in AmbiguityState}
                or value.get("recovery_policy")
                not in {item.value for item in RecoveryPolicy}
                or not isinstance(value.get("cancellation_available"), bool)
                or value.get("pairing_identity_policy")
                not in {item.value for item in PairingIdentityPolicy}
                or not isinstance(effect, Mapping)
                or set(effect)
                != {
                    "local_effect",
                    "remote_effect",
                    "credential_effect",
                    "mutation_performed",
                    "owned_resource_count",
                    "effect_codes",
                }
                or effect.get("local_effect")
                not in {item.value for item in EffectDisposition}
                or effect.get("remote_effect")
                not in {item.value for item in EffectDisposition}
                or effect.get("credential_effect")
                not in {item.value for item in CredentialEffect}
                or (
                    effect.get("mutation_performed") is not None
                    and not isinstance(effect.get("mutation_performed"), bool)
                )
                or isinstance(effect.get("owned_resource_count"), bool)
                or not isinstance(effect.get("owned_resource_count"), int)
                or effect.get("owned_resource_count", -1) < 0
                or not isinstance(effect.get("effect_codes"), list)
                or any(
                    not isinstance(code, str) or not code
                    for code in effect.get("effect_codes", [])
                )
            ):
                raise ValueError("invalid_operation_arbitration")
            projection.update(
                {
                    "operation_schema": CHECKPOINT_SCHEMA,
                    "journey": value["journey"],
                    "phase": value["phase"],
                    "irreversible_boundary_crossed": value[
                        "irreversible_boundary_crossed"
                    ],
                    "ambiguity_state": value["ambiguity_state"],
                    "recovery_policy": value["recovery_policy"],
                    "effect_summary": {
                        **effect,
                        "effect_codes": list(effect["effect_codes"]),
                    },
                    "cancellation_available": value["cancellation_available"],
                    "pairing_identity_policy": value[
                        "pairing_identity_policy"
                    ],
                }
            )
        return projection

    @staticmethod
    def _support(snapshot: Mapping[str, Any]) -> dict[str, Any]:
        reasons: list[str] = []
        if snapshot["macos"].get("platform") != "Darwin":
            reasons.append("unsupported_desktop_os")
        claudian = snapshot["claudian"]
        if claudian.get("version") not in SUPPORTED_CLAUDIAN_VERSIONS:
            reasons.append("unsupported_claudian_version")
        if not claudian.get("enabled"):
            reasons.append("claudian_not_enabled")
        if not snapshot["installation"].get("secure_provisioning_available"):
            reasons.append("secure_provisioning_missing")
        journey = snapshot.get("journey", {})
        if journey.get("blocked"):
            reasons.append(str(journey.get("reason_code") or "journey_classification_failed"))
        vaults = snapshot["vaults"]
        if not vaults:
            reasons.append("vault_not_found")
        elif len(vaults) > 1:
            reasons.append("vault_selection_required")
        if len({vault["vault_id"] for vault in vaults}) != len(vaults):
            reasons.append("vault_identity_ambiguous")
        return {
            "supported": not reasons,
            "required_claudian_version": SUPPORTED_CLAUDIAN_VERSION,
            "reason_codes": reasons,
        }
