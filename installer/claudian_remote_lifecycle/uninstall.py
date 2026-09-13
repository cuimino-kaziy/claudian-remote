"""Ownership-receipt driven uninstall and confirmed purge."""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path
from typing import Any, Callable, Mapping

from .runtime import RuntimeLayout
from .private_io import tree_digest, write_private_json


class OwnershipUninstaller:
    """Remove only exact, unchanged resources owned by the lifecycle."""

    def __init__(
        self,
        layout: RuntimeLayout,
        *,
        stop_owned_services: Callable[[], None],
        revoke_credentials: Callable[[], None],
        expected_plan_id: str | None = None,
        expected_compatibility_set_id: str | None = None,
        expected_plugin_root: Path | None = None,
        require_operation_binding: bool = False,
    ) -> None:
        self.layout = layout
        self.stop_owned_services = stop_owned_services
        self.revoke_credentials = revoke_credentials
        self.expected_plan_id = expected_plan_id
        self.expected_compatibility_set_id = expected_compatibility_set_id
        self.expected_plugin_root = expected_plugin_root
        self.require_operation_binding = require_operation_binding
        self._receipt_plugin_root: Path | None = None

    def _load_receipt(self) -> Mapping[str, Any] | None:
        try:
            value = json.loads(self.layout.ownership_receipt.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError("ownership_receipt_invalid") from exc
        if not isinstance(value, Mapping) or value.get("receipt_schema") != "claudian-remote.ownership/v1":
            raise ValueError("ownership_receipt_invalid")
        if value.get("status") == "uninstalled":
            return None
        if (
            self.expected_plan_id is not None
            and value.get("plan_id") != self.expected_plan_id
        ):
            raise ValueError("ownership_receipt_invalid")
        if (
            self.expected_compatibility_set_id is not None
            and value.get("compatibility_set_id")
            != self.expected_compatibility_set_id
        ):
            raise ValueError("ownership_receipt_invalid")
        plugin_root = Path(str(value.get("plugin_root") or ""))
        if not plugin_root.is_absolute() or tuple(plugin_root.parts[-3:]) != (
            ".obsidian",
            "plugins",
            "claudian-remote",
        ):
            raise ValueError("ownership_receipt_scope_invalid")
        if self.expected_plugin_root is not None and plugin_root != self.expected_plugin_root:
            raise ValueError("ownership_receipt_scope_invalid")
        if self.require_operation_binding:
            operation_id = str(value.get("operation_id") or "")
            if re.fullmatch(r"op-[0-9a-f]{32}", operation_id) is None:
                raise ValueError("ownership_receipt_invalid")
            try:
                journal = json.loads(
                    (self.layout.state / f"{operation_id}.transaction.json").read_text(
                        encoding="utf-8"
                    )
                )
            except (OSError, json.JSONDecodeError) as exc:
                raise ValueError("ownership_receipt_invalid") from exc
            if (
                not isinstance(journal, Mapping)
                or journal.get("transaction_schema")
                != "claudian-remote.local-transaction/v1"
                or journal.get("operation_id") != operation_id
                or journal.get("plan_id") != self.expected_plan_id
                or journal.get("phase") != "ready"
            ):
                raise ValueError("ownership_receipt_invalid")
        self._receipt_plugin_root = plugin_root
        return value

    def _mark_uninstalled(self) -> None:
        write_private_json(
            self.layout.ownership_receipt,
            {
                "receipt_schema": "claudian-remote.ownership/v1",
                "status": "uninstalled",
                "resources": [],
            },
        )

    def _allowed_path(self, resource_id: str, path: Path) -> bool:
        exact = {
            "managed_runtime": self.layout.runtime,
            "managed_release_store": self.layout.releases,
            "active_release_pointer": self.layout.current,
            "previous_release_pointer": self.layout.previous,
            "relay_launch_agent": self.layout.relay_launch_agent,
            "companion_launch_agent": self.layout.companion_launch_agent,
            "availability_launch_agent": self.layout.availability_launch_agent,
            "availability_config": self.layout.availability_config,
            "connection_profile": self.layout.connection_profile,
            "relay_config": self.layout.relay_config,
            "companion_config": self.layout.companion_config,
            "secure_provisioning": self.layout.secure_provisioning,
            "bridge_bootstrap_ack": self.layout.bridge_bootstrap_ack,
        }
        if resource_id in exact:
            return path == exact[resource_id]
        if resource_id == "bridge_bootstrap":
            is_legacy = path.name == "bridge-bootstrap.json"
            is_scoped = (
                path.name.startswith("bridge-bootstrap.")
                and path.name.endswith(".json")
                and len(path.name) == len("bridge-bootstrap.") + 24 + len(".json")
            )
            return path.parent == self.layout.state and (is_legacy or is_scoped)
        if resource_id == "active_release":
            return path.parent == self.layout.releases and path.name not in {"", ".", ".."}
        if resource_id == "plugin_directory":
            return self._receipt_plugin_root is not None and path == self._receipt_plugin_root
        if resource_id.startswith("plugin_shipped_file:"):
            relative = Path(resource_id.removeprefix("plugin_shipped_file:"))
            if relative.is_absolute() or not relative.parts or ".." in relative.parts:
                return False
            root_length = len(path.parts) - len(relative.parts)
            if root_length < 3 or tuple(path.parts[root_length:]) != relative.parts:
                return False
            root = Path(*path.parts[:root_length])
            return self._receipt_plugin_root is not None and root == self._receipt_plugin_root
        return False

    def preflight(
        self,
        *,
        require_present: bool = False,
        required_resource_ids: frozenset[str] = frozenset(),
    ) -> dict[str, Any]:
        receipt = self._load_receipt()
        if receipt is None:
            if require_present:
                # A missing receipt must never satisfy readiness. It is not
                # evidence of a clean uninstall; an interrupted installation
                # after activation but before receipt recording must follow the
                # safe recovery/install path and recreate the receipt. Only the
                # ordinary uninstall flow (require_present=False) keeps the
                # idempotent already_uninstalled result.
                return {
                    "state": "blocked",
                    "code": "ownership_receipt_missing",
                    "resources": [],
                }
            return {"state": "ready", "code": "already_uninstalled", "resources": []}
        resources = receipt.get("resources")
        if not isinstance(resources, list):
            raise ValueError("ownership_receipt_invalid")
        checked: list[tuple[str, Path, str]] = []
        conflicts: list[str] = []
        missing: list[str] = []
        observed: set[str] = set()
        for resource in resources:
            if not isinstance(resource, Mapping) or resource.get("owned") is not True:
                raise ValueError("ownership_receipt_invalid")
            resource_id = str(resource.get("resource_id") or "")
            observed.add(resource_id)
            path = Path(str(resource.get("path") or ""))
            if not self._allowed_path(resource_id, path):
                raise ValueError("ownership_receipt_scope_invalid")
            if not path.exists() and not path.is_symlink():
                if require_present:
                    missing.append(resource_id)
                continue
            policy = str(resource.get("removal_policy") or "remove")
            if policy != "remove_if_empty_after_shipped_files" and tree_digest(path) != str(resource.get("digest") or ""):
                conflicts.append(resource_id)
            checked.append((resource_id, path, policy))
        if require_present:
            missing.extend(sorted(required_resource_ids - observed))
        if missing:
            return {
                "state": "blocked",
                "code": "owned_resource_missing",
                "missing_resource_ids": sorted(set(missing)),
                "resources": [],
            }
        if conflicts:
            return {
                "state": "blocked",
                "code": "owned_resource_modified",
                "conflict_resource_ids": sorted(set(conflicts)),
                "resources": [],
            }
        return {"state": "ready", "code": "uninstall_preflight_ready", "resources": checked}

    @staticmethod
    def _remove(path: Path, policy: str = "remove") -> None:
        if policy == "remove_if_empty_after_shipped_files":
            try:
                path.rmdir()
            except OSError:
                pass
            return
        if path.is_symlink() or path.is_file():
            path.unlink(missing_ok=True)
        elif path.is_dir():
            shutil.rmtree(path)

    def uninstall(self) -> dict[str, Any]:
        try:
            preflight = self.preflight()
        except ValueError as exc:
            return {"state": "blocked", "code": str(exc), "mutation_performed": False}
        if preflight["state"] != "ready":
            return {**preflight, "mutation_performed": False}
        if preflight["code"] == "already_uninstalled":
            return {"state": "ready", "code": "already_uninstalled", "mutation_performed": False}
        try:
            self.revoke_credentials()
            self.stop_owned_services()
        except Exception:
            # Revocation may have succeeded for only a subset of credentials,
            # or service shutdown may have failed after all credentials were
            # revoked. Conservatively expose the partial mutation and require
            # an explicit resume instead of claiming nothing changed.
            return {
                "state": "recovery_required",
                "code": "uninstall_precondition_incomplete",
                "mutation_performed": True,
            }
        resources = list(preflight["resources"])
        for _resource_id, path, policy in sorted(resources, key=lambda item: len(item[1].parts), reverse=True):
            self._remove(path, policy)
        self._mark_uninstalled()
        return {
            "state": "ready",
            "code": "uninstall_completed",
            "mutation_performed": bool(resources),
            "removed_resource_ids": [resource_id for resource_id, _path, _policy in resources],
        }

    def purge(self, *, confirmation_verified: bool) -> dict[str, Any]:
        if confirmation_verified is not True:
            return {
                "state": "blocked",
                "code": "purge_confirmation_required",
                "mutation_performed": False,
            }
        outcome = self.uninstall()
        if outcome["state"] != "ready":
            return outcome
        try:
            shutil.rmtree(self.layout.base)
        except FileNotFoundError:
            pass
        except OSError:
            return {
                "state": "recovery_required",
                "code": "purge_incomplete",
                "mutation_performed": True,
                "preserved_vault_content": True,
                "preserved_shared_infrastructure": True,
            }
        if self.layout.base.exists():
            return {
                "state": "recovery_required",
                "code": "purge_incomplete",
                "mutation_performed": True,
                "preserved_vault_content": True,
                "preserved_shared_infrastructure": True,
            }
        return {
            "state": "ready",
            "code": "purge_completed",
            "mutation_performed": True,
            "preserved_vault_content": True,
            "preserved_shared_infrastructure": True,
        }
