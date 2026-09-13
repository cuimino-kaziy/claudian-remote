from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from installer.claudian_remote_lifecycle.credentials import CredentialRevocationService
from installer.claudian_remote_lifecycle.runtime import RuntimeLayout
from installer.claudian_remote_lifecycle.uninstall import OwnershipUninstaller, tree_digest


def layout_for(tmp_path: Path) -> RuntimeLayout:
    return RuntimeLayout(tmp_path / "Application Support" / "Claudian Remote", tmp_path / "LaunchAgents")


def write_receipt(layout: RuntimeLayout, resources: list[tuple[str, Path]]) -> None:
    layout.state.mkdir(parents=True, exist_ok=True)
    plugin_root = next(
        (path for resource_id, path in resources if resource_id == "plugin_directory"),
        layout.base.parent / "Receipt Vault" / ".obsidian" / "plugins" / "claudian-remote",
    )
    value = {
        "receipt_schema": "claudian-remote.ownership/v1",
        "operation_id": "op-test",
        "compatibility_set_id": "set-test",
        "plugin_root": str(plugin_root),
        "resources": [
            {
                "resource_id": resource_id,
                "path": str(path),
                "kind": "directory" if path.is_dir() else "file",
                "digest": tree_digest(path),
                "owned": True,
            }
            for resource_id, path in resources
        ],
    }
    layout.ownership_receipt.write_text(json.dumps(value), encoding="utf-8")
    os.chmod(layout.ownership_receipt, 0o600)


def test_uninstall_removes_only_unchanged_owned_resources_and_is_idempotent(tmp_path):
    layout = layout_for(tmp_path)
    layout.runtime.mkdir(parents=True)
    (layout.runtime / "python").write_text("owned", encoding="utf-8")
    layout.relay_launch_agent.parent.mkdir(parents=True)
    layout.relay_launch_agent.write_text("owned", encoding="utf-8")
    vault = tmp_path / "Vault"
    plugin = vault / ".obsidian" / "plugins" / "claudian-remote"
    plugin.mkdir(parents=True)
    (plugin / "main.js").write_text("owned", encoding="utf-8")
    note = vault / "note.md"
    note.write_text("preserve", encoding="utf-8")
    write_receipt(layout, [
        ("managed_runtime", layout.runtime),
        ("relay_launch_agent", layout.relay_launch_agent),
        ("plugin_directory", plugin),
    ])
    calls: list[str] = []
    service = OwnershipUninstaller(
        layout,
        stop_owned_services=lambda: calls.append("stop"),
        revoke_credentials=lambda: calls.append("revoke"),
    )
    outcome = service.uninstall()
    assert outcome["code"] == "uninstall_completed"
    assert calls == ["revoke", "stop"]
    assert not plugin.exists()
    assert not layout.runtime.exists()
    assert not layout.relay_launch_agent.exists()
    assert note.read_text(encoding="utf-8") == "preserve"

    second = service.uninstall()
    assert second["code"] == "already_uninstalled"
    assert second["mutation_performed"] is False
    assert calls == ["revoke", "stop"]


def test_uninstall_accepts_and_removes_the_authenticated_bridge_ack_receipt(tmp_path):
    layout = layout_for(tmp_path)
    layout.bridge_bootstrap_ack.parent.mkdir(parents=True)
    layout.bridge_bootstrap_ack.write_text('{"ack_schema":"claudian-remote.bridge-bootstrap-ack/v1"}')
    write_receipt(layout, [("bridge_bootstrap_ack", layout.bridge_bootstrap_ack)])
    service = OwnershipUninstaller(
        layout,
        stop_owned_services=lambda: None,
        revoke_credentials=lambda: None,
    )

    outcome = service.uninstall()

    assert outcome["code"] == "uninstall_completed"
    assert not layout.bridge_bootstrap_ack.exists()


def test_preflight_require_present_fails_closed_on_missing_receipt(tmp_path):
    layout = layout_for(tmp_path)
    service = OwnershipUninstaller(
        layout,
        stop_owned_services=lambda: None,
        revoke_credentials=lambda: None,
    )

    # A missing ownership receipt must never satisfy readiness: an interrupted
    # installation after activation but before receipt recording must take the
    # safe recovery/install path instead of being reported already ready.
    outcome = service.preflight(require_present=True)
    assert outcome["state"] == "blocked"
    assert outcome["code"] == "ownership_receipt_missing"
    assert outcome["resources"] == []

    # The ordinary uninstall flow (require_present=False) keeps the idempotent
    # already_uninstalled result for a missing receipt.
    assert service.uninstall() == {
        "state": "ready",
        "code": "already_uninstalled",
        "mutation_performed": False,
    }


def test_preflight_require_present_fails_closed_on_uninstalled_receipt(tmp_path):
    layout = layout_for(tmp_path)
    layout.state.mkdir(parents=True, exist_ok=True)
    layout.ownership_receipt.write_text(json.dumps({
        "receipt_schema": "claudian-remote.ownership/v1",
        "status": "uninstalled",
        "resources": [],
    }), encoding="utf-8")
    service = OwnershipUninstaller(
        layout,
        stop_owned_services=lambda: None,
        revoke_credentials=lambda: None,
    )

    assert service.preflight(require_present=True)["code"] == "ownership_receipt_missing"
    assert service.uninstall()["code"] == "already_uninstalled"


def test_modified_owned_resource_blocks_before_any_mutation(tmp_path):
    layout = layout_for(tmp_path)
    layout.runtime.mkdir(parents=True)
    owned = layout.runtime / "python"
    owned.write_text("owned", encoding="utf-8")
    write_receipt(layout, [("managed_runtime", layout.runtime)])
    owned.write_text("user changed", encoding="utf-8")
    calls: list[str] = []
    service = OwnershipUninstaller(
        layout,
        stop_owned_services=lambda: calls.append("stop"),
        revoke_credentials=lambda: calls.append("revoke"),
    )
    outcome = service.uninstall()
    assert outcome["code"] == "owned_resource_modified"
    assert calls == []
    assert owned.exists()


def test_receipt_path_escape_is_rejected_and_purge_requires_confirmation(tmp_path):
    layout = layout_for(tmp_path)
    outside = tmp_path / "unrelated.txt"
    outside.write_text("preserve", encoding="utf-8")
    write_receipt(layout, [("managed_runtime", outside)])
    service = OwnershipUninstaller(layout, stop_owned_services=lambda: None, revoke_credentials=lambda: None)
    assert service.uninstall()["code"] == "ownership_receipt_scope_invalid"
    assert outside.exists()
    assert service.purge(confirmation_verified=False)["code"] == "purge_confirmation_required"
    assert outside.exists()


def test_shipped_plugin_files_are_removed_but_device_local_data_is_preserved(tmp_path):
    layout = layout_for(tmp_path)
    plugin = tmp_path / "Vault" / ".obsidian" / "plugins" / "claudian-remote"
    plugin.mkdir(parents=True)
    shipped = plugin / "main.js"
    shipped.write_text("owned", encoding="utf-8")
    device_data = plugin / "data.json"
    device_data.write_text('{"local":true}', encoding="utf-8")
    layout.state.mkdir(parents=True)
    receipt = {
        "receipt_schema": "claudian-remote.ownership/v1",
        "plugin_root": str(plugin),
        "resources": [
            {
                "resource_id": "plugin_directory",
                "path": str(plugin),
                "kind": "directory",
                "owned": True,
                "removal_policy": "remove_if_empty_after_shipped_files",
            },
            {
                "resource_id": "plugin_shipped_file:main.js",
                "path": str(shipped),
                "kind": "file",
                "owned": True,
                "digest": tree_digest(shipped),
            },
        ],
    }
    layout.ownership_receipt.write_text(json.dumps(receipt), encoding="utf-8")
    service = OwnershipUninstaller(layout, stop_owned_services=lambda: None, revoke_credentials=lambda: None)
    assert service.uninstall()["code"] == "uninstall_completed"
    assert not shipped.exists()
    assert device_data.exists()


def test_receipt_cannot_redirect_shipped_files_to_another_vault(tmp_path):
    layout = layout_for(tmp_path)
    owned_plugin = tmp_path / "Owned" / ".obsidian" / "plugins" / "claudian-remote"
    other_plugin = tmp_path / "Other" / ".obsidian" / "plugins" / "claudian-remote"
    owned_plugin.mkdir(parents=True)
    other_plugin.mkdir(parents=True)
    other_file = other_plugin / "main.js"
    other_file.write_text("preserve", encoding="utf-8")
    layout.state.mkdir(parents=True)
    layout.ownership_receipt.write_text(json.dumps({
        "receipt_schema": "claudian-remote.ownership/v1",
        "plugin_root": str(owned_plugin),
        "resources": [{
            "resource_id": "plugin_shipped_file:main.js",
            "path": str(other_file),
            "kind": "file",
            "owned": True,
            "digest": tree_digest(other_file),
        }],
    }), encoding="utf-8")

    service = OwnershipUninstaller(layout, stop_owned_services=lambda: None, revoke_credentials=lambda: None)
    assert service.uninstall()["code"] == "ownership_receipt_scope_invalid"
    assert other_file.read_text(encoding="utf-8") == "preserve"


class FakeCredentialStore:
    def __init__(self) -> None:
        self.deleted: list[str] = []

    def delete(self, reference: str) -> None:
        self.deleted.append(reference)


def test_credential_revocation_blocks_before_deleting_local_keys_when_relay_is_offline():
    store = FakeCredentialStore()
    service = CredentialRevocationService(
        list_devices=lambda: (_ for _ in ()).throw(OSError("offline")),
        revoke_device=lambda _identifier: {"state": "ready", "code": "device_revoked"},
        credential_store=store,
        credential_references=lambda: {"pairing_admin_credential_ref": "admin-ref"},
    )
    try:
        service.revoke_all()
    except RuntimeError as exc:
        assert str(exc) == "device_revocation_unavailable"
    else:  # pragma: no cover - assertion guard
        raise AssertionError("revocation should fail closed")
    assert store.deleted == []


def test_credential_revocation_requires_authoritative_empty_active_device_list():
    store = FakeCredentialStore()
    responses: list[dict[str, Any]] = [
        {"devices": [{"device_id": "phone-1", "status": "active"}]},
        {"devices": [{"device_id": "phone-1", "status": "active"}]},
    ]
    service = CredentialRevocationService(
        list_devices=lambda: responses.pop(0),
        revoke_device=lambda _identifier: {"state": "ready", "code": "device_revoked"},
        credential_store=store,
        credential_references=lambda: {"pairing_admin_credential_ref": "admin-ref"},
    )
    try:
        service.revoke_all()
    except RuntimeError as exc:
        assert str(exc) == "device_revocation_unverified"
    else:  # pragma: no cover - assertion guard
        raise AssertionError("revocation should be verified")
    assert store.deleted == []


def test_credential_revocation_deletes_local_keys_only_after_remote_verification():
    store = FakeCredentialStore()
    responses: list[dict[str, Any]] = [
        {"devices": [{"device_id": "phone-1", "revoked": False}]},
        {"devices": [{"device_id": "phone-1", "revoked": True}]},
    ]
    revoked: list[str] = []
    service = CredentialRevocationService(
        list_devices=lambda: responses.pop(0),
        revoke_device=lambda identifier: (
            revoked.append(identifier) or {"state": "ready", "code": "device_revoked"}
        ),
        credential_store=store,
        credential_references=lambda: {
            "pairing_admin_credential_ref": "admin-ref",
            "bridge_credential_ref": "bridge-ref",
            "relay_token_ref": "relay-ref",
        },
    )
    service.revoke_all()
    assert revoked == ["phone-1"]
    assert store.deleted == ["admin-ref", "bridge-ref", "relay-ref"]


def test_uninstall_blocks_without_mutation_when_credential_revocation_fails(tmp_path):
    layout = layout_for(tmp_path)
    layout.runtime.mkdir(parents=True)
    (layout.runtime / "python").write_text("owned", encoding="utf-8")
    write_receipt(layout, [("managed_runtime", layout.runtime)])
    stopped: list[bool] = []
    service = OwnershipUninstaller(
        layout,
        stop_owned_services=lambda: stopped.append(True),
        revoke_credentials=lambda: (_ for _ in ()).throw(RuntimeError("device_revocation_unverified")),
    )
    outcome = service.uninstall()
    assert outcome == {
        "state": "recovery_required",
        "code": "uninstall_precondition_incomplete",
        "mutation_performed": True,
    }
    assert stopped == []
    assert layout.runtime.exists()


def test_uninstall_reports_partial_mutation_when_shutdown_fails_after_revocation(tmp_path):
    layout = layout_for(tmp_path)
    layout.runtime.mkdir(parents=True)
    (layout.runtime / "python").write_text("owned", encoding="utf-8")
    write_receipt(layout, [("managed_runtime", layout.runtime)])
    calls: list[str] = []
    service = OwnershipUninstaller(
        layout,
        revoke_credentials=lambda: calls.append("revoke"),
        stop_owned_services=lambda: (_ for _ in ()).throw(RuntimeError("launchd_stop_failed")),
    )

    assert service.uninstall() == {
        "state": "recovery_required",
        "code": "uninstall_precondition_incomplete",
        "mutation_performed": True,
    }
    assert calls == ["revoke"]
    assert layout.runtime.exists()
