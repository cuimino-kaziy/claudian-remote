import io
import json
from pathlib import Path

import pytest

from installer.claudian_remote_lifecycle.cli import LifecycleServices, main
from installer.claudian_remote_lifecycle.inspect import Inspector, LocalInspectionProbe
from installer.claudian_remote_lifecycle.model import SNAPSHOT_SCHEMA
from installer.claudian_remote_lifecycle.plan import PlanBuilder
from installer.claudian_remote_lifecycle.private_io import tree_digest
from installer.claudian_remote_lifecycle.runtime import RuntimeLayout


class FakeProbe:
    def __init__(self, *, claudian_version="2.0.4", vaults=None):
        self.claudian_version = claudian_version
        self._vaults = vaults if vaults is not None else [{"vault_id": "vault-a", "display_name": "Notes"}]
        self.calls = []

    def macos(self):
        self.calls.append("macos")
        return {"platform": "Darwin", "version": "15.5", "architecture": "arm64"}

    def obsidian(self):
        self.calls.append("obsidian")
        return {"installed": True, "version": "1.12.3", "running": True}

    def claudian(self):
        self.calls.append("claudian")
        return {"installed": True, "enabled": True, "version": self.claudian_version}

    def vaults(self):
        self.calls.append("vaults")
        return list(self._vaults)

    def installation(self):
        self.calls.append("installation")
        return {
            "installed": False,
            "compatibility_set_id": None,
            "operation_id": None,
            "secure_provisioning_available": True,
            "secure_provisioning_probe": "verified_test_adapter",
        }

    def network(self):
        self.calls.append("network")
        return {"tailscale_installed": True, "tailscale_logged_in": True}


def _market_plugin(home, version="0.2.0"):
    vault = home / "Notes"
    plugin = vault / ".obsidian" / "plugins" / "claudian-remote"
    plugin.mkdir(parents=True)
    (plugin / "manifest.json").write_text(json.dumps({"id": "claudian-remote", "version": version}))
    (plugin / "main.js").write_text("market plugin")
    (vault / ".obsidian" / "community-plugins.json").write_text('["claudian-remote"]')
    registration = home / "Library" / "Application Support" / "obsidian"
    registration.mkdir(parents=True)
    (registration / "obsidian.json").write_text(json.dumps({"vaults": {"vault-a": {"path": str(vault)}}}))
    return plugin


def _managed_background(home, version="0.2.0-beta.6.7"):
    layout = RuntimeLayout(home / "Library" / "Application Support" / "Claudian Remote", home / "Library" / "LaunchAgents")
    target = layout.release_path("claudian-remote-" + version)
    for name in ("plugin", "companion", "relay", "installer"):
        (target / name).mkdir(parents=True)
    (target / "plugin" / "manifest.json").write_text(json.dumps({"id": "claudian-remote", "version": version}))
    (target / "companion" / "main.py").write_text("pass\n")
    layout.runtime.mkdir()
    layout.current.symlink_to(target)
    layout.config.mkdir()
    layout.connection_profile.write_text(json.dumps({"mode": "local_tailscale", "installation_id": "installation-a", "vault_id": "vault-a", "endpoint": "https://mac.example.ts.net", "endpoint_audience": "claudian-remote:local_tailscale:installation-a", "epoch": "epoch-a"}))
    layout.state.mkdir()
    operation = "op-" + "a" * 32
    plan = "plan-" + "b" * 64
    (layout.state / f"{operation}.transaction.json").write_text(json.dumps({"transaction_schema": "claudian-remote.local-transaction/v1", "operation_id": operation, "plan_id": plan, "phase": "ready", "completed_phases": ["staging", "secure_provisioning", "plugin_activation", "launchd", "tailscale_serve", "verified", "paired"], "prior_availability_vault": None, "prior_release_id": None, "activation_started": True, "plugin_activated": True}))
    resources = [{"resource_id": name, "path": str(path), "kind": "symlink" if path.is_symlink() else "directory" if path.is_dir() else "file", "owned": True, "digest": tree_digest(path)} for name, path in (("active_release", target), ("active_release_pointer", layout.current), ("connection_profile", layout.connection_profile))]
    layout.ownership_receipt.write_text(json.dumps({"receipt_schema": "claudian-remote.ownership/v1", "operation_id": operation, "plan_id": plan, "compatibility_set_id": target.name, "plugin_root": str(home / "Notes" / ".obsidian" / "plugins" / "claudian-remote"), "resources": resources}))
    return layout, target


def test_market_plugin_alone_is_a_fresh_background_install(tmp_path):
    _market_plugin(tmp_path)
    snapshot = Inspector(LocalInspectionProbe(home=tmp_path)).snapshot()
    assert snapshot["installation"]["managed_runtime_state"] == "absent"
    assert snapshot["installation"]["plugin_versions"] == ["0.2.0"]
    assert snapshot["journey"]["journey"] == "fresh_install"


def test_market_update_does_not_replace_verified_background_version(tmp_path):
    plugin = _market_plugin(tmp_path)
    layout, _ = _managed_background(tmp_path)
    receipt = json.loads(layout.ownership_receipt.read_text())
    receipt["resources"].append({"resource_id": "plugin_shipped_file:main.js", "path": str(plugin / "main.js"), "kind": "file", "owned": True, "digest": "0" * 64})
    layout.ownership_receipt.write_text(json.dumps(receipt))
    snapshot = Inspector(LocalInspectionProbe(home=tmp_path)).snapshot()
    assert snapshot["installation"]["managed_runtime_state"] == "verified"
    assert snapshot["installation"]["managed_runtime_version"] == "0.2.0-beta.6.7"
    assert snapshot["installation"]["plugin_versions"] == ["0.2.0"]
    assert snapshot["journey"]["journey"] == "current_update"
    assert snapshot["journey"].get("re_pair_required") is None


@pytest.mark.parametrize("fault", ["missing_receipt", "wrong_release", "modified_release", "missing_journal", "pending_journal", "dangling_current"])
def test_inconsistent_managed_background_fails_closed(tmp_path, fault):
    _market_plugin(tmp_path)
    layout, target = _managed_background(tmp_path)
    if fault == "missing_receipt":
        layout.ownership_receipt.unlink()
    elif fault == "wrong_release":
        receipt = json.loads(layout.ownership_receipt.read_text())
        receipt["compatibility_set_id"] = "claudian-remote-0.2.0"
        layout.ownership_receipt.write_text(json.dumps(receipt))
    elif fault == "modified_release":
        (target / "companion" / "main.py").write_text("changed")
    elif fault in {"missing_journal", "pending_journal"}:
        journal = next(layout.state.glob("*.transaction.json"))
        if fault == "missing_journal":
            journal.unlink()
        else:
            value = json.loads(journal.read_text()); value["phase"] = "await_plugin_bootstrap"
            journal.write_text(json.dumps(value))
    else:
        layout.current.unlink(); layout.current.symlink_to(layout.releases / "missing")
    snapshot = Inspector(LocalInspectionProbe(home=tmp_path)).snapshot()
    assert snapshot["installation"]["managed_runtime_state"] == "inconsistent"
    assert snapshot["installation"]["managed_runtime_version"] is None
    assert snapshot["journey"]["reason_code"] == "managed_runtime_inconsistent"
    assert snapshot["journey"]["blocked"]


def test_managed_residue_without_current_is_not_clean(tmp_path):
    root = tmp_path / "Library" / "Application Support" / "Claudian Remote"
    (root / "runtime").mkdir(parents=True)
    (root / "runtime" / "partial-runtime").write_text("incomplete")
    snapshot = Inspector(LocalInspectionProbe(home=tmp_path)).snapshot()
    assert snapshot["journey"]["reason_code"] == "managed_runtime_inconsistent"


def test_empty_backend_directories_after_uninstall_allow_fresh_install(tmp_path):
    root = tmp_path / "Library" / "Application Support" / "Claudian Remote"
    for name in ("runtime", "releases", "state"):
        (root / name).mkdir(parents=True)
    (root / "state" / "ownership.json").write_text(json.dumps({"receipt_schema": "claudian-remote.ownership/v1", "status": "uninstalled", "resources": []}))
    snapshot = Inspector(LocalInspectionProbe(home=tmp_path)).snapshot()
    assert snapshot["installation"]["managed_runtime_state"] == "absent"
    assert snapshot["journey"]["journey"] == "fresh_install"


def test_market_shared_vault_identity_maps_to_registered_path_without_writing_data(tmp_path):
    plugin = _market_plugin(tmp_path)
    preferences = plugin / "data.json"
    preferences.write_text(json.dumps({"schema_version": 2, "vault_id": "vault-shared-phone-id"}))
    original = preferences.read_bytes()
    probe = LocalInspectionProbe(home=tmp_path)
    snapshot = Inspector(probe).snapshot()
    assert snapshot["vaults"][0]["vault_id"] == "vault-shared-phone-id"
    assert snapshot["vaults"][0]["remote_vault_id_ready"] is True
    assert probe.resolve_vault("vault-shared-phone-id") == probe.resolve_vault("vault-a") == tmp_path / "Notes"
    plan = PlanBuilder().build(snapshot, mode="local_tailscale")
    assert plan["vault_id"] == "vault-shared-phone-id"
    assert plan["journey"] == "fresh_install"
    assert preferences.read_bytes() == original
    assert "_registration_id" not in json.dumps(snapshot)


def test_shared_vault_identity_collision_fails_closed(tmp_path):
    plugin = _market_plugin(tmp_path)
    (plugin / "data.json").write_text('{"vault_id":"vault-shared"}')
    other = tmp_path / "Other" / ".obsidian" / "plugins" / "claudian-remote"
    other.mkdir(parents=True)
    (other / "data.json").write_text('{"vault_id":"vault-shared"}')
    registration = tmp_path / "Library" / "Application Support" / "obsidian" / "obsidian.json"
    registration.write_text(json.dumps({"vaults": {"local-a": {"path": str(tmp_path / "Notes")}, "local-b": {"path": str(tmp_path / "Other")}}}))
    probe = LocalInspectionProbe(home=tmp_path)
    assert "vault_identity_ambiguous" in Inspector(probe).snapshot()["support"]["reason_codes"]
    with pytest.raises(ValueError, match="vault_identity_ambiguous"):
        probe.resolve_vault("vault-shared")


@pytest.mark.parametrize(("phase", "completed_count"), [("after_activation", 5), ("await_plugin_bootstrap", 5), ("await_pairing", 6)])
def test_receipt_bound_pending_background_keeps_identity_for_resume(tmp_path, phase, completed_count):
    _market_plugin(tmp_path)
    layout, _ = _managed_background(tmp_path)
    journal = next(layout.state.glob("*.transaction.json"))
    value = json.loads(journal.read_text())
    value["phase"] = phase
    value["completed_phases"] = value["completed_phases"][:completed_count]
    journal.write_text(json.dumps(value))
    snapshot = Inspector(LocalInspectionProbe(home=tmp_path)).snapshot()
    assert snapshot["installation"]["managed_runtime_state"] == "verified"
    assert snapshot["installation"]["managed_runtime_version"] == "0.2.0-beta.6.7"


@pytest.mark.parametrize("owner_matches", [True, False])
def test_community_background_requires_receipt_and_journal_owner_agreement(tmp_path, owner_matches):
    _market_plugin(tmp_path)
    layout, _ = _managed_background(tmp_path, version="0.2.0")
    journal_path = next(layout.state.glob("*.transaction.json"))
    journal = json.loads(journal_path.read_text())
    journal.update(plugin_update_owner="obsidian", plugin_activated=False)
    journal["completed_phases"].remove("plugin_activation")
    journal_path.write_text(json.dumps(journal))
    if owner_matches:
        receipt = json.loads(layout.ownership_receipt.read_text())
        receipt["plugin_update_owner"] = "obsidian"
        layout.ownership_receipt.write_text(json.dumps(receipt))
    installation = LocalInspectionProbe(home=tmp_path)._managed_installation_status()
    assert installation["managed_runtime_state"] == ("verified" if owner_matches else "inconsistent")
    assert installation["managed_runtime_version"] == ("0.2.0" if owner_matches else None)


def test_inspect_is_read_only_versioned_and_deterministic():
    probe = FakeProbe(vaults=[{"display_name": "Work", "vault_id": "vault-b"}, {"display_name": "Home", "vault_id": "vault-a"}])
    first = Inspector(probe).snapshot()
    second = Inspector(probe).snapshot()

    assert first == second
    assert first["snapshot_schema"] == SNAPSHOT_SCHEMA
    assert first["snapshot_id"].startswith("inspection-")
    assert first["read_only"] is True
    assert first["journey"]["journey"] == "fresh_install"
    assert [vault["vault_id"] for vault in first["vaults"]] == ["vault-a", "vault-b"]
    assert first["support"]["reason_codes"] == ["vault_selection_required"]


def test_unsupported_claudian_blocks_mutation_but_inspection_still_returns_snapshot(tmp_path):
    output = io.StringIO()
    code = main(
        ["--state-dir", str(tmp_path), "inspect"],
        stdout=output,
        services=LifecycleServices(FakeProbe(claudian_version="2.0.3"), {}),
    )
    result = json.loads(output.getvalue())
    assert code == 2
    assert result["state"] == "blocked"
    assert result["code"] == "unsupported_claudian_version"
    assert result["data"]["snapshot"]["support"]["required_claudian_version"] == "2.2.6"
    assert result["data"]["mutation_performed"] is False


@pytest.mark.parametrize("version", ["2.0.4", "2.2.6", "2.2.7", "2.2.5", "2.2.8"])
def test_exact_version_allowlist_agrees_for_inspection_and_selected_vault(version):
    probe = FakeProbe(claudian_version=version, vaults=[{
        "vault_id": "vault-a", "display_name": "Notes",
        "claudian_version": version, "claudian_enabled": True,
    }])
    snapshot = Inspector(probe).snapshot()
    supported = version in {"2.0.4", "2.2.6", "2.2.7"}
    assert ("unsupported_claudian_version" not in snapshot["support"]["reason_codes"]) == supported
    plan = PlanBuilder().build(snapshot, mode="local_tailscale", vault_id="vault-a")
    assert ("unsupported_claudian_version" not in plan["blockers"]) == supported


def test_local_probe_discovers_vault_and_claudian_without_exposing_local_path(tmp_path):
    home = tmp_path / "home"
    vault = tmp_path / "Private Person" / "Notes"
    plugin = vault / ".obsidian" / "plugins" / "claudian"
    plugin.mkdir(parents=True)
    (vault / ".obsidian" / "community-plugins.json").write_text('["claudian"]', encoding="utf-8")
    (plugin / "manifest.json").write_text(
        json.dumps({"id": "claudian", "name": "Claudian", "version": "2.0.4"}),
        encoding="utf-8",
    )
    obsidian_config = home / "Library" / "Application Support" / "obsidian"
    obsidian_config.mkdir(parents=True)
    (obsidian_config / "obsidian.json").write_text(
        json.dumps({"vaults": {"vault-opaque": {"path": str(vault), "open": True}}}),
        encoding="utf-8",
    )

    snapshot = Inspector(LocalInspectionProbe(home=home)).snapshot()
    encoded = json.dumps(snapshot)
    assert snapshot["vaults"] == [
        {
            "claudian_enabled": True,
            "claudian_version": "2.0.4",
            "display_name": "Notes",
            "open": True,
            "vault_id": "vault-opaque",
            "remote_vault_id_ready": False,
        }
    ]
    assert snapshot["claudian"]["enabled"] is True
    assert "secure_provisioning_missing" in snapshot["support"]["reason_codes"]
    assert snapshot["installation"]["secure_provisioning_available"] is False
    assert str(tmp_path) not in encoded
    assert "Private Person" not in encoded


def test_missing_secure_provisioning_is_bootstrappable_and_does_not_block_inspection(tmp_path):
    probe = FakeProbe()
    original = probe.installation
    probe.installation = lambda: {
        **original(),
        "secure_provisioning_available": False,
        "secure_provisioning_probe": "companion_route_unavailable",
    }
    output = io.StringIO()
    assert main(
        ["--state-dir", str(tmp_path), "inspect"],
        stdout=output,
        services=LifecycleServices(probe, {}),
    ) == 0
    result = json.loads(output.getvalue())
    assert result["state"] == "ready"
    assert result["code"] == "inspection_ready"
    assert "secure_provisioning_missing" in result["data"]["snapshot"]["support"]["reason_codes"]


def test_local_probe_hashes_profile_generation_without_exposing_endpoint(tmp_path):
    home = tmp_path / "home"
    root = home / "Library" / "Application Support" / "Claudian Remote"
    release = root / "releases" / "claudian-remote-0.2.0-beta.1"
    release.mkdir(parents=True)
    root.mkdir(parents=True, exist_ok=True)
    (root / "current").symlink_to(release)
    (root / "config").mkdir()
    endpoint = "https://private-relay.user.example"
    (root / "config" / "connection-profile.json").write_text(json.dumps({
        "mode": "remote_vps",
        "installation_id": "installation-a",
        "vault_id": "vault-a",
        "endpoint": endpoint,
        "endpoint_audience": "claudian-remote:remote_vps:installation-a",
        "epoch": "epoch-a",
        "cursor": 999,
    }), encoding="utf-8")

    installation = LocalInspectionProbe(home=home).installation()
    encoded = json.dumps(installation)
    assert installation["compatibility_set_id"] == "claudian-remote-0.2.0-beta.1"
    assert installation["profile_mode"] == "remote_vps"
    assert str(installation["profile_generation_id"]).startswith("profile-generation-")
    assert endpoint not in encoded
    assert str(tmp_path) not in encoded


def test_local_probe_classifies_recognized_legacy_plugin_without_exposing_credential(tmp_path):
    home = tmp_path / "home"
    vault = tmp_path / "Private" / "Notes"
    plugin = vault / ".obsidian" / "plugins" / "whale-agent-bridge"
    plugin.mkdir(parents=True)
    (plugin / "manifest.json").write_text(
        json.dumps(
            {
                "id": "whale-agent-bridge",
                "version": "recognized-dogfood-lineage",
            }
        ),
        encoding="utf-8",
    )
    (plugin / "data.json").write_text(
        json.dumps({"mobile_token": "synthetic-secret-must-not-leak"}),
        encoding="utf-8",
    )
    (vault / ".obsidian" / "community-plugins.json").write_text(
        '["whale-agent-bridge"]', encoding="utf-8"
    )
    config = home / "Library" / "Application Support" / "obsidian"
    config.mkdir(parents=True)
    (config / "obsidian.json").write_text(
        json.dumps({"vaults": {"vault-a": {"path": str(vault), "open": True}}}),
        encoding="utf-8",
    )

    snapshot = Inspector(LocalInspectionProbe(home=home)).snapshot()
    encoded = json.dumps(snapshot)

    assert snapshot["journey"]["journey"] == "legacy_upgrade"
    assert snapshot["journey"]["legacy_authority_capability"] == "unavailable"
    assert snapshot["installation"]["legacy_authority_adapter"] == "unclassified"
    assert snapshot["installation"]["plugin_lineage"]["legacy"] == {
        "enabled": True,
        "present": True,
        "recognized": True,
        "versions": ["recognized-dogfood-lineage"],
    }
    assert "synthetic-secret-must-not-leak" not in encoded
    assert str(tmp_path) not in encoded


@pytest.mark.parametrize("version, build, recognized", [
    ("custom-build", b"known-build", False),
    ("0.2.0", b"known-build", True),
    ("0.2.0", b"unknown-build", False),
])
def test_local_probe_binds_legacy_version_to_known_build(tmp_path, monkeypatch, version, build, recognized):
    import hashlib
    from installer.claudian_remote_lifecycle import inspect as inspection
    monkeypatch.setattr(inspection, "SUPPORTED_LEGACY_PLUGIN_BUILDS", {"0.2.0": hashlib.sha256(b"known-build").hexdigest()})
    home = tmp_path / "home"
    vault = tmp_path / "Private" / "Notes"
    plugin = vault / ".obsidian" / "plugins" / "whale-agent-bridge"
    plugin.mkdir(parents=True)
    (plugin / "manifest.json").write_text(
        json.dumps({"id": "whale-agent-bridge", "version": version}),
        encoding="utf-8",
    )
    (plugin / "main.js").write_bytes(build)
    (vault / ".obsidian" / "community-plugins.json").write_text(
        '["whale-agent-bridge"]', encoding="utf-8"
    )
    config = home / "Library" / "Application Support" / "obsidian"
    config.mkdir(parents=True)
    (config / "obsidian.json").write_text(
        json.dumps({"vaults": {"vault-a": {"path": str(vault), "open": True}}}),
        encoding="utf-8",
    )

    snapshot = Inspector(LocalInspectionProbe(home=home)).snapshot()

    assert snapshot["installation"]["plugin_lineage"]["legacy"] == {
        "enabled": True,
        "present": True,
        "recognized": recognized,
        "versions": [version],
    }
    if not recognized:
        assert snapshot["journey"]["journey"] == "coexistence_conflict"
        assert snapshot["journey"]["reason_code"] == "unsupported_legacy_lineage"
        assert snapshot["journey"]["blocked"] is True
    else:
        assert snapshot["journey"]["journey"] == "legacy_upgrade"


def test_both_enabled_remote_plugins_are_reported_as_a_conflict(tmp_path):
    home = tmp_path / "home"
    vault = tmp_path / "Notes"
    for plugin_id in ("whale-agent-bridge", "claudian-remote"):
        plugin = vault / ".obsidian" / "plugins" / plugin_id
        plugin.mkdir(parents=True, exist_ok=True)
        version = (
            "recognized-dogfood-lineage"
            if plugin_id == "whale-agent-bridge"
            else "fixture"
        )
        (plugin / "manifest.json").write_text(
            json.dumps({"id": plugin_id, "version": version}), encoding="utf-8"
        )
    (vault / ".obsidian" / "community-plugins.json").write_text(
        '["whale-agent-bridge","claudian-remote"]', encoding="utf-8"
    )
    config = home / "Library" / "Application Support" / "obsidian"
    config.mkdir(parents=True)
    (config / "obsidian.json").write_text(
        json.dumps({"vaults": {"vault-a": {"path": str(vault)}}}), encoding="utf-8"
    )

    snapshot = Inspector(LocalInspectionProbe(home=home)).snapshot()

    assert snapshot["journey"]["journey"] == "coexistence_conflict"
    assert snapshot["journey"]["reason_code"] == "legacy_and_current_plugin_enabled"
    assert "legacy_and_current_plugin_enabled" in snapshot["support"]["reason_codes"]


def test_inspection_binds_unresolved_operation_arbitration_before_journey_selection():
    arbitration = {
        "state": "reconciliation_required",
        "reason_code": "prior_operation_recovery_required",
        "prior_operation_terminal": False,
        "terminal_operation_ids": [],
        "operation_id": "op-" + "a" * 32,
        "recommended_action": "rollback",
    }

    snapshot = Inspector(FakeProbe()).snapshot(operation_arbitration=arbitration)

    assert snapshot["operation_arbitration"] == arbitration
    assert snapshot["journey"]["journey"] == "unclassified"
    assert snapshot["journey"]["prior_operation_terminal"] is False
    assert snapshot["journey"]["existing_operation"] == {
        "operation_id": "op-" + "a" * 32,
        "terminal": False,
        "recommended_action": "rollback",
    }
    assert "operation_reconciliation_required" in snapshot["support"]["reason_codes"]


def test_invalid_prior_artifact_without_readable_operation_id_still_blocks_inspection():
    arbitration = {
        "state": "blocked",
        "reason_code": "prior_operation_artifact_invalid",
        "prior_operation_terminal": False,
        "terminal_operation_ids": [],
        "recommended_action": "manual_recovery_required",
    }

    snapshot = Inspector(FakeProbe()).snapshot(operation_arbitration=arbitration)

    assert snapshot["journey"]["journey"] == "unclassified"
    assert "existing_operation" not in snapshot["journey"]
    assert snapshot["operation_arbitration"]["reason_code"] == (
        "prior_operation_artifact_invalid"
    )
