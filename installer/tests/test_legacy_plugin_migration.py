import json

import pytest

from installer.claudian_remote_lifecycle.migrations import LegacyPluginMigration


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def enabled_plugins(vault):
    return json.loads((vault / ".obsidian/community-plugins.json").read_text(encoding="utf-8"))


def verified_revoker(calls):
    def revoke(credential):
        calls.append(credential)
        return {"verified": True}

    return revoke


def test_old_and_new_enabled_plugins_block_before_any_mutation(tmp_path):
    vault = tmp_path / "vault"
    old = vault / ".obsidian/plugins/whale-agent-bridge"
    new = vault / ".obsidian/plugins/claudian-remote"
    write_json(old / "data.json", {"mobile_token": "legacy-secret"})
    write_json(new / "manifest.json", {"id": "claudian-remote"})
    write_json(vault / ".obsidian/community-plugins.json", ["whale-agent-bridge", "claudian-remote"])

    migration = LegacyPluginMigration(
        vault,
        tmp_path / "state",
        lambda _credential: {"verified": True},
        target_vault_id="vault-a",
        target_mode="local_tailscale",
    )
    with pytest.raises(ValueError, match="legacy_and_current_plugin_enabled"):
        migration.prepare(operation_id="op-" + "a" * 32)

    assert json.loads((old / "data.json").read_text())["mobile_token"] == "legacy-secret"
    assert old.is_dir() and new.is_dir()


def test_legacy_plugin_is_sanitized_isolated_and_committed_without_secret_journal(tmp_path):
    vault = tmp_path / "vault"
    state = tmp_path / "state"
    old = vault / ".obsidian/plugins/whale-agent-bridge"
    new = vault / ".obsidian/plugins/claudian-remote"
    write_json(
        old / "data.json",
        {
            "vault_id": "vault-a",
            "connection_mode": "local_tailscale",
            "notifications_enabled": False,
            "mobile_token": "legacy-secret",
            "relay_base_url": "https://private.example",
            "upload_directory": "/Users/example/private",
        },
    )
    write_json(old / "manifest.json", {"id": "whale-agent-bridge"})
    write_json(vault / ".obsidian/community-plugins.json", ["whale-agent-bridge", "other-plugin"])
    revoked = []
    operation_id = "op-" + "b" * 32

    migration = LegacyPluginMigration(
        vault,
        state,
        verified_revoker(revoked),
        target_vault_id="vault-a",
        target_mode="local_tailscale",
    )
    prepared = migration.prepare(operation_id=operation_id)
    assert prepared["legacy_present"] is True
    assert revoked == ["legacy-secret"]
    assert not old.exists()
    assert "whale-agent-bridge" not in enabled_plugins(vault)

    new.mkdir(parents=True)
    migration.activate_new(operation_id=operation_id, destination=new)
    assert enabled_plugins(vault) == ["other-plugin", "claudian-remote"]
    assert json.loads((new / "data.json").read_text()) == {
        "schema_version": 2,
        "vault_id": "vault-a",
        "connection_mode": "local_tailscale",
        "notifications_enabled": False,
        "haptics_enabled": True,
    }

    migration.commit(operation_id=operation_id)
    assert migration.quarantine_path(operation_id).is_dir()
    assert "legacy-secret" not in (migration.quarantine_path(operation_id) / "data.json").read_text()
    encoded = "\n".join(path.read_text(encoding="utf-8") for path in state.glob("*.json"))
    assert "legacy-secret" not in encoded
    assert "private.example" not in encoded
    assert "/Users/example" not in encoded

    repeated = migration.prepare(operation_id=operation_id)
    assert repeated["already_completed"] is True
    assert revoked == ["legacy-secret"]


def test_rollback_restores_old_code_but_never_restores_legacy_token(tmp_path):
    vault = tmp_path / "vault"
    state = tmp_path / "state"
    old = vault / ".obsidian/plugins/whale-agent-bridge"
    new = vault / ".obsidian/plugins/claudian-remote"
    write_json(old / "manifest.json", {"id": "whale-agent-bridge"})
    write_json(old / "data.json", {"mobile_token": "legacy-secret", "notifications_enabled": True})
    write_json(vault / ".obsidian/community-plugins.json", ["whale-agent-bridge"])
    operation_id = "op-" + "c" * 32

    migration = LegacyPluginMigration(
        vault,
        state,
        lambda _credential: {"verified": True},
        target_vault_id="vault-a",
        target_mode="local_tailscale",
    )
    migration.prepare(operation_id=operation_id)
    new.mkdir(parents=True)
    migration.activate_new(operation_id=operation_id, destination=new)
    migration.rollback(operation_id=operation_id)

    assert old.is_dir()
    assert "whale-agent-bridge" in enabled_plugins(vault)
    assert "claudian-remote" not in enabled_plugins(vault)
    restored = json.loads((old / "data.json").read_text())
    assert restored == {
        "schema_version": 2,
        "vault_id": "vault-a",
        "connection_mode": "local_tailscale",
        "notifications_enabled": True,
        "haptics_enabled": True,
    }
    assert "legacy-secret" not in json.dumps(restored)


def test_no_legacy_plugin_is_a_strict_noop_for_existing_current_preferences(tmp_path):
    vault = tmp_path / "vault"
    current = vault / ".obsidian/plugins/claudian-remote"
    original = {
        "schema_version": 2,
        "vault_id": "vault-a",
        "connection_mode": "local_tailscale",
        "notifications_enabled": False,
    }
    write_json(current / "manifest.json", {"id": "claudian-remote"})
    write_json(current / "data.json", original)
    write_json(vault / ".obsidian/community-plugins.json", ["claudian-remote"])
    operation_id = "op-" + "d" * 32
    migration = LegacyPluginMigration(
        vault,
        tmp_path / "state",
        lambda _credential: pytest.fail("revoker must not be called"),
        target_vault_id="vault-a",
        target_mode="local_tailscale",
    )

    assert migration.prepare(operation_id=operation_id)["legacy_present"] is False
    migration.activate_new(operation_id=operation_id, destination=current)
    migration.commit(operation_id=operation_id)

    assert json.loads((current / "data.json").read_text()) == original
    assert not (tmp_path / "state" / f"{operation_id}.legacy-plugin.json").exists()


def test_migration_rejects_legacy_symlink_without_touching_external_data(tmp_path):
    vault = tmp_path / "vault"
    external = tmp_path / "external"
    write_json(external / "manifest.json", {"id": "whale-agent-bridge"})
    write_json(external / "data.json", {"mobile_token": "outside-secret"})
    plugins = vault / ".obsidian/plugins"
    plugins.mkdir(parents=True)
    (plugins / "whale-agent-bridge").symlink_to(external, target_is_directory=True)
    write_json(vault / ".obsidian/community-plugins.json", ["whale-agent-bridge"])
    migration = LegacyPluginMigration(
        vault,
        tmp_path / "state",
        lambda _credential: {"verified": True},
        target_vault_id="vault-a",
        target_mode="local_tailscale",
    )

    with pytest.raises(ValueError, match="legacy_plugin_unsafe_path"):
        migration.prepare(operation_id="op-" + "e" * 32)

    assert json.loads((external / "data.json").read_text()) == {"mobile_token": "outside-secret"}


def test_resume_reconciles_interruption_after_revocation_without_secret_journal(tmp_path):
    vault = tmp_path / "vault"
    state = tmp_path / "state"
    old = vault / ".obsidian/plugins/whale-agent-bridge"
    write_json(old / "manifest.json", {"id": "whale-agent-bridge"})
    write_json(old / "data.json", {"mobile_token": "legacy-secret", "vault_id": "wrong-vault"})
    write_json(vault / ".obsidian/community-plugins.json", ["whale-agent-bridge"])
    calls = []
    interrupted = {"done": False}

    def interrupt(phase):
        if phase == "after_credential_revoked" and not interrupted["done"]:
            interrupted["done"] = True
            raise RuntimeError("simulated_crash")

    operation_id = "op-" + "f" * 32
    first = LegacyPluginMigration(
        vault,
        state,
        verified_revoker(calls),
        target_vault_id="vault-a",
        target_mode="local_tailscale",
        interruption_probe=interrupt,
    )
    with pytest.raises(RuntimeError, match="simulated_crash"):
        first.prepare(operation_id=operation_id)

    encoded = "\n".join(path.read_text(encoding="utf-8") for path in state.glob("*.json"))
    assert "legacy-secret" not in encoded
    resumed = LegacyPluginMigration(
        vault,
        state,
        verified_revoker(calls),
        target_vault_id="vault-a",
        target_mode="local_tailscale",
    )
    assert resumed.prepare(operation_id=operation_id)["legacy_present"] is True
    assert calls == ["legacy-secret"]
    assert not old.exists()
    migrated_state = json.loads((state / f"{operation_id}.legacy-plugin.json").read_text())
    assert migrated_state["synchronized"]["vault_id"] == "vault-a"
