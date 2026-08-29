import json

import pytest

from installer.claudian_remote_lifecycle.legacy_authority import (
    LegacyCredentialRetirementService,
    LegacyRetirementOutcomeUnknown,
    RetirementCommit,
    RetirementReconciliationResult,
)
from installer.claudian_remote_lifecycle.migrations import LegacyPluginMigration


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def enabled_plugins(vault):
    return json.loads((vault / ".obsidian/community-plugins.json").read_text(encoding="utf-8"))


def retirement_commit(
    operation_id,
    plan_id,
    installation_id,
    vault_id,
    role="mobile",
):
    return RetirementCommit(
        authority_instance_id="authority-a",
        authority_origin_digest="a" * 64,
        runtime_key_id="runtime-key-a",
        owner_id="owner-a",
        installation_id=installation_id,
        mac_id="mac-a",
        vault_id=vault_id,
        role=role,
        slot_id="slot-a",
        old_generation=1,
        target_generation=2,
        operation_id=operation_id,
        plan_id=plan_id,
        release_digest="b" * 64,
        helper_digest="c" * 64,
        nonce_digest="d" * 64,
        idempotency_digest="e" * 64,
        proof_digest="f" * 64,
        consumed_at_epoch=1_800_000_000,
    )


class RecordingRetirementService(LegacyCredentialRetirementService):
    def __init__(self, calls, outcome="commit"):
        self.calls = calls
        self.outcome = outcome

    def retire(
        self,
        *,
        credential,
        operation_id,
        plan_id,
        installation_id,
        vault_id,
        role,
    ):
        self.calls.append(credential.read_once().decode("utf-8"))
        if self.outcome == "commit":
            return retirement_commit(
                operation_id,
                plan_id,
                installation_id,
                vault_id,
                role,
            )
        return self.outcome


class NeverRetireService(LegacyCredentialRetirementService):
    def retire(self, **_kwargs):
        pytest.fail("retirement service must not be called")


class LeakyFailureService(LegacyCredentialRetirementService):
    def retire(self, *, credential, **_kwargs):
        leaked = credential.read_once().decode("utf-8")
        raise RuntimeError(f"adapter echoed {leaked}")


class WrongPlanRetirementService(LegacyCredentialRetirementService):
    def retire(
        self,
        *,
        credential,
        operation_id,
        plan_id,
        installation_id,
        vault_id,
        role,
    ):
        credential.read_once()
        return retirement_commit(
            operation_id,
            "plan-wrong",
            installation_id,
            vault_id,
            role,
        )


class RecoveringRetirementService(LegacyCredentialRetirementService):
    def __init__(self, outcome):
        self.outcome = outcome
        self.dispatches = 0
        self.reconciliations = 0

    def retire(self, *, credential, **_kwargs):
        self.dispatches += 1
        credential.read_once()
        raise LegacyRetirementOutcomeUnknown("response_lost_after_dispatch")

    def reconcile(
        self,
        *,
        credential,
        operation_id,
        plan_id,
        installation_id,
        vault_id,
        role,
        **_kwargs,
    ):
        self.reconciliations += 1
        credential.read_once()
        commit = (
            retirement_commit(
                operation_id,
                plan_id,
                installation_id,
                vault_id,
                role,
            )
            if self.outcome == "retired"
            else None
        )
        return RetirementReconciliationResult(self.outcome, commit)


def verified_revoker(calls):
    return RecordingRetirementService(calls)


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
        RecordingRetirementService([]),
        target_plan_id="plan-beta5",
        target_installation_id="installation-a",
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
        target_plan_id="plan-beta5",
        target_installation_id="installation-a",
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


def test_rollback_is_rejected_after_retirement_commit(tmp_path):
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
        RecordingRetirementService([]),
        target_plan_id="plan-beta5",
        target_installation_id="installation-a",
        target_vault_id="vault-a",
        target_mode="local_tailscale",
    )
    migration.prepare(operation_id=operation_id)
    new.mkdir(parents=True)
    migration.activate_new(operation_id=operation_id, destination=new)
    with pytest.raises(ValueError, match="legacy_credential_already_retired"):
        migration.rollback(operation_id=operation_id)

    assert not old.exists()
    assert enabled_plugins(vault) == ["claudian-remote"]


@pytest.mark.parametrize("permissive_outcome", [True, {"verified": True}])
def test_rollback_before_verified_revocation_preserves_legacy_credential(
    tmp_path, permissive_outcome
):
    vault = tmp_path / "vault"
    state = tmp_path / "state"
    old = vault / ".obsidian/plugins/whale-agent-bridge"
    write_json(old / "manifest.json", {"id": "whale-agent-bridge"})
    write_json(old / "data.json", {"mobile_token": "still-active"})
    write_json(vault / ".obsidian/community-plugins.json", ["whale-agent-bridge"])
    operation_id = "op-" + "d" * 32
    migration = LegacyPluginMigration(
        vault,
        state,
        RecordingRetirementService([], outcome=permissive_outcome),
        target_plan_id="plan-beta5",
        target_installation_id="installation-a",
        target_vault_id="vault-a",
        target_mode="local_tailscale",
    )

    with pytest.raises(ValueError, match="legacy_credential_revocation_unverified"):
        migration.prepare(operation_id=operation_id)
    migration.rollback(operation_id=operation_id)

    assert json.loads((old / "data.json").read_text()) == {
        "mobile_token": "still-active"
    }
    assert enabled_plugins(vault) == ["whale-agent-bridge"]
    assert json.loads(
        (state / f"{operation_id}.legacy-plugin.json").read_text()
    )["phase"] == "rolled_back"


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
        NeverRetireService(),
        target_plan_id="plan-beta5",
        target_installation_id="installation-a",
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
        RecordingRetirementService([]),
        target_plan_id="plan-beta5",
        target_installation_id="installation-a",
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
        target_plan_id="plan-beta5",
        target_installation_id="installation-a",
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
        target_plan_id="plan-beta5",
        target_installation_id="installation-a",
        target_vault_id="vault-a",
        target_mode="local_tailscale",
    )
    assert resumed.prepare(operation_id=operation_id)["legacy_present"] is True
    assert calls == ["legacy-secret"]
    assert not old.exists()
    migrated_state = json.loads((state / f"{operation_id}.legacy-plugin.json").read_text())
    assert migrated_state["synchronized"]["vault_id"] == "vault-a"


def test_resume_reconciles_crash_after_commit_before_journal_promotion(tmp_path):
    vault = tmp_path / "vault"
    state = tmp_path / "state"
    old = vault / ".obsidian/plugins/whale-agent-bridge"
    write_json(old / "manifest.json", {"id": "whale-agent-bridge"})
    write_json(old / "data.json", {"mobile_token": "legacy-secret"})
    write_json(vault / ".obsidian/community-plugins.json", ["whale-agent-bridge"])
    operation_id = "op-" + "1" * 32

    class CommitThenReconcileService(LegacyCredentialRetirementService):
        def __init__(self):
            self.reconciliations = 0

        def retire(
            self,
            *,
            credential,
            operation_id,
            plan_id,
            installation_id,
            vault_id,
            role,
            **_kwargs,
        ):
            credential.read_once()
            return retirement_commit(
                operation_id,
                plan_id,
                installation_id,
                vault_id,
                role,
            )

        def reconcile(
            self,
            *,
            credential,
            operation_id,
            plan_id,
            installation_id,
            vault_id,
            role,
            **_kwargs,
        ):
            self.reconciliations += 1
            credential.read_once()
            return RetirementReconciliationResult(
                "retired",
                retirement_commit(
                    operation_id,
                    plan_id,
                    installation_id,
                    vault_id,
                    role,
                ),
            )

    service = CommitThenReconcileService()

    def interrupt(phase):
        if phase == "after_retirement_commit_consumed":
            raise RuntimeError("simulated_commit_journal_split")

    first = LegacyPluginMigration(
        vault,
        state,
        service,
        target_plan_id="plan-beta5",
        target_installation_id="installation-a",
        target_vault_id="vault-a",
        target_mode="local_tailscale",
        interruption_probe=interrupt,
    )
    with pytest.raises(RuntimeError, match="simulated_commit_journal_split"):
        first.prepare(operation_id=operation_id)

    journal = json.loads(
        (state / f"{operation_id}.legacy-plugin.json").read_text()
    )
    assert journal["phase"] == "retirement_outcome_unknown"
    assert old.is_dir()
    assert json.loads((old / "data.json").read_text())["mobile_token"] == "legacy-secret"

    resumed = LegacyPluginMigration(
        vault,
        state,
        service,
        target_plan_id="plan-beta5",
        target_installation_id="installation-a",
        target_vault_id="vault-a",
        target_mode="local_tailscale",
    )
    assert resumed.prepare(operation_id=operation_id)["legacy_present"] is True
    assert service.reconciliations == 1
    assert not old.exists()


@pytest.mark.parametrize(
    ("outcome", "expected_phase", "expected_error"),
    [
        (
            "not_applied",
            "retirement_not_applied",
            "legacy_credential_retirement_not_applied",
        ),
        (
            "inconclusive",
            "retirement_inconclusive",
            "legacy_credential_retirement_inconclusive",
        ),
    ],
)
def test_resume_preserves_non_retired_reconciliation_outcome(
    tmp_path,
    outcome,
    expected_phase,
    expected_error,
):
    vault = tmp_path / "vault"
    state = tmp_path / "state"
    old = vault / ".obsidian/plugins/whale-agent-bridge"
    write_json(old / "manifest.json", {"id": "whale-agent-bridge"})
    write_json(old / "data.json", {"mobile_token": "legacy-secret"})
    write_json(vault / ".obsidian/community-plugins.json", ["whale-agent-bridge"])
    service = RecoveringRetirementService(outcome)
    operation_id = "op-" + "7" * 32
    migration = LegacyPluginMigration(
        vault,
        state,
        service,
        target_plan_id="plan-beta5",
        target_installation_id="installation-a",
        target_vault_id="vault-a",
        target_mode="local_tailscale",
    )

    with pytest.raises(
        ValueError, match="legacy_credential_retirement_outcome_unknown"
    ):
        migration.prepare(operation_id=operation_id)
    with pytest.raises(ValueError, match=expected_error):
        migration.prepare(operation_id=operation_id)

    journal = json.loads(
        (state / f"{operation_id}.legacy-plugin.json").read_text()
    )
    assert journal["phase"] == expected_phase
    assert service.dispatches == 1
    assert service.reconciliations == 1
    assert json.loads((old / "data.json").read_text())["mobile_token"] == "legacy-secret"


def test_resume_finishes_forward_after_authority_proves_retired(tmp_path):
    vault = tmp_path / "vault"
    state = tmp_path / "state"
    old = vault / ".obsidian/plugins/whale-agent-bridge"
    write_json(old / "manifest.json", {"id": "whale-agent-bridge"})
    write_json(old / "data.json", {"mobile_token": "legacy-secret"})
    write_json(vault / ".obsidian/community-plugins.json", ["whale-agent-bridge"])
    service = RecoveringRetirementService("retired")
    operation_id = "op-" + "6" * 32
    migration = LegacyPluginMigration(
        vault,
        state,
        service,
        target_plan_id="plan-beta5",
        target_installation_id="installation-a",
        target_vault_id="vault-a",
        target_mode="local_tailscale",
    )

    with pytest.raises(
        ValueError, match="legacy_credential_retirement_outcome_unknown"
    ):
        migration.prepare(operation_id=operation_id)
    result = migration.prepare(operation_id=operation_id)

    assert result["legacy_present"] is True
    assert service.dispatches == 1
    assert service.reconciliations == 1
    assert not old.exists()


def test_post_retirement_journal_without_bound_commit_fails_before_mutation(tmp_path):
    vault = tmp_path / "vault"
    state = tmp_path / "state"
    old = vault / ".obsidian/plugins/whale-agent-bridge"
    write_json(old / "manifest.json", {"id": "whale-agent-bridge"})
    write_json(old / "data.json", {"mobile_token": "still-active"})
    write_json(vault / ".obsidian/community-plugins.json", ["whale-agent-bridge"])
    operation_id = "op-" + "8" * 32
    write_json(
        state / f"{operation_id}.legacy-plugin.json",
        {
            "migration_schema": "claudian-remote.legacy-plugin/v2",
            "operation_id": operation_id,
            "plan_id": "plan-beta5",
            "installation_id": "installation-a",
            "vault_id": "vault-a",
            "connection_mode": "local_tailscale",
            "phase": "credential_revoked",
            "legacy_present": True,
            "legacy_was_enabled": True,
            "current_was_enabled": False,
            "re_pair_required": True,
            "synchronized": {
                "schema_version": 2,
                "vault_id": "vault-a",
                "connection_mode": "local_tailscale",
                "notifications_enabled": True,
                "haptics_enabled": True,
            },
        },
    )
    migration = LegacyPluginMigration(
        vault,
        state,
        NeverRetireService(),
        target_plan_id="plan-beta5",
        target_installation_id="installation-a",
        target_vault_id="vault-a",
        target_mode="local_tailscale",
    )

    with pytest.raises(ValueError, match="legacy_plugin_retirement_commit_required"):
        migration.prepare(operation_id=operation_id)

    assert json.loads((old / "data.json").read_text()) == {
        "mobile_token": "still-active"
    }
    assert old.is_dir()
    assert enabled_plugins(vault) == ["whale-agent-bridge"]


def test_retirement_commit_for_wrong_plan_fails_before_legacy_mutation(tmp_path):
    vault = tmp_path / "vault"
    state = tmp_path / "state"
    old = vault / ".obsidian/plugins/whale-agent-bridge"
    write_json(old / "manifest.json", {"id": "whale-agent-bridge"})
    write_json(old / "data.json", {"mobile_token": "still-active"})
    write_json(vault / ".obsidian/community-plugins.json", ["whale-agent-bridge"])
    migration = LegacyPluginMigration(
        vault,
        state,
        WrongPlanRetirementService(),
        target_plan_id="plan-beta5",
        target_installation_id="installation-a",
        target_vault_id="vault-a",
        target_mode="local_tailscale",
    )

    with pytest.raises(
        ValueError, match="legacy_credential_retirement_binding_mismatch"
    ):
        migration.prepare(operation_id="op-" + "7" * 32)

    assert json.loads((old / "data.json").read_text()) == {
        "mobile_token": "still-active"
    }
    assert old.is_dir()


def test_adapter_failure_cannot_echo_credential_into_error_or_journal(tmp_path):
    marker = "CANARY-LEGACY-CREDENTIAL"
    vault = tmp_path / "vault"
    state = tmp_path / "state"
    old = vault / ".obsidian/plugins/whale-agent-bridge"
    write_json(old / "manifest.json", {"id": "whale-agent-bridge"})
    write_json(old / "data.json", {"mobile_token": marker})
    write_json(vault / ".obsidian/community-plugins.json", ["whale-agent-bridge"])
    migration = LegacyPluginMigration(
        vault,
        state,
        LeakyFailureService(),
        target_plan_id="plan-beta5",
        target_installation_id="installation-a",
        target_vault_id="vault-a",
        target_mode="local_tailscale",
    )

    with pytest.raises(ValueError, match="legacy_credential_retirement_failed") as error:
        migration.prepare(operation_id="op-" + "9" * 32)

    assert marker not in str(error.value)
    encoded = "\n".join(path.read_text(encoding="utf-8") for path in state.glob("*.json"))
    assert marker not in encoded
