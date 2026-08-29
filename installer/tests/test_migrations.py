import json

import pytest

from installer.claudian_remote_lifecycle.legacy_authority import (
    LegacyCredentialRetirementService,
    RetirementCommit,
)
from installer.claudian_remote_lifecycle.migrations import migrate_legacy_shared_token


class RecordingService(LegacyCredentialRetirementService):
    def __init__(self, calls):
        self.calls = calls

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


def test_legacy_shared_token_migration_revokes_once_and_never_journals_secret():
    state = {}
    synchronized = {
        "mobile_token": "legacy-shared-secret",
        "device_id": "legacy-device",
        "remote_v2_recovery": {"applied_cursor": 9},
        "notifications_enabled": True,
    }
    revoked = []

    service = RecordingService(revoked)
    first = migrate_legacy_shared_token(
        synchronized,
        state,
        service,
        operation_id="op-" + "a" * 32,
        plan_id="plan-beta5",
        target_installation_id="installation-a",
        target_vault_id="vault-a",
    )
    second = migrate_legacy_shared_token(
        synchronized,
        state,
        service,
        operation_id="op-" + "a" * 32,
        plan_id="plan-beta5",
        target_installation_id="installation-a",
        target_vault_id="vault-a",
    )

    assert revoked == ["legacy-shared-secret"]
    assert first["re_pair_required"] is True
    assert second["already_completed"] is True
    assert first["synchronized"] == {"schema_version": 2, "vault_id": "", "connection_mode": "", "notifications_enabled": True, "haptics_enabled": True}
    serialized = json.dumps({"state": state, "result": first})
    assert "legacy-shared-secret" not in serialized
    assert "legacy-device" not in serialized


def test_purge_and_revocation_actions_include_offline_cache_removal():
    state = {"device_cache_present": True}
    result = migrate_legacy_shared_token({}, state, None, purge=True)
    assert result["remove_device_cache"] is True
    assert state["device_cache_present"] is False


@pytest.mark.parametrize(
    "marker",
    [True, {}, {"completed": False}, {"completed": True, "re_pair_required": True}],
)
def test_legacy_shared_token_migration_rejects_unbound_completion_markers(marker):
    state = {"migrations": {"legacy_shared_token_v1": marker}}
    with pytest.raises(ValueError, match="legacy_migration_.*invalid|commit_required"):
        migrate_legacy_shared_token(
            {},
            state,
            None,
            operation_id="op-" + "a" * 32,
            target_vault_id="vault-a",
        )
