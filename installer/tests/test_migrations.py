import json

from installer.claudian_remote_lifecycle.migrations import migrate_legacy_shared_token


def test_legacy_shared_token_migration_revokes_once_and_never_journals_secret():
    state = {}
    synchronized = {
        "mobile_token": "legacy-shared-secret",
        "device_id": "legacy-device",
        "remote_v2_recovery": {"applied_cursor": 9},
        "notifications_enabled": True,
    }
    revoked = []

    first = migrate_legacy_shared_token(synchronized, state, revoked.append)
    second = migrate_legacy_shared_token(synchronized, state, revoked.append)

    assert revoked == ["legacy-shared-secret"]
    assert first["re_pair_required"] is True
    assert second["already_completed"] is True
    assert first["synchronized"] == {"schema_version": 2, "vault_id": "", "connection_mode": "", "notifications_enabled": True, "haptics_enabled": True}
    serialized = json.dumps({"state": state, "result": first})
    assert "legacy-shared-secret" not in serialized
    assert "legacy-device" not in serialized


def test_purge_and_revocation_actions_include_offline_cache_removal():
    state = {"device_cache_present": True}
    result = migrate_legacy_shared_token({}, state, lambda _credential: None, purge=True)
    assert result["remove_device_cache"] is True
    assert state["device_cache_present"] is False
