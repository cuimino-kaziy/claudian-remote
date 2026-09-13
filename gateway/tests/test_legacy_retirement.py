from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import asdict

import pytest

from gateway.relay.app import create_app
from gateway.relay.legacy_retirement import (
    LegacyRetirementRequest,
    LegacyRetirementStore,
    read_private_runtime_key,
)
from gateway.relay.relay_server import RelayConfig, RelayToken


NOW = 2_000_000_000


def test_runtime_key_reader_rejects_symlink_and_oversize(tmp_path):
    key = tmp_path / "runtime.key"
    key.write_bytes(b"runtime-proof-key")
    key.chmod(0o600)
    assert read_private_runtime_key(key) == b"runtime-proof-key"

    link = tmp_path / "runtime-link.key"
    link.symlink_to(key)
    with pytest.raises(ValueError, match="runtime_key"):
        read_private_runtime_key(link)

    oversized = tmp_path / "oversized.key"
    oversized.write_bytes(b"x" * 4097)
    oversized.chmod(0o600)
    with pytest.raises(ValueError, match="runtime_key_unsafe"):
        read_private_runtime_key(oversized)


def request(**changes):
    value = {
        "operation_id": "op-" + "a" * 32,
        "plan_id": "plan-" + "b" * 64,
        "authority_origin": "https://relay.example",
        "owner_id": "owner-a",
        "installation_id": "installation-a",
        "mac_id": "mac-a",
        "vault_id": "vault-a",
        "role": "mobile",
        "slot_id": "slot-a",
        "old_generation": 1,
        "target_generation": 2,
        "release_digest": "c" * 64,
        "helper_digest": "d" * 64,
        "nonce": "nonce-a",
        "idempotency_key": "idempotency-a",
    }
    value.update(changes)
    return LegacyRetirementRequest.from_mapping(value)


@pytest.mark.parametrize("profile_id", ["unsupported", "", None, []])
def test_invalid_retirement_profile_is_rejected_before_storage(tmp_path, profile_id):
    with pytest.raises(ValueError, match="legacy_retirement_profile_invalid"):
        RelayConfig(legacy_retirement_profile_id=profile_id)
    config_path = tmp_path / "relay.json"
    config_path.write_text(json.dumps({"legacy_retirement_profile_id": profile_id}))
    with pytest.raises(ValueError, match="legacy_retirement_profile_invalid"):
        RelayConfig.from_file(config_path)
    database = tmp_path / "retirement.db"
    with pytest.raises(ValueError, match="legacy_retirement_profile_invalid"):
        LegacyRetirementStore(
            database,
            profile_id=profile_id,
            authority_instance_id="authority-a",
            protocol_version="legacy-retirement/v1",
            runtime_key_id="runtime-key-a",
            runtime_key=b"runtime-proof-key",
            restart_epoch=1,
            clock=lambda: NOW,
        )
    assert not database.exists()


def test_local_retirement_is_idempotent_and_persists_across_restart(tmp_path):
    database = tmp_path / "legacy-retirement.db"
    runtime_key = b"runtime-proof-key"
    store = LegacyRetirementStore(
        database,
        authority_instance_id="authority-a",
        protocol_version="legacy-retirement/v1",
        runtime_key_id="runtime-key-a",
        runtime_key=runtime_key,
        restart_epoch=7,
        clock=lambda: NOW,
    )
    store.register_credential(
        slot_id="slot-a",
        credential=b"old-mobile-secret",
        owner_id="owner-a",
        installation_id="installation-a",
        mac_id="mac-a",
        vault_id="vault-a",
        role="mobile",
        consumer_installation_ids=("installation-a",),
        generation=1,
    )
    assert store.descriptor("slot-a", authority_origin="https://relay.example")[
        "authority"
    ]["profile_id"] == "dogfood-local-v1"

    first = store.retire(request(), b"old-mobile-secret")
    assert first["outcome"] == "retired"
    assert first["target_generation"] == 2
    assert store.credential_active("slot-a", b"old-mobile-secret") is False

    reopened = LegacyRetirementStore(
        database,
        authority_instance_id="authority-a",
        protocol_version="legacy-retirement/v1",
        runtime_key_id="runtime-key-a",
        runtime_key=runtime_key,
        restart_epoch=8,
        clock=lambda: NOW + 1,
    )
    replay = reopened.retire(request(), b"old-mobile-secret")
    assert replay["outcome"] == "already_retired"
    assert replay["target_generation"] == 2
    assert reopened.credential_active("slot-a", b"old-mobile-secret") is False

    evidence = base64.b64decode(replay["evidence"], validate=True)
    expected = hmac.new(
        runtime_key,
        reopened.canonical_proof_payload(replay),
        hashlib.sha256,
    ).digest()
    assert hmac.compare_digest(evidence, expected)


def test_reconciliation_distinguishes_not_applied_from_retired(tmp_path):
    runtime_key = b"runtime-proof-key"
    store = LegacyRetirementStore(
        tmp_path / "legacy-retirement.db",
        authority_instance_id="authority-a",
        protocol_version="legacy-retirement/v1",
        runtime_key_id="runtime-key-a",
        runtime_key=runtime_key,
        restart_epoch=7,
        clock=lambda: NOW,
    )
    store.register_credential(
        slot_id="slot-a",
        credential=b"old-mobile-secret",
        owner_id="owner-a",
        installation_id="installation-a",
        mac_id="mac-a",
        vault_id="vault-a",
        role="mobile",
        consumer_installation_ids=("installation-a",),
        generation=1,
    )

    not_applied = store.reconcile(request(), b"old-mobile-secret")
    assert not_applied["outcome"] == "not_applied"
    assert not_applied["receipt"]["current_generation"] == 1
    receipt_evidence = base64.b64decode(
        not_applied["receipt"]["evidence"], validate=True
    )
    assert hmac.compare_digest(
        receipt_evidence,
        hmac.new(
            runtime_key,
            store.canonical_proof_payload(not_applied["receipt"]),
            hashlib.sha256,
        ).digest(),
    )

    store.retire(request(), b"old-mobile-secret")
    retired = store.reconcile(request(), b"old-mobile-secret")
    assert retired["outcome"] == "retired"
    assert retired["proof"]["outcome"] == "already_retired"
    assert retired["verification"]["old_credential_rejected"] is True


def test_unbounded_scope_is_rejected_before_any_retirement(tmp_path):
    store = LegacyRetirementStore(
        tmp_path / "legacy-retirement.db",
        authority_instance_id="authority-a",
        protocol_version="legacy-retirement/v1",
        runtime_key_id="runtime-key-a",
        runtime_key=b"runtime-proof-key",
        restart_epoch=1,
        clock=lambda: NOW,
    )
    with pytest.raises(ValueError, match="shared_credential_scope_unsupported"):
        store.register_credential(
            slot_id="slot-a",
            credential=b"old-mobile-secret",
            owner_id="owner-a",
            installation_id="installation-a",
            mac_id="mac-a",
            vault_id="vault-a",
            role="mobile",
            consumer_installation_ids=("installation-a", "installation-b"),
            generation=1,
        )
    assert not (tmp_path / "legacy-retirement.db").exists()


def test_wrong_binding_and_generation_leave_the_old_credential_active(tmp_path):
    store = LegacyRetirementStore(
        tmp_path / "legacy-retirement.db",
        authority_instance_id="authority-a",
        protocol_version="legacy-retirement/v1",
        runtime_key_id="runtime-key-a",
        runtime_key=b"runtime-proof-key",
        restart_epoch=1,
        clock=lambda: NOW,
    )
    store.register_credential(
        slot_id="slot-a",
        credential=b"old-mobile-secret",
        owner_id="owner-a",
        installation_id="installation-a",
        mac_id="mac-a",
        vault_id="vault-a",
        role="mobile",
        consumer_installation_ids=("installation-a",),
        generation=1,
    )

    with pytest.raises(ValueError, match="retirement_scope_mismatch"):
        store.retire(request(vault_id="vault-b"), b"old-mobile-secret")
    with pytest.raises(ValueError, match="retirement_generation_mismatch"):
        store.retire(
            request(old_generation=2, target_generation=3),
            b"old-mobile-secret",
        )
    assert store.credential_active("slot-a", b"old-mobile-secret") is True


@pytest.mark.asyncio
@pytest.mark.parametrize("profile_id", ["dogfood-local-v1", "dogfood-vps-v1"])
async def test_relay_route_retires_old_token_and_rejects_it_immediately(
    tmp_path,
    aiohttp_client,
    profile_id,
):
    runtime_key = tmp_path / "runtime-proof.key"
    runtime_key.write_bytes(b"runtime-proof-key")
    runtime_key.chmod(0o600)
    token = RelayToken(
        name="mobile",
        role="mobile",
        pairing_id="room-a",
        token="old-mobile-secret",
        installation_id="installation-a",
        vault_id="vault-a",
        device_id="iphone",
        endpoint_audience="claudian-remote:local_tailscale:installation-a",
    )
    config = RelayConfig(
        public_base_url="https://relay.example",
        installation_id="installation-a",
        vault_id="vault-a",
        endpoint_audience="claudian-remote:local_tailscale:installation-a",
        tokens=[token],
        database_path=str(tmp_path / "relay.db"),
        upload_root=str(tmp_path / "uploads"),
        upload_reserve_min_bytes=0,
        upload_reserve_fraction=0,
        legacy_retirement_enabled=True,
        legacy_retirement_profile_id=profile_id,
        legacy_retirement_database_path=str(tmp_path / "retirement.db"),
        legacy_retirement_authority_instance_id="authority-a",
        legacy_retirement_runtime_key_id="runtime-key-a",
        legacy_retirement_runtime_key_path=str(runtime_key),
        legacy_retirement_owner_id="owner-a",
        legacy_retirement_mac_id="mac-a",
    )
    config_data = asdict(config)
    if profile_id == "dogfood-local-v1":
        config_data.pop("legacy_retirement_profile_id")
    config_path = tmp_path / "relay.json"
    config_path.write_text(json.dumps(config_data))
    client = await aiohttp_client(create_app(RelayConfig.from_file(config_path)))
    headers = {"Authorization": "Bearer old-mobile-secret"}

    descriptor_response = await client.get(
        "/api/v2/legacy-retirement/descriptor",
        headers=headers,
    )
    assert descriptor_response.status == 200
    descriptor = await descriptor_response.json()
    assert descriptor["authority"]["profile_id"] == profile_id
    slot = descriptor["slot"]

    retirement = request(
        authority_origin="https://relay.example",
        slot_id=slot["slot_id"],
        old_generation=slot["old_generation"],
        target_generation=slot["target_generation"],
    )
    foreign_authority = request(
        authority_origin="https://foreign.example",
        slot_id=slot["slot_id"],
        old_generation=slot["old_generation"],
        target_generation=slot["target_generation"],
    )
    foreign_commit = await client.post(
        "/api/v2/legacy-retirement/commit",
        headers=headers,
        json=foreign_authority.to_mapping(),
    )
    assert foreign_commit.status == 409
    assert (await foreign_commit.json())["error"] == "retirement_scope_mismatch"

    foreign_reconcile = await client.post(
        "/api/v2/legacy-retirement/reconcile",
        headers=headers,
        json=foreign_authority.to_mapping(),
    )
    assert foreign_reconcile.status == 409
    assert (await foreign_reconcile.json())["error"] == "retirement_scope_mismatch"

    before = await client.post(
        "/api/v2/legacy-retirement/reconcile",
        headers=headers,
        json=retirement.to_mapping(),
    )
    assert before.status == 200
    assert (await before.json())["reconciliation"]["outcome"] == "not_applied"

    response = await client.post(
        "/api/v2/legacy-retirement/commit",
        headers=headers,
        json=retirement.to_mapping(),
    )
    assert response.status == 200
    assert (await response.json())["proof"]["outcome"] == "retired"

    reconciled = await client.post(
        "/api/v2/legacy-retirement/reconcile",
        headers=headers,
        json=retirement.to_mapping(),
    )
    assert reconciled.status == 200
    reconciled_body = await reconciled.json()
    assert reconciled_body["reconciliation"]["outcome"] == "retired"
    assert reconciled_body["reconciliation"]["proof"]["outcome"] == "already_retired"

    replay = await client.post(
        "/api/v2/legacy-retirement/commit",
        headers=headers,
        json=retirement.to_mapping(),
    )
    assert replay.status == 200
    assert (await replay.json())["proof"]["outcome"] == "already_retired"

    verified = await client.post(
        "/api/v2/legacy-retirement/verify",
        headers=headers,
        json=retirement.to_mapping(),
    )
    assert verified.status == 200
    health = (await verified.json())["verification"]
    assert health["authority_instance_id"] == "authority-a"
    assert health["protocol_version"] == "legacy-retirement/v1"
    assert health["target_generation"] == slot["target_generation"]
    assert health["old_credential_rejected"] is True

    denied = await client.post(
        "/api/v2/legacy-retirement/verify",
        headers={"Authorization": "Bearer wrong-secret"},
        json=retirement.to_mapping(),
    )
    assert denied.status == 409
    assert (await denied.json())["error"] == "retirement_verification_binding_invalid"

    rejected = await client.get(
        "/api/v2/legacy-retirement/descriptor",
        headers=headers,
    )
    assert rejected.status == 401
    assert (await rejected.json())["error"] == "revoked"
