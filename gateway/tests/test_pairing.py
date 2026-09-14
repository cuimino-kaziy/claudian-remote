import asyncio
import hashlib
import sqlite3

import pytest
import pytest_asyncio

from gateway.relay.auth import AuthError, TokenAuthenticator
from gateway.relay.pairing import PairingError, PairingStore
from gateway.relay.relay_server import RelayToken


def admin_token():
    return RelayToken(
        name="pairing-admin",
        role="pairing_admin",
        pairing_id="room-a",
        token="admin-secret",
        installation_id="installation-a",
        vault_id="vault-a",
        device_id="mac-a",
        endpoint_audience="claudian-remote:local_tailscale:installation-a",
    )


@pytest_asyncio.fixture
async def pairing(tmp_path):
    clock = [1_000.0]
    auth = TokenAuthenticator([admin_token()])
    store = PairingStore(
        tmp_path / "pairing.db",
        authenticator=auth,
        ttl_seconds=60,
        max_attempts=3,
        clock=lambda: clock[0],
    )
    await store.start()
    try:
        yield store, auth, clock
    finally:
        await store.close()


async def create(store):
    return await store.create_claim(
        installation_id="installation-a",
        vault_id="vault-a",
        endpoint_audience="claudian-remote:local_tailscale:installation-a",
        pairing_id="room-a",
    )


async def redeem(store, claim, *, device_id="iphone-a", requester="198.51.100.2"):
    return await store.redeem(
        claim_id=claim.claim_id,
        claim_token=claim.claim_token,
        short_code=None,
        device_id=device_id,
        device_name="Alice's iPhone",
        requester=requester,
        installation_id="installation-a",
        vault_id="vault-a",
        endpoint_audience="claudian-remote:local_tailscale:installation-a",
    )


def profile_a():
    return {
        "installation_id": "installation-a",
        "vault_id": "vault-a",
        "endpoint_audience": "claudian-remote:local_tailscale:installation-a",
    }


@pytest.mark.asyncio
async def test_claim_replay_and_expiry_do_not_mint_additional_credentials(pairing):
    store, auth, clock = pairing
    claim = await create(store)
    pending = await redeem(store, claim)
    assert pending.status == "approved"
    assert pending.redemption_handle not in repr(pending)

    with pytest.raises(PairingError, match="claim_replayed"):
        await redeem(store, claim)
    assert auth.credential_count(role="mobile") == 1

    expired = await create(store)
    clock[0] += 61
    with pytest.raises(PairingError, match="claim_expired"):
        await redeem(store, expired)
    assert (await store.inspect_claim(expired.claim_id)).status == "expired"
    assert auth.credential_count(role="mobile") == 1


@pytest.mark.asyncio
async def test_short_code_attempt_limit_fails_closed_without_leaking_claim(pairing):
    store, auth, _ = pairing
    claim = await create(store)
    for _ in range(2):
        with pytest.raises(PairingError, match="claim_invalid"):
            await store.redeem(
                claim_id=None,
                claim_token=None,
                short_code="AAAAAAAA",
                device_id="iphone-a",
                device_name="Alice's iPhone",
                requester="198.51.100.9",
                installation_id="installation-a",
                vault_id="vault-a",
                endpoint_audience="claudian-remote:local_tailscale:installation-a",
            )
    with pytest.raises(PairingError, match="attempt_limit_exceeded"):
        await store.redeem(
            claim_id=None,
            claim_token=None,
            short_code="AAAAAAAA",
            device_id="iphone-a",
            device_name="Alice's iPhone",
            requester="198.51.100.9",
            installation_id="installation-a",
            vault_id="vault-a",
            endpoint_audience="claudian-remote:local_tailscale:installation-a",
        )
    assert auth.credential_count(role="mobile") == 0
    assert claim.claim_token not in repr(await store.diagnostic_summary())
    assert claim.short_code not in repr(await store.diagnostic_summary())


@pytest.mark.asyncio
async def test_blocked_requester_cannot_switch_to_a_valid_claim(pairing):
    store, auth, _ = pairing
    claim = await create(store)
    for _ in range(3):
        with pytest.raises(PairingError):
            await store.redeem(
                claim_id=None,
                claim_token=None,
                short_code="AAAAAAAA",
                device_id="iphone-a",
                device_name="Alice's iPhone",
                requester="198.51.100.10",
                installation_id="installation-a",
                vault_id="vault-a",
                endpoint_audience="claudian-remote:local_tailscale:installation-a",
            )
    with pytest.raises(PairingError, match="attempt_limit_exceeded"):
        await redeem(store, claim, requester="198.51.100.10")
    assert auth.credential_count(role="mobile") == 0


@pytest.mark.asyncio
async def test_wrong_claim_token_exhausts_that_claim_terminally(pairing):
    store, auth, _ = pairing
    claim = await create(store)
    for attempt in range(3):
        expected = "attempt_limit_exceeded" if attempt == 2 else "claim_invalid"
        with pytest.raises(PairingError, match=expected):
            await store.redeem(
                claim_id=claim.claim_id,
                claim_token="wrong-token",
                short_code=None,
                device_id="iphone-a",
                device_name="Alice's iPhone",
                requester="198.51.100.11",
                installation_id="installation-a",
                vault_id="vault-a",
                endpoint_audience="claudian-remote:local_tailscale:installation-a",
            )
    assert (await store.inspect_claim(claim.claim_id)).status == "attempts_exhausted"
    with pytest.raises(PairingError, match="attempt_limit_exceeded"):
        await redeem(store, claim, requester="198.51.100.12")
    assert auth.credential_count(role="mobile") == 0


@pytest.mark.asyncio
async def test_concurrent_redemption_issues_exactly_one_digest_only_credential(pairing):
    store, auth, _ = pairing
    claim = await create(store)
    results = await asyncio.gather(
        *(redeem(store, claim) for _ in range(8)),
        return_exceptions=True,
    )
    approved = [item for item in results if not isinstance(item, Exception)]
    rejected = [item for item in results if isinstance(item, PairingError)]
    assert len(approved) == 1
    assert len(rejected) == 7
    assert all(str(item) == "claim_replayed" for item in rejected)
    pending = approved[0]
    assert pending.status == "approved"
    assert auth.credential_count(role="mobile") == 1

    with pytest.raises(PairingError, match="claim_invalid"):
        await store.complete(claim.claim_id, "wrong-handle", device_id="iphone-a")
    with pytest.raises(PairingError, match="wrong_device"):
        await store.complete(claim.claim_id, pending.redemption_handle, device_id="iphone-b")
    issued = await store.complete(
        claim.claim_id,
        pending.redemption_handle,
        device_id="iphone-a",
    )
    persisted = "\n".join(store.connection.iterdump())
    for secret in (claim.claim_token, claim.short_code, pending.redemption_handle, issued.credential):
        assert secret not in persisted
    assert len(issued.credential) >= 43
    assert issued.credential not in repr(await store.inspect_claim(claim.claim_id))
    assert issued.credential not in repr(await store.diagnostic_summary())
    principal = auth.authenticate(
        f"Bearer {issued.credential}",
        "mobile",
        installation_id="installation-a",
        vault_id="vault-a",
        device_id="iphone-a",
        endpoint_audience="claudian-remote:local_tailscale:installation-a",
    )
    assert principal.credential_id == issued.credential_id
    with pytest.raises(PairingError, match="claim_replayed"):
        await store.complete(claim.claim_id, pending.redemption_handle, device_id="iphone-a")


@pytest.mark.asyncio
async def test_delivered_pairing_survives_claim_expiry_cleanup_and_relay_restart(pairing):
    store, _, clock = pairing
    claim = await create(store)
    pending = await redeem(store, claim)
    issued = await store.complete(claim.claim_id, pending.redemption_handle, device_id="iphone-a")
    clock[0] += 365 * 24 * 60 * 60
    await store.prune_claims()
    await store.close()
    store.authenticator = TokenAuthenticator([admin_token()])
    await store.start()

    principal = store.authenticator.authenticate(
        f"Bearer {issued.credential}", "mobile", device_id="iphone-a", **profile_a()
    )
    assert principal.credential_id == issued.credential_id
    assert principal.generation == issued.generation


@pytest.mark.asyncio
async def test_revoke_invalidates_current_and_future_authentication(pairing):
    store, auth, _ = pairing
    claim = await create(store)
    pending = await redeem(store, claim)
    issued = await store.complete(claim.claim_id, pending.redemption_handle, device_id="iphone-a")
    auth.authenticate(f"Bearer {issued.credential}", "mobile")

    revoked = await store.revoke_device(
        device_id="iphone-a",
        installation_id="installation-a",
        vault_id="vault-a",
        endpoint_audience="claudian-remote:local_tailscale:installation-a",
        reason="device_lost",
    )
    assert revoked == [issued.credential_id]
    with pytest.raises(AuthError, match="revoked"):
        auth.authenticate(f"Bearer {issued.credential}", "mobile")


@pytest.mark.asyncio
async def test_legacy_repair_rejects_old_identity_and_binds_replacement_role_and_vault(pairing):
    store, auth, _ = pairing
    first = await create(store)
    pending = await redeem(store, first)
    issued = await store.complete(first.claim_id, pending.redemption_handle, device_id="iphone-a")
    assert auth.authenticate(
        f"Bearer {issued.credential}",
        "mobile",
        installation_id="installation-a",
        vault_id="vault-a",
    ).credential_id == issued.credential_id
    await store.revoke_device(
        device_id="iphone-a",
        installation_id="installation-a",
        vault_id="vault-a",
        endpoint_audience="claudian-remote:local_tailscale:installation-a",
        reason="legacy_migration",
    )
    with pytest.raises(AuthError, match="revoked"):
        auth.authenticate(f"Bearer {issued.credential}", "mobile")

    second = await create(store)
    with pytest.raises(PairingError, match="wrong_audience"):
        await store.redeem(
            claim_id=second.claim_id,
            claim_token=second.claim_token,
            short_code=None,
            device_id="iphone-a",
            device_name="Alice's iPhone",
            requester="198.51.100.2",
            installation_id="installation-a",
            vault_id="vault-a",
            endpoint_audience="claudian-remote:remote_vps:installation-a",
        )
    pending2 = await redeem(store, second)
    reissued = await store.complete(second.claim_id, pending2.redemption_handle, device_id="iphone-a")
    assert reissued.credential_id != issued.credential_id
    assert reissued.credential != issued.credential
    assert auth.credential_count(role="mobile", active_only=True) == 1
    assert auth.authenticate(
        f"Bearer {reissued.credential}",
        "mobile",
        installation_id="installation-a",
        vault_id="vault-a",
    ).credential_id == reissued.credential_id
    with pytest.raises(AuthError, match="wrong_role"):
        auth.authenticate(f"Bearer {reissued.credential}", "pairing_admin")
    with pytest.raises(AuthError, match="wrong_vault"):
        auth.authenticate(
            f"Bearer {reissued.credential}",
            "mobile",
            installation_id="installation-a",
            vault_id="vault-b",
        )
    # Terminal claim digests are scrubbed immediately, so a later presentation
    # is rejected as an invalid claim rather than revealing terminal history.
    with pytest.raises(PairingError, match="claim_invalid"):
        await redeem(store, second)


@pytest.mark.asyncio
async def test_approved_but_unclaimed_credential_expires_without_active_orphan(pairing):
    store, auth, clock = pairing
    claim = await create(store)
    pending = await redeem(store, claim)
    assert auth.credential_count(role="mobile", active_only=True) == 1
    clock[0] += 61
    assert await store.expire_claims() == 1
    assert auth.credential_count(role="mobile", active_only=True) == 0
    with pytest.raises(PairingError, match="credential_delivery_expired"):
        await store.complete(claim.claim_id, pending.redemption_handle, device_id="iphone-a")


@pytest.mark.asyncio
async def test_restart_loses_one_time_delivery_and_revokes_undelivered_credential(tmp_path):
    path = tmp_path / "pairing.db"
    clock = [1000.0]
    first_auth = TokenAuthenticator([admin_token()])
    first = PairingStore(path, authenticator=first_auth, ttl_seconds=60, clock=lambda: clock[0])
    await first.start()
    claim = await create(first)
    pending = await redeem(first, claim)
    await first.close()

    second_auth = TokenAuthenticator([admin_token()])
    second = PairingStore(path, authenticator=second_auth, ttl_seconds=60, clock=lambda: clock[0])
    await second.start()
    try:
        with pytest.raises(PairingError, match="credential_delivery_expired"):
            await second.complete(claim.claim_id, pending.redemption_handle, device_id="iphone-a")
        assert second_auth.credential_count(role="mobile", active_only=True) == 0
    finally:
        await second.close()


@pytest.mark.asyncio
async def test_terminal_claims_remove_raw_verifiers_then_prune_after_short_retention(tmp_path):
    path = tmp_path / "private" / "pairing.db"
    clock = [1000.0]
    auth = TokenAuthenticator([admin_token()])
    store = PairingStore(
        path,
        authenticator=auth,
        ttl_seconds=60,
        terminal_retention_seconds=30,
        clock=lambda: clock[0],
    )
    await store.start()
    try:
        claim = await create(store)
        pending = await redeem(store, claim)
        await store.complete(claim.claim_id, pending.redemption_handle, device_id="iphone-a")
        row = store.connection.execute(
            "SELECT claim_digest, short_digest, redemption_digest FROM pairing_claims WHERE claim_id=?",
            (claim.claim_id,),
        ).fetchone()
        assert tuple(row) == (None, None, None)

        clock[0] = claim.expires_at + 31
        result = await store.prune_claims()
        assert result["expired"] == 0
        assert result["deleted_terminal"] == 1
        assert await store.pending_claims(**profile_a()) == []
        assert store.connection.execute("SELECT COUNT(*) FROM pairing_claims").fetchone()[0] == 0
        assert path.parent.stat().st_mode & 0o777 == 0o700
        assert path.stat().st_mode & 0o777 == 0o600
    finally:
        await store.close()


def seed_legacy_pending(store, claim, device_id):
    handle = "legacy-delivery-handle"
    store.connection.execute(
        """UPDATE pairing_claims SET status='pending_approval', short_digest=NULL,
           redemption_digest=?, device_id=?, device_name=? WHERE claim_id=?""",
        (hashlib.sha256(handle.encode()).hexdigest(), device_id, "Legacy phone", claim.claim_id),
    )
    return handle


@pytest.mark.asyncio
async def test_legacy_pending_claim_can_still_be_approved_once(pairing):
    store, auth, _ = pairing
    claim = await create(store)
    handle = seed_legacy_pending(store, claim, "iphone-a")
    with pytest.raises(PairingError, match="claim_pending_approval"):
        await store.complete(claim.claim_id, handle, device_id="iphone-a")
    with pytest.raises(PairingError, match="wrong_device"):
        await store.approve(claim.claim_id, expected_device_id="iphone-b", **profile_a())
    await store.approve(claim.claim_id, expected_device_id="iphone-a", **profile_a())
    with pytest.raises(PairingError, match="claim_replayed"):
        await store.approve(claim.claim_id, expected_device_id="iphone-a", **profile_a())
    issued = await store.complete(claim.claim_id, handle, device_id="iphone-a")
    assert auth.authenticate(f"Bearer {issued.credential}", "mobile").device_id == "iphone-a"


@pytest.mark.asyncio
async def test_legacy_pending_and_reject_are_scoped_to_pairing_admin_profile(pairing):
    store, _auth, _clock = pairing
    claim_a = await create(store)
    seed_legacy_pending(store, claim_a, "iphone-a")
    claim_b = await store.create_claim(
        installation_id="installation-b",
        vault_id="vault-b",
        endpoint_audience="claudian-remote:remote_vps:installation-b",
        pairing_id="room-b",
    )
    seed_legacy_pending(store, claim_b, "iphone-b")

    visible = await store.pending_claims(**profile_a())
    assert [item.claim_id for item in visible] == [claim_a.claim_id]
    with pytest.raises(PairingError, match="wrong_vault"):
        await store.reject(claim_b.claim_id, **profile_a())
    assert (await store.inspect_claim(claim_b.claim_id)).status == "pending_approval"

    rejected = await store.reject(claim_a.claim_id, **profile_a())
    assert rejected.status == "rejected"


@pytest.mark.asyncio
@pytest.mark.parametrize("field,value,error", [
    ("vault_id", "vault-b", "wrong_vault"),
    ("installation_id", "installation-b", "wrong_installation"),
    ("endpoint_audience", "other-audience", "wrong_audience"),
])
async def test_wrong_profile_cannot_consume_code_or_mint_credential(pairing, field, value, error):
    store, auth, _ = pairing
    claim = await create(store)
    profile = {**profile_a(), field: value}
    with pytest.raises(PairingError, match=error):
        await store.redeem(
            claim_id=None, claim_token=None, short_code=claim.short_code,
            device_id="iphone-a", device_name="Phone", requester="198.51.100.7", **profile,
        )
    assert (await store.inspect_claim(claim.claim_id)).status == "created"
    assert auth.credential_count(role="mobile") == 0
    assert (await redeem(store, claim)).status == "approved"


@pytest.mark.asyncio
async def test_claim_update_failure_rolls_back_credential_and_keeps_code_available(pairing):
    store, auth, _ = pairing
    claim = await create(store)
    store.connection.execute(
        """CREATE TRIGGER fail_issuance BEFORE UPDATE OF status ON pairing_claims
           WHEN NEW.status = 'approved'
           BEGIN SELECT RAISE(ABORT, 'injected write failure'); END"""
    )
    with pytest.raises(sqlite3.IntegrityError, match="injected write failure"):
        await redeem(store, claim)
    assert (await store.inspect_claim(claim.claim_id)).status == "created"
    assert store.connection.execute("SELECT COUNT(*) FROM device_credentials").fetchone()[0] == 0
    assert auth.credential_count(role="mobile") == 0
    store.connection.execute("DROP TRIGGER fail_issuance")
    assert (await redeem(store, claim)).status == "approved"


@pytest.mark.asyncio
async def test_bad_token_replays_cannot_erase_authorized_delivery(pairing):
    store, auth, _ = pairing
    claim = await create(store)
    approved = await redeem(store, claim)
    for attempt in range(3):
        error = "attempt_limit_exceeded" if attempt == 2 else "claim_invalid"
        with pytest.raises(PairingError, match=error):
            await store.redeem(
                claim_id=claim.claim_id, claim_token="bad-token", short_code=None,
                device_id="intruder", device_name="Other phone", requester="198.51.100.99", **profile_a(),
            )
    assert (await store.inspect_claim(claim.claim_id)).status == "approved"
    assert auth.credential_count(role="mobile", active_only=True) == 1
    issued = await store.complete(claim.claim_id, approved.redemption_handle, device_id="iphone-a")
    assert auth.authenticate(f"Bearer {issued.credential}", "mobile").device_id == "iphone-a"
