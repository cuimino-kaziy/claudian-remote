import asyncio

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
async def test_claim_replay_and_expiry_are_terminal_and_mint_nothing(pairing):
    store, auth, clock = pairing
    claim = await create(store)
    pending = await redeem(store, claim)
    assert pending.status == "pending_approval"
    assert pending.redemption_handle not in repr(pending)

    with pytest.raises(PairingError, match="claim_replayed"):
        await redeem(store, claim)
    assert auth.credential_count(role="mobile") == 0

    expired = await create(store)
    clock[0] += 61
    with pytest.raises(PairingError, match="claim_expired"):
        await redeem(store, expired)
    assert (await store.inspect_claim(expired.claim_id)).status == "expired"
    assert auth.credential_count(role="mobile") == 0


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
async def test_concurrent_approval_issues_exactly_one_digest_only_credential(pairing):
    store, auth, _ = pairing
    claim = await create(store)
    pending = await redeem(store, claim)

    results = await asyncio.gather(
        *(
            store.approve(
                claim.claim_id,
                expected_device_id="iphone-a",
                installation_id="installation-a",
                vault_id="vault-a",
                endpoint_audience="claudian-remote:local_tailscale:installation-a",
            )
            for _ in range(8)
        ),
        return_exceptions=True,
    )
    approved = [item for item in results if not isinstance(item, Exception)]
    rejected = [item for item in results if isinstance(item, PairingError)]
    assert len(approved) == 1
    assert len(rejected) == 7
    assert all(str(item) == "claim_replayed" for item in rejected)
    assert auth.credential_count(role="mobile") == 1

    issued = await store.complete(
        claim.claim_id,
        pending.redemption_handle,
        device_id="iphone-a",
    )
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
async def test_revoke_invalidates_current_and_future_authentication(pairing):
    store, auth, _ = pairing
    claim = await create(store)
    pending = await redeem(store, claim)
    await store.approve(
        claim.claim_id,
        expected_device_id="iphone-a",
        installation_id="installation-a",
        vault_id="vault-a",
        endpoint_audience="claudian-remote:local_tailscale:installation-a",
    )
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
async def test_wrong_profile_rejection_and_repair_never_reuses_identity(pairing):
    store, auth, _ = pairing
    first = await create(store)
    pending = await redeem(store, first)
    await store.approve(
        first.claim_id,
        expected_device_id="iphone-a",
        installation_id="installation-a",
        vault_id="vault-a",
        endpoint_audience="claudian-remote:local_tailscale:installation-a",
    )
    issued = await store.complete(first.claim_id, pending.redemption_handle, device_id="iphone-a")
    await store.revoke_device(
        device_id="iphone-a",
        installation_id="installation-a",
        vault_id="vault-a",
        endpoint_audience="claudian-remote:local_tailscale:installation-a",
        reason="mode_changed",
    )

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
    await store.approve(
        second.claim_id,
        expected_device_id="iphone-a",
        installation_id="installation-a",
        vault_id="vault-a",
        endpoint_audience="claudian-remote:local_tailscale:installation-a",
    )
    reissued = await store.complete(second.claim_id, pending2.redemption_handle, device_id="iphone-a")
    assert reissued.credential_id != issued.credential_id
    assert reissued.credential != issued.credential
    assert auth.credential_count(role="mobile", active_only=True) == 1


@pytest.mark.asyncio
async def test_approved_but_unclaimed_credential_expires_without_active_orphan(pairing):
    store, auth, clock = pairing
    claim = await create(store)
    pending = await redeem(store, claim)
    await store.approve(
        claim.claim_id,
        expected_device_id="iphone-a",
        installation_id="installation-a",
        vault_id="vault-a",
        endpoint_audience="claudian-remote:local_tailscale:installation-a",
    )
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
    await first.approve(
        claim.claim_id,
        expected_device_id="iphone-a",
        installation_id="installation-a",
        vault_id="vault-a",
        endpoint_audience="claudian-remote:local_tailscale:installation-a",
    )
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
        await store.approve(
            claim.claim_id,
            expected_device_id="iphone-a",
            installation_id="installation-a",
            vault_id="vault-a",
            endpoint_audience="claudian-remote:local_tailscale:installation-a",
        )
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


@pytest.mark.asyncio
async def test_pending_and_reject_are_scoped_to_pairing_admin_profile(pairing):
    store, _auth, _clock = pairing
    claim_a = await create(store)
    await redeem(store, claim_a)
    claim_b = await store.create_claim(
        installation_id="installation-b",
        vault_id="vault-b",
        endpoint_audience="claudian-remote:remote_vps:installation-b",
        pairing_id="room-b",
    )
    await store.redeem(
        claim_id=claim_b.claim_id,
        claim_token=claim_b.claim_token,
        short_code=None,
        device_id="iphone-b",
        device_name="Bob's iPhone",
        requester="198.51.100.3",
        installation_id="installation-b",
        vault_id="vault-b",
        endpoint_audience="claudian-remote:remote_vps:installation-b",
    )

    visible = await store.pending_claims(**profile_a())
    assert [item.claim_id for item in visible] == [claim_a.claim_id]
    with pytest.raises(PairingError, match="wrong_vault"):
        await store.reject(claim_b.claim_id, **profile_a())
    assert (await store.inspect_claim(claim_b.claim_id)).status == "pending_approval"

    rejected = await store.reject(claim_a.claim_id, **profile_a())
    assert rejected.status == "rejected"
