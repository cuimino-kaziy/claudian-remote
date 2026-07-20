import asyncio
from datetime import datetime, timedelta, timezone

import pytest
from aiohttp import WSMsgType

from gateway.relay.app import STORE, create_app
from gateway.relay.auth import AuthError, TicketStore, TokenAuthenticator, origin_allowed
from gateway.relay.relay_server import RelayConfig, RelayToken


def principals():
    return [
        RelayToken(name="mac", role="mac", pairing_id="room-a", token="mac-secret"),
        RelayToken(name="mobile", role="mobile", pairing_id="room-a", token="mobile-secret"),
    ]


def test_role_authentication_is_constant_scope_and_deny_by_default():
    auth = TokenAuthenticator(principals())
    assert auth.authenticate("Bearer mobile-secret", "mobile").pairing_id == "room-a"
    with pytest.raises(AuthError, match="wrong_role"):
        auth.authenticate("Bearer mac-secret", "mobile")
    with pytest.raises(AuthError, match="unauthorized"):
        auth.authenticate("Bearer missing", "mac")


@pytest.mark.asyncio
async def test_mobile_ticket_is_single_use_role_and_binding_scoped():
    clock = [100.0]
    store = TicketStore(ttl_seconds=30, clock=lambda: clock[0])
    mobile = principals()[1]
    ticket, grant = await store.issue(mobile, "iphone", "view-1")
    assert ticket not in repr(grant)
    consumed = await store.consume(
        ticket, role="mobile", device_id="iphone", client_instance_id="view-1"
    )
    assert consumed.pairing_id == "room-a"
    with pytest.raises(AuthError, match="ticket_invalid_or_used"):
        await store.consume(ticket, role="mobile", device_id="iphone", client_instance_id="view-1")


@pytest.mark.asyncio
async def test_expired_wrong_role_and_wrong_binding_tickets_are_rejected_atomically():
    clock = [100.0]
    store = TicketStore(ttl_seconds=1, clock=lambda: clock[0])
    mobile = principals()[1]
    ticket, _ = await store.issue(mobile, "iphone", "view-1")
    with pytest.raises(AuthError, match="wrong_role"):
        await store.consume(ticket, role="mac", device_id="iphone", client_instance_id="view-1")
    assert await store.count() == 0  # A failed consume cannot be retried with another role.

    ticket, _ = await store.issue(mobile, "iphone", "view-1")
    with pytest.raises(AuthError, match="ticket_binding_mismatch"):
        await store.consume(ticket, role="mobile", device_id="other", client_instance_id="view-1")

    ticket, _ = await store.issue(mobile, "iphone", "view-1")
    clock[0] = 102.0
    with pytest.raises(AuthError, match="ticket_invalid_or_used|ticket_expired"):
        await store.consume(ticket, role="mobile", device_id="iphone", client_instance_id="view-1")

    with pytest.raises(AuthError, match="wrong_role"):
        await store.issue(principals()[0], "mac", "process")


def test_origin_allowlist_is_additional_defense_not_authentication():
    assert origin_allowed(None, ["app://obsidian.md"])
    assert origin_allowed("app://obsidian.md", ["app://obsidian.md"])
    assert not origin_allowed("https://evil.example", ["app://obsidian.md"])


def relay_config(tmp_path):
    return RelayConfig(
        tokens=principals(),
        database_path=str(tmp_path / "relay.db"),
        upload_root=str(tmp_path / "uploads"),
        allowed_origins=["app://obsidian.md"],
        websocket_heartbeat_seconds=2,
    )


async def issue_mobile_ticket(client, *, device="iphone", instance="view-1"):
    response = await client.post(
        "/api/v2/ws-ticket",
        headers={"Authorization": "Bearer mobile-secret"},
        json={"device_id": device, "client_instance_id": instance},
    )
    assert response.status == 201
    return (await response.json())["ticket"]


async def connect_mobile(client, ticket, *, device="iphone", instance="view-1", epoch=None, cursor=0):
    socket = await client.ws_connect(
        "/api/v2/ws/mobile",
        protocols=("claudian.remote.v2",),
        headers={"Origin": "app://obsidian.md"},
    )
    await socket.send_json(
        {
            "type": "authenticate",
            "role": "mobile",
            "ticket": ticket,
            "device_id": device,
            "client_instance_id": instance,
            "epoch": epoch,
            "cursor": cursor,
        }
    )
    authenticated = await socket.receive_json(timeout=1)
    assert authenticated["type"] == "authenticated"
    return socket


async def connect_mac(client, session="mac-session", generation=1):
    socket = await client.ws_connect(
        "/api/v2/ws/mac",
        protocols=("claudian.remote.v2",),
        headers={
            "Origin": "app://obsidian.md",
            "Authorization": "Bearer mac-secret",
        },
    )
    await socket.send_json(
        {
            "type": "mac.hello",
            "protocol": "claudian.remote.v2",
            "mac_session_id": session,
            "mac_connection_generation": generation,
        }
    )
    hello = await socket.receive_json(timeout=1)
    assert hello["type"] == "mac.hello.ack"
    return socket


def command(session="mac-session", generation=1, delivery="delivery-1"):
    return {
        "protocol": "claudian.remote.v2",
        "kind": "command",
        "command_type": "message.submit",
        "delivery_id": delivery,
        "mac_session_id": session,
        "mac_connection_generation": generation,
        "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat().replace("+00:00", "Z"),
        "expected_revision": 0,
        "target": {"conversation_id": "conversation-1"},
        "payload": {"text": "hello", "attachment_refs": [], "mode": "enqueue"},
    }


def semantic_event(sequence=1, text="hello"):
    return {
        "protocol": "claudian.remote.v2",
        "kind": "event",
        "event_type": "text.delta",
        "source": {"instance_id": "bridge-test", "sequence": sequence},
        "entity": {
            "conversation_id": "conversation-1",
            "turn_id": "turn-1",
            "message_id": "message-1",
            "block_id": "block-1",
        },
        "revision": sequence,
        "payload": {"text": text, "base_revision": sequence - 1, "offset": sequence - 1},
        "occurred_at": "2026-07-15T00:00:00Z",
    }


async def receive_type(socket, wanted, timeout=1):
    async def receive():
        while True:
            frame = await socket.receive_json()
            if frame.get("type") == wanted:
                return frame

    return await asyncio.wait_for(receive(), timeout=timeout)


@pytest.mark.asyncio
async def test_real_ticket_websocket_publish_commit_replay_uid_and_url_security(aiohttp_client, tmp_path):
    client = await aiohttp_client(create_app(relay_config(tmp_path)))

    ticket = await issue_mobile_ticket(client)
    mobile = await connect_mobile(client, ticket)
    mac = await connect_mac(client)
    await receive_type(mobile, "presence.changed")

    publish = {
        "type": "event.publish",
        "mac_session_id": "mac-session",
        "mac_connection_generation": 1,
        "event": semantic_event(),
    }
    await mac.send_json(publish)
    ack = await receive_type(mac, "event.ack")
    committed = await receive_type(mobile, "event.committed")
    assert committed["cursor"] == ack["cursor"]
    rows = await client.server.app[STORE].replay("room-a", 0)
    assert [row.cursor for row in rows] == [committed["cursor"]]  # broadcast follows commit

    await mac.send_json(publish)
    duplicate = await receive_type(mac, "event.ack")
    assert duplicate["duplicate"] is True
    assert (await client.server.app[STORE].stats())["rows"] == 1
    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(mobile.receive_json(), timeout=0.05)

    resumed_ticket = await issue_mobile_ticket(client, instance="view-2")
    resumed = await connect_mobile(
        client,
        resumed_ticket,
        instance="view-2",
        epoch=committed["epoch"],
        cursor=0,
    )
    replayed = await receive_type(resumed, "event.committed")
    assert replayed["replayed"] is True

    reused = await client.ws_connect(
        "/api/v2/ws/mobile",
        protocols=("claudian.remote.v2",),
        headers={"Origin": "app://obsidian.md"},
    )
    await reused.send_json(
        {"type": "authenticate", "role": "mobile", "ticket": ticket, "device_id": "iphone", "client_instance_id": "view-1"}
    )
    closed = await reused.receive(timeout=1)
    assert closed.type in {WSMsgType.CLOSE, WSMsgType.CLOSED}

    forbidden = await client.get("/api/v2/ws/mobile?ticket=not-allowed")
    assert forbidden.status == 400

    await resumed.close()
    await mac.close()
    await mobile.close()


@pytest.mark.asyncio
async def test_https_command_receipt_generation_and_commands_never_enter_sqlite(aiohttp_client, tmp_path):
    client = await aiohttp_client(create_app(relay_config(tmp_path)))
    mobile = await connect_mobile(client, await issue_mobile_ticket(client))
    mac = await connect_mac(client)
    await receive_type(mobile, "presence.changed")

    response = await client.post(
        "/api/v2/commands",
        headers={"Authorization": "Bearer mobile-secret"},
        json={"command": command()},
    )
    assert response.status == 202
    assert (await response.json())["type"] == "relay.accepted"
    routed = await receive_type(mac, "command")
    assert routed["command"]["delivery_id"] == "delivery-1"

    await mac.send_json(
        {
            "type": "command.receipt",
            "mac_session_id": "mac-session",
            "mac_connection_generation": 1,
            "receipt": {"delivery_id": "delivery-1", "status": "executed"},
        }
    )
    receipt = await receive_type(mobile, "command.receipt")
    assert receipt["receipt"]["status"] == "executed"
    assert (await client.server.app[STORE].stats())["rows"] == 0

    new_mac = await connect_mac(client, generation=2)
    await receive_type(mobile, "presence.changed")
    rejected = await client.post(
        "/api/v2/commands",
        headers={"Authorization": "Bearer mobile-secret"},
        json=command(generation=1, delivery="stale-delivery"),
    )
    assert rejected.status == 409
    assert (await rejected.json())["status"] == "connection_generation_mismatch"
    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(new_mac.receive_json(), timeout=0.05)
    assert (await client.server.app[STORE].stats())["rows"] == 0

    await new_mac.close()
    await mobile.close()


@pytest.mark.asyncio
async def test_stale_publish_is_rejected_and_source_gap_requests_keyframe(aiohttp_client, tmp_path):
    client = await aiohttp_client(create_app(relay_config(tmp_path)))
    mobile = await connect_mobile(client, await issue_mobile_ticket(client))
    mac = await connect_mac(client, generation=2)
    await receive_type(mobile, "presence.changed")

    await mac.send_json(
        {
            "type": "event.publish",
            "mac_session_id": "mac-session",
            "mac_connection_generation": 1,
            "event": semantic_event(),
        }
    )
    error = await receive_type(mac, "protocol.error")
    assert error["error"] == "invalid_frame"
    assert (await client.server.app[STORE].stats())["rows"] == 0

    await mac.send_json({"type": "source.gap", "reason": "bridge_retained_gap"})
    reset = await receive_type(mobile, "reset_required")
    request = await receive_type(mac, "keyframe.request")
    assert reset["reason"] == "bridge_retained_gap"
    assert request["reason"] == "bridge_retained_gap"
    assert (await client.server.app[STORE].stats())["rows"] == 0

    await mac.close()
    await mobile.close()


@pytest.mark.asyncio
async def test_mobile_reset_and_explicit_recovery_request_current_mac_keyframe(aiohttp_client, tmp_path):
    client = await aiohttp_client(create_app(relay_config(tmp_path)))
    mac = await connect_mac(client)

    stale_ticket = await issue_mobile_ticket(client)
    mobile = await connect_mobile(client, stale_ticket, epoch="obsolete-epoch", cursor=0)
    reset = await receive_type(mobile, "reset_required")
    automatic = await receive_type(mac, "keyframe.request")
    assert reset["reason"] == "epoch_mismatch"
    assert automatic["reason"] == "epoch_mismatch"

    await mobile.send_json({"type": "keyframe.request", "reason": "text_delta_mismatch"})
    explicit = await receive_type(mac, "keyframe.request")
    accepted = await receive_type(mobile, "keyframe.request.accepted")
    assert explicit["reason"] == "text_delta_mismatch"
    assert accepted["status"] == "routed"
    assert (await client.server.app[STORE].stats())["rows"] == 0

    await mobile.close()
    await mac.close()
