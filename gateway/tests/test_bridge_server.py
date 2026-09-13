import asyncio
import json

import pytest

from gateway.mac_companion.bridge_server import (
    BRIDGE_SUBPROTOCOL,
    BridgeBootstrapStore,
    BridgeIdentityStore,
    BridgeServerError,
    CompanionBridgeServer,
    bridge_auth_proof,
)


def test_bootstrap_is_confirmed_single_use_and_issues_revocable_identity():
    bootstrap = BridgeBootstrapStore()
    claim = bootstrap.create(confirmed=False)
    with pytest.raises(BridgeServerError, match="bridge_bootstrap_not_confirmed"):
        bootstrap.consume(claim)
    bootstrap.confirm(claim)
    identity = bootstrap.consume(claim)
    assert identity.credential_id
    assert identity.secret
    bootstrap.identities.revoke(identity.credential_id)
    assert bootstrap.identities.verify(
        identity.credential_id, "nonce-a", bridge_auth_proof(identity.secret, "nonce-a")
    ) is False
    with pytest.raises(BridgeServerError, match="bridge_bootstrap_used"):
        bootstrap.consume(claim)


def test_loopback_and_fixed_port_are_fail_closed():
    with pytest.raises(BridgeServerError, match="bridge_non_loopback_forbidden"):
        CompanionBridgeServer(host="0.0.0.0", port=27125, identities=BridgeIdentityStore())
    with pytest.raises(BridgeServerError, match="bridge_fixed_port_required"):
        CompanionBridgeServer(host="127.0.0.1", port=0, identities=BridgeIdentityStore())


@pytest.mark.asyncio
async def test_port_conflict_has_one_stable_error_and_never_selects_another_port(monkeypatch):
    async def conflict(_site):
        raise OSError("address in use")

    monkeypatch.setattr("gateway.mac_companion.bridge_server.web.TCPSite.start", conflict)
    server = CompanionBridgeServer(host="127.0.0.1", port=27125, identities=BridgeIdentityStore())
    with pytest.raises(BridgeServerError, match="bridge_port_conflict"):
        await server.start()


@pytest.mark.asyncio
async def test_authenticated_loopback_websocket_is_command_and_event_adapter(aiohttp_client):
    identities = BridgeIdentityStore()
    identity = identities.issue("bridge-a", "bridge-secret")
    server = CompanionBridgeServer(host="127.0.0.1", port=27125, identities=identities)
    client = await aiohttp_client(server.create_app())
    ws = await client.ws_connect("/bridge", protocols=[BRIDGE_SUBPROTOCOL])
    challenge = await ws.receive_json()
    assert set(challenge) == {"type", "nonce"}
    await ws.send_json({
        "type": "auth.response",
        "credential_id": identity.credential_id,
        "nonce": challenge["nonce"],
        "proof": bridge_auth_proof(identity.secret, challenge["nonce"]),
    })
    accepted = await ws.receive_json()
    assert accepted["type"] == "auth.accepted"

    command_task = asyncio.create_task(server.command("/command", {"delivery_id": "delivery-a"}))
    request = await ws.receive_json()
    assert request["operation"] == "command.execute"
    await ws.send_json({
        "type": "response", "request_id": request["request_id"],
        "ok": True, "result": {"delivery_id": "delivery-a", "status": "executed"}
    })
    assert (await command_task)["status"] == "executed"

    stream = server.events(0)
    await ws.send_json({"type": "event.publish", "event": {"source": {"sequence": 1}, "event_type": "text.delta"}})
    message = await asyncio.wait_for(anext(stream), timeout=1)
    assert json.loads(message.data)["event_type"] == "text.delta"
    await ws.close()


@pytest.mark.asyncio
async def test_authenticated_callback_runs_only_after_valid_bridge_authentication(aiohttp_client):
    identities = BridgeIdentityStore()
    identity = identities.issue("bridge-a", "bridge-secret")
    authenticated = []
    server = CompanionBridgeServer(
        host="127.0.0.1",
        port=27125,
        identities=identities,
        authenticated_handler=authenticated.append,
    )
    client = await aiohttp_client(server.create_app())

    rejected = await client.ws_connect("/bridge", protocols=[BRIDGE_SUBPROTOCOL])
    challenge = await rejected.receive_json()
    await rejected.send_json({
        "type": "auth.response",
        "credential_id": identity.credential_id,
        "nonce": challenge["nonce"],
        "proof": "invalid-proof",
    })
    assert (await rejected.receive_json())["type"] == "auth.rejected"
    assert authenticated == []

    accepted = await client.ws_connect("/bridge", protocols=[BRIDGE_SUBPROTOCOL])
    challenge = await accepted.receive_json()
    await accepted.send_json({
        "type": "auth.response",
        "credential_id": identity.credential_id,
        "nonce": challenge["nonce"],
        "proof": bridge_auth_proof(identity.secret, challenge["nonce"]),
    })
    assert (await accepted.receive_json())["type"] == "auth.accepted"
    assert authenticated == [identity.credential_id]
    await accepted.close()


@pytest.mark.asyncio
async def test_unanswered_bridge_request_times_out_and_releases_pending_state(aiohttp_client):
    identities = BridgeIdentityStore()
    identity = identities.issue("bridge-a", "bridge-secret")
    server = CompanionBridgeServer(
        host="127.0.0.1",
        port=27125,
        identities=identities,
        request_timeout_seconds=0.02,
    )
    client = await aiohttp_client(server.create_app())
    ws = await client.ws_connect("/bridge", protocols=[BRIDGE_SUBPROTOCOL])
    challenge = await ws.receive_json()
    await ws.send_json({
        "type": "auth.response",
        "credential_id": identity.credential_id,
        "nonce": challenge["nonce"],
        "proof": bridge_auth_proof(identity.secret, challenge["nonce"]),
    })
    assert (await ws.receive_json())["type"] == "auth.accepted"

    pending = asyncio.create_task(server.command("/command", {"delivery_id": "delivery-timeout"}))
    assert (await ws.receive_json())["operation"] == "command.execute"
    with pytest.raises(BridgeServerError, match="bridge_request_timeout"):
        await pending
    assert server._pending == {}
    await ws.close()


@pytest.mark.asyncio
async def test_event_queue_overflow_emits_resync_marker_instead_of_hiding_loss(aiohttp_client):
    identities = BridgeIdentityStore()
    identity = identities.issue("bridge-a", "bridge-secret")
    server = CompanionBridgeServer(host="127.0.0.1", port=27125, identities=identities)
    server._events = asyncio.Queue(maxsize=1)
    client = await aiohttp_client(server.create_app())
    ws = await client.ws_connect("/bridge", protocols=[BRIDGE_SUBPROTOCOL])
    challenge = await ws.receive_json()
    await ws.send_json({
        "type": "auth.response",
        "credential_id": identity.credential_id,
        "nonce": challenge["nonce"],
        "proof": bridge_auth_proof(identity.secret, challenge["nonce"]),
    })
    assert (await ws.receive_json())["type"] == "auth.accepted"
    for sequence in (1, 2):
        await ws.send_json({
            "type": "event.publish",
            "event": {"source": {"sequence": sequence}, "event_type": "text.delta"},
        })

    marker = await asyncio.wait_for(anext(server.events(0)), timeout=1)
    assert marker.event == "resync"
    assert marker.event_id == ""
    await ws.close()


@pytest.mark.asyncio
async def test_slow_management_does_not_block_event_ingestion(aiohttp_client):
    identities = BridgeIdentityStore()
    identity = identities.issue("bridge-a", "bridge-secret")
    release_management = asyncio.Event()

    async def management(_operation, _payload):
        await release_management.wait()
        return {"devices": []}

    server = CompanionBridgeServer(
        host="127.0.0.1",
        port=27125,
        identities=identities,
        management_handler=management,
    )
    client = await aiohttp_client(server.create_app())
    ws = await client.ws_connect("/bridge", protocols=[BRIDGE_SUBPROTOCOL])
    challenge = await ws.receive_json()
    await ws.send_json({
        "type": "auth.response",
        "credential_id": identity.credential_id,
        "nonce": challenge["nonce"],
        "proof": bridge_auth_proof(identity.secret, challenge["nonce"]),
    })
    assert (await ws.receive_json())["type"] == "auth.accepted"
    await ws.send_json({
        "type": "management.request",
        "request_id": "management-a",
        "operation": "pairing.devices",
        "payload": {},
    })
    await ws.send_json({
        "type": "event.publish",
        "event": {"source": {"sequence": 7}, "event_type": "text.delta"},
    })
    event = await asyncio.wait_for(anext(server.events(0)), timeout=0.2)
    assert event.event_id == "7"
    release_management.set()
    assert (await ws.receive_json())["request_id"] == "management-a"
    await ws.close()


@pytest.mark.asyncio
async def test_missing_invalid_and_revoked_credentials_reveal_nothing(aiohttp_client):
    identities = BridgeIdentityStore()
    identity = identities.issue("bridge-a", "bridge-secret")
    identities.revoke(identity.credential_id)
    server = CompanionBridgeServer(host="127.0.0.1", port=27125, identities=identities)
    client = await aiohttp_client(server.create_app())
    ws = await client.ws_connect("/bridge", protocols=[BRIDGE_SUBPROTOCOL])
    challenge = await ws.receive_json()
    await ws.send_json({
        "type": "auth.response", "credential_id": identity.credential_id,
        "nonce": challenge["nonce"], "proof": bridge_auth_proof(identity.secret, challenge["nonce"])
    })
    rejected = await ws.receive_json()
    assert rejected == {"type": "auth.rejected", "error_code": "bridge_auth_failed"}


@pytest.mark.asyncio
async def test_plugin_restart_requests_one_keyframe_when_transport_is_already_bound(aiohttp_client):
    identities = BridgeIdentityStore()
    identity = identities.issue("bridge-a", "bridge-secret")
    server = CompanionBridgeServer(host="127.0.0.1", port=27125, identities=identities)
    client = await aiohttp_client(server.create_app())

    async def connect():
        socket = await client.ws_connect("/bridge", protocols=[BRIDGE_SUBPROTOCOL])
        challenge = await socket.receive_json()
        await socket.send_json({
            "type": "auth.response", "credential_id": identity.credential_id,
            "nonce": challenge["nonce"], "proof": bridge_auth_proof(identity.secret, challenge["nonce"])
        })
        assert (await socket.receive_json())["type"] == "auth.accepted"
        return socket

    first = await connect()
    binding = asyncio.create_task(server.bind("/bind", "session-a", 1, {"id": "set-a"}))
    request = await first.receive_json()
    assert request["operation"] == "transport.bind"
    await first.send_json({"type": "response", "request_id": request["request_id"], "ok": True, "result": {}})
    await binding
    await first.close()

    second = await connect()
    recovery = await second.receive_json()
    assert recovery["operation"] == "keyframe.request"
    await second.send_json({"type": "response", "request_id": recovery["request_id"], "ok": True, "result": {}})
    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(second.receive_json(), timeout=0.02)
    await second.close()
