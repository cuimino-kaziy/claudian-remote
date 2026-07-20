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
        CompanionBridgeServer(host="0.0.0.0", port=27124, identities=BridgeIdentityStore())
    with pytest.raises(BridgeServerError, match="bridge_fixed_port_required"):
        CompanionBridgeServer(host="127.0.0.1", port=0, identities=BridgeIdentityStore())


@pytest.mark.asyncio
async def test_port_conflict_has_one_stable_error_and_never_selects_another_port(monkeypatch):
    async def conflict(_site):
        raise OSError("address in use")

    monkeypatch.setattr("gateway.mac_companion.bridge_server.web.TCPSite.start", conflict)
    server = CompanionBridgeServer(host="127.0.0.1", port=27124, identities=BridgeIdentityStore())
    with pytest.raises(BridgeServerError, match="bridge_port_conflict"):
        await server.start()


@pytest.mark.asyncio
async def test_authenticated_loopback_websocket_is_command_and_event_adapter(aiohttp_client):
    identities = BridgeIdentityStore()
    identity = identities.issue("bridge-a", "bridge-secret")
    server = CompanionBridgeServer(host="127.0.0.1", port=27124, identities=identities)
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
async def test_missing_invalid_and_revoked_credentials_reveal_nothing(aiohttp_client):
    identities = BridgeIdentityStore()
    identity = identities.issue("bridge-a", "bridge-secret")
    identities.revoke(identity.credential_id)
    server = CompanionBridgeServer(host="127.0.0.1", port=27124, identities=identities)
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
    server = CompanionBridgeServer(host="127.0.0.1", port=27124, identities=identities)
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
