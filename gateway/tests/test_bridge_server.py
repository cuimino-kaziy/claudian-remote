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
    await bind_bridge(server, ws)

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

    await bind_bridge(server, ws)
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


async def connect_bridge(client, identity):
    socket = await client.ws_connect("/bridge", protocols=[BRIDGE_SUBPROTOCOL])
    challenge = await socket.receive_json()
    await socket.send_json({
        "type": "auth.response", "credential_id": identity.credential_id,
        "nonce": challenge["nonce"], "proof": bridge_auth_proof(identity.secret, challenge["nonce"])
    })
    assert (await socket.receive_json())["type"] == "auth.accepted"
    return socket


async def bind_bridge(server, socket, generation=1):
    binding = asyncio.create_task(server.bind("/bind", "session-a", generation, {"id": "set-a"}))
    request = await socket.receive_json()
    assert request["operation"] == "transport.bind"
    await socket.send_json({"type": "response", "request_id": request["request_id"], "ok": True, "result": {}})
    await binding


@pytest.mark.asyncio
async def test_plugin_restart_ends_old_event_pump_instead_of_only_requesting_keyframe(aiohttp_client):
    identities = BridgeIdentityStore()
    identity = identities.issue("bridge-a", "bridge-secret")
    server = CompanionBridgeServer(identities=identities)
    client = await aiohttp_client(server.create_app())
    first = await connect_bridge(client, identity)
    await bind_bridge(server, first)
    old_events = server.events(0)
    waiting = asyncio.create_task(anext(old_events))
    await asyncio.sleep(0)
    await first.close()
    with pytest.raises(BridgeServerError, match="bridge_disconnected"):
        await asyncio.wait_for(waiting, timeout=0.2)
    with pytest.raises(BridgeServerError, match="bridge_offline|bridge_not_ready"):
        await server.command("/command", {"delivery_id": "offline"})
    second = await connect_bridge(client, identity)
    # No keyframe can substitute for binding the replacement native instance.
    with pytest.raises(BridgeServerError, match="bridge_not_ready"):
        await server.command("/command", {"delivery_id": "before-bind"})
    await bind_bridge(server, second, 2)
    await second.close()


@pytest.mark.asyncio
async def test_replaced_socket_ends_old_pump_without_ending_new_generation(aiohttp_client):
    identities = BridgeIdentityStore()
    identity = identities.issue("bridge-a", "bridge-secret")
    server = CompanionBridgeServer(identities=identities)
    client = await aiohttp_client(server.create_app())
    first = await connect_bridge(client, identity)
    await bind_bridge(server, first)
    old_generation = server._generation
    old_events = server.events(0)
    old_wait = asyncio.create_task(anext(old_events))
    await asyncio.sleep(0)
    second = await connect_bridge(client, identity)
    with pytest.raises(BridgeServerError, match="bridge_disconnected"):
        await asyncio.wait_for(old_wait, timeout=0.2)
    await bind_bridge(server, second, 2)
    new_events = server.events(0)
    new_wait = asyncio.create_task(anext(new_events))
    # The first socket's late finally/close must not end the new transport.
    server._end_transport(old_generation)
    await first.close()
    await second.send_json({"type": "event.publish", "event": {
        "source": {"sequence": 1}, "event_type": "capability.state"
    }})
    assert (await asyncio.wait_for(new_wait, timeout=0.2)).event == "semantic"
    await second.close()
    await new_events.aclose()


@pytest.mark.asyncio
async def test_native_reload_restarts_real_runner_bind_ack_and_hello_compatibility(aiohttp_client):
    from types import SimpleNamespace
    from gateway.mac_companion.stream_pump import AsyncMacCompanion
    from gateway.protocol.compatibility import COMPATIBILITY_SET

    class RelaySocket:
        def __init__(self):
            self.incoming = asyncio.Queue()
            self.sent = asyncio.Queue()
        async def receive_json(self):
            return await self.incoming.get()
        async def send_json(self, frame):
            await self.sent.put(frame)

    config = SimpleNamespace(v2_state_path="", outbound_max_events=32, outbound_max_bytes=64000,
        bridge_command_path="/command", bridge_bind_path="/bind", bridge_invalidate_path="/invalidate")
    runtime = AsyncMacCompanion(config)
    identities = BridgeIdentityStore()
    identity = identities.issue("bridge-a", "bridge-secret")
    server = CompanionBridgeServer(identities=identities, request_timeout_seconds=0.2)
    client = await aiohttp_client(server.create_app())
    first = await connect_bridge(client, identity)
    relay = RelaySocket()
    run = asyncio.create_task(runtime.run_connection(relay, server, server))
    try:
        request = await first.receive_json()
        assert request["operation"] == "transport.bind"
        assert request["payload"]["compatibility"] == COMPATIBILITY_SET
        await first.send_json({"type": "response", "request_id": request["request_id"], "ok": True,
            "result": {"compatibility": {"writable": True, "reason": "ready"}}})
        hello = await asyncio.wait_for(relay.sent.get(), timeout=0.2)
        assert hello["type"] == "mac.hello"
        await first.close()
        with pytest.raises(BridgeServerError, match="bridge_disconnected"):
            await asyncio.wait_for(run, timeout=0.3)

        second = await connect_bridge(client, identity)
        next_relay = RelaySocket()
        run = asyncio.create_task(runtime.run_connection(next_relay, server, server))
        request = await second.receive_json()
        assert request["operation"] == "transport.bind"
        assert request["payload"]["mac_connection_generation"] == hello["mac_connection_generation"] + 1
        assert next_relay.sent.empty(), "Relay must not announce readiness before the native bind ACK"
        # The updated native plugin has a new compatibility result. It must
        # reach the new hello rather than reuse the old writable result.
        changed = {"writable": False, "reason": "compatibility_set_mismatch"}
        await second.send_json({"type": "response", "request_id": request["request_id"], "ok": True,
            "result": {"compatibility": changed}})
        next_hello = await asyncio.wait_for(next_relay.sent.get(), timeout=0.2)
        assert next_hello["type"] == "mac.hello"
        assert next_hello["bridge_compatibility"] == changed
        assert next_hello["compatibility"] == COMPATIBILITY_SET
        await next_relay.incoming.put(None)
        invalidation = await second.receive_json()
        assert invalidation["operation"] == "transport.invalidate"
        await second.send_json({"type": "response", "request_id": invalidation["request_id"], "ok": True, "result": {}})
        await run
        await second.close()
    finally:
        if not run.done():
            run.cancel()
        await asyncio.gather(run, return_exceptions=True)
        await runtime.outbound.close()
