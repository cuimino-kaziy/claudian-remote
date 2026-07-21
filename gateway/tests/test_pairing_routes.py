import asyncio
from urllib.parse import parse_qs, urlparse

import pytest
from aiohttp import WSMsgType

from gateway.protocol.compatibility import COMPATIBILITY_SET
from gateway.relay.app import create_app
from gateway.relay.relay_server import RelayConfig, RelayToken


def config(tmp_path):
    return RelayConfig(
        installation_id="installation-a",
        vault_id="vault-a",
        endpoint_audience="claudian-remote:local_tailscale:installation-a",
        tokens=[
            RelayToken("mac", "mac", "room-a", "mac-secret", device_id="mac-a"),
            RelayToken("admin", "pairing_admin", "room-a", "admin-secret", device_id="mac-a"),
        ],
        database_path=str(tmp_path / "relay.db"),
        pairing_database_path=str(tmp_path / "pairing.db"),
        upload_root=str(tmp_path / "uploads"),
        allowed_origins=["app://obsidian.md"],
        websocket_heartbeat_seconds=2,
    )


async def pair(client):
    created_response = await client.post(
        "/api/v2/pairing/claims",
        headers={"Authorization": "Bearer admin-secret"},
    )
    assert created_response.status == 201
    created = await created_response.json()
    assert created["deep_link"].startswith("obsidian://claudian-remote?")
    deep_link = parse_qs(urlparse(created["deep_link"]).query)
    assert deep_link["relay_base_url"] == ["https://relay.example.invalid"]
    assert deep_link["installation_id"] == ["installation-a"]
    assert deep_link["vault_id"] == ["vault-a"]
    assert deep_link["endpoint_audience"] == ["claudian-remote:local_tailscale:installation-a"]
    assert len(created["short_code"]) == 8
    assert "camera" not in str(created).lower()

    redeemed_response = await client.post(
        "/api/v2/pairing/redeem",
        json={
            "claim_id": created["claim_id"],
            "claim_token": created["claim_token"],
            "device_id": "iphone-a",
            "device_name": "Alice's iPhone",
            "vault_id": "vault-a",
        },
    )
    assert redeemed_response.status == 202
    redeemed = await redeemed_response.json()
    assert redeemed["profile"] == {
        "installation_id": "installation-a",
        "vault_id": "vault-a",
        "endpoint_audience": "claudian-remote:local_tailscale:installation-a",
    }

    pending_complete = await client.post(
        f"/api/v2/pairing/claims/{created['claim_id']}/complete",
        json={"redemption_handle": redeemed["redemption_handle"], "device_id": "iphone-a"},
    )
    assert pending_complete.status == 202
    assert (await pending_complete.json())["status"] == "pending_approval"

    approved_response = await client.post(
        f"/api/v2/pairing/claims/{created['claim_id']}/approve",
        headers={"Authorization": "Bearer admin-secret"},
        json={"device_id": "iphone-a"},
    )
    assert approved_response.status == 200
    approved = await approved_response.json()
    assert "credential" not in approved

    completed_response = await client.post(
        f"/api/v2/pairing/claims/{created['claim_id']}/complete",
        json={"redemption_handle": redeemed["redemption_handle"], "device_id": "iphone-a"},
    )
    assert completed_response.status == 200
    completed = await completed_response.json()
    return created, completed


async def mobile_socket(client, credential):
    ticket_response = await client.post(
        "/api/v2/ws-ticket",
        headers={"Authorization": f"Bearer {credential}"},
        json={"device_id": "iphone-a", "client_instance_id": "view-a"},
    )
    assert ticket_response.status == 201
    ticket = (await ticket_response.json())["ticket"]
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
            "device_id": "iphone-a",
            "client_instance_id": "view-a",
            "cursor": 0,
            "compatibility": COMPATIBILITY_SET,
        }
    )
    assert (await socket.receive_json())["type"] == "authenticated"
    return socket


@pytest.mark.asyncio
async def test_route_roles_and_pairing_claim_are_non_interchangeable(aiohttp_client, tmp_path):
    client = await aiohttp_client(create_app(config(tmp_path)))
    assert (await client.post("/api/v2/pairing/claims")).status == 401
    assert (
        await client.post(
            "/api/v2/pairing/claims", headers={"Authorization": "Bearer mac-secret"}
        )
    ).status == 403

    created, completed = await pair(client)
    assert completed["credential"] != created["claim_token"]
    assert completed["credential"] != "admin-secret"
    assert (
        await client.post(
            "/api/v2/ws-ticket",
            headers={"Authorization": f"Bearer {created['claim_token']}"},
            json={"device_id": "iphone-a", "client_instance_id": "view-a"},
        )
    ).status == 401


@pytest.mark.asyncio
async def test_revocation_closes_current_socket_and_blocks_every_mobile_route(aiohttp_client, tmp_path):
    client = await aiohttp_client(create_app(config(tmp_path)))
    _, completed = await pair(client)
    devices = await client.get(
        "/api/v2/pairing/devices", headers={"Authorization": "Bearer admin-secret"}
    )
    assert devices.status == 200
    assert (await devices.json())["devices"] == [
        {
            "credential_id": completed["credential_id"],
            "device_id": "iphone-a",
            "device_name": "Alice's iPhone",
            "status": "active",
            "generation": 1,
        }
    ]
    socket = await mobile_socket(client, completed["credential"])

    revoked = await client.post(
        "/api/v2/pairing/devices/iphone-a/revoke",
        headers={"Authorization": "Bearer admin-secret"},
        json={"reason": "device_lost"},
    )
    assert revoked.status == 200
    revoked_body = await revoked.json()
    assert completed["credential_id"] in revoked_body["credential_ids"]
    assert revoked_body["closed_connections"] == 1
    close = await asyncio.wait_for(socket.receive(), timeout=1)
    assert close.type in {WSMsgType.CLOSE, WSMsgType.CLOSED, WSMsgType.CLOSING}
    assert close.data == 4003
    assert close.extra == "device_revoked"
    assert socket.closed

    headers = {"Authorization": f"Bearer {completed['credential']}"}
    assert (
        await client.post(
            "/api/v2/ws-ticket",
            headers=headers,
            json={"device_id": "iphone-a", "client_instance_id": "view-b"},
        )
    ).status == 401
    assert (
        await client.post(
            "/api/v2/commands",
            headers=headers,
            json={"compatibility": COMPATIBILITY_SET, "command": {}},
        )
    ).status == 401
    assert (await client.post("/api/v2/uploads", headers=headers, json={})).status == 401

    inspected = await client.get(
        "/api/v2/pairing/devices", headers={"Authorization": "Bearer admin-secret"}
    )
    assert (await inspected.json())["devices"][0]["status"] == "revoked"

    _, replacement = await pair(client)
    assert replacement["credential_id"] != completed["credential_id"]
