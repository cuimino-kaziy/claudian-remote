import asyncio
import hashlib
import os
import uuid
from pathlib import Path
from types import SimpleNamespace

import aiohttp
import pytest
from aiohttp import web

from gateway.mac_companion.stream_pump import AsyncMacCompanion
from gateway.mac_companion.upload_receiver import DownloadedUpload, UploadReceiver
from gateway.relay.app import STORE, UPLOADS, create_app
from gateway.tests.test_relay_aiohttp import (
    connect_mac,
    connect_mobile,
    issue_mobile_ticket,
    receive_type,
    relay_config,
)


def digest(data):
    return hashlib.sha256(data).hexdigest()


async def begin_http_upload(client, data, session="mac-session", generation=1):
    response = await client.post(
        "/api/v2/uploads",
        headers={"Authorization": "Bearer mobile-secret"},
        json={
            "display_name": "../../lecture.md",
            "total_bytes": len(data),
            "total_sha256": digest(data),
            "mac_session_id": session,
            "mac_connection_generation": generation,
        },
    )
    return response, await response.json()


async def put_chunk(client, upload_id, index, offset, data, session="mac-session", generation=1):
    return await client.put(
        f"/api/v2/uploads/{upload_id}/chunks/{index}",
        headers={
            "Authorization": "Bearer mobile-secret",
            "Content-Type": "application/octet-stream",
            "X-Chunk-Offset": str(offset),
            "X-Chunk-SHA256": digest(data),
            "X-Mac-Session-ID": session,
            "X-Mac-Connection-Generation": str(generation),
        },
        data=data,
    )


@pytest.mark.asyncio
async def test_relay_multichunk_finalize_mac_pull_ack_delete_and_mobile_artifact(aiohttp_client, tmp_path):
    config = relay_config(tmp_path)
    config.upload_reserve_min_bytes = 0
    config.upload_reserve_fraction = 0
    client = await aiohttp_client(create_app(config))
    mobile = await connect_mobile(client, await issue_mobile_ticket(client))
    mac = await connect_mac(client)
    await receive_type(mobile, "presence.changed")

    data = b"a" * (1024 * 1024) + b"tail"
    response, started = await begin_http_upload(client, data)
    assert response.status == 201
    assert started["display_name"] == "lecture.md"
    assert started["next_offset"] == 0
    upload_id = started["upload_id"]

    first = data[:1024 * 1024]
    first_response = await put_chunk(client, upload_id, 0, 0, first)
    assert first_response.status == 200
    assert (await first_response.json())["next_offset"] == len(first)
    second_response = await put_chunk(client, upload_id, 1, len(first), data[len(first):])
    assert second_response.status == 200

    finalized = await client.post(
        f"/api/v2/uploads/{upload_id}/finalize",
        headers={"Authorization": "Bearer mobile-secret"},
        json={"mac_session_id": "mac-session", "mac_connection_generation": 1},
    )
    assert finalized.status == 202
    available = await receive_type(mac, "upload.available")
    assert available["upload"]["upload_id"] == upload_id
    assert available["upload"]["download_path"].endswith("/content")

    downloaded = await client.get(
        available["upload"]["download_path"],
        headers={
            "Authorization": "Bearer mac-secret",
            "X-Mac-Session-ID": "mac-session",
            "X-Mac-Connection-Generation": "1",
        },
    )
    assert downloaded.status == 200
    assert await downloaded.read() == data

    await mac.send_json(
        {
            "type": "upload.ack",
            "mac_session_id": "mac-session",
            "mac_connection_generation": 1,
            "upload_id": upload_id,
            "status": "imported",
            "result": {
                "vault_path": f"Claudian Remote/Uploads/lecture-{upload_id[:8]}.md",
                "kind": "markdown",
                "label": "lecture.md",
            },
        }
    )
    imported = await receive_type(mobile, "upload.imported")
    assert imported["upload_id"] == upload_id
    assert imported["result"]["kind"] == "markdown"
    assert (await client.server.app[UPLOADS].stats())["active"] == 0
    assert not list((tmp_path / "uploads").iterdir())
    assert (await client.server.app[STORE].stats())["rows"] == 0

    # A transport retry of the same ACK is harmless and does not recreate or
    # redeliver the temporary file.
    await mac.send_json(
        {
            "type": "upload.ack",
            "mac_session_id": "mac-session",
            "mac_connection_generation": 1,
            "upload_id": upload_id,
            "status": "imported",
            "result": {"vault_path": "Claudian Remote/Uploads/existing.md", "kind": "markdown", "label": "lecture.md"},
        }
    )
    await asyncio.sleep(0)
    assert not mac.closed
    await mac.close()
    await mobile.close()


@pytest.mark.asyncio
async def test_upload_is_aborted_on_disconnect_and_never_crosses_generation(aiohttp_client, tmp_path):
    config = relay_config(tmp_path)
    config.upload_reserve_min_bytes = 0
    config.upload_reserve_fraction = 0
    client = await aiohttp_client(create_app(config))
    old_mac = await connect_mac(client, generation=1)
    data = b"private attachment"
    response, started = await begin_http_upload(client, data, generation=1)
    assert response.status == 201
    upload_id = started["upload_id"]
    assert (await put_chunk(client, upload_id, 0, 0, data, generation=1)).status == 200

    await old_mac.close()
    for _ in range(50):
        if (await client.server.app[UPLOADS].stats())["active"] == 0:
            break
        await asyncio.sleep(0.01)
    assert (await client.server.app[UPLOADS].stats())["active"] == 0
    assert not list((tmp_path / "uploads").iterdir())

    new_mac = await connect_mac(client, generation=2)
    stale_finalize = await client.post(
        f"/api/v2/uploads/{upload_id}/finalize",
        headers={"Authorization": "Bearer mobile-secret"},
        json={"mac_session_id": "mac-session", "mac_connection_generation": 1},
    )
    assert stale_finalize.status in {404, 409}
    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(new_mac.receive_json(), timeout=0.05)
    await new_mac.close()


@pytest.mark.asyncio
async def test_upload_receiver_streams_verifies_and_cleans_local_blob(aiohttp_server, tmp_path):
    data = (b"streamed" * 20_000) + b"end"
    seen = {}

    async def content(request):
        seen["session"] = request.headers.get("Upload-Session-ID")
        seen["generation"] = request.headers.get("Upload-Connection-Generation")
        return web.Response(body=data, content_type="application/octet-stream")

    app = web.Application()
    app.router.add_get("/api/v2/uploads/{upload_id}/content", content)
    server = await aiohttp_server(app)
    async with aiohttp.ClientSession() as session:
        receiver = await UploadReceiver(
            session, str(server.make_url("/")).rstrip("/"), "mac-secret", tmp_path / "receiver"
        ).start()
        upload_id = str(uuid.uuid4())
        downloaded = await receiver.download(
            {
                "upload_id": upload_id,
                "display_name": "lecture.md",
                "content_type": "text/markdown",
                "total_bytes": len(data),
                "sha256": digest(data),
            },
            mac_session_id="session-a",
            mac_connection_generation=7,
            is_current=lambda: True,
        )
        assert downloaded.path.name == f"{upload_id}.blob"
        assert downloaded.path.read_bytes() == data
        assert downloaded.path.stat().st_mode & 0o777 == 0o600
        assert seen == {"session": "session-a", "generation": "7"}
        await receiver.cleanup(upload_id)
        assert not downloaded.path.exists()


class FakeUploadReceiver:
    def __init__(self, path):
        self.path = path
        self.cleaned = []

    async def download(self, upload, **_kwargs):
        return DownloadedUpload(
            upload_id=upload["upload_id"], path=self.path, display_name="lecture.md",
            content_type="text/markdown", total_bytes=self.path.stat().st_size,
            sha256=digest(self.path.read_bytes()),
        )

    async def cleanup(self, upload_id):
        self.cleaned.append(upload_id)


class FakeImportBridge:
    def __init__(self):
        self.imports = []

    async def import_upload(self, path, body):
        self.imports.append((path, body))
        return {"result": {"vault_path": "Claudian Remote/Uploads/lecture.md", "kind": "markdown", "label": "lecture.md"}}


@pytest.mark.asyncio
async def test_companion_upload_worker_imports_once_and_emits_session_bound_ack(tmp_path):
    source = tmp_path / "upload.blob"
    source.write_bytes(b"document")
    config = SimpleNamespace(
        v2_state_path="", outbound_max_events=32, outbound_max_bytes=128_000,
        bridge_import_path="/claudian-remote/v2/import",
    )
    runtime = AsyncMacCompanion(config)
    runtime.mac_session_id = "session-a"
    runtime.connection_generation = 3
    receiver = FakeUploadReceiver(source)
    bridge = FakeImportBridge()
    uploads = asyncio.Queue(maxsize=1)
    upload_id = str(uuid.uuid4())
    await uploads.put({"upload_id": upload_id})
    worker = asyncio.create_task(runtime._upload_worker(receiver, bridge, 3, uploads))
    ack = (await asyncio.wait_for(runtime.outbound.get(), timeout=1)).frame
    worker.cancel()
    await asyncio.gather(worker, return_exceptions=True)

    assert bridge.imports[0][0] == "/claudian-remote/v2/import"
    assert bridge.imports[0][1]["temp_path"] == str(source)
    assert bridge.imports[0][1]["total_sha256"] == digest(b"document")
    assert ack["type"] == "upload.ack"
    assert ack["status"] == "imported"
    assert ack["mac_connection_generation"] == 3
    assert receiver.cleaned == [upload_id]
