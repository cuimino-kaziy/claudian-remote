import hashlib
import os
from types import SimpleNamespace

import pytest

from gateway.relay.upload_store import GIB, MIB, UploadError, UploadStore


def usage(total=100 * GIB, free=90 * GIB):
    return SimpleNamespace(total=total, used=total - free, free=free)


async def stream(data, piece=64 * 1024):
    for offset in range(0, len(data), piece):
        yield data[offset:offset + piece]


async def begin(store, data, **overrides):
    values = {
        "pairing_id": "room-a",
        "mac_session_id": "session-a",
        "mac_connection_generation": 1,
        "display_name": "notes.md",
        "content_type": "text/markdown",
        "total_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
    values.update(overrides)
    return await store.begin(**values)


@pytest.mark.asyncio
async def test_multichunk_duplicate_finalize_atomic_ack_and_opaque_paths(tmp_path):
    root = tmp_path / "spool"
    store = await UploadStore(root, reserve_min_bytes=0, reserve_fraction=0).start()
    data = b"alpha" * 250_000 + b"omega"
    started = await begin(store, data, display_name="../../private/notes.md")
    upload_id = started["upload_id"]
    assert started["display_name"] == "notes.md"
    assert started["next_offset"] == 0
    assert list(root.iterdir())[0].name == f"{upload_id}.part"
    assert list(root.iterdir())[0].stat().st_mode & 0o777 == 0o600
    assert root.stat().st_mode & 0o777 == 0o700

    first = data[:MIB]
    first_hash = hashlib.sha256(first).hexdigest()
    result = await store.append_chunk(
        upload_id,
        pairing_id="room-a",
        mac_session_id="session-a",
        mac_connection_generation=1,
        index=0,
        offset=0,
        sha256=first_hash,
        chunks=stream(first),
    )
    assert result["next_offset"] == len(first)
    duplicate = await store.append_chunk(
        upload_id,
        pairing_id="room-a",
        mac_session_id="session-a",
        mac_connection_generation=1,
        index=0,
        offset=0,
        sha256=first_hash,
        chunks=stream(first),
    )
    assert duplicate["duplicate"] is True
    remainder = data[len(first):]
    await store.append_chunk(
        upload_id,
        pairing_id="room-a",
        mac_session_id="session-a",
        mac_connection_generation=1,
        index=1,
        offset=len(first),
        sha256=hashlib.sha256(remainder).hexdigest(),
        chunks=stream(remainder),
    )
    finalized = await store.finalize(
        upload_id,
        pairing_id="room-a",
        mac_session_id="session-a",
        mac_connection_generation=1,
        sha256=None,
    )
    assert finalized["state"] == "ready"
    assert not (root / f"{upload_id}.part").exists()
    assert (root / f"{upload_id}.blob").read_bytes() == data
    assert (await store.finalize(
        upload_id,
        pairing_id="room-a",
        mac_session_id="session-a",
        mac_connection_generation=1,
        sha256=hashlib.sha256(data).hexdigest(),
    ))["duplicate"] is True

    first_ack = await store.acknowledge(
        upload_id,
        pairing_id="room-a",
        mac_session_id="session-a",
        mac_connection_generation=1,
    )
    assert first_ack["duplicate"] is False
    assert not list(root.iterdir())
    retry_ack = await store.acknowledge(
        upload_id,
        pairing_id="room-a",
        mac_session_id="session-a",
        mac_connection_generation=1,
    )
    assert retry_ack["duplicate"] is True
    await store.close()


@pytest.mark.asyncio
async def test_single_active_dynamic_disk_reserve_and_no_product_size_cap(tmp_path):
    disk = {"value": usage()}
    store = await UploadStore(
        tmp_path / "spool",
        disk_usage=lambda _path: disk["value"],
        reserve_min_bytes=GIB,
        reserve_fraction=0.10,
    ).start()
    huge = await store.begin(
        pairing_id="room-a",
        mac_session_id="session-a",
        mac_connection_generation=1,
        display_name="huge.bin",
        content_type="application/octet-stream",
        total_bytes=2 * GIB,
        sha256="a" * 64,
    )
    with pytest.raises(UploadError, match="upload_already_active"):
        await begin(store, b"other")
    await store.abort(huge["upload_id"], "room-a")

    disk["value"] = usage(total=20 * GIB, free=2 * GIB)
    with pytest.raises(UploadError, match="insufficient_storage") as error:
        await begin(store, b"x" * MIB)
    assert error.value.status == 507

    disk["value"] = usage()
    active = await begin(store, b"x" * MIB)
    disk["value"] = usage(total=20 * GIB, free=2 * GIB - 1)
    with pytest.raises(UploadError, match="insufficient_storage"):
        await store.append_chunk(
            active["upload_id"], pairing_id="room-a", mac_session_id="session-a",
            mac_connection_generation=1, index=0, offset=0,
            sha256=hashlib.sha256(b"x" * MIB).hexdigest(), chunks=stream(b"x" * MIB),
        )
    assert (await store.stats())["active"] == 0
    assert not list((tmp_path / "spool").iterdir())
    await store.close()


@pytest.mark.asyncio
async def test_conflict_hash_ttl_binding_and_restart_orphans_are_removed(tmp_path):
    now = [10.0]
    root = tmp_path / "spool"
    root.mkdir()
    orphan = root / "old.blob"
    orphan.write_bytes(b"private")
    store = await UploadStore(
        root, ttl_seconds=30, reserve_min_bytes=0, reserve_fraction=0, clock=lambda: now[0]
    ).start()
    assert not orphan.exists()
    data = b"payload"
    active = await begin(store, data)
    with pytest.raises(UploadError, match="upload_session_mismatch"):
        await store.append_chunk(
            active["upload_id"], pairing_id="room-a", mac_session_id="other",
            mac_connection_generation=1, index=0, offset=0,
            sha256=hashlib.sha256(data).hexdigest(), chunks=stream(data),
        )
    with pytest.raises(UploadError, match="chunk_hash_mismatch"):
        await store.append_chunk(
            active["upload_id"], pairing_id="room-a", mac_session_id="session-a",
            mac_connection_generation=1, index=0, offset=0, sha256="0" * 64,
            chunks=stream(data),
        )
    assert not list(root.iterdir())

    expiring = await begin(store, data)
    now[0] = 41.0
    assert await store.cleanup_expired() == 1
    assert not list(root.iterdir())

    bound = await begin(store, data, mac_connection_generation=2)
    assert await store.abort_except_binding("room-a", "session-a", 3) == 1
    assert not (root / f"{bound['upload_id']}.part").exists()

    (root / "crash.part").write_bytes(b"orphan")
    restarted = await UploadStore(root, reserve_min_bytes=0, reserve_fraction=0).start()
    assert not list(root.iterdir())
    await restarted.close()
    await store.close()
