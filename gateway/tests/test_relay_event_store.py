import os
from pathlib import Path

import pytest

from gateway.relay.event_store import EventStore


def semantic_event(sequence=1, text="hello", event_type="text.delta"):
    payload = {"text": text, "base_revision": sequence - 1, "offset": sequence - 1}
    entity = {"conversation_id": "conv-1", "turn_id": "turn-1", "message_id": "msg-1", "block_id": "block-1"}
    if event_type == "turn.completed":
        payload = {"status": "completed", "duration_ms": 10, "checksum": "sha256:" + "a" * 64}
        entity = {"conversation_id": "conv-1", "turn_id": "turn-1"}
    return {
        "protocol": "claudian.remote.v2",
        "kind": "event",
        "event_type": event_type,
        "source": {"instance_id": "bridge-a", "sequence": sequence},
        "entity": entity,
        "revision": sequence,
        "payload": payload,
        "occurred_at": "2099-01-01T00:00:00Z",
    }


@pytest.mark.asyncio
async def test_event_is_committed_before_append_returns_and_replays_with_cursor(tmp_path):
    store = await EventStore(tmp_path / "relay.db").start()
    committed = await store.append("room-a", semantic_event())
    replay = await store.replay("room-a", 0)
    assert committed.inserted is True
    assert replay[0].cursor == committed.cursor == 1
    assert replay[0].event == semantic_event()
    assert (tmp_path / "relay.db").stat().st_mode & 0o777 == 0o600
    await store.close()


@pytest.mark.asyncio
async def test_epoch_and_cursor_survive_restart_but_database_replacement_gets_new_epoch(tmp_path):
    path = tmp_path / "relay.db"
    first = await EventStore(path).start()
    epoch = first.epoch
    assert (await first.append("room-a", semantic_event(1))).cursor == 1
    await first.close()

    second = await EventStore(path).start()
    assert second.epoch == epoch
    assert (await second.append("room-a", semantic_event(2))).cursor == 2
    await second.close()

    for suffix in ("", "-wal", "-shm"):
        candidate = Path(str(path) + suffix)
        if candidate.exists():
            candidate.unlink()
    replacement = await EventStore(path).start()
    assert replacement.epoch != epoch
    assert (await replacement.append("room-a", semantic_event(1))).cursor == 1
    await replacement.close()


@pytest.mark.asyncio
async def test_event_uid_retry_is_idempotent_and_conflicting_body_is_rejected(tmp_path):
    store = await EventStore(tmp_path / "relay.db").start()
    first = await store.append("room-a", semantic_event(1, "one"))
    duplicate = await store.append("room-a", semantic_event(1, "one"))
    assert duplicate.cursor == first.cursor
    assert duplicate.inserted is False
    with pytest.raises(ValueError, match="event_uid_conflict"):
        await store.append("room-a", semantic_event(1, "different"))
    assert (await store.stats())["rows"] == 1
    await store.close()


@pytest.mark.asyncio
async def test_prune_advances_retained_floor_and_keeps_store_bounded(tmp_path):
    store = await EventStore(
        tmp_path / "relay.db", retention_seconds=5, completed_grace_seconds=20,
        max_rows=3, max_bytes=10_000,
    ).start()
    for sequence in range(1, 6):
        await store.append("room-a", semantic_event(sequence), now=float(sequence))
    result = await store.prune(now=100)
    assert result["remaining"] <= 3
    assert await store.retained_floor("room-a") >= 2
    await store.close()


@pytest.mark.asyncio
async def test_checkpoint_and_online_backup_are_owned_by_store_worker(tmp_path):
    store = await EventStore(tmp_path / "relay.db").start()
    await store.append("room-a", semantic_event())
    checkpoint = await store.checkpoint("PASSIVE")
    assert len(checkpoint) == 3
    backup = tmp_path / "backup" / "relay.db"
    await store.backup(backup)
    assert backup.exists()
    assert backup.stat().st_mode & 0o777 == 0o600
    await store.close()
