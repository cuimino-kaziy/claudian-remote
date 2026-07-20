import asyncio

import pytest

from gateway.relay.event_store import EventStore
from gateway.relay.websocket_hub import WebSocketClient, WebSocketHub
from gateway.tests.test_relay_event_store import semantic_event


class FakeWebSocket:
    def __init__(self):
        self.sent = []
        self.closed = []

    async def send_json(self, frame, **_kwargs):
        self.sent.append(frame)

    async def close(self, **kwargs):
        self.closed.append(kwargs)


async def drain(client):
    frames = []
    while client.queue.count:
        frames.append(await client.queue.get())
    return frames


@pytest.mark.asyncio
async def test_restart_replay_uses_persistent_epoch_and_cursor(tmp_path):
    path = tmp_path / "relay.db"
    store = await EventStore(path).start()
    epoch = store.epoch
    first = await store.append("room-a", semantic_event(1))
    await store.close()
    store = await EventStore(path).start()
    second = await store.append("room-a", semantic_event(2))
    hub = WebSocketHub(store)
    client = WebSocketClient(FakeWebSocket(), "room-a", "mobile")
    result = await hub.register_mobile(client, epoch, first.cursor)
    frames = await drain(client)
    assert result["mode"] == "live"
    assert [frame["cursor"] for frame in frames] == [second.cursor]
    assert frames[0]["replayed"] is True
    await store.close()


@pytest.mark.asyncio
async def test_epoch_and_retention_gap_require_keyframe_reset(tmp_path):
    store = await EventStore(tmp_path / "relay.db", max_rows=1).start()
    for sequence in range(1, 4):
        await store.append("room-a", semantic_event(sequence), now=sequence)
    await store.prune(now=4)
    hub = WebSocketHub(store)
    stale_epoch = WebSocketClient(FakeWebSocket(), "room-a", "mobile")
    assert (await hub.register_mobile(stale_epoch, "old-epoch", 0))["reason"] == "epoch_mismatch"
    assert (await drain(stale_epoch))[0]["type"] == "reset_required"
    old_cursor = WebSocketClient(FakeWebSocket(), "room-a", "mobile")
    assert (await hub.register_mobile(old_cursor, store.epoch, 0))["reason"] == "cursor_below_retained_floor"
    await store.close()


class SeamStore:
    def __init__(self, existing, live):
        self.epoch = "epoch-a"
        self.existing = existing
        self.live = live
        self.high_read = asyncio.Event()
        self.release_replay = asyncio.Event()

    async def retained_floor(self, _pairing):
        return 0

    async def high_water(self, _pairing):
        self.high_read.set()
        return self.existing.cursor

    async def replay(self, _pairing, _after, _through):
        await self.release_replay.wait()
        return [self.existing]


@pytest.mark.asyncio
async def test_replay_live_seam_buffers_commit_after_high_water_without_gap_or_duplicate():
    from gateway.relay.event_store import CommittedEvent

    existing = CommittedEvent(10, "epoch-a", "bridge-a:1", semantic_event(1), True)
    live = CommittedEvent(11, "epoch-a", "bridge-a:2", semantic_event(2), True)
    store = SeamStore(existing, live)
    hub = WebSocketHub(store)  # type: ignore[arg-type]
    client = WebSocketClient(FakeWebSocket(), "room-a", "mobile")
    subscribe = asyncio.create_task(hub.register_mobile(client, "epoch-a", 0))
    await store.high_read.wait()
    broadcast = asyncio.create_task(hub.broadcast_committed(live, "room-a"))
    await asyncio.sleep(0)
    store.release_replay.set()
    await asyncio.gather(subscribe, broadcast)
    frames = await drain(client)
    assert [frame["cursor"] for frame in frames] == [10, 11]
