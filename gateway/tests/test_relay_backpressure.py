import pytest

from gateway.relay.event_store import CommittedEvent
from gateway.relay.presence import PresenceRegistry
from gateway.relay.websocket_hub import BoundedSendQueue, SlowConsumer, WebSocketClient, WebSocketHub
from gateway.tests.test_relay_event_store import semantic_event
from gateway.tests.test_relay_replay import FakeWebSocket


def committed(cursor, text="x"):
    return CommittedEvent(cursor, "epoch-a", f"bridge-a:{cursor}", semantic_event(cursor, text), True)


def test_client_queue_is_bounded_by_count_and_bytes():
    queue = BoundedSendQueue(max_events=2, max_bytes=600)
    queue.put_nowait({"type": "small", "value": "x"})
    queue.put_nowait({"type": "small", "value": "y"})
    with pytest.raises(SlowConsumer, match="slow_consumer"):
        queue.put_nowait({"type": "small", "value": "z"})
    assert queue.count == 2
    assert queue.bytes <= 600


@pytest.mark.asyncio
async def test_slow_mobile_is_closed_without_blocking_other_mobile(tmp_path):
    class Store:
        epoch = "epoch-a"

    hub = WebSocketHub(Store())  # type: ignore[arg-type]
    slow_ws, fast_ws = FakeWebSocket(), FakeWebSocket()
    slow = WebSocketClient(slow_ws, "room-a", "mobile", max_events=1, max_bytes=450)
    fast = WebSocketClient(fast_ws, "room-a", "mobile")
    slow.phase = fast.phase = "live"
    hub._mobiles.update({slow, fast})
    await hub.broadcast_committed(committed(1, "x" * 100), "room-a")
    await hub.broadcast_committed(committed(2, "y" * 100), "room-a")
    assert slow.closed_reason == "slow_consumer_gap"
    assert fast.queue.count == 2


class CommandClient:
    def __init__(self, connection_id):
        self.connection_id = connection_id
        self.frames = []

    def enqueue_nowait(self, frame):
        self.frames.append(frame)


@pytest.mark.asyncio
async def test_presence_race_and_old_generation_never_route_to_new_connection():
    registry = PresenceRegistry()
    old = CommandClient("old")
    new = CommandClient("new")
    await registry.register_mac("room-a", "session-a", 7, old)
    command = {"mac_session_id": "session-a", "mac_connection_generation": 7}
    assert (await registry.route_command("room-a", command))["status"] == "routed"
    await registry.register_mac("room-a", "session-a", 8, new)
    assert (await registry.route_command("room-a", command))["status"] == "connection_generation_mismatch"
    assert new.frames == []
    command["mac_connection_generation"] = 8
    assert (await registry.route_command("room-a", command))["status"] == "routed"
    assert len(new.frames) == 1
    assert await registry.unregister_mac("room-a", old) is False
    assert (await registry.mac_snapshot("room-a"))["online"] is True


@pytest.mark.asyncio
async def test_shutdown_closes_every_socket_and_discards_pending_frames():
    class Store:
        epoch = "epoch-a"

    hub = WebSocketHub(Store())  # type: ignore[arg-type]
    mobile_ws, mac_ws = FakeWebSocket(), FakeWebSocket()
    mobile = WebSocketClient(mobile_ws, "room-a", "mobile")
    mac = WebSocketClient(mac_ws, "room-a", "mac")
    mobile.enqueue_nowait({"type": "pending"})
    mac.enqueue_nowait({"type": "pending"})
    hub._mobiles.add(mobile)
    hub._macs.add(mac)

    await hub.close_all()

    assert mobile.queue.closed and mac.queue.closed
    assert mobile.queue.count == 0 and mac.queue.count == 0
    assert mobile_ws.closed[0]["code"] == 1001
    assert mac_ws.closed[0]["code"] == 1001
