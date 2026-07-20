import asyncio
import json
from types import SimpleNamespace

import pytest

from gateway.mac_companion.sse_client import SSEDecoder, SSEMessage
from gateway.mac_companion.stream_pump import (
    AsyncMacCompanion,
    BoundedOutboundQueue,
    CommandDispatcher,
    CompanionState,
    OutboundQueueFull,
)
from gateway.protocol.compatibility import COMPATIBILITY_SET


def test_sse_decoder_handles_utf8_byte_splits_crlf_multiline_comments_and_empty_fields():
    decoder = SSEDecoder()
    raw = (
        ": keepalive\r\n"
        "id: 7\r\n"
        "event: semantic\r\n"
        "data: {\"label\":\"你好\",\r\n"
        "data: \"status\":\"running\"}\r\n\r\n"
        "event\r"
        "data: second\r\r"
    ).encode("utf-8")
    output = []
    for byte in raw:
        output.extend(decoder.feed(bytes([byte])))
    assert len(output) == 2
    assert output[0].event == "semantic"
    assert output[0].event_id == "7"
    assert json.loads(output[0].data) == {"label": "你好", "status": "running"}
    assert output[1].event == "message"
    assert output[1].data == "second"
    assert output[1].event_id == "7"


def test_sse_decoder_ignores_nul_id_invalid_retry_and_unclosed_eof_frame():
    decoder = SSEDecoder()
    output = decoder.feed(b"id: bad\x00id\nretry: later\ndata: complete\n\n")
    output.extend(decoder.feed(b"id: 9\ndata: incomplete"))
    output.extend(decoder.finish())
    assert [(item.event_id, item.retry_ms, item.data) for item in output] == [("", None, "complete")]


def semantic_event(sequence=1, event_type="text.delta"):
    return {
        "protocol": "claudian.remote.v2",
        "kind": "event",
        "event_type": event_type,
        "source": {"instance_id": "bridge-test", "sequence": sequence},
        "entity": {
            "conversation_id": "conv-1",
            "turn_id": "turn-1",
            "message_id": "message-1",
            "block_id": "block-1",
        },
        "revision": sequence,
        "payload": {"text": "x", "base_revision": sequence - 1, "offset": sequence - 1}
        if event_type == "text.delta"
        else {"status": "completed", "checksum": "sha256:" + "0" * 64},
    }


@pytest.mark.asyncio
async def test_outbound_queue_is_bounded_and_preserves_terminal_with_explicit_gap():
    queue = BoundedOutboundQueue(max_events=2, max_bytes=16_000)
    await queue.put({"type": "event.publish", "event": semantic_event(1)})
    await queue.put({"type": "event.publish", "event": semantic_event(2)})

    await queue.put({"type": "command.receipt", "receipt": {"status": "executed"}})

    assert queue.size <= 2
    assert queue.bytes <= 16_000
    first = await queue.get()
    assert first.frame == {"type": "source.gap", "reason": "companion_backpressure"}
    remaining = [(await queue.get()).frame, (await queue.get()).frame]
    assert any(item.get("type") == "command.receipt" for item in remaining)


@pytest.mark.asyncio
async def test_noncritical_overflow_is_rejected_instead_of_growing_memory():
    queue = BoundedOutboundQueue(max_events=1, max_bytes=8_000)
    await queue.put({"type": "event.publish", "event": semantic_event(1)})
    with pytest.raises(OutboundQueueFull, match="outbound_queue_full"):
        await queue.put({"type": "event.publish", "event": semantic_event(2)})


class FakeBridge:
    def __init__(self):
        self.commands = []
        self.bindings = []
        self.invalidations = []
        self.keyframes = []

    async def bind(self, path, session_id, generation, compatibility=None):
        self.bindings.append((path, session_id, generation, compatibility))
        return {"ok": True, "compatibility": {"writable": True, "actual": COMPATIBILITY_SET}}

    async def invalidate(self, path, session_id, generation):
        self.invalidations.append((path, session_id, generation))
        return {"ok": True}

    async def command(self, path, command):
        self.commands.append((path, command))
        return {"result": {"delivery_id": command["delivery_id"], "status": "executed"}}

    async def keyframe(self, path):
        self.keyframes.append(path)
        return {"ok": True, "checksum": "sha256:" + "0" * 64}


def command(session_id, generation, delivery_id="delivery-1"):
    return {
        "protocol": "claudian.remote.v2",
        "kind": "command",
        "command_type": "turn.stop",
        "delivery_id": delivery_id,
        "mac_session_id": session_id,
        "mac_connection_generation": generation,
        "expires_at": "2099-12-31T23:59:59Z",
        "expected_revision": 1,
        "target": {"conversation_id": "conv-1", "turn_id": "turn-1"},
        "payload": {},
    }


@pytest.mark.asyncio
async def test_same_session_old_generation_command_never_crosses_reconnect():
    bridge = FakeBridge()
    dispatcher = CommandDispatcher(bridge, "/command", "mac-session")
    dispatcher.activate(1)
    old = command("mac-session", 1)
    queued = asyncio.create_task(dispatcher.dispatch(old, 1))
    dispatcher.activate(2)

    result = await queued

    assert result["error_code"] == "stale_connection"
    assert bridge.commands == []
    fresh = await dispatcher.dispatch(command("mac-session", 2, "delivery-2"), 2)
    assert fresh["status"] == "executed"
    assert len(bridge.commands) == 1


@pytest.mark.asyncio
async def test_companion_bridge_and_relay_hello_bind_exact_compatibility_metadata():
    config = SimpleNamespace(
        state_path="",
        v2_state_path="",
        outbound_max_events=32,
        outbound_max_bytes=64_000,
        bridge_command_path="/command",
        bridge_bind_path="/bind",
        bridge_invalidate_path="/invalidate",
        bridge_keyframe_path="/keyframe",
        bridge_import_path="/import",
    )
    runtime = AsyncMacCompanion(config)
    bridge = FakeBridge()
    socket = FakeSocket(runtime)
    socket.receive_json = lambda: asyncio.sleep(0, result=None)
    sse = FakeSSE()

    await runtime.run_connection(socket, bridge, sse)

    assert bridge.bindings[0][3] == COMPATIBILITY_SET
    hello = socket.sent[0]
    assert hello["type"] == "mac.hello"
    assert hello["compatibility"] == COMPATIBILITY_SET


class FakeSSE:
    async def events(self, last_event_id):
        assert last_event_id == 0
        yield SSEMessage("semantic", json.dumps(semantic_event(1)), "1")
        await asyncio.Future()


class FakeSocket:
    def __init__(self, runtime):
        self.runtime = runtime
        self.sent = []
        self.receipt_sent = asyncio.Event()
        self.receive_count = 0

    async def send_json(self, frame):
        self.sent.append(frame)
        if frame.get("type") == "command.receipt":
            self.receipt_sent.set()

    async def receive_json(self):
        self.receive_count += 1
        if self.receive_count == 1:
            return {"type": "command", "command": command(self.runtime.mac_session_id, 1)}
        await self.receipt_sent.wait()
        return None


@pytest.mark.asyncio
async def test_event_and_control_pumps_progress_without_waiting_for_each_other():
    config = SimpleNamespace(
        state_path="",
        v2_state_path="",
        outbound_max_events=32,
        outbound_max_bytes=128_000,
        bridge_command_path="/command",
        bridge_bind_path="/bind",
        bridge_invalidate_path="/invalidate",
        bridge_keyframe_path="/keyframe",
    )
    runtime = AsyncMacCompanion(config)
    bridge = FakeBridge()
    socket = FakeSocket(runtime)

    await asyncio.wait_for(runtime.run_connection(socket, bridge, FakeSSE()), timeout=1)

    assert bridge.commands[0][1]["command_type"] == "turn.stop"
    assert any(frame.get("type") == "event.publish" for frame in socket.sent)
    assert any(frame.get("type") == "command.receipt" for frame in socket.sent)
    assert bridge.invalidations[-1][2] == 1


class BlockingBridge(FakeBridge):
    def __init__(self):
        super().__init__()
        self.started = []
        self.executed = []

    async def command(self, path, incoming):
        self.started.append(incoming["delivery_id"])
        try:
            await asyncio.Future()
        except asyncio.CancelledError:
            raise
        self.executed.append(incoming["delivery_id"])


class DisconnectingSocket:
    def __init__(self, runtime, generation, deliveries):
        self.frames = [
            {"type": "command", "command": command(runtime.mac_session_id, generation, delivery)}
            for delivery in deliveries
        ]
        self.sent = []

    async def send_json(self, frame):
        self.sent.append(frame)

    async def receive_json(self):
        if self.frames:
            return self.frames.pop(0)
        await asyncio.sleep(0)
        return None


class EmptySSE:
    async def events(self, last_event_id):
        await asyncio.Future()
        yield  # pragma: no cover - keeps this an async generator


@pytest.mark.asyncio
async def test_disconnect_cancels_unaccepted_command_queue_before_same_session_reconnect():
    config = SimpleNamespace(
        state_path="", v2_state_path="", outbound_max_events=32, outbound_max_bytes=128_000,
        bridge_command_path="/command", bridge_bind_path="/bind", bridge_invalidate_path="/invalidate",
        bridge_keyframe_path="/keyframe",
    )
    runtime = AsyncMacCompanion(config)
    bridge = BlockingBridge()

    await runtime.run_connection(DisconnectingSocket(runtime, 1, ["old-a", "old-b"]), bridge, EmptySSE())
    assert bridge.executed == []

    # A fresh generation receives no old work.  The old in-memory queue belonged
    # to generation 1 and was destroyed when that socket closed.
    await runtime.run_connection(DisconnectingSocket(runtime, 2, []), bridge, EmptySSE())
    assert bridge.executed == []
    assert all(delivery in {"old-a", "old-b"} for delivery in bridge.started)


class KeyframeRequestSocket:
    def __init__(self):
        self.sent = []
        self.frames = [{"type": "keyframe.request", "reason": "mobile_reset"}]

    async def send_json(self, frame):
        self.sent.append(frame)

    async def receive_json(self):
        if self.frames:
            return self.frames.pop(0)
        await asyncio.sleep(0)
        return None


@pytest.mark.asyncio
async def test_connection_local_keyframe_control_calls_bridge_without_entering_command_queue():
    config = SimpleNamespace(
        state_path="", v2_state_path="", outbound_max_events=32, outbound_max_bytes=128_000,
        bridge_command_path="/command", bridge_bind_path="/bind", bridge_invalidate_path="/invalidate",
        bridge_keyframe_path="/keyframe",
    )
    runtime = AsyncMacCompanion(config)
    bridge = FakeBridge()
    await runtime.run_connection(KeyframeRequestSocket(), bridge, EmptySSE())
    assert bridge.keyframes == ["/keyframe"]
    assert bridge.commands == []


def test_v2_state_file_contains_only_recovery_coordinates(tmp_path):
    path = tmp_path / "state.json"
    state = CompanionState(path)
    state.last_bridge_event_id = 7
    state.relay_epoch = "epoch-a"
    state.relay_cursor = 12
    state.save()
    saved = json.loads(path.read_text(encoding="utf-8"))
    assert saved == {"last_bridge_event_id": 7, "relay_epoch": "epoch-a", "relay_cursor": 12}
    assert "token" not in path.read_text(encoding="utf-8").lower()
