"""Bounded WebSocket writers and replay/live subscription ownership."""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from collections import deque
from typing import Any, Deque, Dict, List, Optional, Set

from gateway.relay.event_store import CommittedEvent, EventStore
from gateway.relay.presence import PresenceRegistry


class SlowConsumer(RuntimeError):
    pass


def _frame_size(frame: Dict[str, Any]) -> int:
    return len(json.dumps(frame, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))


def _text_entity(frame: Dict[str, Any]) -> Optional[str]:
    if frame.get("type") != "event.committed":
        return None
    event = frame.get("event") or {}
    if event.get("event_type") != "text.delta":
        return None
    entity = event.get("entity") or {}
    return ":".join(str(entity.get(key) or "") for key in ("conversation_id", "turn_id", "message_id", "block_id"))


class BoundedSendQueue:
    def __init__(self, max_events: int = 256, max_bytes: int = 2 * 1024 * 1024) -> None:
        self.max_events = max_events
        self.max_bytes = max_bytes
        self._items: Deque[Dict[str, Any]] = deque()
        self._bytes = 0
        self._condition = asyncio.Condition()
        self.closed = False
        self.coalesced_count = 0

    @property
    def count(self) -> int:
        return len(self._items)

    @property
    def bytes(self) -> int:
        return self._bytes

    def put_nowait(self, frame: Dict[str, Any]) -> None:
        size = _frame_size(frame)
        if size > self.max_bytes:
            raise SlowConsumer("frame_exceeds_client_budget")
        if len(self._items) >= max(1, self.max_events // 2) and self._items:
            entity = _text_entity(frame)
            previous = self._items[-1]
            if entity and _text_entity(previous) == entity:
                batch = {"type": "event.batch", "events": [previous, frame]}
                batch_size = _frame_size(batch)
                if batch_size <= self.max_bytes:
                    self._items.pop()
                    self._bytes -= _frame_size(previous)
                    frame, size = batch, batch_size
                    self.coalesced_count += 1
        if self.closed or len(self._items) + 1 > self.max_events or self._bytes + size > self.max_bytes:
            raise SlowConsumer("slow_consumer")
        self._items.append(frame)
        self._bytes += size
        try:
            asyncio.get_running_loop().call_soon(self._notify)
        except RuntimeError:
            pass

    def _notify(self) -> None:
        async def wake() -> None:
            async with self._condition:
                self._condition.notify()

        asyncio.create_task(wake())

    async def get(self) -> Optional[Dict[str, Any]]:
        async with self._condition:
            while not self._items and not self.closed:
                await self._condition.wait()
            if not self._items:
                return None
            frame = self._items.popleft()
            self._bytes -= _frame_size(frame)
            return frame

    async def close(self, discard: bool = False) -> None:
        async with self._condition:
            self.closed = True
            if discard:
                self._items.clear()
                self._bytes = 0
            self._condition.notify_all()


class WebSocketClient:
    def __init__(
        self,
        websocket: Any,
        pairing_id: str,
        role: str,
        *,
        max_events: int = 256,
        max_bytes: int = 2 * 1024 * 1024,
    ) -> None:
        self.websocket = websocket
        self.pairing_id = pairing_id
        self.role = role
        self.connection_id = "ws-" + uuid.uuid4().hex
        self.queue = BoundedSendQueue(max_events=max_events, max_bytes=max_bytes)
        self.phase = "new"
        self.high_water = 0
        self.last_cursor = 0
        self.live_buffer: List[CommittedEvent] = []
        self.closed_reason: Optional[str] = None
        self.compatibility: Dict[str, Any] = {}
        self.device_id: str = ""
        self.credential_id: str = ""

    def enqueue_nowait(self, frame: Dict[str, Any]) -> None:
        self.queue.put_nowait(frame)

    async def writer(self) -> None:
        while True:
            frame = await self.queue.get()
            if frame is None:
                return
            await self.websocket.send_json(frame, compress=False)

    async def close(self, code: int = 1001, reason: str = "going_away", discard: bool = True) -> None:
        self.closed_reason = reason
        await self.websocket.close(code=code, message=reason.encode("utf-8")[:120])
        await self.queue.close(discard=discard)


class WebSocketHub:
    def __init__(self, store: EventStore, presence: Optional[PresenceRegistry] = None) -> None:
        self.store = store
        self.presence = presence or PresenceRegistry()
        self._mobiles: Set[WebSocketClient] = set()
        self._macs: Set[WebSocketClient] = set()
        self._lock = asyncio.Lock()
        self._replay_count = 0
        self._replay_duration_ms = 0.0
        self._slow_consumer_closes = 0

    async def register_mobile(self, client: WebSocketClient, client_epoch: Optional[str], cursor: int) -> Dict[str, Any]:
        # This lock is the owner boundary shared with broadcast().  A committed
        # live event is either included in H or buffered; there is no seam gap.
        async with self._lock:
            self._mobiles.add(client)
            client.phase = "replaying"
            floor = await self.store.retained_floor(client.pairing_id)
            high_water = await self.store.high_water(client.pairing_id)
            client.high_water = high_water
            client.last_cursor = cursor
            if (client_epoch and client_epoch != self.store.epoch) or cursor < floor:
                reason = "epoch_mismatch" if client_epoch and client_epoch != self.store.epoch else "cursor_below_retained_floor"
                client.phase = "reset"
                client.enqueue_nowait({
                    "type": "reset_required", "reason": reason, "epoch": self.store.epoch,
                    "retained_floor": floor, "high_water": high_water,
                })
                return {"mode": "reset", "reason": reason, "high_water": high_water}

        replay_started = time.monotonic()
        replay = await self.store.replay(client.pairing_id, cursor, high_water)
        self._replay_count += len(replay)
        self._replay_duration_ms += (time.monotonic() - replay_started) * 1000
        for committed in replay:
            client.enqueue_nowait(committed.frame(replayed=True))
            client.last_cursor = max(client.last_cursor, committed.cursor)

        async with self._lock:
            for committed in sorted(client.live_buffer, key=lambda item: item.cursor):
                if committed.cursor > client.last_cursor:
                    client.enqueue_nowait(committed.frame())
                    client.last_cursor = committed.cursor
            client.live_buffer.clear()
            client.phase = "live"
        return {"mode": "live", "high_water": high_water, "replayed": len(replay)}

    async def unregister_mobile(self, client: WebSocketClient) -> None:
        async with self._lock:
            self._mobiles.discard(client)

    async def close_mobile_device(self, device_id: str, *, reason: str = "device_revoked") -> int:
        async with self._lock:
            clients = [client for client in self._mobiles if client.device_id == str(device_id)]
            for client in clients:
                self._mobiles.discard(client)
        await asyncio.gather(
            *(client.close(code=4003, reason=reason, discard=True) for client in clients),
            return_exceptions=True,
        )
        return len(clients)

    async def register_mac(
        self,
        client: WebSocketClient,
        session_id: str,
        generation: int,
        compatibility: Optional[Dict[str, Any]] = None,
    ) -> None:
        old = await self.presence.register_mac(
            client.pairing_id, session_id, generation, client, compatibility
        )
        async with self._lock:
            self._macs.add(client)
            if isinstance(old, WebSocketClient):
                self._macs.discard(old)
        if isinstance(old, WebSocketClient):
            await old.close(code=4001, reason="superseded", discard=True)
        await self.broadcast_ephemeral(client.pairing_id, {
            "type": "presence.changed", "role": "mac", "status": "online",
            "mac_session_id": session_id, "mac_connection_generation": generation,
            "compatibility": dict(compatibility or {}),
        })

    async def unregister_mac(self, client: WebSocketClient) -> bool:
        removed = await self.presence.unregister_mac(client.pairing_id, client)
        async with self._lock:
            self._macs.discard(client)
        if removed:
            await self.broadcast_ephemeral(client.pairing_id, {"type": "presence.changed", "role": "mac", "status": "offline"})
        return removed

    async def broadcast_committed(self, committed: CommittedEvent, pairing_id: str) -> None:
        slow: List[WebSocketClient] = []
        async with self._lock:
            for client in list(self._mobiles):
                if client.pairing_id != pairing_id:
                    continue
                try:
                    if client.phase == "replaying":
                        client.live_buffer.append(committed)
                    elif client.phase == "reset":
                        if committed.event["event_type"] in {"keyframe.page", "keyframe.final"}:
                            client.enqueue_nowait(committed.frame())
                            client.last_cursor = committed.cursor
                            if committed.event["event_type"] == "keyframe.final":
                                for pending in sorted(client.live_buffer, key=lambda item: item.cursor):
                                    if pending.cursor > client.last_cursor:
                                        client.enqueue_nowait(pending.frame())
                                client.live_buffer.clear()
                                client.phase = "live"
                        else:
                            client.live_buffer.append(committed)
                    elif committed.cursor > client.last_cursor:
                        client.enqueue_nowait(committed.frame())
                        client.last_cursor = committed.cursor
                except SlowConsumer:
                    self._mobiles.discard(client)
                    slow.append(client)
        for client in slow:
            self._slow_consumer_closes += 1
            await client.close(code=1013, reason="slow_consumer_gap")

    async def broadcast_ephemeral(self, pairing_id: str, frame: Dict[str, Any]) -> None:
        slow: List[WebSocketClient] = []
        async with self._lock:
            for client in list(self._mobiles):
                if client.pairing_id != pairing_id:
                    continue
                try:
                    client.enqueue_nowait(frame)
                except SlowConsumer:
                    self._mobiles.discard(client)
                    slow.append(client)
        for client in slow:
            self._slow_consumer_closes += 1
            await client.close(code=1013, reason="slow_consumer_gap")

    async def require_reset(self, pairing_id: str, reason: str) -> None:
        """Move every current mobile subscription into keyframe recovery."""
        high_water = await self.store.high_water(pairing_id)
        slow: List[WebSocketClient] = []
        async with self._lock:
            for client in list(self._mobiles):
                if client.pairing_id != pairing_id:
                    continue
                client.phase = "reset"
                client.high_water = high_water
                client.live_buffer.clear()
                try:
                    client.enqueue_nowait(
                        {
                            "type": "reset_required",
                            "reason": reason,
                            "epoch": self.store.epoch,
                            "high_water": high_water,
                        }
                    )
                except SlowConsumer:
                    self._mobiles.discard(client)
                    slow.append(client)
        for client in slow:
            self._slow_consumer_closes += 1
            await client.close(code=1013, reason="slow_consumer_gap")

    def metrics(self) -> Dict[str, Any]:
        clients = list(self._mobiles | self._macs)
        return {
            "mobile_connections": len(self._mobiles),
            "mac_connections": len(self._macs),
            "queue_events": sum(client.queue.count for client in clients),
            "queue_bytes": sum(client.queue.bytes for client in clients),
            "coalesced_count": sum(client.queue.coalesced_count for client in clients),
            "replay_count": self._replay_count,
            "replay_duration_ms": round(self._replay_duration_ms, 3),
            "slow_consumer_closes": self._slow_consumer_closes,
        }

    async def close_all(self) -> None:
        async with self._lock:
            clients = list(self._mobiles | self._macs)
            self._mobiles.clear()
            self._macs.clear()
        await asyncio.gather(
            *(client.close(code=1001, reason="going_away") for client in clients),
            return_exceptions=True,
        )
