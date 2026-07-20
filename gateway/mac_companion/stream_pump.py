"""Async dual-pump runtime for Claudian Remote v2.

The Bridge event stream, Relay reader, and Relay writer are independent tasks.
Only the writer touches ``send_json`` and only the reader touches
``receive_json``.  Mobile commands are valid for one Relay connection
generation and are never persisted for a later reconnect.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import uuid
from collections import OrderedDict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Deque, Dict, Mapping, Optional

import aiohttp

from gateway.mac_companion.relay_ws_client import RelayWSClient, RelayWebSocket
from gateway.mac_companion.sse_client import BridgeSSEClient
from gateway.mac_companion.upload_receiver import UploadReceiveError, UploadReceiver
from gateway.protocol.compatibility import COMPATIBILITY_SET


CRITICAL_FRAME_TYPES = {
    "command.receipt",
    "source.gap",
    "presence",
    "upload.ack",
}
CRITICAL_EVENT_TYPES = {
    "approval.requested",
    "approval.resolved",
    "keyframe.page",
    "keyframe.final",
    "turn.completed",
    "turn.failed",
    "turn.interrupted",
    "resync.required",
}


class OutboundQueueFull(RuntimeError):
    pass


@dataclass
class OutboundItem:
    frame: Dict[str, Any]
    encoded_bytes: int
    critical: bool
    bridge_event_id: int = 0
    event_uid: str = ""


def _frame_size(frame: Mapping[str, Any]) -> int:
    return len(json.dumps(frame, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))


def _event_uid(event: Mapping[str, Any]) -> str:
    source = event.get("source") if isinstance(event.get("source"), Mapping) else {}
    instance = str(source.get("instance_id") or "")
    sequence = source.get("sequence")
    return f"{instance}:{sequence}" if instance and isinstance(sequence, int) else ""


def _critical(frame: Mapping[str, Any]) -> bool:
    if frame.get("type") in CRITICAL_FRAME_TYPES:
        return True
    event = frame.get("event") if isinstance(frame.get("event"), Mapping) else {}
    return event.get("event_type") in CRITICAL_EVENT_TYPES


class BoundedOutboundQueue:
    """A byte-and-count bounded queue with terminal preservation.

    A critical item may evict non-critical stream progress.  Such an eviction
    inserts one ``source.gap`` marker so the Relay/Mobile path calibrates from a
    keyframe instead of silently presenting incomplete text.
    """

    def __init__(self, max_events: int = 256, max_bytes: int = 2 * 1024 * 1024) -> None:
        self.max_events = max_events
        self.max_bytes = max_bytes
        self._items: Deque[OutboundItem] = deque()
        self._bytes = 0
        self._condition = asyncio.Condition()
        self._closed = False
        self._gap_pending = False

    @property
    def size(self) -> int:
        return len(self._items)

    @property
    def bytes(self) -> int:
        return self._bytes

    def _fits(self, item: OutboundItem) -> bool:
        return len(self._items) < self.max_events and self._bytes + item.encoded_bytes <= self.max_bytes

    def _remove_first_noncritical(self) -> bool:
        for index, queued in enumerate(self._items):
            if not queued.critical:
                del self._items[index]
                self._bytes -= queued.encoded_bytes
                return True
        return False

    def _append(self, item: OutboundItem) -> None:
        self._items.append(item)
        self._bytes += item.encoded_bytes

    def _make_item(self, frame: Dict[str, Any], bridge_event_id: int = 0) -> OutboundItem:
        event = frame.get("event") if isinstance(frame.get("event"), Mapping) else {}
        return OutboundItem(
            frame=frame,
            encoded_bytes=_frame_size(frame),
            critical=_critical(frame),
            bridge_event_id=bridge_event_id,
            event_uid=_event_uid(event),
        )

    async def put(self, frame: Dict[str, Any], bridge_event_id: int = 0) -> None:
        item = self._make_item(frame, bridge_event_id)
        if item.encoded_bytes > self.max_bytes:
            raise OutboundQueueFull("frame_exceeds_outbound_budget")
        async with self._condition:
            if self._closed:
                raise OutboundQueueFull("outbound_queue_closed")
            evicted = False
            while not self._fits(item) and item.critical and self._remove_first_noncritical():
                evicted = True
            if not self._fits(item):
                raise OutboundQueueFull("outbound_queue_full")
            if evicted:
                self._gap_pending = True
            self._append(item)
            self._condition.notify()

    async def get(self) -> OutboundItem:
        async with self._condition:
            while not self._items and not self._gap_pending:
                if self._closed:
                    raise asyncio.CancelledError
                await self._condition.wait()
            if self._gap_pending:
                self._gap_pending = False
                return self._make_item({"type": "source.gap", "reason": "companion_backpressure"})
            item = self._items.popleft()
            self._bytes -= item.encoded_bytes
            return item

    async def close(self) -> None:
        async with self._condition:
            self._closed = True
            self._condition.notify_all()


class CompanionState:
    """Body-free restart state; commands and event content are never stored."""

    def __init__(self, path: Optional[Path]) -> None:
        self.path = path
        self.last_bridge_event_id = 0
        self.relay_epoch = ""
        self.relay_cursor = 0
        self.load()

    def load(self) -> None:
        if not self.path or not self.path.exists():
            return
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
            self.last_bridge_event_id = max(0, int(value.get("last_bridge_event_id") or 0))
            self.relay_epoch = str(value.get("relay_epoch") or "")
            self.relay_cursor = max(0, int(value.get("relay_cursor") or 0))
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            self.last_bridge_event_id = 0
            self.relay_epoch = ""
            self.relay_cursor = 0

    def save(self) -> None:
        if not self.path:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "last_bridge_event_id": self.last_bridge_event_id,
            "relay_epoch": self.relay_epoch,
            "relay_cursor": self.relay_cursor,
        }
        temporary = self.path.with_suffix(self.path.suffix + ".v2.tmp")
        temporary.write_text(json.dumps(payload, separators=(",", ":")) + "\n", encoding="utf-8")
        os.chmod(temporary, 0o600)
        temporary.replace(self.path)


class LocalBridgeV2Client:
    def __init__(self, session: aiohttp.ClientSession, base_url: str, token: str, timeout: float = 10.0) -> None:
        self.session = session
        self.base_url = base_url.rstrip("/")
        self.headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        self.timeout = aiohttp.ClientTimeout(total=timeout)

    async def _post(self, path: str, body: Dict[str, Any]) -> Dict[str, Any]:
        async with self.session.post(
            self.base_url + path,
            json=body,
            headers=self.headers,
            timeout=self.timeout,
        ) as response:
            response.raise_for_status()
            value = await response.json()
            if not isinstance(value, dict):
                raise ValueError("Bridge response must be an object")
            return value

    async def bind(
        self,
        path: str,
        session_id: str,
        generation: int,
        compatibility: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return await self._post(path, {
            "mac_session_id": session_id,
            "mac_connection_generation": generation,
            "compatibility": dict(compatibility or COMPATIBILITY_SET),
        })

    async def invalidate(self, path: str, session_id: str, generation: int) -> Dict[str, Any]:
        return await self._post(path, {
            "mac_session_id": session_id,
            "mac_connection_generation": generation,
        })

    async def command(self, path: str, command: Dict[str, Any]) -> Dict[str, Any]:
        return await self._post(path, command)

    async def keyframe(self, path: str) -> Dict[str, Any]:
        return await self._post(path, {})

    async def import_upload(self, path: str, body: Dict[str, Any]) -> Dict[str, Any]:
        return await self._post(path, body)


class CommandDispatcher:
    """Generation gate and bounded idempotency cache for live commands."""

    def __init__(self, bridge: LocalBridgeV2Client, path: str, session_id: str, max_results: int = 1024) -> None:
        self.bridge = bridge
        self.path = path
        self.session_id = session_id
        self.generation = 0
        self.max_results = max_results
        self.results: "OrderedDict[str, tuple[str, Dict[str, Any]]]" = OrderedDict()

    def activate(self, generation: int) -> None:
        self.generation = generation
        self.results.clear()

    def deactivate(self, generation: int) -> None:
        if generation == self.generation:
            self.generation = 0
            self.results.clear()

    @staticmethod
    def _fingerprint(command: Mapping[str, Any]) -> str:
        return json.dumps(command, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

    async def dispatch(self, command: Dict[str, Any], connection_generation: int) -> Dict[str, Any]:
        delivery_id = str(command.get("delivery_id") or "")
        if not delivery_id:
            return {"delivery_id": None, "status": "rejected", "error_code": "missing_delivery_id"}
        fingerprint = self._fingerprint(command)
        prior = self.results.get(delivery_id)
        if prior:
            if prior[0] != fingerprint:
                return {"delivery_id": delivery_id, "status": "rejected", "error_code": "delivery_conflict"}
            return {**prior[1], "status": "duplicate"}
        if connection_generation != self.generation or command.get("mac_connection_generation") != self.generation:
            return {"delivery_id": delivery_id, "status": "rejected", "error_code": "stale_connection"}
        if command.get("mac_session_id") != self.session_id:
            return {"delivery_id": delivery_id, "status": "rejected", "error_code": "stale_session"}
        # Recheck after yielding so a disconnect/reconnect cannot leave a queued
        # command eligible for the next generation.
        await asyncio.sleep(0)
        if connection_generation != self.generation:
            return {"delivery_id": delivery_id, "status": "rejected", "error_code": "stale_connection"}
        response = await self.bridge.command(self.path, command)
        result = response.get("result") if isinstance(response.get("result"), dict) else response
        self.results[delivery_id] = (fingerprint, dict(result))
        while len(self.results) > self.max_results:
            self.results.popitem(last=False)
        return dict(result)


class AsyncMacCompanion:
    def __init__(self, config: Any, *, session_factory: Any = aiohttp.ClientSession) -> None:
        self.config = config
        self.session_factory = session_factory
        self.mac_session_id = f"mac-{uuid.uuid4()}"
        self.connection_generation = 0
        state_value = getattr(config, "v2_state_path", "")
        state_path = Path(state_value).expanduser() if state_value else None
        self.state = CompanionState(state_path)
        self.outbound = BoundedOutboundQueue(config.outbound_max_events, config.outbound_max_bytes)
        self.stop_event = asyncio.Event()
        self._ack_waiting: Dict[str, int] = {}

    @classmethod
    def from_config(cls, config: Any) -> "AsyncMacCompanion":
        config.validate()
        return cls(config)

    async def stop(self) -> None:
        self.stop_event.set()

    async def _event_pump(self, sse: BridgeSSEClient, bridge: LocalBridgeV2Client, generation: int) -> None:
        async for message in sse.events(self.state.last_bridge_event_id):
            if generation != self.connection_generation:
                return
            if message.event == "resync":
                await self.outbound.put({"type": "source.gap", "reason": "bridge_retained_gap"})
                await bridge.keyframe(self.config.bridge_keyframe_path)
                continue
            event = message.json()
            try:
                bridge_event_id = int(message.event_id or event.get("source", {}).get("sequence") or 0)
            except (TypeError, ValueError):
                bridge_event_id = 0
            await self.outbound.put(
                {
                    "type": "event.publish",
                    "mac_session_id": self.mac_session_id,
                    "mac_connection_generation": generation,
                    "event": event,
                },
                bridge_event_id=bridge_event_id,
            )

    async def _writer(self, socket: RelayWebSocket, generation: int, hello: Dict[str, Any]) -> None:
        # This task is the sole owner of every Relay write, including the
        # connection hello.  aiohttp requires serialized WebSocket writes.
        await socket.send_json(hello)
        while generation == self.connection_generation:
            item = await self.outbound.get()
            await socket.send_json(item.frame)
            if item.event_uid and item.bridge_event_id:
                self._ack_waiting[item.event_uid] = item.bridge_event_id

    async def _reader(
        self,
        socket: RelayWebSocket,
        bridge: LocalBridgeV2Client,
        generation: int,
        commands: "asyncio.Queue[Dict[str, Any]]",
        uploads: Optional["asyncio.Queue[Dict[str, Any]]"] = None,
    ) -> None:
        while generation == self.connection_generation:
            frame = await socket.receive_json()
            if frame is None:
                return
            frame_type = frame.get("type")
            if frame_type == "keyframe.request":
                await bridge.keyframe(self.config.bridge_keyframe_path)
                continue
            if frame_type == "event.ack":
                uid = str(frame.get("event_uid") or "")
                event_id = self._ack_waiting.pop(uid, 0)
                if event_id:
                    self.state.last_bridge_event_id = max(self.state.last_bridge_event_id, event_id)
                    self.state.relay_epoch = str(frame.get("epoch") or self.state.relay_epoch)
                    self.state.relay_cursor = max(self.state.relay_cursor, int(frame.get("cursor") or 0))
                    self.state.save()
                continue
            if frame_type == "upload.available":
                upload = frame.get("upload") if isinstance(frame.get("upload"), dict) else {}
                if (
                    uploads is None
                    or upload.get("mac_session_id") != self.mac_session_id
                    or upload.get("mac_connection_generation") != generation
                ):
                    if upload.get("upload_id"):
                        await self.outbound.put({
                            "type": "upload.ack",
                            "mac_session_id": self.mac_session_id,
                            "mac_connection_generation": generation,
                            "upload_id": upload.get("upload_id"),
                            "status": "failed",
                            "error_code": "upload_binding_mismatch",
                        })
                    continue
                try:
                    uploads.put_nowait(upload)
                except asyncio.QueueFull:
                    await self.outbound.put({
                        "type": "upload.ack",
                        "mac_session_id": self.mac_session_id,
                        "mac_connection_generation": generation,
                        "upload_id": upload.get("upload_id"),
                        "status": "failed",
                        "error_code": "upload_backpressure",
                    })
                continue
            if frame_type != "command":
                continue
            command = frame.get("command") if isinstance(frame.get("command"), dict) else {}
            try:
                commands.put_nowait(command)
            except asyncio.QueueFull:
                await self.outbound.put({
                    "type": "command.receipt",
                    "mac_session_id": self.mac_session_id,
                    "mac_connection_generation": generation,
                    "receipt": {
                        "delivery_id": command.get("delivery_id"),
                        "status": "rejected",
                        "error_code": "command_backpressure",
                    },
                })

    async def _command_worker(
        self,
        dispatcher: CommandDispatcher,
        generation: int,
        commands: "asyncio.Queue[Dict[str, Any]]",
    ) -> None:
        while generation == self.connection_generation:
            command = await commands.get()
            result = await dispatcher.dispatch(command, generation)
            await self.outbound.put({
                "type": "command.receipt",
                "mac_session_id": self.mac_session_id,
                "mac_connection_generation": generation,
                "receipt": result,
            })

    async def _upload_worker(
        self,
        receiver: UploadReceiver,
        bridge: LocalBridgeV2Client,
        generation: int,
        uploads: "asyncio.Queue[Dict[str, Any]]",
    ) -> None:
        while generation == self.connection_generation:
            upload = await uploads.get()
            upload_id = str(upload.get("upload_id") or "")
            status = "failed"
            result: Dict[str, Any] = {}
            error_code = "upload_import_failed"
            try:
                downloaded = await receiver.download(
                    upload,
                    mac_session_id=self.mac_session_id,
                    mac_connection_generation=generation,
                    is_current=lambda: generation == self.connection_generation,
                )
                response = await bridge.import_upload(
                    self.config.bridge_import_path,
                    {
                        "upload_id": downloaded.upload_id,
                        "temp_path": str(downloaded.path),
                        "display_name": downloaded.display_name,
                        "content_type": downloaded.content_type,
                        "total_bytes": downloaded.total_bytes,
                        "total_sha256": downloaded.sha256,
                        "mac_session_id": self.mac_session_id,
                        "mac_connection_generation": generation,
                    },
                )
                value = response.get("result") if isinstance(response.get("result"), dict) else response
                if not isinstance(value, dict) or not value.get("vault_path"):
                    raise UploadReceiveError("invalid_vault_import_result")
                result = {
                    "vault_path": str(value.get("vault_path")),
                    "kind": str(value.get("kind") or "file"),
                    "label": str(value.get("label") or downloaded.display_name),
                }
                status = "imported"
                error_code = ""
            except asyncio.CancelledError:
                raise
            except UploadReceiveError as exc:
                error_code = exc.code
            except Exception:
                error_code = "upload_import_failed"
            finally:
                if upload_id:
                    await asyncio.shield(receiver.cleanup(upload_id))
            if generation != self.connection_generation:
                return
            await self.outbound.put({
                "type": "upload.ack",
                "mac_session_id": self.mac_session_id,
                "mac_connection_generation": generation,
                "upload_id": upload_id,
                "status": status,
                "result": result,
                "error_code": error_code or None,
            })

    async def run_connection(
        self,
        socket: RelayWebSocket,
        bridge: LocalBridgeV2Client,
        sse: BridgeSSEClient,
        upload_receiver: Optional[UploadReceiver] = None,
    ) -> None:
        self.connection_generation += 1
        generation = self.connection_generation
        dispatcher = CommandDispatcher(bridge, self.config.bridge_command_path, self.mac_session_id)
        dispatcher.activate(generation)
        binding = await bridge.bind(
            self.config.bridge_bind_path,
            self.mac_session_id,
            generation,
            dict(COMPATIBILITY_SET),
        )
        hello = {
            "type": "mac.hello",
            "protocol": "claudian.remote.v2",
            "mac_session_id": self.mac_session_id,
            "mac_connection_generation": generation,
            "last_relay_epoch": self.state.relay_epoch,
            "last_relay_cursor": self.state.relay_cursor,
            "compatibility": dict(COMPATIBILITY_SET),
            "bridge_compatibility": binding.get("compatibility") if isinstance(binding, dict) else None,
        }
        commands: "asyncio.Queue[Dict[str, Any]]" = asyncio.Queue(maxsize=32)
        uploads: "asyncio.Queue[Dict[str, Any]]" = asyncio.Queue(maxsize=1)
        tasks = {
            asyncio.create_task(self._event_pump(sse, bridge, generation), name="bridge-event-pump"),
            asyncio.create_task(
                self._reader(socket, bridge, generation, commands, uploads if upload_receiver else None),
                name="relay-reader",
            ),
            asyncio.create_task(self._command_worker(dispatcher, generation, commands), name="bridge-command-pump"),
            asyncio.create_task(self._writer(socket, generation, hello), name="relay-writer"),
        }
        if upload_receiver is not None:
            tasks.add(asyncio.create_task(
                self._upload_worker(upload_receiver, bridge, generation, uploads),
                name="relay-upload-pump",
            ))
        try:
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                if not task.cancelled() and task.exception():
                    raise task.exception()  # type: ignore[misc]
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
        finally:
            dispatcher.deactivate(generation)
            self._ack_waiting.clear()
            if upload_receiver is not None:
                await asyncio.shield(upload_receiver.cleanup_all())
            with contextlib.suppress(Exception):
                await asyncio.shield(bridge.invalidate(
                    self.config.bridge_invalidate_path,
                    self.mac_session_id,
                    generation,
                ))
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    async def run_forever(self) -> None:
        delay = self.config.reconnect_min_seconds
        async with self.session_factory() as session:
            bridge = LocalBridgeV2Client(
                session,
                self.config.adapter_base_url,
                self.config.adapter_token,
                self.config.request_timeout_seconds,
            )
            sse = BridgeSSEClient(
                session,
                self.config.adapter_base_url,
                self.config.adapter_token,
                self.config.bridge_sse_path,
            )
            relay = RelayWSClient(
                session,
                self.config.resolved_relay_ws_url(),
                self.config.relay_token,
                self.config.relay_heartbeat_seconds,
            )
            upload_receiver = await UploadReceiver(
                session,
                self.config.relay_base_url,
                self.config.relay_token,
                Path(self.config.upload_temp_dir),
                stream_bytes=self.config.upload_stream_bytes,
            ).start()
            while not self.stop_event.is_set():
                socket: Optional[RelayWebSocket] = None
                try:
                    socket = await relay.connect()
                    await self.run_connection(socket, bridge, sse, upload_receiver)
                    delay = self.config.reconnect_min_seconds
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    # Log only the failure type; URLs, bodies, tokens and local
                    # paths are intentionally excluded.
                    print(f"companion_v2_reconnect error_type={type(exc).__name__}")
                finally:
                    if socket:
                        with contextlib.suppress(Exception):
                            await socket.close()
                if not self.stop_event.is_set():
                    try:
                        await asyncio.wait_for(self.stop_event.wait(), timeout=delay)
                    except asyncio.TimeoutError:
                        pass
                    delay = min(self.config.reconnect_max_seconds, max(delay * 2, self.config.reconnect_min_seconds))
            await upload_receiver.cleanup_all()
        await self.outbound.close()
