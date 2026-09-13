"""Authenticated loopback WebSocket owned by the Mac Companion.

The browser-style Obsidian client cannot attach an Authorization header to a
WebSocket upgrade.  The upgrade therefore uses one fixed, non-secret
subprotocol followed by a nonce/HMAC exchange.  Nothing is disclosed before
authentication except the random challenge.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import inspect
import ipaddress
import json
import math
import re
import secrets
from dataclasses import dataclass
from typing import Any, AsyncIterator, Awaitable, Callable, Dict, Mapping, Optional

from aiohttp import WSMsgType, web


BRIDGE_SUBPROTOCOL = "claudian.remote.bridge.v1"
BRIDGE_HOST = "127.0.0.1"
BRIDGE_PORT = 27125
MAX_BRIDGE_FRAME_BYTES = 1024 * 1024
MAX_INFLIGHT_MANAGEMENT = 8
SAFE_ERROR_CODE = re.compile(r"^[a-z][a-z0-9_]{2,63}$")


class BridgeServerError(RuntimeError):
    pass


@dataclass(frozen=True)
class BridgeIdentity:
    credential_id: str
    secret: str


class BridgeIdentityStore:
    """Injectable lifecycle-owned identity store; tests never touch Keychain."""

    def __init__(self) -> None:
        self._secrets: Dict[str, str] = {}
        self._revoked = set()

    def issue(self, credential_id: str = "", secret: str = "") -> BridgeIdentity:
        identifier = credential_id or f"bridge-{secrets.token_urlsafe(12)}"
        value = secret or secrets.token_urlsafe(32)
        if not identifier or not value:
            raise BridgeServerError("bridge_identity_invalid")
        self._secrets[identifier] = value
        self._revoked.discard(identifier)
        return BridgeIdentity(identifier, value)

    def revoke(self, credential_id: str) -> None:
        self._revoked.add(str(credential_id))

    def verify(self, credential_id: str, nonce: str, proof: str) -> bool:
        identifier = str(credential_id or "")
        secret = self._secrets.get(identifier)
        if not secret or identifier in self._revoked:
            return False
        expected = bridge_auth_proof(secret, nonce)
        return hmac.compare_digest(expected, str(proof or ""))


class BridgeBootstrapStore:
    """Single-use bootstrap abstraction populated by the lifecycle manager."""

    def __init__(self, identities: Optional[BridgeIdentityStore] = None) -> None:
        self._claims: Dict[str, Dict[str, Any]] = {}
        self.identities = identities or BridgeIdentityStore()

    def create(self, *, confirmed: bool = False) -> str:
        claim = secrets.token_urlsafe(24)
        self._claims[claim] = {"confirmed": bool(confirmed), "used": False}
        return claim

    def confirm(self, claim: str) -> None:
        value = self._claims.get(str(claim))
        if not value or value["used"]:
            raise BridgeServerError("bridge_bootstrap_unknown")
        value["confirmed"] = True

    def consume(self, claim: str) -> BridgeIdentity:
        value = self._claims.get(str(claim))
        if not value:
            raise BridgeServerError("bridge_bootstrap_unknown")
        if value["used"]:
            raise BridgeServerError("bridge_bootstrap_used")
        if not value["confirmed"]:
            raise BridgeServerError("bridge_bootstrap_not_confirmed")
        value["used"] = True
        return self.identities.issue()


def bridge_auth_proof(secret: str, nonce: str) -> str:
    import base64

    digest = hmac.new(
        str(secret).encode("utf-8"),
        f"claudian-remote-bridge:{nonce}".encode("utf-8"),
        hashlib.sha256,
    ).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


@dataclass(frozen=True)
class BridgeEventMessage:
    event: str
    data: str
    event_id: str

    def json(self) -> Dict[str, Any]:
        value = json.loads(self.data)
        if not isinstance(value, dict):
            raise ValueError("bridge_event_must_be_object")
        return value


class CompanionBridgeServer:
    def __init__(
        self,
        *,
        host: str = BRIDGE_HOST,
        port: int = BRIDGE_PORT,
        identities: BridgeIdentityStore,
        management_handler: Optional[
            Callable[[str, Mapping[str, Any]], Awaitable[Mapping[str, Any]]]
        ] = None,
        authenticated_handler: Optional[Callable[[str], Any]] = None,
        auth_timeout_seconds: float = 5.0,
        request_timeout_seconds: float = 30.0,
    ) -> None:
        try:
            address = ipaddress.ip_address(host)
        except ValueError as exc:
            raise BridgeServerError("bridge_non_loopback_forbidden") from exc
        if not address.is_loopback:
            raise BridgeServerError("bridge_non_loopback_forbidden")
        if int(port) != BRIDGE_PORT:
            raise BridgeServerError("bridge_fixed_port_required")
        self.host = str(address)
        self.port = int(port)
        self.identities = identities
        self.management_handler = management_handler
        self.authenticated_handler = authenticated_handler
        self.auth_timeout_seconds = auth_timeout_seconds
        timeout = float(request_timeout_seconds)
        if not math.isfinite(timeout) or timeout <= 0 or timeout > 300:
            raise BridgeServerError("bridge_request_timeout_invalid")
        self.request_timeout_seconds = timeout
        self._socket: Optional[web.WebSocketResponse] = None
        self._generation = 0
        self._pending: Dict[str, asyncio.Future] = {}
        self._events: "asyncio.Queue[BridgeEventMessage]" = asyncio.Queue(maxsize=512)
        self._runner: Optional[web.AppRunner] = None
        self._transport_bound = False

    def create_app(self) -> web.Application:
        app = web.Application(client_max_size=MAX_BRIDGE_FRAME_BYTES)
        app.router.add_get("/bridge", self._handle_websocket)
        return app

    async def start(self) -> None:
        if self._runner:
            return
        runner = web.AppRunner(self.create_app())
        await runner.setup()
        try:
            await web.TCPSite(runner, self.host, self.port).start()
        except OSError as exc:
            await runner.cleanup()
            raise BridgeServerError("bridge_port_conflict") from exc
        self._runner = runner

    async def close(self) -> None:
        if self._socket and not self._socket.closed:
            await self._socket.close(code=1001, message=b"bridge shutdown")
        self._fail_pending("bridge_disconnected")
        if self._runner:
            await self._runner.cleanup()
            self._runner = None

    def _fail_pending(self, code: str) -> None:
        for future in list(self._pending.values()):
            if not future.done():
                future.set_exception(BridgeServerError(code))
        self._pending.clear()

    async def _reject(self, socket: web.WebSocketResponse) -> web.WebSocketResponse:
        await socket.send_json({"type": "auth.rejected", "error_code": "bridge_auth_failed"})
        await socket.close(code=1008, message=b"authentication failed")
        return socket

    async def _handle_websocket(self, request: web.Request) -> web.StreamResponse:
        socket = web.WebSocketResponse(protocols=[BRIDGE_SUBPROTOCOL], max_msg_size=MAX_BRIDGE_FRAME_BYTES)
        await socket.prepare(request)
        if socket.ws_protocol != BRIDGE_SUBPROTOCOL:
            return await self._reject(socket)
        nonce = secrets.token_urlsafe(32)
        await socket.send_json({"type": "auth.challenge", "nonce": nonce})
        try:
            incoming = await asyncio.wait_for(socket.receive(), timeout=self.auth_timeout_seconds)
        except asyncio.TimeoutError:
            return await self._reject(socket)
        if incoming.type != WSMsgType.TEXT:
            return await self._reject(socket)
        try:
            frame = json.loads(incoming.data)
        except (TypeError, json.JSONDecodeError):
            return await self._reject(socket)
        valid = (
            isinstance(frame, dict)
            and frame.get("type") == "auth.response"
            and frame.get("nonce") == nonce
            and self.identities.verify(frame.get("credential_id", ""), nonce, frame.get("proof", ""))
        )
        if not valid:
            return await self._reject(socket)
        if self.authenticated_handler is not None:
            try:
                acknowledged = self.authenticated_handler(str(frame.get("credential_id") or ""))
                if inspect.isawaitable(acknowledged):
                    await acknowledged
            except Exception:
                return await self._reject(socket)

        previous = self._socket
        self._generation += 1
        generation = self._generation
        if previous and previous is not socket:
            self._fail_pending("bridge_generation_changed")
        self._socket = socket
        if previous and previous is not socket and not previous.closed:
            await previous.close(code=1008, message=b"bridge replaced")
        await socket.send_json({"type": "auth.accepted", "generation": generation})
        recovery_task = None
        management_tasks: set[asyncio.Task[None]] = set()
        if self._transport_bound:
            recovery_task = asyncio.create_task(
                self._request("keyframe.request", {}), name="bridge-reconnect-keyframe"
            )
        try:
            async for message in socket:
                if message.type != WSMsgType.TEXT:
                    if message.type in (WSMsgType.CLOSE, WSMsgType.CLOSED, WSMsgType.ERROR):
                        break
                    continue
                try:
                    value = json.loads(message.data)
                except (TypeError, json.JSONDecodeError):
                    continue
                if not isinstance(value, dict):
                    continue
                if value.get("type") == "response":
                    future = self._pending.pop(str(value.get("request_id") or ""), None)
                    if future and not future.done():
                        if value.get("ok") is True:
                            future.set_result(value.get("result") if isinstance(value.get("result"), dict) else {})
                        else:
                            future.set_exception(BridgeServerError(str(value.get("error_code") or "bridge_operation_failed")))
                elif value.get("type") == "event.publish" and isinstance(value.get("event"), dict):
                    event = value["event"]
                    source = event.get("source") if isinstance(event.get("source"), dict) else {}
                    sequence = source.get("sequence")
                    if isinstance(sequence, int) and sequence > 0:
                        item = BridgeEventMessage("semantic", json.dumps(event, ensure_ascii=False), str(sequence))
                        try:
                            self._events.put_nowait(item)
                        except asyncio.QueueFull:
                            # Never hide local loss. Drop the stale retained
                            # window and publish one marker that makes the Relay
                            # pump request an authoritative Keyframe.
                            while not self._events.empty():
                                try:
                                    self._events.get_nowait()
                                except asyncio.QueueEmpty:
                                    break
                            self._events.put_nowait(BridgeEventMessage("resync", "{}", ""))
                elif value.get("type") == "management.request" and value.get("request_id"):
                    request_id = str(value["request_id"])
                    if len(management_tasks) >= MAX_INFLIGHT_MANAGEMENT:
                        await socket.send_json({
                            "type": "management.response",
                            "request_id": request_id,
                            "ok": False,
                            "error_code": "management_backpressure",
                        })
                        continue
                    task = asyncio.create_task(
                        self._serve_management(
                            socket,
                            request_id,
                            str(value.get("operation") or ""),
                            value.get("payload") if isinstance(value.get("payload"), dict) else {},
                        ),
                        name=f"bridge-management-{request_id}",
                    )
                    management_tasks.add(task)
                    task.add_done_callback(management_tasks.discard)
        finally:
            if recovery_task and not recovery_task.done():
                recovery_task.cancel()
            if recovery_task:
                await asyncio.gather(recovery_task, return_exceptions=True)
            for task in management_tasks:
                task.cancel()
            await asyncio.gather(*management_tasks, return_exceptions=True)
            if self._socket is socket:
                self._socket = None
                self._fail_pending("bridge_disconnected")
        return socket

    async def _serve_management(
        self,
        socket: web.WebSocketResponse,
        request_id: str,
        operation: str,
        payload: Mapping[str, Any],
    ) -> None:
        try:
            result = await self._handle_management(operation, payload)
            response: dict[str, Any] = {
                "type": "management.response",
                "request_id": request_id,
                "ok": True,
                "result": result,
            }
        except Exception as exc:
            candidate = str(exc)
            response = {
                "type": "management.response",
                "request_id": request_id,
                "ok": False,
                "error_code": (
                    candidate
                    if SAFE_ERROR_CODE.fullmatch(candidate)
                    else "management_operation_failed"
                ),
            }
        if not socket.closed:
            await socket.send_json(response)

    async def _handle_management(
        self,
        operation: str,
        payload: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        if self.management_handler is None:
            raise BridgeServerError("management_operation_forbidden")
        if not str(operation).startswith("pairing."):
            raise BridgeServerError("management_operation_forbidden")
        return await self.management_handler(str(operation), dict(payload))

    async def _request(self, operation: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        socket = self._socket
        if not socket or socket.closed:
            raise BridgeServerError("bridge_offline")
        request_id = f"request-{secrets.token_urlsafe(12)}"
        future = asyncio.get_running_loop().create_future()
        self._pending[request_id] = future
        try:
            await socket.send_json({
                "type": "request", "request_id": request_id,
                "operation": operation, "payload": payload,
            })
            try:
                return await asyncio.wait_for(future, timeout=self.request_timeout_seconds)
            except asyncio.TimeoutError:
                raise BridgeServerError("bridge_request_timeout") from None
        finally:
            self._pending.pop(request_id, None)

    async def bind(self, _path: str, session_id: str, generation: int, compatibility=None) -> Dict[str, Any]:
        result = await self._request("transport.bind", {
            "mac_session_id": session_id,
            "mac_connection_generation": generation,
            "compatibility": dict(compatibility or {}),
        })
        self._transport_bound = True
        return result

    async def invalidate(self, _path: str, session_id: str, generation: int) -> Dict[str, Any]:
        self._transport_bound = False
        return await self._request("transport.invalidate", {
            "mac_session_id": session_id,
            "mac_connection_generation": generation,
        })

    async def command(self, _path: str, command: Dict[str, Any]) -> Dict[str, Any]:
        return await self._request("command.execute", command)

    async def keyframe(self, _path: str) -> Dict[str, Any]:
        return await self._request("keyframe.request", {})

    async def import_upload(self, _path: str, body: Dict[str, Any]) -> Dict[str, Any]:
        return await self._request("upload.import", body)

    async def cutover(self, session_id: str, generation: int, compatibility=None, *, rollback: bool = False) -> Dict[str, Any]:
        return await self._request("transport.rollback" if rollback else "transport.cutover", {
            "mac_session_id": session_id,
            "mac_connection_generation": generation,
            "compatibility": dict(compatibility or {}),
        })

    async def events(self, _last_event_id: int = 0) -> AsyncIterator[BridgeEventMessage]:
        while True:
            yield await self._events.get()
