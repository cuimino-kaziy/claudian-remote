"""aiohttp REST + WebSocket application for Claudian Remote Relay v2."""

from __future__ import annotations

import asyncio
import contextlib
import json
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Optional

from aiohttp import WSMsgType, web

from gateway.protocol.stream_protocol import ProtocolError, validate_command, validate_event
from gateway.protocol.compatibility import COMPATIBILITY_SET, combine_compatibility
from gateway.relay.auth import AuthError, TicketStore, TokenAuthenticator, origin_allowed
from gateway.relay.event_store import EventStore
from gateway.relay.relay_server import RelayConfig, RelayService, VERSION
from gateway.relay.retention import RetentionCoordinator
from gateway.relay.upload_store import UploadError, UploadStore
from gateway.relay.websocket_hub import SlowConsumer, WebSocketClient, WebSocketHub


CONFIG = web.AppKey("config", RelayConfig)
STORE = web.AppKey("store", EventStore)
AUTH = web.AppKey("auth", TokenAuthenticator)
TICKETS = web.AppKey("tickets", TicketStore)
HUB = web.AppKey("hub", WebSocketHub)
LEGACY = web.AppKey("legacy", RelayService)
PRUNE_TASK = web.AppKey("prune_task", asyncio.Task)
REJECT_COMMANDS = web.AppKey("reject_commands", dict)
UPLOADS = web.AppKey("uploads", UploadStore)
RETENTION = web.AppKey("retention", RetentionCoordinator)


def _error(code: str, status: int = 400) -> web.Response:
    return web.json_response({"ok": False, "error": code}, status=status)


def _bearer(request: web.Request) -> str:
    return request.headers.get("Authorization", "")


def _authenticate(request: web.Request, role: Optional[str]):
    config = request.app[CONFIG]
    return request.app[AUTH].authenticate(
        _bearer(request),
        required_role=role,
        installation_id=config.installation_id,
        vault_id=config.vault_id,
        endpoint_audience=config.endpoint_audience,
    )


def _require_subprotocol(request: web.Request) -> None:
    offered = {item.strip() for item in request.headers.get("Sec-WebSocket-Protocol", "").split(",")}
    if "claudian.remote.v2" not in offered:
        raise web.HTTPBadRequest(text="required WebSocket subprotocol is missing")


def _require_origin(request: web.Request) -> None:
    if not origin_allowed(request.headers.get("Origin"), request.app[CONFIG].allowed_origins):
        raise web.HTTPForbidden(text="origin is not allowed")


def _reject_url_credentials(request: web.Request) -> None:
    forbidden = {"token", "ticket", "authorization", "api_key", "secret"}
    if any(str(key).lower() in forbidden for key in request.query):
        raise web.HTTPBadRequest(text="credentials are forbidden in the URL")


async def health(request: web.Request) -> web.Response:
    try:
        _authenticate(request, "pairing_admin")
    except AuthError as exc:
        return _error(exc.code, 403 if exc.code == "wrong_role" else 401)
    stats = await request.app[STORE].stats()
    upload_stats = await request.app[UPLOADS].stats()
    socket_stats = request.app[HUB].metrics()
    return web.json_response(
        {
            "ok": True,
            "service": "claudian-remote-relay",
            "version": VERSION,
            "protocol": "claudian.remote.v2",
            "epoch": stats["epoch"],
            "event_rows": stats["rows"],
            "event_bytes": stats["bytes"],
            "database_bytes": stats["database_bytes"],
            "wal_bytes": stats["wal_bytes"],
            "checkpoint_busy": stats["checkpoint_busy"],
            "sqlite_version": stats["sqlite_version"],
            "upload_active": upload_stats["active"],
            "upload_bytes": upload_stats["bytes"],
            "upload_disk_free_bytes": upload_stats["disk_free_bytes"],
            "upload_disk_reserve_bytes": upload_stats["disk_reserve_bytes"],
            "stream": socket_stats,
            "retention": request.app[RETENTION].last_result,
            "v1_compatibility": request.app[CONFIG].enable_v1_compatibility,
        }
    )


def _upload_error(exc: UploadError) -> web.Response:
    return _error(exc.code, exc.status)


def _binding(body: Dict[str, Any]) -> tuple[str, int]:
    session_id = str(body.get("mac_session_id") or "")
    generation = body.get("mac_connection_generation")
    if not session_id or isinstance(generation, bool) or not isinstance(generation, int) or generation < 1:
        raise UploadError("invalid_upload_binding")
    return session_id, generation


async def begin_upload(request: web.Request) -> web.Response:
    try:
        principal = _authenticate(request, "mobile")
        body = await request.json()
        if not isinstance(body, dict):
            raise UploadError("invalid_json")
        session_id, generation = _binding(body)
        result = await request.app[HUB].presence.run_for_binding(
            principal.pairing_id,
            session_id,
            generation,
            lambda: request.app[UPLOADS].begin(
                installation_id=principal.installation_id,
                pairing_id=principal.pairing_id,
                mac_session_id=session_id,
                mac_connection_generation=generation,
                display_name=body.get("filename") or body.get("display_name"),
                content_type=body.get("content_type"),
                total_bytes=body.get("total_bytes"),
                sha256=body.get("sha256") or body.get("total_sha256"),
            ),
        )
    except AuthError as exc:
        return _error(exc.code, 403 if exc.code == "wrong_role" else 401)
    except UploadError as exc:
        return _upload_error(exc)
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        code = str(exc) if str(exc) in {"mac_offline", "session_mismatch", "connection_generation_mismatch"} else "invalid_json"
        return _error(code, 409 if code != "invalid_json" else 400)
    return web.json_response(
        {
            "ok": True,
            **result,
            "chunk_bytes": request.app[CONFIG].upload_chunk_bytes,
            "chunk_path": f"/api/v2/uploads/{result['upload_id']}/chunks/{{index}}",
        },
        status=201,
    )


async def append_upload_chunk(request: web.Request) -> web.Response:
    upload_id = request.match_info["upload_id"]
    try:
        principal = _authenticate(request, "mobile")
        session_id = request.headers.get("Upload-Session-ID") or request.headers.get("X-Mac-Session-ID") or ""
        generation = int(request.headers.get("Upload-Connection-Generation") or request.headers.get("X-Mac-Connection-Generation") or "0")
        index = int(request.match_info["index"])
        offset = int(
            request.headers.get("Upload-Offset")
            or request.headers.get("X-Upload-Offset")
            or request.headers.get("X-Chunk-Offset")
            or "-1"
        )
        digest = request.headers.get("Upload-SHA256") or request.headers.get("X-Chunk-SHA256") or ""
        if not await request.app[HUB].presence.binding_matches(principal.pairing_id, session_id, generation):
            raise UploadError("upload_binding_inactive", 409)
        result = await request.app[UPLOADS].append_chunk(
            upload_id,
            pairing_id=principal.pairing_id,
            mac_session_id=session_id,
            mac_connection_generation=generation,
            index=index,
            offset=offset,
            sha256=digest,
            chunks=request.content.iter_chunked(request.app[CONFIG].upload_stream_bytes),
        )
        if not await request.app[HUB].presence.binding_matches(principal.pairing_id, session_id, generation):
            await request.app[UPLOADS].abort(upload_id, principal.pairing_id)
            raise UploadError("upload_binding_inactive", 409)
    except AuthError as exc:
        return _error(exc.code, 403 if exc.code == "wrong_role" else 401)
    except UploadError as exc:
        return _upload_error(exc)
    except (TypeError, ValueError):
        return _error("invalid_chunk_headers", 400)
    return web.json_response({"ok": True, **result})


async def finalize_upload(request: web.Request) -> web.Response:
    upload_id = request.match_info["upload_id"]
    try:
        principal = _authenticate(request, "mobile")
        body = await request.json()
        if not isinstance(body, dict):
            raise UploadError("invalid_json")
        session_id, generation = _binding(body)
        if not await request.app[HUB].presence.binding_matches(principal.pairing_id, session_id, generation):
            raise UploadError("upload_binding_inactive", 409)
        result = await request.app[UPLOADS].finalize(
            upload_id,
            pairing_id=principal.pairing_id,
            mac_session_id=session_id,
            mac_connection_generation=generation,
            sha256=body.get("sha256"),
        )
        routed = await request.app[HUB].presence.route_control_bound(
            principal.pairing_id,
            session_id,
            generation,
            {
                "type": "upload.available",
                "upload": {
                    **result,
                    "download_path": f"/api/v2/uploads/{upload_id}/content",
                },
            },
        )
        if routed.get("status") != "routed":
            await request.app[UPLOADS].abort(upload_id, principal.pairing_id)
            raise UploadError(str(routed.get("status") or "upload_delivery_failed"), 409)
    except AuthError as exc:
        return _error(exc.code, 403 if exc.code == "wrong_role" else 401)
    except UploadError as exc:
        return _upload_error(exc)
    except (json.JSONDecodeError, TypeError, ValueError):
        return _error("invalid_json", 400)
    return web.json_response({"ok": True, "type": "upload.available", **result}, status=202)


async def upload_status(request: web.Request) -> web.Response:
    try:
        principal = _authenticate(request, "mobile")
        result = await request.app[UPLOADS].status(request.match_info["upload_id"], principal.pairing_id)
    except AuthError as exc:
        return _error(exc.code, 403 if exc.code == "wrong_role" else 401)
    except UploadError as exc:
        return _upload_error(exc)
    return web.json_response({"ok": True, **result})


async def cancel_upload(request: web.Request) -> web.Response:
    try:
        principal = _authenticate(request, "mobile")
        removed = await request.app[UPLOADS].abort(request.match_info["upload_id"], principal.pairing_id)
    except AuthError as exc:
        return _error(exc.code, 403 if exc.code == "wrong_role" else 401)
    return web.json_response({"ok": True, "removed": removed})


async def download_upload(request: web.Request) -> web.StreamResponse:
    try:
        principal = _authenticate(request, "mac")
        session_id = request.headers.get("Upload-Session-ID") or request.headers.get("X-Mac-Session-ID") or ""
        generation = int(request.headers.get("Upload-Connection-Generation") or request.headers.get("X-Mac-Connection-Generation") or "0")
        if not await request.app[HUB].presence.binding_matches(principal.pairing_id, session_id, generation):
            raise UploadError("upload_binding_inactive", 409)
        path, metadata = await request.app[UPLOADS].ready_path(
            request.match_info["upload_id"],
            pairing_id=principal.pairing_id,
            mac_session_id=session_id,
            mac_connection_generation=generation,
        )
    except AuthError as exc:
        return _error(exc.code, 403 if exc.code == "wrong_role" else 401)
    except UploadError as exc:
        return _upload_error(exc)
    except (TypeError, ValueError):
        return _error("invalid_upload_binding", 400)

    response = web.StreamResponse(
        status=200,
        headers={
            "Content-Type": "application/octet-stream",
            "Content-Length": str(metadata["total_bytes"]),
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )
    await response.prepare(request)
    try:
        handle = await asyncio.to_thread(open, path, "rb", buffering=0)
        try:
            while True:
                if not await request.app[HUB].presence.binding_matches(principal.pairing_id, session_id, generation):
                    raise ConnectionResetError("upload binding changed")
                chunk = await asyncio.to_thread(handle.read, request.app[CONFIG].upload_stream_bytes)
                if not chunk:
                    break
                await response.write(chunk)
        finally:
            await asyncio.to_thread(handle.close)
        await response.write_eof()
    except (asyncio.CancelledError, ConnectionError):
        await request.app[UPLOADS].abort(request.match_info["upload_id"], principal.pairing_id)
        raise
    return response


async def issue_ticket(request: web.Request) -> web.Response:
    try:
        principal = _authenticate(request, "mobile")
        body = await request.json()
        if not isinstance(body, dict):
            raise TypeError("ticket body must be an object")
        ticket, grant = await request.app[TICKETS].issue(
            principal,
            str(body.get("device_id") or ""),
            str(body.get("client_instance_id") or ""),
        )
    except AuthError as exc:
        return _error(exc.code, 403 if exc.code == "wrong_role" else 401)
    except (json.JSONDecodeError, TypeError):
        return _error("invalid_json")
    return web.json_response(
        {
            "ok": True,
            "ticket": ticket,
            "expires_at": datetime.fromtimestamp(grant.expires_at, timezone.utc).isoformat().replace("+00:00", "Z"),
            "subprotocol": "claudian.remote.v2",
        },
        status=201,
    )


async def submit_command(request: web.Request) -> web.Response:
    """Route a command immediately; commands are never persisted or queued."""
    try:
        principal = _authenticate(request, "mobile")
        body = await request.json()
        if not isinstance(body, dict) or "command" not in body:
            raise TypeError("command envelope is required")
        mobile_compatibility = combine_compatibility(
            body.get("compatibility"),
            {"writable": True, "reason": "ready"},
        )
        raw_command = body.get("command")
        command = dict(validate_command(raw_command or {}, now=datetime.now(timezone.utc)))
    except AuthError as exc:
        return _error(exc.code, 403 if exc.code == "wrong_role" else 401)
    except ProtocolError as exc:
        return _error(exc.code, 400)
    except (json.JSONDecodeError, TypeError, ValueError):
        return _error("invalid_json", 400)

    if request.app[REJECT_COMMANDS]["value"]:
        return _error("relay_shutting_down", 503)
    if mobile_compatibility.get("writable") is not True:
        return web.json_response(
            {
                "ok": False,
                "type": "command.rejected",
                "delivery_id": command["delivery_id"],
                "status": "compatibility_mismatch",
                "remediation": mobile_compatibility.get("remediation") or "Update required components",
            },
            status=409,
        )
    routed = await request.app[HUB].presence.route_command(principal.pairing_id, command)
    status = routed.get("status")
    if status == "routed":
        return web.json_response(
            {"ok": True, "type": "relay.accepted", "delivery_id": command["delivery_id"], **routed},
            status=202,
        )
    return web.json_response(
        {"ok": False, "type": "command.rejected", "delivery_id": command["delivery_id"], **routed},
        status=409 if status in {"mac_offline", "session_mismatch", "connection_generation_mismatch", "compatibility_mismatch"} else 503,
    )


async def mobile_websocket(request: web.Request) -> web.StreamResponse:
    _reject_url_credentials(request)
    _require_subprotocol(request)
    _require_origin(request)
    config = request.app[CONFIG]
    ws = web.WebSocketResponse(
        protocols=("claudian.remote.v2",),
        heartbeat=config.websocket_heartbeat_seconds,
        max_msg_size=config.websocket_max_message_bytes,
        compress=False,
        autoping=True,
    )
    await ws.prepare(request)
    try:
        first = await ws.receive(timeout=config.ticket_auth_timeout_seconds)
        if first.type != WSMsgType.TEXT:
            raise AuthError("ticket_first_frame_required")
        frame = first.json()
        if not isinstance(frame, dict) or frame.get("type") != "authenticate":
            raise AuthError("ticket_first_frame_required")
        grant = await request.app[TICKETS].consume(
            str(frame.get("ticket") or ""),
            role=str(frame.get("role") or ""),
            device_id=str(frame.get("device_id") or ""),
            client_instance_id=str(frame.get("client_instance_id") or ""),
        )
        if grant.installation_id != config.installation_id:
            raise AuthError("wrong_installation")
        if grant.vault_id != config.vault_id:
            raise AuthError("wrong_vault")
        if grant.endpoint_audience != config.endpoint_audience:
            raise AuthError("wrong_audience")
        mobile_compatibility = combine_compatibility(
            frame.get("compatibility"),
            {"writable": True, "reason": "ready"},
        )
    except (AuthError, asyncio.TimeoutError, TypeError, ValueError, json.JSONDecodeError) as exc:
        code = exc.code if isinstance(exc, AuthError) else "ticket_auth_failed"
        await ws.close(code=1008, message=code.encode("utf-8"))
        return ws

    client = WebSocketClient(
        ws,
        grant.pairing_id,
        "mobile",
        max_events=config.client_queue_max_events,
        max_bytes=config.client_queue_max_bytes,
    )
    client.compatibility = mobile_compatibility
    writer = asyncio.create_task(client.writer(), name=f"mobile-writer-{client.connection_id}")
    try:
        client.enqueue_nowait({
            "type": "authenticated",
            "protocol": "claudian.remote.v2",
            "compatibility": mobile_compatibility,
        })
        registration = await request.app[HUB].register_mobile(
            client,
            str(frame.get("epoch") or "") or None,
            max(0, int(frame.get("cursor") or 0)),
        )
        if registration.get("mode") == "reset":
            await request.app[HUB].presence.route_control(
                client.pairing_id,
                {"type": "keyframe.request", "reason": registration.get("reason") or "mobile_reset"},
            )
        snapshot = await request.app[HUB].presence.mac_snapshot(client.pairing_id)
        client.enqueue_nowait(
            {
                "type": "presence.changed",
                "role": "mac",
                "status": "online" if snapshot["online"] else "offline",
                "mac_session_id": snapshot["mac_session_id"],
                "mac_connection_generation": snapshot["connection_generation"],
                "compatibility": snapshot["compatibility"],
            }
        )
        reader = asyncio.create_task(_mobile_receive(request.app, client, ws), name=f"mobile-reader-{client.connection_id}")
        done, pending = await asyncio.wait({reader, writer}, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        for task in done:
            with contextlib.suppress(asyncio.CancelledError, ConnectionError):
                task.result()
    except (SlowConsumer, TypeError, ValueError):
        await client.close(code=1013, reason="slow_consumer_gap")
    finally:
        await request.app[HUB].unregister_mobile(client)
        await client.queue.close(discard=True)
        writer.cancel()
        await asyncio.gather(writer, return_exceptions=True)
        if not ws.closed:
            await ws.close()
    return ws


async def _mobile_receive(app: web.Application, client: WebSocketClient, ws: web.WebSocketResponse) -> None:
    async for message in ws:
        if message.type == WSMsgType.TEXT:
            try:
                frame = message.json()
                if not isinstance(frame, dict):
                    raise ValueError("frame_not_object")
                if frame.get("type") == "command":
                    if client.compatibility.get("writable") is False:
                        client.enqueue_nowait({
                            "type": "command.rejected",
                            "status": "compatibility_mismatch",
                            "remediation": client.compatibility.get("remediation") or "Update required components",
                        })
                        continue
                    if app[REJECT_COMMANDS]["value"]:
                        client.enqueue_nowait({"type": "command.rejected", "status": "relay_shutting_down"})
                        continue
                    command = validate_command(frame.get("command") or {}, now=datetime.now(timezone.utc))
                    routed = await app[HUB].presence.route_command(client.pairing_id, dict(command))
                    response_type = "relay.accepted" if routed.get("status") == "routed" else "command.rejected"
                    client.enqueue_nowait(
                        {"type": response_type, "delivery_id": command["delivery_id"], **routed}
                    )
                elif frame.get("type") == "ping":
                    client.enqueue_nowait({"type": "pong"})
                elif frame.get("type") == "keyframe.request":
                    routed = await app[HUB].presence.route_control(
                        client.pairing_id,
                        {"type": "keyframe.request", "reason": str(frame.get("reason") or "mobile_reset")[:128]},
                    )
                    client.enqueue_nowait({"type": "keyframe.request.accepted", **routed})
                else:
                    client.enqueue_nowait({"type": "protocol.error", "error": "unknown_mobile_frame"})
            except (ProtocolError, TypeError, ValueError, json.JSONDecodeError) as exc:
                code = exc.code if isinstance(exc, ProtocolError) else "invalid_frame"
                client.enqueue_nowait({"type": "protocol.error", "error": code})
        elif message.type in {WSMsgType.CLOSE, WSMsgType.CLOSED, WSMsgType.ERROR}:
            return


async def mac_websocket(request: web.Request) -> web.StreamResponse:
    _reject_url_credentials(request)
    _require_subprotocol(request)
    _require_origin(request)
    try:
        principal = _authenticate(request, "mac")
    except AuthError as exc:
        return _error(exc.code, 403 if exc.code == "wrong_role" else 401)
    config = request.app[CONFIG]
    ws = web.WebSocketResponse(
        protocols=("claudian.remote.v2",),
        heartbeat=config.websocket_heartbeat_seconds,
        max_msg_size=config.websocket_max_message_bytes,
        compress=False,
        autoping=True,
    )
    await ws.prepare(request)
    try:
        first = await ws.receive(timeout=5)
        hello = first.json() if first.type == WSMsgType.TEXT else None
        if not isinstance(hello, dict) or hello.get("type") != "mac.hello":
            raise ValueError("mac_hello_required")
        session_id = str(hello.get("mac_session_id") or "")
        generation = int(hello.get("mac_connection_generation") or 0)
        if not session_id or generation < 1:
            raise ValueError("invalid_mac_hello")
        compatibility = combine_compatibility(
            hello.get("compatibility"), hello.get("bridge_compatibility")
        )
    except (asyncio.TimeoutError, TypeError, ValueError, json.JSONDecodeError):
        await ws.close(code=1008, message=b"invalid_mac_hello")
        return ws

    client = WebSocketClient(
        ws,
        principal.pairing_id,
        "mac",
        max_events=config.client_queue_max_events,
        max_bytes=config.client_queue_max_bytes,
    )
    writer = asyncio.create_task(client.writer(), name=f"mac-writer-{client.connection_id}")
    try:
        await request.app[HUB].register_mac(client, session_id, generation, compatibility)
        await request.app[UPLOADS].abort_except_binding(principal.pairing_id, session_id, generation)
        client.enqueue_nowait({
            "type": "mac.hello.ack",
            "epoch": request.app[STORE].epoch,
            "compatibility": compatibility,
        })
        reader = asyncio.create_task(
            _mac_receive(request.app, client, ws, session_id, generation),
            name=f"mac-reader-{client.connection_id}",
        )
        done, pending = await asyncio.wait({reader, writer}, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        for task in done:
            with contextlib.suppress(asyncio.CancelledError, ConnectionError):
                task.result()
    except (SlowConsumer, TypeError, ValueError):
        await client.close(code=1013, reason="mac_connection_backpressure")
    finally:
        removed = await request.app[HUB].unregister_mac(client)
        if removed:
            await request.app[UPLOADS].abort_binding(principal.pairing_id, session_id, generation)
        await client.queue.close(discard=True)
        writer.cancel()
        await asyncio.gather(writer, return_exceptions=True)
        if not ws.closed:
            await ws.close()
    return ws


async def _mac_receive(
    app: web.Application,
    client: WebSocketClient,
    ws: web.WebSocketResponse,
    session_id: str,
    generation: int,
) -> None:
    async for message in ws:
        if message.type == WSMsgType.TEXT:
            try:
                frame = message.json()
                if not isinstance(frame, dict):
                    raise ValueError("frame_not_object")
                if frame.get("type") == "event.publish":
                    await _commit_mac_event(app, client, frame, session_id, generation)
                elif frame.get("type") == "event.batch":
                    events = frame.get("events") or []
                    if not isinstance(events, list) or len(events) > 64:
                        raise ValueError("invalid_event_batch")
                    for event in events:
                        batch_frame = {
                            "mac_session_id": frame.get("mac_session_id"),
                            "mac_connection_generation": frame.get("mac_connection_generation"),
                            "event": event,
                        }
                        await _commit_mac_event(app, client, batch_frame, session_id, generation)
                elif frame.get("type") in {"command.receipt", "command.result"}:
                    receipt = frame.get("receipt") if isinstance(frame.get("receipt"), dict) else frame.get("result")
                    if not isinstance(receipt, dict):
                        raise ValueError("invalid_command_receipt")
                    await app[HUB].presence.run_if_current(
                        client.pairing_id,
                        client,
                        str(frame.get("mac_session_id") or session_id),
                        int(frame.get("mac_connection_generation") or generation),
                        lambda: app[HUB].broadcast_ephemeral(
                            client.pairing_id, {"type": "command.receipt", "receipt": receipt}
                        ),
                    )
                elif frame.get("type") == "source.gap":
                    await _handle_source_gap(app, client, frame, session_id, generation)
                elif frame.get("type") == "upload.ack":
                    await _handle_upload_ack(app, client, frame, session_id, generation)
                else:
                    client.enqueue_nowait({"type": "protocol.error", "error": "unknown_mac_frame"})
            except (ProtocolError, TypeError, ValueError, json.JSONDecodeError) as exc:
                code = exc.code if isinstance(exc, ProtocolError) else "invalid_frame"
                client.enqueue_nowait({"type": "protocol.error", "error": code})
        elif message.type in {WSMsgType.CLOSE, WSMsgType.CLOSED, WSMsgType.ERROR}:
            return


async def _commit_mac_event(
    app: web.Application,
    client: WebSocketClient,
    frame: Dict[str, Any],
    session_id: str,
    generation: int,
) -> None:
    if frame.get("mac_session_id") != session_id:
        raise ValueError("stale_mac_session")
    if frame.get("mac_connection_generation") != generation:
        raise ValueError("stale_mac_generation")
    event = dict(validate_event(frame.get("event") or {}))
    committed = await app[HUB].presence.run_if_current(
        client.pairing_id,
        client,
        session_id,
        generation,
        lambda: app[STORE].append(client.pairing_id, event),
    )
    client.enqueue_nowait(
        {
            "type": "event.ack",
            "epoch": committed.epoch,
            "cursor": committed.cursor,
            "event_uid": committed.event_uid,
            "duplicate": not committed.inserted,
        }
    )
    if committed.inserted:
        if event["event_type"] in {"turn.completed", "turn.interrupted", "turn.failed"}:
            await app[UPLOADS].mark_terminal(client.pairing_id)
        await app[HUB].broadcast_committed(committed, client.pairing_id)


async def _handle_source_gap(
    app: web.Application,
    client: WebSocketClient,
    frame: Dict[str, Any],
    session_id: str,
    generation: int,
) -> None:
    reason = str(frame.get("reason") or "source_gap")[:128]

    async def recover() -> None:
        await app[HUB].require_reset(client.pairing_id, reason)
        # This is connection-local recovery control, not a user command.  It
        # deliberately bypasses command persistence, revision preconditions,
        # and active-conversation targeting.
        client.enqueue_nowait({"type": "keyframe.request", "reason": reason})

    await app[HUB].presence.run_if_current(
        client.pairing_id,
        client,
        session_id,
        generation,
        recover,
    )


def _safe_vault_result(value: Any) -> Dict[str, str]:
    if not isinstance(value, dict):
        raise ValueError("invalid_upload_result")
    vault_path = str(value.get("vault_path") or "")
    normalized = PurePosixPath(vault_path.replace("\\", "/"))
    if not vault_path or normalized.is_absolute() or ".." in normalized.parts:
        raise ValueError("invalid_vault_path")
    return {
        "vault_path": normalized.as_posix(),
        "kind": str(value.get("kind") or "file")[:64],
        "label": str(value.get("label") or normalized.name)[:255],
    }


async def _handle_upload_ack(
    app: web.Application,
    client: WebSocketClient,
    frame: Dict[str, Any],
    session_id: str,
    generation: int,
) -> None:
    if frame.get("mac_session_id") != session_id or frame.get("mac_connection_generation") != generation:
        raise ValueError("stale_upload_ack")
    upload_id = str(frame.get("upload_id") or "")
    status = str(frame.get("status") or "")
    if not upload_id or status not in {"imported", "failed"}:
        raise ValueError("invalid_upload_ack")
    result = _safe_vault_result(frame.get("result")) if status == "imported" else {}

    async def acknowledge() -> None:
        acknowledged = await app[UPLOADS].acknowledge(
            upload_id,
            pairing_id=client.pairing_id,
            mac_session_id=session_id,
            mac_connection_generation=generation,
        )
        if acknowledged.get("duplicate"):
            return
        await app[HUB].broadcast_ephemeral(
            client.pairing_id,
            {
                "type": "upload.imported" if status == "imported" else "upload.failed",
                "upload_id": upload_id,
                "result": result,
                "error_code": None if status == "imported" else str(frame.get("error_code") or "import_failed")[:128],
            },
        )

    await app[HUB].presence.run_if_current(
        client.pairing_id,
        client,
        session_id,
        generation,
        acknowledge,
    )


def _legacy_enabled(request: web.Request) -> Optional[web.Response]:
    if not request.app[CONFIG].enable_v1_compatibility:
        return _error("v1_compatibility_disabled", 410)
    return None


async def legacy_join(request: web.Request) -> web.Response:
    if disabled := _legacy_enabled(request):
        return disabled
    try:
        token = _authenticate(request, None)
    except AuthError as exc:
        return _error(exc.code, 401)
    body = await request.json()
    result = await asyncio.to_thread(request.app[LEGACY].join, token, str(body.get("session_id") or "") or None)
    return web.json_response(result)


async def legacy_heartbeat(request: web.Request) -> web.Response:
    if disabled := _legacy_enabled(request):
        return disabled
    try:
        token = _authenticate(request, None)
    except AuthError as exc:
        return _error(exc.code, 401)
    return web.json_response(await asyncio.to_thread(request.app[LEGACY].heartbeat, token))


async def legacy_submit(request: web.Request) -> web.Response:
    if disabled := _legacy_enabled(request):
        return disabled
    try:
        token = _authenticate(request, None)
    except AuthError as exc:
        return _error(exc.code, 401)
    status, result = await asyncio.to_thread(request.app[LEGACY].submit, token, await request.json())
    return web.json_response(result, status=status)


async def legacy_poll(request: web.Request) -> web.Response:
    if disabled := _legacy_enabled(request):
        return disabled
    try:
        token = _authenticate(request, None)
    except AuthError as exc:
        return _error(exc.code, 401)
    try:
        since = int(request.query.get("since", "0"))
        timeout = float(request.query.get("timeout", "0"))
    except ValueError:
        return _error("invalid_cursor")
    result = await asyncio.to_thread(request.app[LEGACY].poll, token, since, timeout)
    return web.json_response(result)


async def _prune_loop(app: web.Application) -> None:
    while True:
        await asyncio.sleep(60)
        await app[RETENTION].run_once()


async def _startup(app: web.Application) -> None:
    config = app[CONFIG]
    store = EventStore(
        Path(config.database_path),
        retention_seconds=config.retention_seconds,
        completed_grace_seconds=config.completed_grace_seconds,
        max_bytes=config.event_store_max_bytes,
        max_rows=config.event_store_max_rows,
    )
    await store.start()
    uploads = UploadStore(
        Path(config.upload_root),
        ttl_seconds=config.upload_ttl_seconds,
        terminal_ttl_seconds=config.upload_ttl_seconds,
        absolute_ttl_seconds=config.upload_absolute_seconds,
        max_file_bytes=config.upload_max_file_bytes,
        max_outstanding_bytes_per_installation=config.upload_max_outstanding_bytes_per_installation,
        max_concurrent_uploads=config.upload_max_concurrent,
        managed_volume_refusal_percent=config.managed_volume_refusal_percent,
        max_chunk_bytes=config.upload_chunk_bytes,
        stream_bytes=config.upload_stream_bytes,
        reserve_min_bytes=config.upload_reserve_min_bytes,
        reserve_fraction=config.upload_reserve_fraction,
    )
    await uploads.start()
    app[STORE] = store
    app[UPLOADS] = uploads
    app[RETENTION] = RetentionCoordinator(store, uploads)
    app[AUTH] = TokenAuthenticator(config.tokens)
    app[TICKETS] = TicketStore(config.ticket_ttl_seconds)
    app[HUB] = WebSocketHub(store)
    app[LEGACY] = RelayService(config)
    app[REJECT_COMMANDS] = {"value": False}
    app[PRUNE_TASK] = asyncio.create_task(_prune_loop(app), name="relay-prune")


async def _shutdown(app: web.Application) -> None:
    app[REJECT_COMMANDS]["value"] = True
    await app[HUB].close_all()


async def _cleanup(app: web.Application) -> None:
    task = app[PRUNE_TASK]
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    await app[UPLOADS].close()
    await app[STORE].close()


def create_app(config: RelayConfig) -> web.Application:
    app = web.Application(client_max_size=max(config.websocket_max_message_bytes, config.upload_chunk_bytes))
    app[CONFIG] = config
    app.add_routes(
        [
            web.get("/health", health),
            web.post("/api/v2/ws-ticket", issue_ticket),
            web.post("/api/v2/commands", submit_command),
            web.post("/api/v2/uploads", begin_upload),
            web.put("/api/v2/uploads/{upload_id}/chunks/{index}", append_upload_chunk),
            web.post("/api/v2/uploads/{upload_id}/finalize", finalize_upload),
            web.get("/api/v2/uploads/{upload_id}/status", upload_status),
            web.delete("/api/v2/uploads/{upload_id}", cancel_upload),
            web.get("/api/v2/uploads/{upload_id}/content", download_upload),
            web.get("/api/v2/ws/mobile", mobile_websocket),
            web.get("/api/v2/ws/mac", mac_websocket),
            web.post("/api/session/join", legacy_join),
            web.post("/api/session/heartbeat", legacy_heartbeat),
            web.post("/api/envelopes", legacy_submit),
            web.get("/api/events", legacy_poll),
        ]
    )
    app.on_startup.append(_startup)
    app.on_shutdown.append(_shutdown)
    app.on_cleanup.append(_cleanup)
    return app


def run_relay(config: RelayConfig) -> None:
    if config.host not in {"127.0.0.1", "::1", "localhost"}:
        raise ValueError("relay_must_bind_loopback")
    web.run_app(
        create_app(config),
        host=config.host,
        port=config.port,
        access_log=None,
        print=lambda message: print(str(message).replace(config.public_base_url, "<public-relay>")),
    )
