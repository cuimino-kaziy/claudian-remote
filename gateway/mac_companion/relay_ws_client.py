"""Authenticated Relay WebSocket transport for the Mac Companion."""

from __future__ import annotations

from typing import Any, Dict, Optional

import aiohttp


class RelayWebSocket:
    def __init__(self, socket: aiohttp.ClientWebSocketResponse) -> None:
        self.socket = socket

    async def receive_json(self) -> Optional[Dict[str, Any]]:
        message = await self.socket.receive()
        if message.type == aiohttp.WSMsgType.TEXT:
            value = message.json()
            if not isinstance(value, dict):
                raise ValueError("Relay frame must be a JSON object")
            return value
        if message.type == aiohttp.WSMsgType.BINARY:
            raise ValueError("binary Relay frames are not supported")
        if message.type in {aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.CLOSING}:
            return None
        if message.type == aiohttp.WSMsgType.ERROR:
            raise self.socket.exception() or ConnectionError("Relay WebSocket error")
        return {}

    async def send_json(self, frame: Dict[str, Any]) -> None:
        await self.socket.send_json(frame)

    async def close(self) -> None:
        await self.socket.close()


class RelayWSClient:
    def __init__(
        self,
        session: aiohttp.ClientSession,
        url: str,
        token: str,
        heartbeat_seconds: float = 20.0,
    ) -> None:
        self.session = session
        self.url = url
        self.token = token
        self.heartbeat_seconds = heartbeat_seconds

    async def connect(self) -> RelayWebSocket:
        socket = await self.session.ws_connect(
            self.url,
            headers={"Authorization": f"Bearer {self.token}"},
            protocols=("claudian.remote.v2",),
            heartbeat=self.heartbeat_seconds,
            max_msg_size=256 * 1024,
            autoclose=True,
        )
        if socket.protocol != "claudian.remote.v2":
            await socket.close()
            raise ConnectionError("Relay did not negotiate claudian.remote.v2")
        return RelayWebSocket(socket)
