"""Incremental SSE decoding and the localhost Bridge event client."""

from __future__ import annotations

import codecs
import json
from dataclasses import dataclass
from typing import Any, AsyncIterator, Dict, List, Optional

import aiohttp


@dataclass(frozen=True)
class SSEMessage:
    event: str
    data: str
    event_id: str = ""
    retry_ms: Optional[int] = None

    def json(self) -> Dict[str, Any]:
        value = json.loads(self.data)
        if not isinstance(value, dict):
            raise ValueError("SSE data must be a JSON object")
        return value


class SSEDecoder:
    """WHATWG-compatible frame decoder for arbitrarily split UTF-8 chunks."""

    def __init__(self) -> None:
        self._decoder = codecs.getincrementaldecoder("utf-8")("strict")
        self._line = ""
        self._skip_lf = False
        self._event = ""
        self._data: List[str] = []
        self._last_event_id = ""
        self._retry_ms: Optional[int] = None

    def feed(self, chunk: bytes) -> List[SSEMessage]:
        return self._feed_text(self._decoder.decode(chunk, final=False))

    def finish(self) -> List[SSEMessage]:
        # An event is dispatched only by a blank line.  An unterminated EOF
        # frame is deliberately discarded so reconnect replay remains exact.
        self._feed_text(self._decoder.decode(b"", final=True))
        self._line = ""
        self._reset_event()
        return []

    def _feed_text(self, text: str) -> List[SSEMessage]:
        output: List[SSEMessage] = []
        for char in text:
            if self._skip_lf:
                self._skip_lf = False
                if char == "\n":
                    continue
            if char == "\r":
                output.extend(self._consume_line())
                self._skip_lf = True
            elif char == "\n":
                output.extend(self._consume_line())
            else:
                self._line += char
        return output

    def _consume_line(self) -> List[SSEMessage]:
        line, self._line = self._line, ""
        if line == "":
            if not self._data:
                self._reset_event()
                return []
            message = SSEMessage(
                event=self._event or "message",
                data="\n".join(self._data),
                event_id=self._last_event_id,
                retry_ms=self._retry_ms,
            )
            self._reset_event()
            return [message]
        if line.startswith(":"):
            return []
        if ":" in line:
            field, value = line.split(":", 1)
            if value.startswith(" "):
                value = value[1:]
        else:
            field, value = line, ""
        if field == "event":
            self._event = value
        elif field == "data":
            self._data.append(value)
        elif field == "id" and "\x00" not in value:
            self._last_event_id = value
        elif field == "retry" and value.isdigit():
            self._retry_ms = int(value)
        return []

    def _reset_event(self) -> None:
        self._event = ""
        self._data = []
        self._retry_ms = None


async def decode_sse(content: Any, chunk_size: int = 4096) -> AsyncIterator[SSEMessage]:
    decoder = SSEDecoder()
    async for chunk in content.iter_chunked(chunk_size):
        for message in decoder.feed(chunk):
            yield message
    decoder.finish()


class BridgeSSEClient:
    def __init__(
        self,
        session: aiohttp.ClientSession,
        base_url: str,
        token: str,
        path: str = "/claudian-remote/v2/events",
        timeout_seconds: float = 45.0,
    ) -> None:
        self.session = session
        self.url = base_url.rstrip("/") + path
        self.token = token
        self.timeout = aiohttp.ClientTimeout(total=None, sock_connect=timeout_seconds, sock_read=None)

    async def events(self, last_event_id: int = 0) -> AsyncIterator[SSEMessage]:
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "text/event-stream",
            "Cache-Control": "no-cache",
        }
        if last_event_id > 0:
            headers["Last-Event-ID"] = str(last_event_id)
        async with self.session.get(self.url, headers=headers, timeout=self.timeout) as response:
            response.raise_for_status()
            content_type = response.headers.get("Content-Type", "")
            if "text/event-stream" not in content_type:
                raise ValueError("Bridge event route did not return text/event-stream")
            async for message in decode_sse(response.content):
                yield message
