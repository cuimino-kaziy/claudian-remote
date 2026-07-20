"""Constant-memory Mac download staging for session-bound Relay uploads."""

from __future__ import annotations

import asyncio
import hashlib
import os
import shutil
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict
from urllib.parse import quote

import aiohttp


STREAM_BYTES = 64 * 1024


class UploadReceiveError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class DownloadedUpload:
    upload_id: str
    path: Path
    display_name: str
    content_type: str
    total_bytes: int
    sha256: str


class UploadReceiver:
    def __init__(
        self,
        session: aiohttp.ClientSession,
        relay_base_url: str,
        relay_token: str,
        temp_root: Path,
        *,
        stream_bytes: int = STREAM_BYTES,
    ) -> None:
        self.session = session
        self.relay_base_url = relay_base_url.rstrip("/")
        self.relay_token = relay_token
        self.temp_root = Path(temp_root).expanduser()
        self.stream_bytes = min(max(4096, int(stream_bytes)), STREAM_BYTES)
        self._paths: Dict[str, Path] = {}
        self._lock = asyncio.Lock()

    async def start(self) -> "UploadReceiver":
        await asyncio.to_thread(self._prepare_root)
        return self

    async def download(
        self,
        upload: Dict[str, Any],
        *,
        mac_session_id: str,
        mac_connection_generation: int,
        is_current: Callable[[], bool],
    ) -> DownloadedUpload:
        upload_id = str(upload.get("upload_id") or "")
        try:
            uuid.UUID(upload_id)
        except (ValueError, AttributeError) as exc:
            raise UploadReceiveError("invalid_upload_id") from exc
        total = upload.get("total_bytes")
        if isinstance(total, bool) or not isinstance(total, int) or total < 0:
            raise UploadReceiveError("invalid_upload_size")
        digest = str(upload.get("sha256") or "").lower().removeprefix("sha256:")
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise UploadReceiveError("invalid_upload_hash")
        if not is_current():
            raise UploadReceiveError("stale_upload_connection")

        part = self.temp_root / f"{upload_id}.part"
        ready = self.temp_root / f"{upload_id}.blob"
        async with self._lock:
            await asyncio.to_thread(part.unlink, missing_ok=True)
            await asyncio.to_thread(ready.unlink, missing_ok=True)
            descriptor = await asyncio.to_thread(os.open, part, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            handle = os.fdopen(descriptor, "wb", buffering=0)
            hasher = hashlib.sha256()
            received = 0
            url = self.relay_base_url + "/api/v2/uploads/" + quote(upload_id, safe="") + "/content"
            headers = {
                "Authorization": "Bearer " + self.relay_token,
                "Upload-Session-ID": mac_session_id,
                "Upload-Connection-Generation": str(mac_connection_generation),
                "Accept": "application/octet-stream",
            }
            try:
                async with self.session.get(url, headers=headers, timeout=None) as response:
                    if response.status != 200:
                        raise UploadReceiveError("upload_download_rejected")
                    if response.content_length is not None and response.content_length != total:
                        raise UploadReceiveError("upload_download_size_mismatch")
                    async for chunk in response.content.iter_chunked(self.stream_bytes):
                        if not is_current():
                            raise UploadReceiveError("stale_upload_connection")
                        received += len(chunk)
                        if received > total:
                            raise UploadReceiveError("upload_download_size_mismatch")
                        hasher.update(chunk)
                        if chunk:
                            await asyncio.to_thread(handle.write, chunk)
                if received != total:
                    raise UploadReceiveError("upload_download_size_mismatch")
                if hasher.hexdigest() != digest:
                    raise UploadReceiveError("upload_download_hash_mismatch")
                await asyncio.to_thread(os.fsync, handle.fileno())
                await asyncio.to_thread(handle.close)
                handle = None
                await asyncio.to_thread(os.replace, part, ready)
                await asyncio.to_thread(os.chmod, ready, 0o600)
                self._paths[upload_id] = ready
                return DownloadedUpload(
                    upload_id=upload_id,
                    path=ready,
                    display_name=str(upload.get("display_name") or "upload")[:255],
                    content_type=str(upload.get("content_type") or "application/octet-stream")[:255],
                    total_bytes=total,
                    sha256=digest,
                )
            except asyncio.CancelledError:
                raise
            except UploadReceiveError:
                raise
            except Exception as exc:
                raise UploadReceiveError("upload_download_failed") from exc
            finally:
                if handle is not None:
                    await asyncio.to_thread(handle.close)
                if upload_id not in self._paths:
                    await asyncio.to_thread(part.unlink, missing_ok=True)
                    await asyncio.to_thread(ready.unlink, missing_ok=True)

    async def cleanup(self, upload_id: str) -> None:
        async with self._lock:
            path = self._paths.pop(upload_id, None)
            if path is not None:
                await asyncio.to_thread(path.unlink, missing_ok=True)
            await asyncio.to_thread((self.temp_root / f"{upload_id}.part").unlink, missing_ok=True)

    async def cleanup_all(self) -> None:
        async with self._lock:
            self._paths.clear()
            await asyncio.to_thread(self._remove_contents)

    def _prepare_root(self) -> None:
        self.temp_root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.temp_root, 0o700)
        self._remove_contents()

    def _remove_contents(self) -> None:
        if not self.temp_root.exists():
            return
        for item in self.temp_root.iterdir():
            if item.is_file() or item.is_symlink():
                item.unlink(missing_ok=True)
            elif item.is_dir():
                shutil.rmtree(item)
