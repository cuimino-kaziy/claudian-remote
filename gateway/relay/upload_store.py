"""Session-bound, constant-memory temporary upload storage."""

from __future__ import annotations

import asyncio
import hashlib
import os
import re
import shutil
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, AsyncIterable, Callable, Dict, Optional


MIB = 1024 * 1024
GIB = 1024 * MIB
STREAM_BYTES = 64 * 1024


class UploadError(RuntimeError):
    def __init__(self, code: str, status: int = 400) -> None:
        super().__init__(code)
        self.code = code
        self.status = status


@dataclass(frozen=True)
class ChunkRecord:
    index: int
    offset: int
    size: int
    sha256: str


@dataclass
class UploadSession:
    upload_id: str
    pairing_id: str
    mac_session_id: str
    mac_connection_generation: int
    display_name: str
    content_type: str
    total_bytes: int
    sha256: str
    part_path: Path
    ready_path: Path
    created_at: float
    updated_at: float
    received_bytes: int = 0
    next_index: int = 0
    state: str = "uploading"
    chunks: Dict[int, ChunkRecord] = field(default_factory=dict)

    def public(self) -> Dict[str, Any]:
        return {
            "upload_id": self.upload_id,
            "display_name": self.display_name,
            "content_type": self.content_type,
            "total_bytes": self.total_bytes,
            "sha256": self.sha256,
            "received_bytes": self.received_bytes,
            "next_offset": self.received_bytes,
            "next_index": self.next_index,
            "state": self.state,
            "mac_session_id": self.mac_session_id,
            "mac_connection_generation": self.mac_connection_generation,
        }


@dataclass(frozen=True)
class AcknowledgedUpload:
    pairing_id: str
    mac_session_id: str
    mac_connection_generation: int
    expires_at: float


def normalize_sha256(value: Any) -> str:
    digest = str(value or "").lower()
    if digest.startswith("sha256:"):
        digest = digest[7:]
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise UploadError("invalid_sha256")
    return digest


def safe_display_name(value: Any) -> str:
    # User metadata never contributes to a real path.  Keep only a printable
    # basename so the UI can display the original intent safely.
    name = str(value or "").replace("\\", "/").rsplit("/", 1)[-1]
    name = "".join(char for char in name if char >= " " and char != "\x7f").strip()
    if name in {"", ".", ".."}:
        raise UploadError("invalid_filename")
    return name[:255]


class UploadStore:
    def __init__(
        self,
        root: Path,
        *,
        ttl_seconds: float = 30 * 60,
        max_chunk_bytes: int = MIB,
        stream_bytes: int = STREAM_BYTES,
        reserve_min_bytes: int = GIB,
        reserve_fraction: float = 0.10,
        clock: Callable[[], float] = time.time,
        disk_usage: Callable[[Path], Any] = shutil.disk_usage,
    ) -> None:
        self.root = Path(root)
        self.ttl_seconds = ttl_seconds
        self.max_chunk_bytes = min(max(1, int(max_chunk_bytes)), MIB)
        self.stream_bytes = min(max(4096, int(stream_bytes)), STREAM_BYTES)
        self.reserve_min_bytes = max(0, int(reserve_min_bytes))
        self.reserve_fraction = max(0.0, min(float(reserve_fraction), 0.90))
        self.clock = clock
        self.disk_usage = disk_usage
        self._sessions: Dict[str, UploadSession] = {}
        self._active_by_pairing: Dict[str, str] = {}
        self._acknowledged: Dict[str, AcknowledgedUpload] = {}
        self._lock = asyncio.Lock()

    async def start(self) -> "UploadStore":
        await asyncio.to_thread(self._prepare_root_and_remove_orphans)
        return self

    async def close(self) -> None:
        async with self._lock:
            sessions = list(self._sessions.values())
            self._sessions.clear()
            self._active_by_pairing.clear()
            self._acknowledged.clear()
        await asyncio.gather(*(asyncio.to_thread(self._delete_files, item) for item in sessions))

    async def begin(
        self,
        *,
        pairing_id: str,
        mac_session_id: str,
        mac_connection_generation: int,
        display_name: Any,
        content_type: Any,
        total_bytes: Any,
        sha256: Any,
    ) -> Dict[str, Any]:
        if not pairing_id or not mac_session_id or mac_connection_generation < 1:
            raise UploadError("invalid_upload_binding")
        if isinstance(total_bytes, bool) or not isinstance(total_bytes, int) or total_bytes < 0:
            raise UploadError("invalid_total_bytes")
        name = safe_display_name(display_name)
        digest = normalize_sha256(sha256)
        mime = str(content_type or "application/octet-stream")[:255]
        async with self._lock:
            await self._cleanup_expired_locked(self.clock())
            if pairing_id in self._active_by_pairing:
                raise UploadError("upload_already_active", 409)
            await asyncio.to_thread(self._assert_disk_space, total_bytes)
            upload_id = str(uuid.uuid4())
            session = UploadSession(
                upload_id=upload_id,
                pairing_id=pairing_id,
                mac_session_id=mac_session_id,
                mac_connection_generation=mac_connection_generation,
                display_name=name,
                content_type=mime,
                total_bytes=total_bytes,
                sha256=digest,
                part_path=self.root / f"{upload_id}.part",
                ready_path=self.root / f"{upload_id}.blob",
                created_at=self.clock(),
                updated_at=self.clock(),
            )
            await asyncio.to_thread(self._create_part, session.part_path)
            self._sessions[upload_id] = session
            self._active_by_pairing[pairing_id] = upload_id
            return session.public()

    async def append_chunk(
        self,
        upload_id: str,
        *,
        pairing_id: str,
        mac_session_id: str,
        mac_connection_generation: int,
        index: int,
        offset: int,
        sha256: Any,
        chunks: AsyncIterable[bytes],
    ) -> Dict[str, Any]:
        digest = normalize_sha256(sha256)
        async with self._lock:
            session = self._require(upload_id, pairing_id, mac_session_id, mac_connection_generation)
            if session.state != "uploading":
                raise UploadError("upload_not_writable", 409)
            if isinstance(index, bool) or not isinstance(index, int) or index < 0:
                raise UploadError("invalid_chunk_index")
            if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
                raise UploadError("invalid_chunk_offset")

            prior = session.chunks.get(index)
            duplicate = prior is not None
            if prior and (prior.offset != offset or prior.sha256 != digest):
                await self._fail_locked(session)
                raise UploadError("chunk_conflict", 409)
            if not prior and (index != session.next_index or offset != session.received_bytes):
                raise UploadError("upload_offset_mismatch", 409)

            remaining = max(0, session.total_bytes - session.received_bytes)
            if not duplicate:
                try:
                    await asyncio.to_thread(self._assert_disk_space, min(self.max_chunk_bytes, remaining))
                except UploadError:
                    await self._fail_locked(session)
                    raise
            hasher = hashlib.sha256()
            count = 0
            handle = None
            try:
                if not duplicate:
                    handle = await asyncio.to_thread(open, session.part_path, "r+b", buffering=0)
                    await asyncio.to_thread(handle.seek, offset)
                async for raw in chunks:
                    data = bytes(raw)
                    count += len(data)
                    if count > self.max_chunk_bytes or (not duplicate and offset + count > session.total_bytes):
                        raise UploadError("chunk_too_large", 413)
                    hasher.update(data)
                    if handle is not None and data:
                        await asyncio.to_thread(handle.write, data)
                if hasher.hexdigest() != digest:
                    raise UploadError("chunk_hash_mismatch", 422)
                if duplicate:
                    if prior is None or prior.size != count:
                        raise UploadError("chunk_conflict", 409)
                    session.updated_at = self.clock()
                    return {**session.public(), "duplicate": True}
                if count == 0 and session.total_bytes != 0:
                    raise UploadError("empty_chunk", 422)
                if handle is not None:
                    await asyncio.to_thread(os.fsync, handle.fileno())
                record = ChunkRecord(index, offset, count, digest)
                session.chunks[index] = record
                session.received_bytes += count
                session.next_index += 1
                session.updated_at = self.clock()
                return {**session.public(), "duplicate": False}
            except UploadError:
                # A body/hash/size conflict makes this upload unsafe.  A pure
                # cursor mismatch was rejected before touching the file.
                await self._fail_locked(session)
                raise
            except Exception as exc:
                await self._fail_locked(session)
                raise UploadError("upload_write_failed", 500) from exc
            finally:
                if handle is not None:
                    await asyncio.to_thread(handle.close)

    async def finalize(
        self,
        upload_id: str,
        *,
        pairing_id: str,
        mac_session_id: str,
        mac_connection_generation: int,
        sha256: Any,
    ) -> Dict[str, Any]:
        async with self._lock:
            session = self._require(upload_id, pairing_id, mac_session_id, mac_connection_generation)
            digest = session.sha256 if sha256 in {None, ""} else normalize_sha256(sha256)
            if digest != session.sha256:
                await self._fail_locked(session)
                raise UploadError("upload_hash_mismatch", 422)
            if session.state == "ready":
                session.updated_at = self.clock()
                return {**session.public(), "duplicate": True}
            if session.received_bytes != session.total_bytes:
                await self._fail_locked(session)
                raise UploadError("upload_size_mismatch", 422)
            try:
                await asyncio.to_thread(self._verify_fsync_and_rename, session)
            except UploadError:
                await self._fail_locked(session)
                raise
            except Exception as exc:
                await self._fail_locked(session)
                raise UploadError("upload_finalize_failed", 500) from exc
            session.state = "ready"
            session.updated_at = self.clock()
            return {**session.public(), "duplicate": False}

    async def ready_path(
        self,
        upload_id: str,
        *,
        pairing_id: str,
        mac_session_id: str,
        mac_connection_generation: int,
    ) -> tuple[Path, Dict[str, Any]]:
        async with self._lock:
            session = self._require(upload_id, pairing_id, mac_session_id, mac_connection_generation)
            if session.state != "ready" or not session.ready_path.is_file():
                raise UploadError("upload_not_ready", 409)
            session.updated_at = self.clock()
            return session.ready_path, session.public()

    async def status(self, upload_id: str, pairing_id: str) -> Dict[str, Any]:
        async with self._lock:
            session = self._sessions.get(upload_id)
            if session is None or session.pairing_id != pairing_id:
                raise UploadError("upload_not_found", 404)
            return session.public()

    async def acknowledge(
        self,
        upload_id: str,
        *,
        pairing_id: str,
        mac_session_id: str,
        mac_connection_generation: int,
    ) -> Dict[str, Any]:
        async with self._lock:
            session = self._sessions.get(upload_id)
            if session is None:
                prior = self._acknowledged.get(upload_id)
                if (
                    prior
                    and prior.expires_at > self.clock()
                    and prior.pairing_id == pairing_id
                    and prior.mac_session_id == mac_session_id
                    and prior.mac_connection_generation == mac_connection_generation
                ):
                    return {"upload_id": upload_id, "state": "acknowledged", "duplicate": True}
                raise UploadError("upload_not_found", 404)
            session = self._require(upload_id, pairing_id, mac_session_id, mac_connection_generation)
            result = session.public()
            await self._remove_locked(session)
            self._acknowledged[upload_id] = AcknowledgedUpload(
                pairing_id,
                mac_session_id,
                mac_connection_generation,
                self.clock() + self.ttl_seconds,
            )
            return {**result, "duplicate": False}

    async def abort(self, upload_id: str, pairing_id: str) -> bool:
        async with self._lock:
            session = self._sessions.get(upload_id)
            if session is None or session.pairing_id != pairing_id:
                return False
            await self._remove_locked(session)
            return True

    async def abort_binding(self, pairing_id: str, session_id: str, generation: int) -> int:
        async with self._lock:
            matches = [
                item for item in self._sessions.values()
                if item.pairing_id == pairing_id
                and item.mac_session_id == session_id
                and item.mac_connection_generation == generation
            ]
            for item in matches:
                await self._remove_locked(item)
            return len(matches)

    async def abort_except_binding(self, pairing_id: str, session_id: str, generation: int) -> int:
        async with self._lock:
            matches = [
                item for item in self._sessions.values()
                if item.pairing_id == pairing_id
                and (item.mac_session_id != session_id or item.mac_connection_generation != generation)
            ]
            for item in matches:
                await self._remove_locked(item)
            return len(matches)

    async def cleanup_expired(self) -> int:
        async with self._lock:
            return await self._cleanup_expired_locked(self.clock())

    async def stats(self) -> Dict[str, int]:
        async with self._lock:
            usage = await asyncio.to_thread(self.disk_usage, self.root)
            reserve = max(self.reserve_min_bytes, int(usage.total * self.reserve_fraction))
            return {
                "active": len(self._sessions),
                "bytes": sum(item.received_bytes for item in self._sessions.values()),
                "disk_free_bytes": int(usage.free),
                "disk_reserve_bytes": reserve,
            }

    async def _cleanup_expired_locked(self, now: float) -> int:
        expired = [item for item in self._sessions.values() if now - item.updated_at >= self.ttl_seconds]
        for item in expired:
            await self._remove_locked(item)
        self._acknowledged = {
            upload_id: item for upload_id, item in self._acknowledged.items() if item.expires_at > now
        }
        return len(expired)

    def _require(self, upload_id: str, pairing_id: str, session_id: str, generation: int) -> UploadSession:
        session = self._sessions.get(str(upload_id))
        if session is None or session.pairing_id != pairing_id:
            raise UploadError("upload_not_found", 404)
        if session.mac_session_id != session_id:
            raise UploadError("upload_session_mismatch", 409)
        if session.mac_connection_generation != generation:
            raise UploadError("upload_generation_mismatch", 409)
        return session

    async def _fail_locked(self, session: UploadSession) -> None:
        await self._remove_locked(session)

    async def _remove_locked(self, session: UploadSession) -> None:
        self._sessions.pop(session.upload_id, None)
        if self._active_by_pairing.get(session.pairing_id) == session.upload_id:
            self._active_by_pairing.pop(session.pairing_id, None)
        await asyncio.to_thread(self._delete_files, session)

    def _assert_disk_space(self, incoming_bytes: int) -> None:
        usage = self.disk_usage(self.root)
        reserve = max(self.reserve_min_bytes, int(usage.total * self.reserve_fraction))
        if int(usage.free) - max(0, int(incoming_bytes)) < reserve:
            raise UploadError("insufficient_storage", 507)

    def _prepare_root_and_remove_orphans(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)
        for item in self.root.iterdir():
            if item.is_file() or item.is_symlink():
                item.unlink(missing_ok=True)
            elif item.is_dir():
                shutil.rmtree(item)

    @staticmethod
    def _create_part(path: Path) -> None:
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(descriptor)
        os.chmod(path, 0o600)

    @staticmethod
    def _delete_files(session: UploadSession) -> None:
        session.part_path.unlink(missing_ok=True)
        session.ready_path.unlink(missing_ok=True)

    @staticmethod
    def _verify_fsync_and_rename(session: UploadSession) -> None:
        hasher = hashlib.sha256()
        size = 0
        with session.part_path.open("rb", buffering=0) as handle:
            while True:
                data = handle.read(STREAM_BYTES)
                if not data:
                    break
                size += len(data)
                hasher.update(data)
        if size != session.total_bytes:
            raise UploadError("upload_size_mismatch", 422)
        if hasher.hexdigest() != session.sha256:
            raise UploadError("upload_hash_mismatch", 422)
        with session.part_path.open("rb") as handle:
            os.fsync(handle.fileno())
        os.replace(session.part_path, session.ready_path)
        os.chmod(session.ready_path, 0o600)
        directory = os.open(session.ready_path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
