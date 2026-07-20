"""Single-owner SQLite WAL event log for Claudian Remote v2."""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from gateway.protocol.stream_protocol import event_uid, validate_event


@dataclass(frozen=True)
class CommittedEvent:
    cursor: int
    epoch: str
    event_uid: str
    event: Dict[str, Any]
    inserted: bool

    def frame(self, replayed: bool = False) -> Dict[str, Any]:
        return {
            "type": "event.committed",
            "epoch": self.epoch,
            "cursor": self.cursor,
            "event_uid": self.event_uid,
            "replayed": replayed,
            "event": self.event,
        }


@dataclass
class _Request:
    operation: str
    args: Tuple[Any, ...]
    future: asyncio.Future[Any]


class EventStore:
    """All connection use is serialized through one asyncio owner task."""

    def __init__(
        self,
        path: Path,
        *,
        retention_seconds: float = 6 * 60 * 60,
        completed_grace_seconds: float = 60 * 60,
        terminal_recovery_seconds: Optional[float] = None,
        stale_in_flight_seconds: Optional[float] = None,
        max_bytes: int = 64 * 1024 * 1024,
        max_rows: int = 100_000,
    ) -> None:
        self.path = Path(path)
        self.stale_in_flight_seconds = float(
            retention_seconds if stale_in_flight_seconds is None else stale_in_flight_seconds
        )
        self.terminal_recovery_seconds = float(
            completed_grace_seconds if terminal_recovery_seconds is None else terminal_recovery_seconds
        )
        # Backward-compatible attribute names are retained for callers while
        # the actual policy names match the support matrix.
        self.retention_seconds = self.stale_in_flight_seconds
        self.completed_grace_seconds = self.terminal_recovery_seconds
        self.max_bytes = max_bytes
        self.max_rows = max_rows
        self._requests: asyncio.Queue[Optional[_Request]] = asyncio.Queue()
        self._worker: Optional[asyncio.Task[None]] = None
        self._epoch: Optional[str] = None
        self._last_checkpoint_busy = 0
        self.sqlite_version = sqlite3.sqlite_version

    @property
    def epoch(self) -> str:
        if self._epoch is None:
            raise RuntimeError("event store has not started")
        return self._epoch

    async def start(self) -> "EventStore":
        if self._worker is not None:
            return self
        loop = asyncio.get_running_loop()
        ready: asyncio.Future[str] = loop.create_future()
        self._worker = asyncio.create_task(self._run(ready), name="relay-sqlite-owner")
        self._epoch = await ready
        return self

    async def close(self) -> None:
        if self._worker is None:
            return
        await self._call("checkpoint", "TRUNCATE")
        await self._requests.put(None)
        await self._worker
        self._worker = None

    async def append(self, pairing_id: str, event: Dict[str, Any], now: Optional[float] = None) -> CommittedEvent:
        validate_event(event)
        return await self._call("append", pairing_id, event, float(now if now is not None else time.time()))

    async def high_water(self, pairing_id: str) -> int:
        return await self._call("high_water", pairing_id)

    async def retained_floor(self, pairing_id: str) -> int:
        """Return the oldest cursor from which an exact resume is possible."""
        return await self._call("retained_floor", pairing_id)

    async def replay(self, pairing_id: str, after: int, through: Optional[int] = None, limit: int = 10_000) -> List[CommittedEvent]:
        return await self._call("replay", pairing_id, int(after), through, int(limit))

    async def prune(self, now: Optional[float] = None) -> Dict[str, int]:
        return await self._call("prune", float(now if now is not None else time.time()))

    async def stats(self) -> Dict[str, Any]:
        return await self._call("stats")

    async def checkpoint(self, mode: str = "PASSIVE") -> Tuple[int, int, int]:
        if mode not in {"PASSIVE", "TRUNCATE"}:
            raise ValueError("checkpoint mode must be PASSIVE or TRUNCATE")
        return await self._call("checkpoint", mode)

    async def backup(self, destination: Path) -> None:
        await self._call("backup", Path(destination))

    async def _call(self, operation: str, *args: Any) -> Any:
        if self._worker is None:
            raise RuntimeError("event store has not started")
        future = asyncio.get_running_loop().create_future()
        await self._requests.put(_Request(operation, args, future))
        return await future

    async def _run(self, ready: asyncio.Future[str]) -> None:
        connection: Optional[sqlite3.Connection] = None
        try:
            connection, epoch = await asyncio.to_thread(self._open_connection)
            ready.set_result(epoch)
            while True:
                request = await self._requests.get()
                if request is None:
                    break
                try:
                    result = await asyncio.to_thread(
                        self._dispatch, connection, request.operation, request.args, epoch
                    )
                except Exception as exc:
                    if not request.future.done():
                        request.future.set_exception(exc)
                else:
                    if not request.future.done():
                        request.future.set_result(result)
        except Exception as exc:
            if not ready.done():
                ready.set_exception(exc)
            raise
        finally:
            if connection is not None:
                await asyncio.to_thread(connection.close)

    def _open_connection(self) -> Tuple[sqlite3.Connection, str]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(self.path.parent, 0o700)
        connection = sqlite3.connect(
            self.path, isolation_level=None, timeout=5.0, check_same_thread=False
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA busy_timeout=5000")
        connection.execute("PRAGMA foreign_keys=ON")
        self._create_schema(connection)
        os.chmod(self.path, 0o600)
        return connection, self._load_or_create_epoch(connection)

    @staticmethod
    def _create_schema(connection: sqlite3.Connection) -> None:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS events (
                cursor INTEGER PRIMARY KEY AUTOINCREMENT,
                event_uid TEXT NOT NULL UNIQUE,
                pairing_id TEXT NOT NULL,
                source_instance_id TEXT NOT NULL,
                source_sequence INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                revision INTEGER NOT NULL,
                turn_id TEXT,
                terminal INTEGER NOT NULL DEFAULT 0,
                event_json TEXT NOT NULL,
                event_bytes INTEGER NOT NULL,
                created_at REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS events_pairing_cursor
                ON events(pairing_id, cursor);
            CREATE INDEX IF NOT EXISTS events_created_at
                ON events(created_at);
            CREATE TABLE IF NOT EXISTS retention_floor (
                pairing_id TEXT PRIMARY KEY,
                resumable_cursor INTEGER NOT NULL
            );
            """
        )

    @staticmethod
    def _load_or_create_epoch(connection: sqlite3.Connection) -> str:
        row = connection.execute("SELECT value FROM metadata WHERE key='epoch'").fetchone()
        if row:
            return str(row[0])
        epoch = "epoch-" + uuid.uuid4().hex
        connection.execute("BEGIN IMMEDIATE")
        try:
            connection.execute("INSERT INTO metadata(key,value) VALUES('epoch',?)", (epoch,))
            connection.execute("COMMIT")
        except Exception:
            connection.execute("ROLLBACK")
            raise
        return epoch

    def _dispatch(self, connection: sqlite3.Connection, operation: str, args: Tuple[Any, ...], epoch: str) -> Any:
        if operation == "append":
            return self._append(connection, epoch, *args)
        if operation == "high_water":
            row = connection.execute("SELECT COALESCE(MAX(cursor),0) FROM events WHERE pairing_id=?", (args[0],)).fetchone()
            return int(row[0])
        if operation == "retained_floor":
            row = connection.execute("SELECT MIN(cursor) FROM events WHERE pairing_id=?", (args[0],)).fetchone()
            saved = connection.execute("SELECT resumable_cursor FROM retention_floor WHERE pairing_id=?", (args[0],)).fetchone()
            first_floor = max(0, int(row[0]) - 1) if row[0] is not None else 0
            return max(first_floor, int(saved[0]) if saved else 0)
        if operation == "replay":
            return self._replay(connection, epoch, *args)
        if operation == "prune":
            return self._prune(connection, *args)
        if operation == "stats":
            row = connection.execute("SELECT COUNT(*), COALESCE(SUM(event_bytes),0), COALESCE(MAX(cursor),0) FROM events").fetchone()
            return {
                "rows": int(row[0]),
                "bytes": int(row[1]),
                "high_water": int(row[2]),
                "epoch": epoch,
                "sqlite_version": self.sqlite_version,
                "database_bytes": self.path.stat().st_size if self.path.exists() else 0,
                "wal_bytes": self.path.with_name(self.path.name + "-wal").stat().st_size
                if self.path.with_name(self.path.name + "-wal").exists()
                else 0,
                "checkpoint_busy": self._last_checkpoint_busy,
            }
        if operation == "checkpoint":
            row = connection.execute(f"PRAGMA wal_checkpoint({args[0]})").fetchone()
            result = tuple(int(value) for value in row)
            self._last_checkpoint_busy = result[0]
            return result
        if operation == "backup":
            destination: Path = args[0]
            destination.parent.mkdir(parents=True, exist_ok=True)
            target = sqlite3.connect(destination)
            try:
                connection.backup(target)
            finally:
                target.close()
            os.chmod(destination, 0o600)
            return None
        raise ValueError(f"unknown event store operation: {operation}")

    @staticmethod
    def _append(connection: sqlite3.Connection, epoch: str, pairing_id: str, event: Dict[str, Any], now: float) -> CommittedEvent:
        uid = event_uid(event)
        encoded = json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        source = event["source"]
        entity = event["entity"]
        terminal = int(event["event_type"] in {"turn.completed", "turn.interrupted", "turn.failed"})
        connection.execute("BEGIN IMMEDIATE")
        try:
            cursor = connection.execute(
                """
                INSERT INTO events(
                    event_uid,pairing_id,source_instance_id,source_sequence,event_type,
                    revision,turn_id,terminal,event_json,event_bytes,created_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(event_uid) DO NOTHING
                RETURNING cursor
                """,
                (
                    uid, pairing_id, source["instance_id"], source["sequence"], event["event_type"],
                    event["revision"], entity.get("turn_id"), terminal, encoded,
                    len(encoded.encode("utf-8")), now,
                ),
            ).fetchone()
            inserted = cursor is not None
            if cursor is None:
                existing = connection.execute("SELECT cursor,event_json,pairing_id FROM events WHERE event_uid=?", (uid,)).fetchone()
                if existing is None or existing["pairing_id"] != pairing_id or existing["event_json"] != encoded:
                    raise ValueError("event_uid_conflict")
                cursor_value = int(existing["cursor"])
            else:
                cursor_value = int(cursor[0])
            connection.execute("COMMIT")
        except Exception:
            connection.execute("ROLLBACK")
            raise
        return CommittedEvent(cursor_value, epoch, uid, event, inserted)

    @staticmethod
    def _replay(
        connection: sqlite3.Connection,
        epoch: str,
        pairing_id: str,
        after: int,
        through: Optional[int],
        limit: int,
    ) -> List[CommittedEvent]:
        ceiling = int(through) if through is not None else 2**63 - 1
        rows = connection.execute(
            "SELECT cursor,event_uid,event_json FROM events WHERE pairing_id=? AND cursor>? AND cursor<=? ORDER BY cursor LIMIT ?",
            (pairing_id, after, ceiling, min(max(limit, 1), 10_000)),
        ).fetchall()
        return [
            CommittedEvent(int(row["cursor"]), epoch, str(row["event_uid"]), json.loads(row["event_json"]), False)
            for row in rows
        ]

    def _prune(self, connection: sqlite3.Connection, now: float) -> Dict[str, int]:
        before = int(connection.execute("SELECT COUNT(*) FROM events").fetchone()[0])
        stale_cutoff = now - self.stale_in_flight_seconds
        terminal_cutoff = now - self.terminal_recovery_seconds
        connection.execute("BEGIN IMMEDIATE")
        try:
            expired = connection.execute(
                """
                SELECT pairing_id,MAX(cursor) AS floor FROM events e
                WHERE (
                    turn_id IS NULL AND created_at<?
                  ) OR (
                    turn_id IS NOT NULL AND EXISTS(
                      SELECT 1 FROM events done
                      WHERE done.pairing_id=e.pairing_id AND done.turn_id=e.turn_id AND done.terminal=1
                    ) AND (
                      SELECT MAX(done.created_at) FROM events done
                      WHERE done.pairing_id=e.pairing_id AND done.turn_id=e.turn_id AND done.terminal=1
                    ) < ?
                  ) OR (
                    turn_id IS NOT NULL AND NOT EXISTS(
                      SELECT 1 FROM events done
                      WHERE done.pairing_id=e.pairing_id AND done.turn_id=e.turn_id AND done.terminal=1
                    ) AND (
                      SELECT MAX(active.created_at) FROM events active
                      WHERE active.pairing_id=e.pairing_id AND active.turn_id=e.turn_id
                    ) < ?
                  )
                GROUP BY pairing_id
                """,
                (terminal_cutoff, terminal_cutoff, stale_cutoff),
            ).fetchall()
            self._record_floors(connection, expired)
            connection.execute(
                """
                DELETE FROM events AS e
                WHERE (
                    turn_id IS NULL AND created_at<?
                  ) OR (
                    turn_id IS NOT NULL AND EXISTS(
                      SELECT 1 FROM events done
                      WHERE done.pairing_id=e.pairing_id AND done.turn_id=e.turn_id AND done.terminal=1
                    ) AND (
                      SELECT MAX(done.created_at) FROM events done
                      WHERE done.pairing_id=e.pairing_id AND done.turn_id=e.turn_id AND done.terminal=1
                    ) < ?
                  ) OR (
                    turn_id IS NOT NULL AND NOT EXISTS(
                      SELECT 1 FROM events done
                      WHERE done.pairing_id=e.pairing_id AND done.turn_id=e.turn_id AND done.terminal=1
                    ) AND (
                      SELECT MAX(active.created_at) FROM events active
                      WHERE active.pairing_id=e.pairing_id AND active.turn_id=e.turn_id
                    ) < ?
                  )
                """,
                (terminal_cutoff, terminal_cutoff, stale_cutoff),
            )
            while True:
                row = connection.execute("SELECT COUNT(*),COALESCE(SUM(event_bytes),0) FROM events").fetchone()
                if int(row[0]) <= self.max_rows and int(row[1]) <= self.max_bytes:
                    break
                batch = connection.execute(
                    """
                    SELECT e.cursor FROM events e
                    ORDER BY CASE
                      WHEN e.turn_id IS NOT NULL AND EXISTS(
                        SELECT 1 FROM events done
                        WHERE done.pairing_id=e.pairing_id AND done.turn_id=e.turn_id
                          AND done.terminal=1 AND done.created_at<?
                      ) THEN 0
                      WHEN e.turn_id IS NOT NULL AND EXISTS(
                        SELECT 1 FROM events done
                        WHERE done.pairing_id=e.pairing_id AND done.turn_id=e.turn_id
                          AND done.terminal=1
                      ) THEN 1
                      WHEN e.turn_id IS NULL THEN 2
                      ELSE 3
                    END, e.cursor
                    LIMIT 256
                    """,
                    (terminal_cutoff,),
                ).fetchall()
                if not batch:
                    break
                placeholders = ",".join("?" for _ in batch)
                trimmed = connection.execute(
                    f"SELECT pairing_id,MAX(cursor) AS floor FROM events WHERE cursor IN ({placeholders}) GROUP BY pairing_id",
                    tuple(item[0] for item in batch),
                ).fetchall()
                self._record_floors(connection, trimmed)
                connection.executemany("DELETE FROM events WHERE cursor=?", [(item[0],) for item in batch])
            connection.execute("COMMIT")
        except Exception:
            connection.execute("ROLLBACK")
            raise
        after = int(connection.execute("SELECT COUNT(*) FROM events").fetchone()[0])
        return {"deleted": before - after, "remaining": after}

    @staticmethod
    def _record_floors(connection: sqlite3.Connection, rows: Iterable[sqlite3.Row]) -> None:
        for row in rows:
            connection.execute(
                """
                INSERT INTO retention_floor(pairing_id,resumable_cursor) VALUES(?,?)
                ON CONFLICT(pairing_id) DO UPDATE SET
                    resumable_cursor=MAX(resumable_cursor,excluded.resumable_cursor)
                """,
                (row["pairing_id"], int(row["floor"])),
            )
