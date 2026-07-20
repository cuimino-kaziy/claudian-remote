"""Race-safe in-memory Mac presence and instantaneous command routing."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, Optional, Protocol, TypeVar


T = TypeVar("T")


class CommandTarget(Protocol):
    connection_id: str

    def enqueue_nowait(self, frame: Dict[str, Any]) -> None: ...


@dataclass(frozen=True)
class MacBinding:
    pairing_id: str
    mac_session_id: str
    connection_generation: int
    client: CommandTarget
    compatibility: Dict[str, Any]


class PresenceRegistry:
    def __init__(self) -> None:
        self._macs: Dict[str, MacBinding] = {}
        self._lock = asyncio.Lock()

    async def register_mac(
        self,
        pairing_id: str,
        mac_session_id: str,
        connection_generation: int,
        client: CommandTarget,
        compatibility: Optional[Dict[str, Any]] = None,
    ) -> Optional[CommandTarget]:
        if not mac_session_id or connection_generation < 1:
            raise ValueError("invalid_mac_hello")
        async with self._lock:
            current = self._macs.get(pairing_id)
            if (
                current
                and current.mac_session_id == mac_session_id
                and connection_generation <= current.connection_generation
                and current.client is not client
            ):
                raise ValueError("stale_connection_generation")
            self._macs[pairing_id] = MacBinding(
                pairing_id, mac_session_id, connection_generation, client, dict(compatibility or {})
            )
            return current.client if current and current.client is not client else None

    async def unregister_mac(self, pairing_id: str, client: CommandTarget) -> bool:
        async with self._lock:
            current = self._macs.get(pairing_id)
            if current is None or current.client is not client:
                return False
            del self._macs[pairing_id]
            return True

    async def route_command(self, pairing_id: str, command: Dict[str, Any]) -> Dict[str, Any]:
        """Check and enqueue under one lock so reconnect never inherits a command."""
        async with self._lock:
            current = self._macs.get(pairing_id)
            if current is None:
                return {"status": "mac_offline"}
            if current.compatibility.get("writable") is False:
                return {
                    "status": "compatibility_mismatch",
                    "remediation": current.compatibility.get("remediation") or "Update required components",
                }
            if command.get("mac_session_id") != current.mac_session_id:
                return {"status": "session_mismatch"}
            if command.get("mac_connection_generation") != current.connection_generation:
                return {"status": "connection_generation_mismatch"}
            try:
                current.client.enqueue_nowait({"type": "command", "command": command})
            except Exception:
                return {"status": "delivery_unknown", "error_code": "mac_connection_backpressure"}
            return {
                "status": "routed",
                "mac_session_id": current.mac_session_id,
                "mac_connection_generation": current.connection_generation,
            }

    async def route_control(self, pairing_id: str, frame: Dict[str, Any]) -> Dict[str, Any]:
        """Route an ephemeral recovery control to the current Mac connection."""
        async with self._lock:
            current = self._macs.get(pairing_id)
            if current is None:
                return {"status": "mac_offline"}
            try:
                current.client.enqueue_nowait(dict(frame))
            except Exception:
                return {"status": "delivery_unknown", "error_code": "mac_connection_backpressure"}
            return {
                "status": "routed",
                "mac_session_id": current.mac_session_id,
                "mac_connection_generation": current.connection_generation,
            }

    async def route_control_bound(
        self,
        pairing_id: str,
        mac_session_id: str,
        connection_generation: int,
        frame: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Route a control only to the exact live session/generation."""
        async with self._lock:
            current = self._macs.get(pairing_id)
            if current is None:
                return {"status": "mac_offline"}
            if current.mac_session_id != mac_session_id:
                return {"status": "session_mismatch"}
            if current.connection_generation != connection_generation:
                return {"status": "connection_generation_mismatch"}
            try:
                current.client.enqueue_nowait(dict(frame))
            except Exception:
                return {"status": "delivery_unknown", "error_code": "mac_connection_backpressure"}
            return {
                "status": "routed",
                "mac_session_id": current.mac_session_id,
                "mac_connection_generation": current.connection_generation,
            }

    async def run_for_binding(
        self,
        pairing_id: str,
        mac_session_id: str,
        connection_generation: int,
        operation: Callable[[], Awaitable[T]],
    ) -> T:
        """Run a short operation only while an exact Mac binding is current."""
        async with self._lock:
            current = self._macs.get(pairing_id)
            if current is None:
                raise ValueError("mac_offline")
            if current.mac_session_id != mac_session_id:
                raise ValueError("session_mismatch")
            if current.connection_generation != connection_generation:
                raise ValueError("connection_generation_mismatch")
            return await operation()

    async def binding_matches(self, pairing_id: str, session_id: str, generation: int) -> bool:
        async with self._lock:
            current = self._macs.get(pairing_id)
            return bool(
                current
                and current.mac_session_id == session_id
                and current.connection_generation == generation
            )

    async def run_if_current(
        self,
        pairing_id: str,
        client: CommandTarget,
        mac_session_id: str,
        connection_generation: int,
        operation: Callable[[], Awaitable[T]],
    ) -> T:
        """Run an operation while the supplied Mac binding remains current.

        Holding the presence owner lock across the operation closes the small
        reconnect race where an obsolete socket validated itself and then
        published after a newer generation had replaced it.
        """
        async with self._lock:
            current = self._macs.get(pairing_id)
            if current is None or current.client is not client:
                raise ValueError("stale_mac_connection")
            if mac_session_id != current.mac_session_id:
                raise ValueError("stale_mac_session")
            if connection_generation != current.connection_generation:
                raise ValueError("stale_mac_generation")
            return await operation()

    async def mac_snapshot(self, pairing_id: str) -> Dict[str, Any]:
        async with self._lock:
            current = self._macs.get(pairing_id)
            if current is None:
                return {"online": False, "mac_session_id": None, "connection_generation": None, "compatibility": None}
            return {
                "online": True,
                "mac_session_id": current.mac_session_id,
                "connection_generation": current.connection_generation,
                "compatibility": dict(current.compatibility),
            }
