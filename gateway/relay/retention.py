"""Retryable coordinator for exact Relay recovery cleanup."""

from __future__ import annotations

from typing import Any


class RetentionCoordinator:
    def __init__(self, events: Any, uploads: Any) -> None:
        self.events = events
        self.uploads = uploads
        self.consecutive_failures = 0
        self.last_result: dict[str, Any] = {"state": "not_run", "consecutive_failures": 0}

    async def run_once(self) -> dict[str, Any]:
        try:
            event_cleanup = await self.events.prune()
            checkpoint = await self.events.checkpoint("PASSIVE")
            upload_cleanup = await self.uploads.cleanup_expired()
        except Exception as exc:  # Cleanup must degrade and retry, never kill the managed loop.
            self.consecutive_failures += 1
            self.last_result = {
                "state": "degraded",
                "retry": True,
                "failure_type": type(exc).__name__,
                "consecutive_failures": self.consecutive_failures,
            }
            return dict(self.last_result)
        self.consecutive_failures = 0
        self.last_result = {
            "state": "ready",
            "event_cleanup": event_cleanup,
            "checkpoint_busy": int(checkpoint[0]),
            "upload_cleanup": upload_cleanup,
            "consecutive_failures": 0,
        }
        return dict(self.last_result)
