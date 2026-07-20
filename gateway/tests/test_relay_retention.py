import hashlib
import json
from types import SimpleNamespace

import pytest

from gateway.relay.config import RelayLimits, load_support_matrix
from gateway.relay.relay_server import RelayConfig
from gateway.relay.event_store import EventStore
from gateway.relay.retention import RetentionCoordinator
from gateway.relay.upload_store import UploadError, UploadStore


def semantic_event(sequence, event_type="text.delta"):
    terminal = event_type == "turn.completed"
    return {
        "protocol": "claudian.remote.v2",
        "kind": "event",
        "event_type": event_type,
        "source": {"instance_id": "bridge", "sequence": sequence},
        "entity": (
            {"conversation_id": "conversation", "turn_id": f"turn-{sequence // 10}"}
            if terminal
            else {
                "conversation_id": "conversation",
                "turn_id": f"turn-{sequence // 10}",
                "message_id": f"message-{sequence // 10}",
                "block_id": "block-1",
            }
        ),
        "revision": sequence,
        "payload": (
            {"status": "completed", "duration_ms": 1, "checksum": "sha256:" + "a" * 64}
            if terminal
            else {"text": "x", "base_revision": sequence - 1, "offset": sequence - 1}
        ),
        "occurred_at": "2026-07-20T00:00:00Z",
    }


def test_support_matrix_is_the_single_exact_relay_limit_contract():
    matrix = load_support_matrix()
    assert matrix == RelayLimits(
        terminal_recovery_seconds=3600,
        stale_in_flight_seconds=21600,
        upload_after_terminal_seconds=1800,
        upload_absolute_seconds=7200,
        max_file_bytes=268435456,
        max_outstanding_bytes_per_installation=536870912,
        max_concurrent_uploads=2,
        max_frame_bytes=1048576,
        managed_volume_refusal_percent=80,
    )


def test_relay_config_rejects_external_binding_fallback_and_limit_drift(tmp_path):
    base = {
        "host": "127.0.0.1",
        "fallback_base_url": "",
        "retention_seconds": 21600,
        "completed_grace_seconds": 3600,
        "upload_ttl_seconds": 1800,
        "upload_absolute_seconds": 7200,
        "upload_max_file_bytes": 268435456,
        "upload_max_outstanding_bytes_per_installation": 536870912,
        "upload_max_concurrent": 2,
        "websocket_max_message_bytes": 1048576,
        "managed_volume_refusal_percent": 80,
    }
    for field, value, code in (
        ("host", "0.0.0.0", "relay_must_bind_loopback"),
        ("fallback_base_url", "https://fallback.example", "relay_fallback_forbidden"),
        ("retention_seconds", 999, "relay_limit_drift"),
    ):
        document = {**base, field: value}
        path = tmp_path / f"{field}.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        with pytest.raises(ValueError, match=code):
            RelayConfig.from_file(path)


@pytest.mark.asyncio
async def test_terminal_events_expire_at_one_hour_and_stale_inflight_at_six_hours(tmp_path):
    store = await EventStore(
        tmp_path / "relay.db",
        terminal_recovery_seconds=3600,
        stale_in_flight_seconds=21600,
    ).start()
    await store.append("installation-a", semantic_event(10), now=10)
    await store.append("installation-a", semantic_event(11, "turn.completed"), now=20)
    await store.append("installation-a", semantic_event(20), now=30)

    await store.prune(now=3619)
    assert len(await store.replay("installation-a", 0)) == 3
    await store.prune(now=3621)
    remaining = await store.replay("installation-a", 0)
    assert [event.event["source"]["sequence"] for event in remaining] == [20]
    await store.prune(now=21631)
    assert await store.replay("installation-a", 0) == []
    await store.close()


def usage(total=1000, used=100):
    return SimpleNamespace(total=total, used=used, free=total - used)


async def begin(store, installation, pairing, size=1):
    return await store.begin(
        installation_id=installation,
        pairing_id=pairing,
        mac_session_id="session",
        mac_connection_generation=1,
        display_name="file.bin",
        content_type="application/octet-stream",
        total_bytes=size,
        sha256=hashlib.sha256(b"x" * size).hexdigest(),
    )


@pytest.mark.asyncio
async def test_upload_exact_file_installation_concurrency_and_watermark_limits(tmp_path):
    disk = {"usage": usage()}
    store = await UploadStore(
        tmp_path / "uploads",
        max_file_bytes=10,
        max_outstanding_bytes_per_installation=15,
        max_concurrent_uploads=2,
        managed_volume_refusal_percent=80,
        reserve_min_bytes=0,
        reserve_fraction=0,
        disk_usage=lambda _path: disk["usage"],
    ).start()
    with pytest.raises(UploadError, match="file_too_large"):
        await begin(store, "installation-a", "room-0", 11)
    first = await begin(store, "installation-a", "room-1", 8)
    second = await begin(store, "installation-a", "room-2", 7)
    with pytest.raises(UploadError, match="upload_concurrency_limit"):
        await begin(store, "installation-a", "room-3", 1)
    await store.abort(first["upload_id"], "room-1")
    with pytest.raises(UploadError, match="installation_upload_quota"):
        await begin(store, "installation-a", "room-3", 9)
    await store.abort(second["upload_id"], "room-2")

    disk["usage"] = usage(1000, 800)
    with pytest.raises(UploadError, match="managed_volume_watermark"):
        await begin(store, "installation-b", "room-4", 1)
    await store.close()


@pytest.mark.asyncio
async def test_upload_terminal_and_absolute_ttl_survive_cleanup_failure_and_restart(tmp_path):
    now = [0.0]
    root = tmp_path / "uploads"
    store = await UploadStore(
        root,
        terminal_ttl_seconds=30,
        absolute_ttl_seconds=120,
        reserve_min_bytes=0,
        reserve_fraction=0,
        clock=lambda: now[0],
        disk_usage=lambda _path: usage(),
    ).start()
    first = await begin(store, "installation-a", "room-1")
    await store.mark_terminal("room-1", now=10)
    now[0] = 39
    assert await store.cleanup_expired() == 0
    now[0] = 41
    assert await store.cleanup_expired() == 1

    second = await begin(store, "installation-a", "room-2")
    now[0] = 162
    assert await store.cleanup_expired() == 1
    assert not (root / f"{second['upload_id']}.part").exists()
    await store.close()


def test_support_matrix_file_contains_no_derived_or_unbounded_limit():
    raw = json.loads((__import__("pathlib").Path(__file__).parents[2] / "release" / "support-matrix.json").read_text())
    assert set(raw["relay_limits"]) == {
        "terminal_recovery_seconds",
        "stale_in_flight_seconds",
        "upload_after_terminal_seconds",
        "upload_absolute_seconds",
        "max_file_bytes",
        "max_outstanding_bytes_per_installation",
        "max_concurrent_uploads",
        "max_frame_bytes",
        "managed_volume_refusal_percent",
    }


@pytest.mark.asyncio
async def test_cleanup_failure_is_degraded_and_the_next_cycle_retries():
    class Events:
        def __init__(self):
            self.calls = 0

        async def prune(self):
            self.calls += 1
            if self.calls == 1:
                raise OSError("temporary cleanup failure")
            return {"removed": 1}

        async def checkpoint(self, _mode):
            return (0, 0, 0)

    class Uploads:
        async def cleanup_expired(self):
            return 1

    coordinator = RetentionCoordinator(Events(), Uploads())
    first = await coordinator.run_once()
    assert first == {"state": "degraded", "retry": True, "failure_type": "OSError", "consecutive_failures": 1}
    second = await coordinator.run_once()
    assert second["state"] == "ready"
    assert second["event_cleanup"] == {"removed": 1}
    assert second["upload_cleanup"] == 1
    assert second["consecutive_failures"] == 0
