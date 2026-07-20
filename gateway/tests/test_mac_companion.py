import pytest
import json

from gateway.mac_companion.companion import AdapterTimeout, CompanionConfig, CompanionError, MacCompanion, scrub_json_text
from gateway.relay.crypto import PayloadCrypto


class FakeRelay:
    def __init__(self, events=None):
        self.events = events or []
        self.submitted = []
        self.heartbeat_count = 0
        self.joined = False

    def join(self):
        self.joined = True
        return {"ok": True}

    def heartbeat(self):
        self.heartbeat_count += 1
        return {"ok": True}

    def poll(self, since, timeout_seconds):
        return {"ok": True, "events": [event for event in self.events if event["id"] > since]}

    def submit(self, event_type, body, delivery_id, target_role="mobile"):
        event = {
            "ok": True,
            "type": event_type,
            "body": body,
            "delivery_id": delivery_id,
            "target_role": target_role,
        }
        self.submitted.append(event)
        return event


class RejectingMobileRelay(FakeRelay):
    def submit(self, event_type, body, delivery_id, target_role="mobile"):
        if target_role == "mobile":
            raise CompanionError("HTTP Error 409: Conflict")
        return super().submit(event_type, body, delivery_id, target_role)


class ResetRelay(FakeRelay):
    def __init__(self, old_since, events=None):
        super().__init__(events=events)
        self.old_since = old_since

    def poll(self, since, timeout_seconds):
        if since == self.old_since:
            return {"ok": True, "events": []}
        return super().poll(since, timeout_seconds)


class FakeAdapter:
    def __init__(self, response=None, exc=None, snapshot=None):
        self.response = response or {"ok": True, "conversation_id": "active"}
        self.exc = exc
        self.snapshot_response = snapshot or {
            "available": True,
            "conversation_id": "active",
            "messages": [{"role": "assistant", "text": "desktop reply"}],
        }
        self.submitted = []
        self.approvals = []

    def submit_text(self, text, delivery_id, source):
        if self.exc:
            raise self.exc
        self.submitted.append({"text": text, "delivery_id": delivery_id, "source": source})
        return self.response

    def submit_approval(self, approval_id, value, delivery_id, source):
        if self.exc:
            raise self.exc
        self.approvals.append({"approval_id": approval_id, "value": value, "delivery_id": delivery_id, "source": source})
        return {"ok": True, "approval_id": approval_id, "value": value}

    def snapshot(self):
        return self.snapshot_response


def config(**overrides):
    data = {
        "relay_base_url": "https://relay.example.invalid",
        "relay_token": "mac-relay-token",
        "pairing_id": "room-a",
        "adapter_base_url": "http://127.0.0.1:27123",
        "adapter_token": "local-rest-token",
        "payload_secret": "pair secret",
    }
    data.update(overrides)
    return CompanionConfig(**data)


def event(delivery_id="mobile-1", payload=None, event_id=1):
    return {
        "id": event_id,
        "type": "message.submit",
        "source_role": "mobile",
        "delivery_id": delivery_id,
        "body": {"payload": payload or {"text": "hello"}},
    }


def approval_event(delivery_id="approval-1", payload=None, event_id=1):
    return {
        "id": event_id,
        "type": "approval.respond",
        "source_role": "mobile",
        "delivery_id": delivery_id,
        "body": {"payload": payload or {"approval_id": "approval-a", "value": "allow"}},
    }


def snapshot_request_event(delivery_id="snapshot-request-1", payload=None, event_id=1):
    return {
        "id": event_id,
        "type": "snapshot.request",
        "source_role": "mobile",
        "delivery_id": delivery_id,
        "body": {"payload": payload or {"reason": "diagnostics"}},
    }


def test_companion_reconnect_does_not_duplicate_acknowledged_delivery():
    relay = FakeRelay(events=[event(), event(event_id=2)])
    adapter = FakeAdapter()
    companion = MacCompanion(config(), relay, adapter)

    receipts = companion.run_once()

    assert len(adapter.submitted) == 1
    assert adapter.submitted[0]["text"] == "hello"
    assert receipts[0]["body"]["payload"]["status"] == "accepted"
    assert receipts[1]["body"]["payload"]["status"] == "duplicate"


def test_companion_recovers_when_relay_restarts_and_event_ids_reset():
    relay = ResetRelay(old_since=99, events=[event(event_id=1)])
    adapter = FakeAdapter()
    companion = MacCompanion(config(), relay, adapter)
    companion.last_event_id = 99

    receipts = companion.run_once()

    assert adapter.submitted[0]["delivery_id"] == "mobile-1"
    assert companion.last_event_id == 1
    assert receipts[0]["body"]["payload"]["status"] == "accepted"


def test_companion_persists_state_to_skip_old_events_after_restart(tmp_path):
    state_path = tmp_path / "companion_state.json"
    relay = FakeRelay(events=[event()])
    adapter = FakeAdapter()
    first = MacCompanion(config(state_path=str(state_path)), relay, adapter)

    first.run_once()

    assert adapter.submitted[0]["delivery_id"] == "mobile-1"

    second_adapter = FakeAdapter()
    second = MacCompanion(config(state_path=str(state_path)), relay, second_adapter)
    second.run_once()

    assert second_adapter.submitted == []
    assert second.last_event_id == 1


def test_mobile_offline_receipt_refusal_does_not_crash_companion():
    relay = RejectingMobileRelay(events=[event()])
    adapter = FakeAdapter()
    companion = MacCompanion(config(), relay, adapter)

    receipts = companion.run_once()

    assert adapter.submitted[0]["delivery_id"] == "mobile-1"
    assert receipts[0]["ok"] is False
    assert "409" in receipts[0]["error"]


def test_companion_forwards_remote_approval_response_to_adapter():
    relay = FakeRelay(events=[approval_event()])
    adapter = FakeAdapter()
    companion = MacCompanion(config(), relay, adapter)

    receipts = companion.run_once()

    assert adapter.approvals == [
        {"approval_id": "approval-a", "value": "allow", "delivery_id": "approval-1", "source": "mobile"}
    ]
    assert receipts[0]["body"]["payload"]["status"] == "accepted"
    assert receipts[0]["body"]["payload"]["adapter"]["approval_id"] == "approval-a"


def test_invalid_remote_approval_response_becomes_failed_receipt():
    relay = FakeRelay(events=[approval_event(payload={"approval_id": "", "value": ""})])
    adapter = FakeAdapter()
    companion = MacCompanion(config(), relay, adapter)

    receipts = companion.run_once()

    assert adapter.approvals == []
    assert receipts[0]["body"]["payload"]["status"] == "failed"
    assert "missing approval decision" in receipts[0]["body"]["payload"]["message"]


def test_companion_refuses_to_start_with_missing_required_settings():
    with pytest.raises(CompanionError):
        MacCompanion(config(relay_token=""), FakeRelay(), FakeAdapter())


def test_file_config_keeps_request_timeout_longer_than_poll_timeout(tmp_path):
    from gateway.mac_companion.config import InMemoryKeychain

    path = tmp_path / "companion.json"
    data = {
        "relay_base_url": "https://relay.example.invalid",
        "relay_token_ref": "relay",
        "pairing_id": "room-a",
        "adapter_base_url": "http://127.0.0.1:27123",
        "adapter_token_ref": "bridge",
        "poll_timeout_seconds": 15,
        "request_timeout_seconds": 10,
    }
    path.write_text(json.dumps(data), encoding="utf-8")

    loaded = CompanionConfig.from_file(path, InMemoryKeychain({
        "relay": "mac-relay-token",
        "bridge": "local-rest-token",
    }))

    assert loaded.request_timeout_seconds == 20


def test_adapter_token_never_goes_to_relay_receipts():
    relay = FakeRelay(events=[event()])
    companion = MacCompanion(config(adapter_token="super-local-secret"), relay, FakeAdapter())

    companion.run_once()

    assert "super-local-secret" not in str(relay.submitted)


def test_successful_submit_forwards_desktop_snapshot_to_mobile():
    relay = FakeRelay(events=[event()])
    companion = MacCompanion(config(), relay, FakeAdapter())

    companion.run_once()

    assert any(item["type"] == "conversation.snapshot" for item in relay.submitted)


def test_snapshot_request_forces_current_desktop_snapshot_to_mobile():
    relay = FakeRelay(events=[snapshot_request_event()])
    companion = MacCompanion(config(), relay, FakeAdapter())

    receipts = companion.run_once()

    snapshots = [item for item in relay.submitted if item["type"] == "conversation.snapshot"]
    assert len(snapshots) == 1
    assert snapshots[0]["delivery_id"] == "snapshot-snapshot-request-1"
    assert snapshots[0]["body"]["payload"]["available"] is True
    assert receipts[0]["body"]["payload"]["status"] == "accepted"
    assert "published desktop Claudian snapshot" in receipts[0]["body"]["payload"]["message"]


def test_idle_companion_publishes_snapshot_only_when_changed():
    relay = FakeRelay(events=[])
    adapter = FakeAdapter()
    companion = MacCompanion(config(snapshot_interval_seconds=0), relay, adapter)

    companion.run_once()
    companion.run_once()

    snapshots = [item for item in relay.submitted if item["type"] == "conversation.snapshot"]
    assert len(snapshots) == 1
    assert relay.heartbeat_count == 2

    adapter.snapshot_response = {
        "available": True,
        "conversation_id": "active",
        "messages": [{"role": "assistant", "text": "desktop reply changed"}],
    }

    companion.run_once()

    snapshots = [item for item in relay.submitted if item["type"] == "conversation.snapshot"]
    assert len(snapshots) == 2


def test_adapter_timeout_becomes_failed_receipt():
    relay = FakeRelay(events=[event()])
    companion = MacCompanion(config(), relay, FakeAdapter(exc=AdapterTimeout("slow")))

    receipts = companion.run_once()

    assert receipts[0]["body"]["payload"]["status"] == "failed"
    assert "timeout" in receipts[0]["body"]["payload"]["message"]


def test_encrypted_mobile_payload_is_decrypted_before_adapter_submit():
    crypto = PayloadCrypto("pair secret", "room-a")
    relay = FakeRelay(
        events=[
            {
                "id": 1,
                "type": "message.submit",
                "source_role": "mobile",
                "delivery_id": "encrypted-1",
                "body": {"encrypted_payload": crypto.encrypt_json({"text": "secret hello"})},
            }
        ]
    )
    adapter = FakeAdapter()
    companion = MacCompanion(config(), relay, adapter)

    companion.run_once()

    assert adapter.submitted[0]["text"] == "secret hello"


def test_missing_payload_secret_returns_failed_receipt_instead_of_crashing():
    crypto = PayloadCrypto("pair secret", "room-a")
    relay = FakeRelay(
        events=[
            {
                "id": 1,
                "type": "message.submit",
                "source_role": "mobile",
                "delivery_id": "encrypted-1",
                "body": {"encrypted_payload": crypto.encrypt_json({"text": "secret hello"})},
            }
        ]
    )
    companion = MacCompanion(config(payload_secret=""), relay, FakeAdapter())

    receipts = companion.run_once()

    assert receipts[0]["body"]["payload"]["status"] == "failed"
    assert "payload decode error" in receipts[0]["body"]["payload"]["message"]


def test_scrub_json_text_replaces_lone_surrogates_before_http_encoding():
    value = {"message": "bad \ud83c text", "items": ["ok", "\udfff"]}

    scrubbed = scrub_json_text(value)

    assert scrubbed == {"message": "bad � text", "items": ["ok", "�"]}
    assert "bad � text" in json.dumps(scrubbed, ensure_ascii=False).encode("utf-8").decode("utf-8")
