import json
import time

from gateway.relay.relay_server import RelayConfig, RelayService, RelayToken


def service():
    return RelayService(
        RelayConfig(
            presence_ttl_seconds=0.5,
            tokens=[
                RelayToken(name="mac", role="mac", pairing_id="room-a", token="mac-token"),
                RelayToken(name="mobile", role="mobile", pairing_id="room-a", token="mobile-token"),
                RelayToken(name="other", role="mobile", pairing_id="room-b", token="other-token"),
            ],
        )
    )


def test_relay_config_has_no_unverified_fallback_by_default(tmp_path):
    assert RelayConfig().fallback_base_url == ""

    config_path = tmp_path / "relay.json"
    config_path.write_text(json.dumps({"tokens": []}), encoding="utf-8")

    assert RelayConfig.from_file(config_path).fallback_base_url == ""


def auth(relay, token):
    item = relay.authenticate(f"Bearer {token}")
    assert item is not None
    return item


def test_mac_and_mobile_join_same_room_and_receive_presence():
    relay = service()
    mac = auth(relay, "mac-token")
    mobile = auth(relay, "mobile-token")

    mac_join = relay.join(mac, session_id="mac-session", now=100.0)
    mobile_join = relay.join(mobile, session_id="mobile-session", now=101.0)

    assert mac_join["presence"]["mac"] is True
    assert mobile_join["presence"] == {"mac": True, "mobile": True}
    events = relay.poll(mac, since=0)["events"]
    assert any(event["type"] == "presence.changed" and event["body"]["role"] == "mobile" for event in events)


def test_mobile_message_gets_stable_delivery_id_before_mac_ack():
    relay = service()
    mac = auth(relay, "mac-token")
    mobile = auth(relay, "mobile-token")
    relay.join(mac, now=100.0)
    relay.join(mobile, now=100.0)

    status, response = relay.submit(
        mobile,
        {
            "type": "message.submit",
            "delivery_id": "mobile-1",
            "body": {"payload": {"text": "hello"}},
        },
        now=100.1,
    )

    assert status == 202
    assert response["delivery_id"] == "mobile-1"
    events = relay.poll(mac, since=0)["events"]
    message_events = [event for event in events if event["type"] == "message.submit"]
    assert message_events[0]["delivery_id"] == "mobile-1"
    assert message_events[0]["body"]["payload"]["text"] == "hello"


def test_mobile_approval_response_is_allowed_for_mac_target():
    relay = service()
    mac = auth(relay, "mac-token")
    mobile = auth(relay, "mobile-token")
    relay.join(mac, now=100.0)
    relay.join(mobile, now=100.0)

    status, response = relay.submit(
        mobile,
        {
            "type": "approval.respond",
            "delivery_id": "approval-1",
            "target_role": "mac",
            "body": {"payload": {"approval_id": "approval-a", "value": "allow"}},
        },
        now=100.1,
    )

    assert status == 202
    assert response["delivery_id"] == "approval-1"
    events = relay.poll(mac, since=0)["events"]
    approval_events = [event for event in events if event["type"] == "approval.respond"]
    assert approval_events[0]["body"]["payload"] == {"approval_id": "approval-a", "value": "allow"}


def test_mobile_snapshot_request_is_allowed_for_mac_target():
    relay = service()
    mac = auth(relay, "mac-token")
    mobile = auth(relay, "mobile-token")
    relay.join(mac, now=100.0)
    relay.join(mobile, now=100.0)

    status, response = relay.submit(
        mobile,
        {
            "type": "snapshot.request",
            "delivery_id": "snapshot-request-1",
            "target_role": "mac",
            "body": {"payload": {"reason": "diagnostics"}},
        },
        now=100.1,
    )

    assert status == 202
    assert response["delivery_id"] == "snapshot-request-1"
    events = relay.poll(mac, since=0)["events"]
    request_events = [event for event in events if event["type"] == "snapshot.request"]
    assert request_events[0]["body"]["payload"] == {"reason": "diagnostics"}


def test_submit_refreshes_source_presence_for_immediate_replies():
    relay = service()
    mac = auth(relay, "mac-token")
    mobile = auth(relay, "mobile-token")
    relay.join(mac, now=100.0)

    status, response = relay.submit(
        mobile,
        {
            "type": "snapshot.request",
            "delivery_id": "snapshot-request-1",
            "target_role": "mac",
            "body": {"payload": {"reason": "diagnostics"}},
        },
        now=100.1,
    )

    assert status == 202
    assert response["target_online"] is True
    assert relay.presence_snapshot("room-a")["mobile"] is True
    status, response = relay.submit(
        mac,
        {
            "type": "conversation.snapshot",
            "delivery_id": "snapshot-snapshot-request-1",
            "target_role": "mobile",
            "body": {"payload": {"available": True, "message_count": 1}},
        },
        now=100.2,
    )

    assert status == 202
    assert response["queued"] is False


def test_mac_cannot_send_mobile_only_approval_response_event():
    relay = service()
    mac = auth(relay, "mac-token")

    status, response = relay.submit(
        mac,
        {
            "type": "approval.respond",
            "delivery_id": "bad-approval",
            "body": {"payload": {"approval_id": "approval-a", "value": "allow"}},
        },
        now=100.1,
    )

    assert status == 403
    assert response["error"] == "event_type_not_allowed"


def test_message_cannot_cross_pairing_rooms():
    relay = service()
    mac = auth(relay, "mac-token")
    other_mobile = auth(relay, "other-token")
    relay.join(mac, now=100.0)
    relay.join(other_mobile, now=100.0)

    status, response = relay.submit(
        other_mobile,
        {
            "type": "message.submit",
            "delivery_id": "other-1",
            "body": {"payload": {"text": "wrong room"}},
        },
        now=101.0,
    )

    assert status == 409
    assert response["error"] == "offline_queue_requires_encryption"
    assert relay.poll(mac, since=0)["events"] == []


def test_heartbeat_timeout_emits_offline_presence_update():
    relay = service()
    mac = auth(relay, "mac-token")
    mobile = auth(relay, "mobile-token")
    relay.join(mac, now=100.0)
    relay.join(mobile, now=100.0)

    events = relay.poll(mobile, since=0, now=101.0)["events"]

    assert any(event["type"] == "presence.changed" and event["body"] == {"role": "mac", "online": False} for event in events)
    assert relay.presence_snapshot("room-a")["mac"] is False


def test_long_poll_returns_when_event_arrives():
    relay = service()
    mac = auth(relay, "mac-token")
    mobile = auth(relay, "mobile-token")
    relay.join(mac, now=time.time())
    relay.join(mobile, now=time.time())
    before = relay.poll(mac, since=0)["events"][-1]["id"]

    status, response = relay.submit(
        mobile,
        {
            "type": "message.submit",
            "body": {"payload": {"text": "after"}},
        },
    )

    assert status == 202
    assert response["ok"] is True
    events = relay.poll(mac, since=before)["events"]
    assert [event["type"] for event in events] == ["message.submit"]


def test_event_store_is_bounded():
    relay = RelayService(
        RelayConfig(
            max_stored_events=2,
            tokens=[
                RelayToken(name="mac", role="mac", pairing_id="room-a", token="mac-token"),
                RelayToken(name="mobile", role="mobile", pairing_id="room-a", token="mobile-token"),
            ],
        )
    )
    mobile = auth(relay, "mobile-token")
    mac = auth(relay, "mac-token")
    relay.join(mac)
    relay.join(mobile)

    for idx in range(3):
        relay.submit(
            mobile,
            {
                "type": "message.submit",
                "delivery_id": f"mobile-{idx}",
                "body": {"payload": {"text": str(idx)}},
            },
        )

    events = relay.poll(mac, since=0)["events"]
    assert len(events) == 2
    assert [event["delivery_id"] for event in events] == ["mobile-1", "mobile-2"]
