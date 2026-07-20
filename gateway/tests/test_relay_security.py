from gateway.relay.crypto import PayloadCrypto, redact_text
from gateway.relay.relay_server import RelayConfig, RelayService, RelayToken


def service():
    return RelayService(
        RelayConfig(
            tokens=[
                RelayToken(name="mac", role="mac", pairing_id="room-a", token="mac-token"),
                RelayToken(name="mobile", role="mobile", pairing_id="room-a", token="mobile-token"),
            ],
        )
    )


def auth(relay, token):
    item = relay.authenticate(f"Bearer {token}")
    assert item is not None
    return item


def test_role_tokens_cannot_impersonate_counterpart():
    relay = service()
    mac = auth(relay, "mac-token")
    mobile = auth(relay, "mobile-token")

    assert mac.role == "mac"
    assert mobile.role == "mobile"
    assert relay.authenticate("Bearer missing") is None

    status, response = relay.submit(
        mobile,
        {
            "target_role": "mobile",
            "type": "message.submit",
            "body": {"payload": {"text": "loopback"}},
        },
    )

    assert status == 400
    assert response["error"] == "invalid_target_role"


def test_mobile_cannot_send_mac_only_event_types():
    relay = service()
    mobile = auth(relay, "mobile-token")
    status, response = relay.submit(
        mobile,
        {
            "target_role": "mac",
            "type": "conversation.snapshot",
            "body": {"payload": {"messages": []}},
        },
    )

    assert status == 403
    assert response["error"] == "event_type_not_allowed"


def test_offline_plaintext_body_queue_is_refused():
    relay = service()
    mobile = auth(relay, "mobile-token")
    relay.join(mobile, now=100.0)

    status, response = relay.submit(
        mobile,
        {
            "type": "message.submit",
            "body": {"payload": {"text": "plaintext while mac offline"}},
        },
        now=101.0,
    )

    assert status == 409
    assert response["error"] == "offline_queue_requires_encryption"


def test_encrypted_offline_queue_does_not_store_plaintext():
    relay = service()
    mobile = auth(relay, "mobile-token")
    crypto = PayloadCrypto("pair secret", "room-a")
    encrypted = crypto.encrypt_json({"text": "private offline text"})

    status, response = relay.submit(
        mobile,
        {
            "type": "message.submit",
            "body": {"encrypted_payload": encrypted},
        },
        now=100.0,
    )

    assert status == 202
    assert response["queued"] is True
    stored = relay.poll(auth(relay, "mac-token"), since=0)["events"][0]["body"]
    assert "private offline text" not in str(stored)
    assert crypto.decrypt_json(stored["encrypted_payload"]) == {"text": "private offline text"}


def test_health_does_not_expose_rooms_or_token_names():
    relay = service()
    health = relay.health()
    text = str(health)

    assert health["ok"] is True
    assert "room-a" not in text
    assert "mac-token" not in text
    assert "mobile-token" not in text


def test_redaction_removes_tokens_secrets_and_paths():
    raw = 'Authorization: Bearer abcdefghijklmnop {"token":"secret-value","api_key":"key"} /Users/tester/private'

    redacted = redact_text(raw)

    assert "abcdefghijklmnop" not in redacted
    assert "secret-value" not in redacted
    assert "/Users/tester" not in redacted
    assert "[REDACTED]" in redacted
