from gateway.mac_companion.companion import CompanionConfig, MacCompanion
from gateway.relay.crypto import PayloadCrypto
from gateway.relay.relay_server import RelayConfig, RelayService, RelayToken
from gateway.tests.test_mac_companion import FakeAdapter


class ServiceBackedRelayClient:
    def __init__(self, service, token):
        self.service = service
        self.token = token

    def join(self):
        return self.service.join(self.token, session_id=f"{self.token.role}-session")

    def heartbeat(self):
        return self.service.heartbeat(self.token)

    def poll(self, since, timeout_seconds):
        return self.service.poll(self.token, since=since, timeout_seconds=0)

    def submit(self, event_type, body, delivery_id, target_role="mobile"):
        status, response = self.service.submit(
            self.token,
            {
                "type": event_type,
                "delivery_id": delivery_id,
                "target_role": target_role,
                "body": body,
            },
        )
        assert status == 202
        return {"ok": True, **response, "type": event_type, "body": body, "target_role": target_role}


def build_chain():
    service = RelayService(
        RelayConfig(
            tokens=[
                RelayToken(name="mac", role="mac", pairing_id="room-a", token="mac-token"),
                RelayToken(name="mobile", role="mobile", pairing_id="room-a", token="mobile-token"),
            ],
        )
    )
    mac_token = service.authenticate("Bearer mac-token")
    mobile_token = service.authenticate("Bearer mobile-token")
    assert mac_token and mobile_token
    service.join(mac_token)
    service.join(mobile_token)
    adapter = FakeAdapter()
    companion = MacCompanion(
        CompanionConfig(
            relay_base_url="https://relay.example.invalid",
            relay_token="mac-token",
            pairing_id="room-a",
            adapter_base_url="http://127.0.0.1:27123",
            adapter_token="local-rest-token",
            payload_secret="pair secret",
        ),
        ServiceBackedRelayClient(service, mac_token),
        adapter,
    )
    return service, mobile_token, companion, adapter


def test_mobile_text_envelope_round_trips_to_desktop_and_back_as_receipt():
    service, mobile_token, companion, adapter = build_chain()
    crypto = PayloadCrypto("pair secret", "room-a")

    status, submit_response = service.submit(
        mobile_token,
        {
            "type": "message.submit",
            "delivery_id": "mobile-hello-1",
            "body": {"encrypted_payload": crypto.encrypt_json({"text": "hello desktop"})},
        },
    )
    receipts = companion.run_once()
    mobile_events = service.poll(mobile_token, since=submit_response["event_id"], timeout_seconds=0)["events"]

    assert status == 202
    assert adapter.submitted == [{"text": "hello desktop", "delivery_id": "mobile-hello-1", "source": "mobile"}]
    assert receipts[0]["body"]["payload"]["status"] == "accepted"
    assert any(event["type"] == "message.receipt" for event in mobile_events)
    assert any(event["type"] == "conversation.snapshot" for event in mobile_events)


def test_duplicate_delivery_id_is_not_processed_twice_after_reconnect():
    service, mobile_token, companion, adapter = build_chain()

    for _ in range(2):
        status, _ = service.submit(
            mobile_token,
            {
                "type": "message.submit",
                "delivery_id": "dup-1",
                "body": {"payload": {"text": "only once"}},
            },
        )
        assert status == 202

    receipts = companion.run_once()

    assert len(adapter.submitted) == 1
    assert [receipt["body"]["payload"]["status"] for receipt in receipts] == ["accepted", "duplicate"]
