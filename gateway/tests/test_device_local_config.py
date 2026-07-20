import json

import pytest

from gateway.mac_companion.config import (
    CompanionRuntimeConfig,
    InMemoryKeychain,
    KeychainError,
    MacOSKeychain,
    load_secret_fields,
)


def test_public_companion_config_resolves_secret_references_from_keychain():
    keychain = InMemoryKeychain({
        "relay": "relay-secret",
        "bridge": "bridge-secret",
        "payload": "payload-secret",
    })
    public = {
        "relay_token_ref": "relay",
        "bridge_credential_ref": "bridge",
        "payload_secret_ref": "payload",
    }

    resolved = load_secret_fields(public, keychain)

    assert resolved == {
        "relay_token": "relay-secret",
        "bridge_credential": "bridge-secret",
        "payload_secret": "payload-secret",
    }
    encoded_public = json.dumps(public)
    assert "relay-secret" not in encoded_public
    assert "bridge-secret" not in encoded_public
    assert "payload-secret" not in encoded_public


def test_missing_or_unavailable_keychain_fails_closed():
    class FailingKeychain:
        def get(self, reference):
            raise KeychainError("unavailable")

    with pytest.raises(KeychainError, match="unavailable"):
        load_secret_fields({"relay_token_ref": "relay", "bridge_credential_ref": "bridge"}, FailingKeychain())

    with pytest.raises(KeychainError, match="missing secret reference"):
        load_secret_fields({"relay_token_ref": "relay", "bridge_credential_ref": "bridge"}, InMemoryKeychain())


def test_plaintext_credentials_are_rejected_from_public_config():
    with pytest.raises(KeychainError, match="plaintext credential"):
        load_secret_fields({"relay_token": "forbidden", "relay_token_ref": "relay"}, InMemoryKeychain({"relay": "safe"}))


def test_keychain_write_uses_stdin_and_never_places_credential_in_argv():
    calls = []

    class Result:
        returncode = 0
        stdout = ""
        stderr = ""

    def runner(argv, **kwargs):
        calls.append((argv, kwargs))
        return Result()

    store = MacOSKeychain(runner=runner)
    store.set("installation:bridge", "CANARY-KEYCHAIN-SECRET")

    argv, kwargs = calls[0]
    assert "CANARY-KEYCHAIN-SECRET" not in " ".join(argv)
    assert kwargs["input"] == "CANARY-KEYCHAIN-SECRET\n"
    assert argv[-1] == "-w"


def test_production_runtime_config_is_loopback_bridge_only(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({
        "relay_base_url": "https://relay.example.invalid",
        "relay_token_ref": "relay",
        "pairing_id": "installation-a",
        "bridge_credential_ref": "bridge",
        "bridge_credential_id": "bridge-a",
        "bridge_host": "127.0.0.1",
        "bridge_port": 27124,
    }), encoding="utf-8")
    config = CompanionRuntimeConfig.from_file(path, InMemoryKeychain({
        "relay": "relay-secret", "bridge": "bridge-secret"
    }))
    config.validate()
    assert config.bridge_credential == "bridge-secret"
    assert not hasattr(config, "adapter_base_url")
    assert config.resolved_relay_ws_url() == "wss://relay.example.invalid/api/v2/ws/mac"
