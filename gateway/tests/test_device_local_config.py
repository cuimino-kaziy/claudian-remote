import json

import pytest

from gateway.mac_companion.config import (
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
        "adapter_token_ref": "bridge",
        "payload_secret_ref": "payload",
    }

    resolved = load_secret_fields(public, keychain)

    assert resolved == {
        "relay_token": "relay-secret",
        "adapter_token": "bridge-secret",
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
        load_secret_fields({"relay_token_ref": "relay", "adapter_token_ref": "bridge"}, FailingKeychain())

    with pytest.raises(KeychainError, match="missing secret reference"):
        load_secret_fields({"relay_token_ref": "relay", "adapter_token_ref": "bridge"}, InMemoryKeychain())


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
