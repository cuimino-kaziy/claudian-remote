import json
import subprocess

import pytest

from installer.claudian_remote_lifecycle import keychain as bootstrap_keychain
from gateway.mac_companion import config as companion_keychain
from gateway.mac_companion.config import (
    CompanionRuntimeConfig,
    InMemoryKeychain,
    KeychainError,
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


@pytest.mark.parametrize("backend", [bootstrap_keychain, companion_keychain])
@pytest.mark.parametrize("credential", ["CANARY-KEYCHAIN-SECRET", '''spaces ' " \\ $HOME `literal`'''])
def test_keychain_write_uses_stdin_and_never_places_credential_in_argv(monkeypatch, backend, credential):
    monkeypatch.setattr(backend.sys, "platform", "darwin")
    calls = []

    def runner(argv, **kwargs):
        calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0, credential + "\n", "")

    store = backend.MacOSKeychain(runner=runner)
    store.set("installation:bridge", credential)

    argv, kwargs = calls[0]
    assert argv == ["/usr/bin/security", "-i"]
    escaped = credential.replace("\\", "\\\\").replace('"', '\\"')
    assert kwargs["input"] == (
        '"add-generic-password" "-U" "-s" "com.claudian.remote" '
        '"-a" "installation:bridge" "-w" "' + escaped + '"\n'
    )
    assert kwargs["input"].count("\n") == 1
    assert len(calls) == 2
    assert calls[1][0] == [
        "/usr/bin/security", "find-generic-password", "-s", "com.claudian.remote",
        "-a", "installation:bridge", "-w",
    ]
    assert all(credential not in " ".join(argv) for argv, _ in calls)
    assert all(not options.get("shell") for _, options in calls)


@pytest.mark.parametrize("backend", [bootstrap_keychain, companion_keychain])
def test_keychain_write_rejects_command_injection_and_non_ascii_before_running(backend):
    def runner(*_args, **_kwargs):
        pytest.fail("invalid input must never reach security")

    store = backend.MacOSKeychain(runner=runner)
    invalid_characters = [chr(code) for code in range(32)] + ["\x7f", "é", "密"]
    for character in invalid_characters:
        with pytest.raises(backend.KeychainError, match="invalid[_ ]credential"):
            store.set("installation:bridge", "CANARY" + character)
        with pytest.raises(backend.KeychainError, match="invalid[_ ]keychain[_ ]service"):
            backend.MacOSKeychain(runner=runner, service="service" + character).set(
                "installation:bridge", "CANARY"
            )
        with pytest.raises(backend.KeychainError, match="invalid[_ ]secret[_ ]reference"):
            store.set("installation:bridge" + character, "CANARY")


@pytest.mark.parametrize("backend", [bootstrap_keychain, companion_keychain])
@pytest.mark.parametrize("write_code,read_code,stored", [(1, 0, "CANARY"), (0, 0, "wrong"), (0, 0, ""), (0, 44, "")])
def test_keychain_write_requires_exact_readback(monkeypatch, backend, write_code, read_code, stored):
    monkeypatch.setattr(backend.sys, "platform", "darwin")
    calls = []

    def runner(argv, **kwargs):
        calls.append(argv)
        if argv[-1] == "-i":
            return subprocess.CompletedProcess(argv, write_code, "", "CANARY")
        return subprocess.CompletedProcess(argv, read_code, stored + "\n", "CANARY")

    with pytest.raises(backend.KeychainError, match="^unable[_ ]to[_ ]store[_ ]credential$"):
        backend.MacOSKeychain(runner=runner).set("installation:bridge", "CANARY")
    assert len(calls) == (1 if write_code else 2)


def test_production_runtime_config_is_loopback_bridge_only(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({
        "relay_base_url": "https://relay.example.invalid",
        "relay_token_ref": "relay",
        "pairing_id": "installation-a",
        "bridge_credential_ref": "bridge",
        "bridge_credential_id": "bridge-a",
        "bridge_host": "127.0.0.1",
        "bridge_port": 27125,
    }), encoding="utf-8")
    config = CompanionRuntimeConfig.from_file(path, InMemoryKeychain({
        "relay": "relay-secret", "bridge": "bridge-secret"
    }))
    config.validate()
    assert config.bridge_credential == "bridge-secret"
    assert not hasattr(config, "adapter_base_url")
    assert config.resolved_relay_ws_url() == "wss://relay.example.invalid/api/v2/ws/mac"


def test_companion_consumes_authoritative_connection_profile_and_matching_credential_ref(tmp_path):
    profile = tmp_path / "connection-profile.json"
    profile.write_text(json.dumps({
        "schema_version": 1,
        "mode": "local_tailscale",
        "installation_id": "installation-a",
        "vault_id": "vault-a",
        "endpoint": "https://mac.tailnet.ts.net",
        "endpoint_audience": "claudian-remote:local_tailscale:installation-a",
        "companion_credential_ref": "installation-a:local_tailscale:companion",
        "mobile_credential_ref": "installation-a:local_tailscale:mobile",
        "cursor": 0,
        "epoch": "epoch-a",
    }), encoding="utf-8")
    path = tmp_path / "config.json"
    path.write_text(json.dumps({
        "connection_profile_path": str(profile),
        "relay_token_ref": "installation-a:local_tailscale:companion",
        "pairing_id": "installation-a",
        "bridge_credential_ref": "installation-a:bridge",
        "bridge_bootstrap_ack_path": str(tmp_path / "bridge-bootstrap-ack.json"),
        "bootstrap_generation": "bootstrap-abcdefghijklmnop",
    }), encoding="utf-8")
    config = CompanionRuntimeConfig.from_file(path, InMemoryKeychain({
        "installation-a:local_tailscale:companion": "relay-secret",
        "installation-a:bridge": "bridge-secret",
    }))
    config.validate()
    assert config.relay_base_url == "https://mac.tailnet.ts.net"
    assert config.connection_mode == "local_tailscale"
    assert config.installation_id == "installation-a"
    assert config.vault_id == "vault-a"
    assert config.endpoint_audience == "claudian-remote:local_tailscale:installation-a"

    document = json.loads(path.read_text())
    document["relay_token_ref"] = "installation-a:remote_vps:companion"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(KeychainError, match="profile_credential_binding_mismatch"):
        CompanionRuntimeConfig.from_file(path, InMemoryKeychain({
            "installation-a:remote_vps:companion": "wrong",
            "installation-a:bridge": "bridge-secret",
        }))
