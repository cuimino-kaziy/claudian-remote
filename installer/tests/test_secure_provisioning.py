import asyncio
import json

import pytest

from gateway.mac_companion.bridge_server import BridgeIdentityStore, CompanionBridgeServer
from gateway.mac_companion.config import InMemoryKeychain
from gateway.mac_companion.pairing_admin import PairingAdminProxy
from installer.claudian_remote_lifecycle.provisioning import (
    PairingAdminProvisioner,
    SecureInputFile,
    verify_bridge_bootstrap_ack,
)
from installer.claudian_remote_lifecycle.runtime import RuntimeLayout


def test_secure_input_is_0600_consumed_once_and_deleted_on_failure(tmp_path):
    path = tmp_path / "input.json"
    SecureInputFile.create(path, {"value": "one-time"})
    assert path.stat().st_mode & 0o777 == 0o600
    assert SecureInputFile(path).consume()["value"] == "one-time"
    assert not path.exists()

    bad = tmp_path / "bad.json"
    SecureInputFile.create(bad, {"value": "one-time"})
    with pytest.raises(RuntimeError):
        SecureInputFile(bad).consume(lambda _value: (_ for _ in ()).throw(RuntimeError("boom")))
    assert not bad.exists()


def test_pairing_admin_and_bridge_secrets_live_in_keychain_not_public_config(tmp_path):
    layout = RuntimeLayout(tmp_path / "app", tmp_path / "LaunchAgents")
    keychain = InMemoryKeychain()
    provisioner = PairingAdminProvisioner(layout, keychain)
    result = provisioner.provision(
        installation_id="installation-a",
        vault_id="vault-a",
        endpoint="https://mac.tailnet.ts.net",
        endpoint_audience="claudian-remote:local_tailscale:installation-a",
    )
    assert result["secure_provisioning_available"] is True
    relay = layout.relay_config.read_text()
    companion = layout.companion_config.read_text()
    assert "token_ref" in relay and "token\"" not in relay
    assert "pairing_admin_credential_ref" in companion
    assert all(secret not in relay + companion for secret in keychain.values.values())
    assert layout.relay_config.stat().st_mode & 0o777 == 0o600
    assert layout.bridge_bootstrap_for("vault-a").is_file()
    assert not layout.bridge_bootstrap_for("vault-other").exists()
    assert provisioner.probe(result["provisioning_ref"]) is True


def test_bridge_bootstrap_ack_is_bound_to_current_generation_and_selected_vault(tmp_path):
    layout = RuntimeLayout(tmp_path / "app", tmp_path / "LaunchAgents")
    provisioner = PairingAdminProvisioner(layout, InMemoryKeychain())
    provisioner.provision(
        installation_id="installation-a",
        vault_id="vault-a",
        endpoint="https://mac.tailnet.ts.net",
        endpoint_audience="claudian-remote:local_tailscale:installation-a",
    )
    state = json.loads(layout.secure_provisioning.read_text())
    layout.bridge_bootstrap_ack.write_text(json.dumps({
        "ack_schema": "claudian-remote.bridge-bootstrap-ack/v1",
        "installation_id": "installation-a",
        "vault_id": "vault-a",
        "bridge_credential_id": "installation-a:bridge",
        "bootstrap_generation": state["bootstrap_generation"],
    }))
    assert verify_bridge_bootstrap_ack(layout) is True

    ack = json.loads(layout.bridge_bootstrap_ack.read_text())
    ack["vault_id"] = "vault-other"
    layout.bridge_bootstrap_ack.write_text(json.dumps(ack))
    assert verify_bridge_bootstrap_ack(layout) is False

    ack["vault_id"] = "vault-a"
    ack["bootstrap_generation"] = "bootstrap-stale-generation"
    layout.bridge_bootstrap_ack.write_text(json.dumps(ack))
    assert verify_bridge_bootstrap_ack(layout) is False


@pytest.mark.asyncio
async def test_authenticated_bridge_exposes_pairing_admin_proxy_without_secret_disclosure():
    calls = []

    async def request(method, path, body, authorization):
        calls.append((method, path, body, authorization))
        return {"ok": True, "devices": []}

    proxy = PairingAdminProxy(
        relay_base_url="https://mac.tailnet.ts.net",
        credential_provider=lambda: "admin-secret",
        request=request,
    )
    identities = BridgeIdentityStore()
    server = CompanionBridgeServer(identities=identities, management_handler=proxy.handle)
    result = await server._handle_management("pairing.devices", {})
    assert result == {"ok": True, "devices": []}
    assert calls == [("GET", "/api/v2/pairing/devices", None, "Bearer admin-secret")]
    assert "admin-secret" not in json.dumps(result)
    with pytest.raises(Exception, match="management_operation_forbidden"):
        await server._handle_management("arbitrary.command", {})


@pytest.mark.asyncio
async def test_pairing_admin_proxy_rejects_untrusted_inputs_and_redacts_transport_errors():
    async def failing_request(_method, _path, _body, _authorization):
        raise OSError("https://private.example.test/path?secret=value")

    proxy = PairingAdminProxy(
        relay_base_url="https://mac.tailnet.ts.net",
        credential_provider=lambda: "admin-secret",
        request=failing_request,
    )
    with pytest.raises(Exception, match="^management_identifier_invalid$"):
        await proxy.handle("pairing.device.revoke", {"device_id": "../escape"})
    with pytest.raises(Exception, match="^management_revoke_reason_invalid$"):
        await proxy.handle("pairing.device.revoke", {"device_id": "iphone-a", "reason": "private details"})
    with pytest.raises(Exception, match="^management_transport_failed$") as error:
        await proxy.handle("pairing.devices", {})
    assert "private.example" not in str(error.value)
