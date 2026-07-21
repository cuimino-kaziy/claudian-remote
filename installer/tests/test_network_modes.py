import hashlib
import json

import pytest

from installer.claudian_remote_lifecycle.connection_profile import (
    ConnectionProfile,
    ConnectionProfileStore,
    LifecycleAuthority,
    ProfileError,
)
from installer.claudian_remote_lifecycle.lan_gateway import LanGatewayPlanner, LanNetworkGuard
from installer.claudian_remote_lifecycle.network_modes import ConnectionModeController, LocalRuntimePlanner
from installer.claudian_remote_lifecycle.tailscale import CommandResult, TailscaleController, TailscalePlanner
from installer.claudian_remote_lifecycle.vps import RelayArtifact, VpsDeploymentPlanner, VpsHost


def profile(mode="local_tailscale", **overrides):
    values = {
        "schema_version": 1,
        "mode": mode,
        "installation_id": "installation-a",
        "vault_id": "vault-a",
        "endpoint": "https://mac.tailnet.ts.net",
        "endpoint_audience": f"claudian-remote:{mode}:installation-a",
        "companion_credential_ref": f"installation-a:{mode}:companion",
        "mobile_credential_ref": f"installation-a:{mode}:mobile",
        "cursor": 0,
        "epoch": "epoch-a",
    }
    values.update(overrides)
    return ConnectionProfile.from_dict(values)


def test_connection_profile_is_exact_profile_bound_and_lifecycle_is_sole_writer(tmp_path):
    authority = LifecycleAuthority.create()
    store = ConnectionProfileStore(tmp_path / "connection-profile.json", authority)
    current = profile()

    with pytest.raises(PermissionError, match="lifecycle_authority_required"):
        store.write(current, authority=LifecycleAuthority.create())
    store.write(current, authority=authority)
    assert store.read() == current
    assert store.path.stat().st_mode & 0o777 == 0o600

    with pytest.raises(ProfileError, match="unsupported_connection_mode"):
        profile("automatic")
    with pytest.raises(ProfileError, match="profile_credential_binding_mismatch"):
        profile(companion_credential_ref="installation-a:remote_vps:companion")
    with pytest.raises(ProfileError, match="profile_credential_binding_mismatch"):
        profile(companion_credential_ref="installation-b:local_tailscale:companion")
    with pytest.raises(ProfileError, match="profile_credential_binding_mismatch"):
        profile(mobile_credential_ref="installation-a:local_tailscale:companion")
    with pytest.raises(ProfileError, match="local_relay_endpoint_must_be_https"):
        profile(endpoint="http://127.0.0.1:8787")


def test_failed_mode_never_falls_back_or_reuses_credentials(tmp_path):
    authority = LifecycleAuthority.create()
    store = ConnectionProfileStore(tmp_path / "profile.json", authority)
    old = profile()
    store.write(old, authority=authority)
    controller = ConnectionModeController(store, authority)

    blocked = controller.switch(
        profile("remote_vps", endpoint="https://relay.user.example"),
        validate=lambda _candidate: {"state": "blocked", "code": "invalid_tls"},
    )
    assert blocked["state"] == "blocked"
    assert blocked["fallback_performed"] is False
    assert store.read() == old

    ready = controller.switch(
        profile(
            "remote_vps",
            endpoint="https://relay.user.example",
            companion_credential_ref="installation-a:remote_vps:companion",
            mobile_credential_ref="installation-a:remote_vps:mobile",
        ),
        validate=lambda _candidate: {"state": "ready"},
    )
    assert ready["state"] == "ready"
    assert ready["steps"][:2] == ["settle_active_turn", "stop_old_exposure"]
    assert "reset_cursor_epoch" in ready["steps"]
    assert store.read().mode == "remote_vps"


def test_endpoint_change_requires_both_profile_credentials_to_rotate(tmp_path):
    authority = LifecycleAuthority.create()
    store = ConnectionProfileStore(tmp_path / "profile.json", authority)
    old = profile("remote_vps", endpoint="https://relay-one.user.example")
    store.write(old, authority=authority)
    controller = ConnectionModeController(store, authority)
    validation_called = False

    def validate(_candidate):
        nonlocal validation_called
        validation_called = True
        return {"state": "ready"}

    blocked = controller.switch(
        profile("remote_vps", endpoint="https://relay-two.user.example"),
        validate=validate,
    )
    assert blocked["code"] == "profile_credential_rotation_required"
    assert blocked["fallback_performed"] is False
    assert validation_called is False
    assert store.read() == old


def test_managed_runtime_keeps_relay_loopback_for_local_modes_and_stopped_for_vps():
    planner = LocalRuntimePlanner()
    tailscale = planner.plan(profile())
    assert tailscale == {
        "companion": {"desired": "running", "health_check": "authenticated_bridge_and_relay"},
        "relay": {"desired": "running", "bind": "127.0.0.1:8787", "health_check": "authenticated_loopback"},
        "exposure": "tailscale_serve",
    }
    remote = planner.plan(
        profile(
            "remote_vps",
            endpoint="https://relay.user.example",
            companion_credential_ref="installation-a:remote_vps:companion",
            mobile_credential_ref="installation-a:remote_vps:mobile",
        )
    )
    assert remote["relay"] == {"desired": "stopped", "bind": None, "health_check": "must_not_listen"}
    assert remote["exposure"] == "none"


@pytest.mark.parametrize(
    ("probe", "gate"),
    [
        ({"installed": False}, "tailscale_install_required"),
        ({"installed": True, "version": "1.80.0", "logged_in": False}, "tailscale_login_required"),
        ({"installed": True, "version": "1.40.0", "logged_in": True}, "tailscale_update_required"),
        (
            {"installed": True, "version": "1.80.0", "logged_in": True, "https_consent": False},
            "tailscale_https_consent_required",
        ),
    ],
)
def test_tailscale_preconditions_return_human_gates_without_partial_ready(probe, gate):
    planner = TailscalePlanner(lambda _args: CommandResult(0, json.dumps(probe), ""))
    result = planner.plan(loopback_port=8787, test_credential_ref="installation-a:tailscale:test")
    assert result["state"] == "blocked"
    assert result["gate"]["gate_type"] == gate
    assert result["ready"] is False
    assert result["commands"] == []


def test_tailscale_serve_plan_is_private_loopback_https_and_never_funnel():
    probe = {
        "installed": True,
        "version": "1.80.0",
        "logged_in": True,
        "https_consent": True,
        "dns_name": "mac.tailnet.ts.net",
    }
    planner = TailscalePlanner(lambda _args: CommandResult(0, json.dumps(probe), ""))
    result = planner.plan(loopback_port=8787, test_credential_ref="installation-a:tailscale:test")
    encoded = json.dumps(result)
    assert result["state"] == "prepared"
    assert result["endpoint"] == "https://mac.tailnet.ts.net"
    assert result["commands"] == [[
        "tailscale", "serve", "--bg", "--https=443", "--set-path=/",
        "http://127.0.0.1:8787",
    ]]
    assert "funnel" not in encoded.lower()
    assert "installation-a:tailscale:test" not in encoded
    assert result["probe"]["credential_ref"] == "<secure-reference>"


def test_tailscale_controller_uses_real_status_shape_serve_and_never_funnel():
    calls = []
    removed = False

    def runner(args):
        nonlocal removed
        calls.append(list(args))
        if list(args) == ["tailscale", "status", "--json"]:
            return CommandResult(
                0,
                json.dumps({
                    "BackendState": "Running",
                    "Version": "1.80.0",
                    "Self": {"DNSName": "mac.tailnet.ts.net."},
                    "CertDomains": ["mac.tailnet.ts.net"],
                }),
                "",
            )
        if list(args) == ["tailscale", "serve", "status", "--json"]:
            if removed:
                return CommandResult(0, "{}", "")
            return CommandResult(0, json.dumps({
                "TCP": {"443": {"HTTPS": True}},
                "Web": {
                    "mac.tailnet.ts.net:443": {
                        "Handlers": {"/": {"Proxy": "http://127.0.0.1:8787"}},
                    },
                },
                "AllowFunnel": {"mac.tailnet.ts.net:443": False},
            }), "")
        if list(args)[-1:] == ["off"]:
            removed = True
        return CommandResult(0, "", "")

    controller = TailscaleController(runner=runner)
    assert controller.preflight() == {"state": "ready", "endpoint": "https://mac.tailnet.ts.net"}
    controller.activate_serve(8787)
    assert controller.verify("https://mac.tailnet.ts.net") is True
    controller.remove_serve()
    encoded = json.dumps(calls).lower()
    assert "funnel" not in encoded
    assert [
        "tailscale", "serve", "--bg", "--https=443", "--set-path=/",
        "http://127.0.0.1:8787",
    ] in calls
    assert [
        "tailscale", "serve", "--https=443", "--set-path=/",
        "http://127.0.0.1:8787", "off",
    ] in calls
    assert ["tailscale", "serve", "reset"] not in calls


def test_tailscale_controller_requires_https_consent_before_serve_mutation():
    status = {
        "BackendState": "Running",
        "Version": "1.80.0",
        "Self": {"DNSName": "mac.tailnet.ts.net."},
        "CertDomains": [],
    }
    controller = TailscaleController(
        runner=lambda _args: CommandResult(0, json.dumps(status), "")
    )

    outcome = controller.preflight()

    assert outcome["state"] == "blocked"
    assert outcome["code"] == "tailscale_https_consent_required"
    assert outcome["gate"]["verification_probe"] == "tailscale_https_ready"
    assert controller.installed() is True
    assert controller.logged_in() is True
    assert controller.https_ready() is False


def test_tailscale_remove_fails_closed_when_owned_proxy_survives():
    target = "http://127.0.0.1:8787"

    def runner(args):
        if list(args) == ["tailscale", "serve", "status", "--json"]:
            return CommandResult(0, json.dumps({
                "TCP": {"443": {"HTTPS": True}},
                "Web": {"mac.tailnet.ts.net:443": {"Handlers": {"/": {"Proxy": target}}}},
            }), "")
        return CommandResult(0, "", "")

    with pytest.raises(RuntimeError, match="tailscale_serve_remove_unverified"):
        TailscaleController(runner=runner).remove_serve()


@pytest.mark.parametrize(
    "status",
    [
        {"TCP": {"443": {"HTTPS": True}}},
        {
            "TCP": {"443": {"HTTPS": True}},
            "Web": {"other.tailnet.ts.net:443": {"Handlers": {"/": {"Proxy": "http://127.0.0.1:8787"}}}},
        },
        {
            "TCP": {"443": {"HTTPS": True}},
            "Web": {"mac.tailnet.ts.net:443": {"Handlers": {"/": {"Proxy": "http://127.0.0.1:9999"}}}},
        },
        {
            "TCP": {"443": {"HTTPS": True}},
            "Web": {"mac.tailnet.ts.net:443": {"Handlers": {"/": {"Proxy": "http://127.0.0.1:8787"}}}},
            "AllowFunnel": {"mac.tailnet.ts.net:443": True},
        },
    ],
)
def test_tailscale_verify_rejects_unowned_wrong_or_public_routes(status):
    controller = TailscaleController(
        runner=lambda _args: CommandResult(0, json.dumps(status), "")
    )
    assert controller.verify("https://mac.tailnet.ts.net") is False


def test_lan_gateway_requires_consent_private_interface_tls_auth_and_network_guard():
    planner = LanGatewayPlanner()
    blocked = planner.plan(
        approved_interface="en0",
        approved_address="192.168.50.2",
        network_fingerprint="wifi:trusted",
        consent=False,
        certificate_ref="cert-a",
        test_credential_ref="test-a",
    )
    assert blocked["state"] == "blocked"
    assert blocked["gate"]["gate_type"] == "trusted_lan_consent_required"

    prepared = planner.plan(
        approved_interface="en0",
        approved_address="192.168.50.2",
        network_fingerprint="wifi:trusted",
        consent=True,
        certificate_ref="cert-a",
        test_credential_ref="test-a",
    )
    assert prepared["state"] == "prepared"
    assert prepared["listener"] == "192.168.50.2:9443"
    assert prepared["upstream"] == "http://127.0.0.1:8787"
    assert prepared["transport"] == "tls"
    assert prepared["application_auth_required"] is True

    guard = LanNetworkGuard("en0", "wifi:trusted")
    assert guard.observe("en0", "wifi:trusted") == {"state": "ready", "close_listener": False}
    changed = guard.observe("en0", "wifi:other")
    assert changed == {"state": "blocked", "code": "network_identity_changed", "close_listener": True}


def test_vps_plan_uses_exact_artifact_data_only_narrow_surface_and_compensating_rollback():
    body = b"exact relay artifact"
    artifact = RelayArtifact(
        version="0.2.0-beta.1",
        digest="sha256:" + hashlib.sha256(body).hexdigest(),
        bytes=body,
    )
    host = VpsHost(
        hostname="relay.user.example",
        os_id="ubuntu",
        os_version="24.04",
        architecture="x86_64",
        available_bytes=4 * 1024**3,
        host_key_fingerprint="SHA256:user-confirmed",
    )
    planner = VpsDeploymentPlanner()
    result = planner.plan(host, artifact, host_key_confirmed=True, tls_ready=True)
    encoded = json.dumps(result)
    assert result["state"] == "prepared"
    assert result["service_user"] == "claudian-remote"
    assert result["public_routes"] == ["HTTPS /api/v2/*", "WSS /api/v2/ws/*"]
    assert result["private_routes"] == ["health", "management", "database"]
    assert result["artifact"]["digest"] == artifact.digest
    assert result["remote_input"] == "validated_json_stdin"
    assert result["rollback"]
    assert "relay.example.invalid" not in encoded
    assert "shell" not in encoded.lower()

    failed = planner.verify_or_rollback(result, {"tls": False, "wss": True, "storage": True, "protocol": True})
    assert failed["state"] == "blocked"
    assert failed["code"] == "vps_verification_failed"
    assert failed["paired"] is False
    assert failed["completed_compensations"] == []


def test_vps_invalid_inputs_and_unconfirmed_host_key_fail_closed():
    planner = VpsDeploymentPlanner()
    artifact = RelayArtifact("0.2.0-beta.1", "sha256:" + "a" * 64, b"different")
    host = VpsHost("relay.user.example; reboot", "ubuntu", "24.04", "x86_64", 4 * 1024**3, "SHA256:x")
    with pytest.raises(ValueError, match="invalid_vps_hostname"):
        planner.plan(host, artifact, host_key_confirmed=True, tls_ready=True)

    host = VpsHost("relay.user.example", "ubuntu", "24.04", "x86_64", 4 * 1024**3, "SHA256:x")
    blocked = planner.plan(host, artifact, host_key_confirmed=False, tls_ready=True)
    assert blocked["state"] == "blocked"
    assert blocked["gate"]["gate_type"] == "vps_host_key_confirmation_required"
