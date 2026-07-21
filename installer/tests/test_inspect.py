import io
import json
from pathlib import Path

from installer.claudian_remote_lifecycle.cli import LifecycleServices, main
from installer.claudian_remote_lifecycle.inspect import Inspector, LocalInspectionProbe


class FakeProbe:
    def __init__(self, *, claudian_version="2.0.4", vaults=None):
        self.claudian_version = claudian_version
        self._vaults = vaults if vaults is not None else [{"vault_id": "vault-a", "display_name": "Notes"}]
        self.calls = []

    def macos(self):
        self.calls.append("macos")
        return {"platform": "Darwin", "version": "15.5", "architecture": "arm64"}

    def obsidian(self):
        self.calls.append("obsidian")
        return {"installed": True, "version": "1.12.3", "running": True}

    def claudian(self):
        self.calls.append("claudian")
        return {"installed": True, "enabled": True, "version": self.claudian_version}

    def vaults(self):
        self.calls.append("vaults")
        return list(self._vaults)

    def installation(self):
        self.calls.append("installation")
        return {
            "installed": False,
            "compatibility_set_id": None,
            "operation_id": None,
            "secure_provisioning_available": True,
            "secure_provisioning_probe": "verified_test_adapter",
        }

    def network(self):
        self.calls.append("network")
        return {"tailscale_installed": True, "tailscale_logged_in": True}


def test_inspect_is_read_only_versioned_and_deterministic():
    probe = FakeProbe(vaults=[{"display_name": "Work", "vault_id": "vault-b"}, {"display_name": "Home", "vault_id": "vault-a"}])
    first = Inspector(probe).snapshot()
    second = Inspector(probe).snapshot()

    assert first == second
    assert first["snapshot_schema"] == "claudian-remote.inspection/v1"
    assert first["snapshot_id"].startswith("inspection-")
    assert first["read_only"] is True
    assert [vault["vault_id"] for vault in first["vaults"]] == ["vault-a", "vault-b"]
    assert first["support"]["reason_codes"] == ["vault_selection_required"]


def test_unsupported_claudian_blocks_mutation_but_inspection_still_returns_snapshot(tmp_path):
    output = io.StringIO()
    code = main(
        ["--state-dir", str(tmp_path), "inspect"],
        stdout=output,
        services=LifecycleServices(FakeProbe(claudian_version="2.0.3"), {}),
    )
    result = json.loads(output.getvalue())
    assert code == 2
    assert result["state"] == "blocked"
    assert result["code"] == "unsupported_claudian_version"
    assert result["data"]["snapshot"]["support"]["required_claudian_version"] == "2.0.4"
    assert result["data"]["mutation_performed"] is False


def test_local_probe_discovers_vault_and_claudian_without_exposing_local_path(tmp_path):
    home = tmp_path / "home"
    vault = tmp_path / "Private Person" / "Notes"
    plugin = vault / ".obsidian" / "plugins" / "claudian"
    plugin.mkdir(parents=True)
    (vault / ".obsidian" / "community-plugins.json").write_text('["claudian"]', encoding="utf-8")
    (plugin / "manifest.json").write_text(
        json.dumps({"id": "claudian", "name": "Claudian", "version": "2.0.4"}),
        encoding="utf-8",
    )
    obsidian_config = home / "Library" / "Application Support" / "obsidian"
    obsidian_config.mkdir(parents=True)
    (obsidian_config / "obsidian.json").write_text(
        json.dumps({"vaults": {"vault-opaque": {"path": str(vault), "open": True}}}),
        encoding="utf-8",
    )

    snapshot = Inspector(LocalInspectionProbe(home=home)).snapshot()
    encoded = json.dumps(snapshot)
    assert snapshot["vaults"] == [
        {
            "claudian_enabled": True,
            "claudian_version": "2.0.4",
            "display_name": "Notes",
            "open": True,
            "vault_id": "vault-opaque",
        }
    ]
    assert snapshot["claudian"]["enabled"] is True
    assert "secure_provisioning_missing" in snapshot["support"]["reason_codes"]
    assert snapshot["installation"]["secure_provisioning_available"] is False
    assert str(tmp_path) not in encoded
    assert "Private Person" not in encoded


def test_missing_secure_provisioning_is_bootstrappable_and_does_not_block_inspection(tmp_path):
    probe = FakeProbe()
    original = probe.installation
    probe.installation = lambda: {
        **original(),
        "secure_provisioning_available": False,
        "secure_provisioning_probe": "companion_route_unavailable",
    }
    output = io.StringIO()
    assert main(
        ["--state-dir", str(tmp_path), "inspect"],
        stdout=output,
        services=LifecycleServices(probe, {}),
    ) == 0
    result = json.loads(output.getvalue())
    assert result["state"] == "ready"
    assert result["code"] == "inspection_ready"
    assert "secure_provisioning_missing" in result["data"]["snapshot"]["support"]["reason_codes"]


def test_local_probe_hashes_profile_generation_without_exposing_endpoint(tmp_path):
    home = tmp_path / "home"
    root = home / "Library" / "Application Support" / "Claudian Remote"
    release = root / "releases" / "claudian-remote-0.2.0-beta.1"
    release.mkdir(parents=True)
    root.mkdir(parents=True, exist_ok=True)
    (root / "current").symlink_to(release)
    (root / "config").mkdir()
    endpoint = "https://private-relay.user.example"
    (root / "config" / "connection-profile.json").write_text(json.dumps({
        "mode": "remote_vps",
        "installation_id": "installation-a",
        "vault_id": "vault-a",
        "endpoint": endpoint,
        "endpoint_audience": "claudian-remote:remote_vps:installation-a",
        "epoch": "epoch-a",
        "cursor": 999,
    }), encoding="utf-8")

    installation = LocalInspectionProbe(home=home).installation()
    encoded = json.dumps(installation)
    assert installation["compatibility_set_id"] == "claudian-remote-0.2.0-beta.1"
    assert installation["profile_mode"] == "remote_vps"
    assert str(installation["profile_generation_id"]).startswith("profile-generation-")
    assert endpoint not in encoded
    assert str(tmp_path) not in encoded
