import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from gateway.mac_companion.config import InMemoryKeychain
from installer.claudian_remote_lifecycle.launchd import InMemoryLaunchctl, LaunchAgentManager
from installer.claudian_remote_lifecycle.runtime import (
    BootstrapVerifiedReleaseSource,
    ReleaseValidationError,
    RuntimeLayout,
    StagedRelease,
)
from installer.claudian_remote_lifecycle.transaction import (
    LifecycleInterrupted,
    LocalTailscaleTransaction,
    TransactionDependencies,
)


class FixtureReleaseSource:
    """Test-only source representing an already signature-verified release."""

    def __init__(self, *, fail=False, stage_fail=False):
        self.fail = fail
        self.stage_fail = stage_fail
        self.calls = 0

    def verify(self, _plan):
        if self.fail:
            raise ValueError("manifest_signature_invalid")
        return {"release_version": "0.2.0-beta.1", "verified": True}

    def stage(self, plan, destination, runtime_root):
        self.calls += 1
        if self.stage_fail:
            raise ReleaseValidationError("runtime_asset_digest_mismatch")
        destination.mkdir(parents=True, exist_ok=False)
        (destination / "gateway").mkdir()
        (destination / "gateway" / "runtime.txt").write_text("signed runtime\n")
        plugin = destination / "plugin"
        plugin.mkdir()
        (plugin / "manifest.json").write_text(
            json.dumps({"id": "claudian-remote", "version": "0.2.0-beta.1"})
        )
        python = runtime_root / "environments" / str(plan["compatibility_set_id"]) / "bin" / "python"
        python.parent.mkdir(parents=True, exist_ok=True)
        python.write_text("fixture python")
        python.chmod(0o700)
        uv = runtime_root / "uv" / "0.10.12" / "uv"
        uv.parent.mkdir(parents=True, exist_ok=True)
        uv.write_text("fixture uv")
        uv.chmod(0o700)
        return StagedRelease(destination, plugin, python, uv, "0.2.0-beta.1")


class FakeTailscale:
    def __init__(self, *, ready=True):
        self.ready = ready
        self.serve_calls = 0
        self.removed = 0

    def preflight(self):
        if self.ready:
            return {"state": "ready", "endpoint": "https://mac.tailnet.ts.net"}
        return {
            "state": "blocked",
            "code": "tailscale_login_required",
            "gate": {
                "gate_type": "tailscale_login_required",
                "explanation": "Sign in to Tailscale.",
                "exact_action": "Open Tailscale and sign in.",
                "verification_probe": "tailscale_logged_in",
                "resume_reference": "ignored",
            },
        }

    def activate_serve(self, port):
        assert port == 8787
        self.serve_calls += 1

    def verify(self, endpoint):
        return endpoint == "https://mac.tailnet.ts.net"

    def remove_serve(self):
        self.removed += 1


def plan():
    return {
        "plan_id": "plan-" + "a" * 64,
        "compatibility_set_id": "claudian-remote-0.2.0-beta.1",
        "installation_id": "installation-a",
        "vault_id": "vault-a",
        "topology": {"mode": "local_tailscale"},
        "blockers": [],
    }


def dependencies(
    tmp_path, *, source=None, tailscale=None, pairing_ready=True,
    bridge_ready=True, interrupt_after=None, revoked=None,
):
    layout = RuntimeLayout(tmp_path / "app", tmp_path / "LaunchAgents")
    launchctl = InMemoryLaunchctl()
    return TransactionDependencies(
        layout=layout,
        release_source=source or FixtureReleaseSource(),
        launchd=LaunchAgentManager(layout, runner=launchctl),
        tailscale=tailscale or FakeTailscale(),
        keychain=InMemoryKeychain(),
        vault_path=lambda vault_id: tmp_path / f"vault-{vault_id}",
        health_probe=lambda: True,
        pairing_probe=lambda: pairing_ready,
        bridge_ready_probe=lambda: bridge_ready,
        legacy_credential_revoker=(
            lambda credential: ((revoked if revoked is not None else []).append(credential), {"verified": True})[1]
        ),
        migration_safe_probe=lambda: True,
        interruption_probe=(lambda phase: phase == interrupt_after),
        readiness_attempts=1,
        readiness_delay_seconds=0,
    ), launchctl


def test_legacy_migration_requires_obsidian_to_be_closed_before_any_mutation(tmp_path):
    deps, _ = dependencies(tmp_path)
    deps.migration_safe_probe = lambda: False
    vault = deps.vault_path("vault-a")
    legacy = vault / ".obsidian/plugins/whale-agent-bridge"
    legacy.mkdir(parents=True)
    (legacy / "manifest.json").write_text(json.dumps({"id": "whale-agent-bridge"}))
    (legacy / "data.json").write_text(json.dumps({"mobile_token": "still-active"}))
    enabled = vault / ".obsidian/community-plugins.json"
    enabled.parent.mkdir(parents=True, exist_ok=True)
    enabled.write_text(json.dumps(["whale-agent-bridge"]))

    outcome = LocalTailscaleTransaction(deps).install(plan(), operation_id="op-" + "0" * 32)
    assert outcome["code"] == "obsidian_close_for_migration_required"
    assert outcome["mutation_performed"] is False
    assert outcome["gate"]["verification_probe"] == "obsidian_closed_for_migration"
    assert legacy.exists()
    assert not deps.layout.base.exists()


def test_local_install_is_atomic_private_owned_and_idempotent(tmp_path):
    deps, launchctl = dependencies(tmp_path)
    transaction = LocalTailscaleTransaction(deps)

    first = transaction.install(plan(), operation_id="op-" + "1" * 32)
    assert first["state"] == "ready"
    assert deps.layout.current.resolve() == deps.layout.release_path(plan()["compatibility_set_id"])
    assert deps.layout.base.stat().st_mode & 0o777 == 0o700
    assert deps.layout.ownership_receipt.stat().st_mode & 0o777 == 0o600
    receipt = json.loads(deps.layout.ownership_receipt.read_text())
    resource_ids = {item["resource_id"] for item in receipt["resources"]}
    assert resource_ids >= {
        "managed_runtime", "managed_release_store", "active_release_pointer", "active_release",
        "relay_launch_agent", "companion_launch_agent", "plugin_directory",
    }
    assert any(value.startswith("plugin_shipped_file:") for value in resource_ids)
    active_release = next(item for item in receipt["resources"] if item["resource_id"] == "active_release")
    assert active_release["path"] == str(deps.layout.release_path(plan()["compatibility_set_id"]))
    assert all("secret" not in json.dumps(item).lower() for item in receipt["resources"])
    assert len(launchctl.loaded) == 2

    second = transaction.install(plan(), operation_id="op-" + "2" * 32)
    assert second["state"] == "ready"
    assert second["code"] == "already_ready"
    assert len(launchctl.loaded) == 2


@pytest.mark.parametrize("phase", ["before_staging", "before_activation", "after_activation"])
def test_interruption_has_stable_resume_or_rollback_without_duplicate_resources(tmp_path, phase):
    deps, _ = dependencies(tmp_path, interrupt_after=phase)
    transaction = LocalTailscaleTransaction(deps)
    with pytest.raises(LifecycleInterrupted, match=phase):
        transaction.install(plan(), operation_id="op-" + "3" * 32)

    deps.interruption_probe = lambda _phase: False
    resumed = transaction.install(plan(), operation_id="op-" + "3" * 32)
    assert resumed["state"] == "ready"
    assert deps.layout.current.resolve() == deps.layout.release_path(plan()["compatibility_set_id"])
    assert not list(deps.layout.staging.glob("*.partial"))


def test_signature_failure_and_health_failure_fail_closed_or_restore_prior(tmp_path):
    bad_source = FixtureReleaseSource(fail=True)
    deps, _ = dependencies(tmp_path, source=bad_source)
    with pytest.raises(ValueError, match="manifest_signature_invalid"):
        LocalTailscaleTransaction(deps).install(plan(), operation_id="op-" + "4" * 32)
    assert not deps.layout.current.exists()
    assert not deps.layout.launch_agents.exists()

    good, _ = dependencies(tmp_path / "rollback")
    LocalTailscaleTransaction(good).install(plan(), operation_id="op-" + "5" * 32)
    prior = good.layout.current.resolve()
    changed = dict(plan(), compatibility_set_id="claudian-remote-0.2.0-beta.2")
    good.health_probe = lambda: False
    failed = LocalTailscaleTransaction(good).install(changed, operation_id="op-" + "6" * 32)
    assert failed["state"] == "rolled_back"
    assert good.layout.current.resolve() == prior


def test_staging_failure_happens_before_legacy_revocation_or_vault_mutation(tmp_path):
    revoked = []
    deps, _ = dependencies(
        tmp_path,
        source=FixtureReleaseSource(stage_fail=True),
        revoked=revoked,
    )
    vault = deps.vault_path("vault-a")
    legacy = vault / ".obsidian/plugins/whale-agent-bridge"
    legacy.mkdir(parents=True)
    (legacy / "manifest.json").write_text(json.dumps({"id": "whale-agent-bridge"}))
    (legacy / "data.json").write_text(json.dumps({"mobile_token": "still-valid"}))
    enabled = vault / ".obsidian/community-plugins.json"
    enabled.parent.mkdir(parents=True, exist_ok=True)
    enabled.write_text(json.dumps(["whale-agent-bridge"]))

    with pytest.raises(ReleaseValidationError, match="runtime_asset_digest_mismatch"):
        LocalTailscaleTransaction(deps).install(plan(), operation_id="op-" + "e" * 32)

    assert revoked == []
    assert legacy.is_dir()
    assert json.loads((legacy / "data.json").read_text())["mobile_token"] == "still-valid"
    assert json.loads(enabled.read_text()) == ["whale-agent-bridge"]


def test_failure_after_migration_compensates_and_never_restores_token(tmp_path):
    class FailingKeychain(InMemoryKeychain):
        def set(self, reference, value):
            raise RuntimeError("keychain_unavailable")

    revoked = []
    deps, _ = dependencies(tmp_path, revoked=revoked)
    deps.keychain = FailingKeychain()
    vault = deps.vault_path("vault-a")
    legacy = vault / ".obsidian/plugins/whale-agent-bridge"
    legacy.mkdir(parents=True)
    (legacy / "manifest.json").write_text(json.dumps({"id": "whale-agent-bridge"}))
    (legacy / "data.json").write_text(json.dumps({"mobile_token": "retire-me"}))
    enabled = vault / ".obsidian/community-plugins.json"
    enabled.parent.mkdir(parents=True, exist_ok=True)
    enabled.write_text(json.dumps(["whale-agent-bridge"]))

    result = LocalTailscaleTransaction(deps).install(plan(), operation_id="op-" + "f" * 32)

    assert result["state"] == "rolled_back"
    assert result["code"] == "installation_failed_rolled_back"
    assert revoked == ["retire-me"]
    assert legacy.is_dir()
    assert "retire-me" not in (legacy / "data.json").read_text()
    assert json.loads(enabled.read_text()) == ["whale-agent-bridge"]


def test_pairing_is_a_verified_gate_after_runtime_activation(tmp_path):
    deps, _ = dependencies(tmp_path, pairing_ready=False)
    result = LocalTailscaleTransaction(deps).install(plan(), operation_id="op-" + "7" * 32)
    assert result["state"] == "blocked"
    assert result["code"] == "pairing_approval_required"
    assert deps.layout.current.exists()


def test_pairing_waits_until_the_selected_desktop_plugin_authenticates(tmp_path):
    deps, _ = dependencies(tmp_path, bridge_ready=False)
    transaction = LocalTailscaleTransaction(deps)
    operation_id = "op-" + "6" * 32

    waiting = transaction.install(plan(), operation_id=operation_id)

    assert waiting["state"] == "blocked"
    assert waiting["code"] == "desktop_plugin_bootstrap_required"
    assert waiting["gate"]["verification_probe"] == "desktop_plugin_authenticated"
    assert deps.layout.current.exists()
    assert deps.layout.ownership_receipt.is_file()
    deps.bridge_ready_probe = lambda: True
    resumed = transaction.install(plan(), operation_id=operation_id)
    assert resumed["state"] == "ready"


def test_clean_install_seeds_selected_vault_and_mode_into_synced_plugin_preferences(tmp_path):
    deps, _ = dependencies(tmp_path)

    result = LocalTailscaleTransaction(deps).install(plan(), operation_id="op-" + "2" * 32)

    assert result["state"] == "ready"
    data = json.loads((
        deps.vault_path("vault-a") / ".obsidian/plugins/claudian-remote/data.json"
    ).read_text())
    assert data["vault_id"] == "vault-a"
    assert data["connection_mode"] == "local_tailscale"


def test_existing_plugin_bound_to_another_vault_fails_before_replacement(tmp_path):
    deps, _ = dependencies(tmp_path)
    destination = deps.vault_path("vault-a") / ".obsidian/plugins/claudian-remote"
    destination.mkdir(parents=True)
    original_manifest = {"id": "claudian-remote", "version": "old"}
    (destination / "manifest.json").write_text(json.dumps(original_manifest))
    (destination / "data.json").write_text(json.dumps({"vault_id": "vault-other"}))

    with pytest.raises(ValueError, match="plugin_vault_binding_mismatch"):
        LocalTailscaleTransaction(deps).install(plan(), operation_id="op-" + "4" * 32)

    assert json.loads((destination / "manifest.json").read_text()) == original_manifest


def test_plugin_activation_write_failure_restores_original_directory(tmp_path, monkeypatch):
    deps, _ = dependencies(tmp_path)
    destination = deps.vault_path("vault-a") / ".obsidian/plugins/claudian-remote"
    destination.mkdir(parents=True)
    (destination / "manifest.json").write_text("old plugin")
    transaction = LocalTailscaleTransaction(deps)

    def fail_preferences(*_args, **_kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(
        "installer.claudian_remote_lifecycle.transaction.write_sync_preferences",
        fail_preferences,
    )
    result = transaction.install(plan(), operation_id="op-" + "5" * 32)

    assert result["state"] == "rolled_back"
    assert (destination / "manifest.json").read_text() == "old plugin"


def test_resume_after_activation_preserves_original_plugin_rollback_boundary(tmp_path):
    deps, _ = dependencies(tmp_path, interrupt_after="after_activation")
    plugin = deps.vault_path("vault-a") / ".obsidian/plugins/claudian-remote/manifest.json"
    plugin.parent.mkdir(parents=True)
    plugin.write_text("old plugin")
    transaction = LocalTailscaleTransaction(deps)

    with pytest.raises(LifecycleInterrupted, match="after_activation"):
        transaction.install(plan(), operation_id="op-" + "8" * 32)
    deps.interruption_probe = lambda _phase: False
    deps.health_probe = lambda: False
    failed = transaction.install(plan(), operation_id="op-" + "8" * 32)

    assert failed["state"] == "rolled_back"
    assert plugin.read_text() == "old plugin"


def test_resume_rejects_a_tampered_activated_connection_profile(tmp_path):
    deps, _ = dependencies(tmp_path, interrupt_after="after_activation")
    transaction = LocalTailscaleTransaction(deps)
    operation_id = "op-" + "c" * 32
    with pytest.raises(LifecycleInterrupted, match="after_activation"):
        transaction.install(plan(), operation_id=operation_id)
    profile = json.loads(deps.layout.connection_profile.read_text())
    profile["endpoint"] = "https://attacker.tailnet.ts.net"
    deps.layout.connection_profile.write_text(json.dumps(profile))
    deps.interruption_probe = lambda _phase: False

    failed = transaction.install(plan(), operation_id=operation_id)

    assert failed["state"] == "rolled_back"
    assert failed["code"] == "post_activation_verification_failed"


def test_resume_from_pairing_gate_preserves_original_plugin_rollback_boundary(tmp_path):
    deps, _ = dependencies(tmp_path, pairing_ready=False)
    plugin = deps.vault_path("vault-a") / ".obsidian/plugins/claudian-remote/manifest.json"
    plugin.parent.mkdir(parents=True)
    plugin.write_text("old plugin")
    transaction = LocalTailscaleTransaction(deps)
    operation_id = "op-" + "a" * 32

    waiting = transaction.install(plan(), operation_id=operation_id)
    assert waiting["code"] == "pairing_approval_required"
    deps.health_probe = lambda: False
    failed = transaction.install(plan(), operation_id=operation_id)

    assert failed["state"] == "rolled_back"
    assert plugin.read_text() == "old plugin"


def test_install_migrates_old_plugin_id_and_health_rollback_never_restores_token(tmp_path):
    revoked = []
    deps, _ = dependencies(tmp_path, revoked=revoked)
    vault = deps.vault_path("vault-a")
    legacy = vault / ".obsidian/plugins/whale-agent-bridge"
    legacy.mkdir(parents=True)
    (legacy / "manifest.json").write_text(json.dumps({"id": "whale-agent-bridge"}))
    (legacy / "data.json").write_text(json.dumps({
        "mobile_token": "legacy-secret",
        "vault_id": "vault-a",
        "notifications_enabled": False,
    }))
    enabled = vault / ".obsidian/community-plugins.json"
    enabled.parent.mkdir(parents=True, exist_ok=True)
    enabled.write_text(json.dumps(["whale-agent-bridge"]))

    ready = LocalTailscaleTransaction(deps).install(plan(), operation_id="op-" + "9" * 32)
    assert ready["state"] == "ready"
    assert revoked == ["legacy-secret"]
    assert not legacy.exists()
    assert json.loads(enabled.read_text()) == ["claudian-remote"]
    migrated = json.loads((vault / ".obsidian/plugins/claudian-remote/data.json").read_text())
    assert migrated["vault_id"] == "vault-a"
    assert "mobile_token" not in migrated

    failed_deps, _ = dependencies(tmp_path / "failed", revoked=[])
    failed_vault = failed_deps.vault_path("vault-a")
    failed_legacy = failed_vault / ".obsidian/plugins/whale-agent-bridge"
    failed_legacy.mkdir(parents=True)
    (failed_legacy / "manifest.json").write_text(json.dumps({"id": "whale-agent-bridge"}))
    (failed_legacy / "data.json").write_text(json.dumps({"mobile_token": "never-restore"}))
    failed_enabled = failed_vault / ".obsidian/community-plugins.json"
    failed_enabled.parent.mkdir(parents=True, exist_ok=True)
    failed_enabled.write_text(json.dumps(["whale-agent-bridge"]))
    failed_deps.health_probe = lambda: False

    rolled_back = LocalTailscaleTransaction(failed_deps).install(
        plan(), operation_id="op-" + "0" * 32
    )
    assert rolled_back["state"] == "rolled_back"
    assert failed_legacy.is_dir()
    assert json.loads(failed_enabled.read_text()) == ["whale-agent-bridge"]
    assert "never-restore" not in (failed_legacy / "data.json").read_text()


def test_install_blocks_legacy_and_current_enabled_before_release_or_plugin_mutation(tmp_path):
    source = FixtureReleaseSource()
    deps, _ = dependencies(tmp_path, source=source)
    vault = deps.vault_path("vault-a")
    old = vault / ".obsidian/plugins/whale-agent-bridge"
    new = vault / ".obsidian/plugins/claudian-remote"
    old.mkdir(parents=True)
    new.mkdir(parents=True)
    (old / "data.json").write_text(json.dumps({"mobile_token": "keep-until-resolved"}))
    enabled = vault / ".obsidian/community-plugins.json"
    enabled.parent.mkdir(parents=True, exist_ok=True)
    enabled.write_text(json.dumps(["whale-agent-bridge", "claudian-remote"]))

    with pytest.raises(ValueError, match="legacy_and_current_plugin_enabled"):
        LocalTailscaleTransaction(deps).install(plan(), operation_id="op-" + "d" * 32)
    assert source.calls == 0
    assert old.is_dir() and new.is_dir()
    assert "keep-until-resolved" in (old / "data.json").read_text()


def test_locked_private_environment_is_atomic_reused_and_mismatch_fails_closed(tmp_path):
    calls = []

    def runner(arguments, **kwargs):
        calls.append((arguments, kwargs))
        if "venv" in arguments:
            target = Path(arguments[-1])
            executable = target / "bin" / "python"
            executable.parent.mkdir(parents=True)
            executable.write_text("managed environment")
        return subprocess.CompletedProcess(arguments, 0, "", "")

    source = BootstrapVerifiedReleaseSource(tmp_path / "release", runner=runner)
    runtime = tmp_path / "runtime"
    companion = tmp_path / "companion"
    companion.mkdir()
    requirements = companion / "requirements.lock"
    requirements.write_text("aiohttp==3.14.1 --hash=sha256:" + "a" * 64 + "\n")
    python = tmp_path / "python3"
    uv = tmp_path / "uv"
    python.write_text("python")
    uv.write_text("uv")

    first = source._install_environment(
        compatibility_set_id="set-a",
        python=python,
        uv=uv,
        components={"companion": companion},
        runtime_root=runtime,
    )
    second = source._install_environment(
        compatibility_set_id="set-a",
        python=python,
        uv=uv,
        components={"companion": companion},
        runtime_root=runtime,
    )
    assert first == second == runtime / "environments" / "set-a" / "bin" / "python"
    assert len(calls) == 2
    assert all(call[1]["env"]["UV_NO_CONFIG"] == "1" for call in calls)
    assert all("CLAUDIAN_SECRET_CANARY" not in call[1]["env"] for call in calls)
    assert "--require-hashes" in calls[1][0]

    requirements.write_text("aiohttp==3.14.2 --hash=sha256:" + "b" * 64 + "\n")
    with pytest.raises(ReleaseValidationError, match="runtime_environment_mismatch"):
        source._install_environment(
            compatibility_set_id="set-a",
            python=python,
            uv=uv,
            components={"companion": companion},
            runtime_root=runtime,
        )


def test_runtime_subprocess_uses_environment_allowlist(tmp_path, monkeypatch):
    captured = []

    def runner(arguments, **kwargs):
        captured.append(kwargs["env"])
        return subprocess.CompletedProcess(arguments, 0, "", "")

    monkeypatch.setenv("CLAUDIAN_SECRET_CANARY", "must-not-cross-process-boundary")
    monkeypatch.setenv("PIP_INDEX_URL", "https://credential@example.invalid/simple")
    monkeypatch.setenv("UV_INDEX_URL", "https://credential@example.invalid/simple")
    source = BootstrapVerifiedReleaseSource(tmp_path / "release", runner=runner)
    source._run_runtime_command(["/bin/true"], environment_root=tmp_path / "runtime")

    assert len(captured) == 1
    assert "CLAUDIAN_SECRET_CANARY" not in captured[0]
    assert "PIP_INDEX_URL" not in captured[0]
    assert "UV_INDEX_URL" not in captured[0]


def test_runtime_subprocess_timeout_is_normalized_and_partial_environment_is_removed(tmp_path):
    def runner(arguments, **_kwargs):
        raise subprocess.TimeoutExpired(arguments, 300)

    source = BootstrapVerifiedReleaseSource(tmp_path / "release", runner=runner)
    runtime = tmp_path / "runtime"
    with pytest.raises(ReleaseValidationError, match="runtime_environment_install_failed"):
        source._run_runtime_command(["/bin/false"], environment_root=runtime)
    assert (runtime / "cache").is_dir()


def test_activation_waits_for_transient_runtime_readiness(tmp_path):
    deps, _ = dependencies(tmp_path)
    probes = iter((False, False, True))
    delays = []
    deps.health_probe = lambda: next(probes)
    deps.readiness_attempts = 3
    deps.readiness_delay_seconds = 0.1
    deps.sleep = delays.append

    result = LocalTailscaleTransaction(deps).install(
        plan(), operation_id="op-" + "b" * 32
    )

    assert result["state"] == "ready"
    assert delays == [0.1, 0.1]
