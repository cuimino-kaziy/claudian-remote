import hashlib
import json
import subprocess
import io
import tarfile
from pathlib import Path

import pytest

from gateway.mac_companion.config import InMemoryKeychain
from installer.claudian_remote_lifecycle.launchd import InMemoryLaunchctl, LaunchAgentManager
from installer.claudian_remote_lifecycle.legacy_authority import (
    LegacyCredentialRetirementService,
    LegacyRetirementOutcomeUnknown,
    RetirementCommit,
    RetirementReconciliationResult,
)
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


BETA4_VERSION = "0.2.0-beta.4"
BETA4_SET_ID = f"claudian-remote-{BETA4_VERSION}"

COMMUNITY_VERSION = "0.2.0"
COMMUNITY_SET_ID = f"claudian-remote-{COMMUNITY_VERSION}"


class FixtureRetirementService(LegacyCredentialRetirementService):
    def __init__(self, calls=None, *, outcome="commit"):
        self.calls = calls if calls is not None else []
        self.outcome = outcome

    def retire(
        self,
        *,
        credential,
        operation_id,
        plan_id,
        installation_id,
        vault_id,
        role,
    ):
        self.calls.append(credential.read_once().decode("utf-8"))
        if self.outcome != "commit":
            return self.outcome
        return RetirementCommit(
            authority_instance_id="authority-a",
            authority_origin_digest="a" * 64,
            runtime_key_id="runtime-key-a",
            owner_id="owner-a",
            installation_id=installation_id,
            mac_id="mac-a",
            vault_id=vault_id,
            role=role,
            slot_id="slot-a",
            old_generation=1,
            target_generation=2,
            operation_id=operation_id,
            plan_id=plan_id,
            release_digest="b" * 64,
            helper_digest="c" * 64,
            nonce_digest="d" * 64,
            idempotency_digest="e" * 64,
            proof_digest="f" * 64,
            consumed_at_epoch=1_800_000_000,
        )

    def authorized(self, *, operation_id, plan_id):
        return True


class AuthorizationRequiredRetirementService(FixtureRetirementService):
    def authorized(self, *, operation_id, plan_id):
        return False


class ForbiddenRetirementService(FixtureRetirementService):
    """Fail a non-legacy journey if it touches the legacy authority seam."""

    def __init__(self):
        super().__init__()
        self.authority_calls = []

    def authorized(self, *, operation_id, plan_id):
        self.authority_calls.append(("authorized", operation_id, plan_id))
        raise AssertionError("legacy authority must not be called")

    def retire(self, **kwargs):
        self.authority_calls.append(("retire", kwargs.get("operation_id")))
        raise AssertionError("legacy authority must not be called")

    def reconcile(self, **kwargs):
        self.authority_calls.append(("reconcile", kwargs.get("operation_id")))
        raise AssertionError("legacy authority must not be called")


class AmbiguousRetirementService(FixtureRetirementService):
    def __init__(self, *, reconciliation):
        super().__init__()
        self.reconciliation = reconciliation
        self.dispatches = 0
        self.reconciliations = 0

    def retire(self, *, credential, **_kwargs):
        self.dispatches += 1
        credential.read_once()
        raise LegacyRetirementOutcomeUnknown("response_lost_after_dispatch")

    def reconcile(
        self,
        *,
        credential,
        operation_id,
        plan_id,
        installation_id,
        vault_id,
        role,
        **_kwargs,
    ):
        self.reconciliations += 1
        credential.read_once()
        commit = (
            FixtureRetirementService().retire(
                credential=_ReusableCredential(b"unused"),
                operation_id=operation_id,
                plan_id=plan_id,
                installation_id=installation_id,
                vault_id=vault_id,
                role=role,
            )
            if self.reconciliation == "retired"
            else None
        )
        return RetirementReconciliationResult(self.reconciliation, commit)


class _ReusableCredential:
    def __init__(self, value):
        self.value = value

    def read_once(self):
        return self.value


class FixtureReleaseSource:
    """Test-only source representing an already signature-verified release."""

    def __init__(self, *, fail=False, stage_fail=False):
        self.fail = fail
        self.stage_fail = stage_fail
        self.calls = 0

    def verify(self, _plan):
        if self.fail:
            raise ValueError("manifest_signature_invalid")
        return {"release_version": BETA4_VERSION, "verified": True}

    def stage(self, plan, destination, runtime_root):
        self.calls += 1
        if self.stage_fail:
            raise ReleaseValidationError("runtime_asset_digest_mismatch")
        destination.mkdir(parents=True, exist_ok=False)
        (destination / "gateway").mkdir()
        (destination / "gateway" / "runtime.txt").write_text("signed runtime\n")
        for component in ("companion", "relay", "installer"):
            (destination / component).mkdir()
        plugin = destination / "plugin"
        plugin.mkdir()
        version = str(plan["compatibility_set_id"]).removeprefix("claudian-remote-")
        (plugin / "manifest.json").write_text(
            json.dumps({"id": "claudian-remote", "version": version})
        )
        python = runtime_root / "environments" / str(plan["compatibility_set_id"]) / "bin" / "python"
        python.parent.mkdir(parents=True, exist_ok=True)
        python.write_text("fixture python")
        python.chmod(0o700)
        uv = runtime_root / "uv" / "0.10.12" / "uv"
        uv.parent.mkdir(parents=True, exist_ok=True)
        uv.write_text("fixture uv")
        uv.chmod(0o700)
        return StagedRelease(destination, plugin, python, uv, version)


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

    def owned_serve_absent(self, port=8787):
        return port == 8787 and self.serve_calls == 0


def plan():
    return {
        "plan_id": "plan-" + "a" * 64,
        "compatibility_set_id": BETA4_SET_ID,
        "installation_id": "installation-a",
        "vault_id": "vault-a",
        "topology": {"mode": "local_tailscale"},
        "blockers": [],
    }


def legacy_plan(*, prior_operation_terminal=True):
    return {
        **plan(),
        "journey": "legacy_upgrade",
        "prior_operation_terminal": prior_operation_terminal,
    }


def current_update_plan(*, policy="preserve", suffix="2"):
    return {
        **plan(),
        "plan_id": "plan-" + suffix * 64,
        "compatibility_set_id": f"claudian-remote-0.2.0-beta.{suffix}",
        "journey": "current_update",
        "pairing_identity_policy": policy,
    }


def dependencies(
    tmp_path, *, source=None, tailscale=None, pairing_ready=True,
    bridge_ready=True, interrupt_after=None, revoked=None,
    pairing_devices=None, pairing_revocations=None,
):
    layout = RuntimeLayout(tmp_path / "app", tmp_path / "LaunchAgents")
    launchctl = InMemoryLaunchctl()
    devices = (
        pairing_devices
        if pairing_devices is not None
        else ({"iphone-a"} if pairing_ready else set())
    )
    device_revocations = pairing_revocations if pairing_revocations is not None else []

    def revoke_pairing_device(device_id, reason):
        device_revocations.append((device_id, reason))
        devices.discard(device_id)
        return {"state": "ready", "code": "device_revoked"}

    return TransactionDependencies(
        layout=layout,
        release_source=source or FixtureReleaseSource(),
        launchd=LaunchAgentManager(layout, runner=launchctl),
        tailscale=tailscale or FakeTailscale(),
        keychain=InMemoryKeychain(),
        vault_path=lambda vault_id: tmp_path / f"vault-{vault_id}",
        health_probe=lambda: True,
        pairing_probe=lambda: pairing_ready,
        active_pairing_device_ids=lambda: devices,
        revoke_pairing_device=revoke_pairing_device,
        bridge_ready_probe=lambda: bridge_ready,
        legacy_credential_revoker=FixtureRetirementService(revoked),
        migration_safe_probe=lambda: True,
        interruption_probe=(lambda phase: phase == interrupt_after),
        readiness_attempts=1,
        readiness_delay_seconds=0,
        local_listener_absent_probe=lambda port: port == 8787,
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
            "relay_launch_agent", "companion_launch_agent", "availability_launch_agent",
            "availability_config", "plugin_directory",
    }
    assert any(value.startswith("plugin_shipped_file:") for value in resource_ids)
    active_release = next(item for item in receipt["resources"] if item["resource_id"] == "active_release")
    assert active_release["path"] == str(deps.layout.release_path(plan()["compatibility_set_id"]))
    assert all("secret" not in json.dumps(item).lower() for item in receipt["resources"])
    assert len(launchctl.loaded) == 3

    second = transaction.install(plan(), operation_id="op-" + "2" * 32)
    assert second["state"] == "ready"
    assert second["code"] == "already_ready"
    assert len(launchctl.loaded) == 3


def test_reinstall_recreates_ownership_receipt_after_receipt_loss(tmp_path):
    deps, launchctl = dependencies(tmp_path)
    transaction = LocalTailscaleTransaction(deps)
    expected_plan = plan()

    assert transaction.install(expected_plan, operation_id="op-" + "1" * 32)["code"] == "installation_ready"
    assert deps.layout.ownership_receipt.is_file()

    # Simulate an interrupted installation that activated successfully but
    # lost its ownership receipt before recording (or receipt loss after a
    # completed install). A missing receipt must never satisfy readiness, so
    # reinstall must recreate and validate the receipt rather than claiming
    # already_ready.
    deps.layout.ownership_receipt.unlink()
    assert deps.layout.ownership_receipt.is_file() is False

    recovered = transaction.install(expected_plan, operation_id="op-" + "2" * 32)
    assert recovered["state"] == "ready"
    assert recovered["code"] == "installation_ready"
    assert deps.layout.ownership_receipt.is_file()
    receipt = json.loads(deps.layout.ownership_receipt.read_text())
    assert receipt["receipt_schema"] == "claudian-remote.ownership/v1"
    assert receipt["plan_id"] == expected_plan["plan_id"]
    assert transaction.verify(expected_plan)["code"] == "verification_ready"


def test_consumed_bridge_handoff_requires_bound_ack_and_preserves_ownership(tmp_path):
    from installer.claudian_remote_lifecycle.uninstall import OwnershipUninstaller

    deps, _ = dependencies(tmp_path)
    transaction = LocalTailscaleTransaction(deps)
    expected_plan = plan()
    assert transaction.install(expected_plan, operation_id="op-" + "c" * 32)["state"] == "ready"
    layout = deps.layout
    receipt_before = layout.ownership_receipt.read_bytes()
    bootstrap = layout.bridge_bootstrap_for(expected_plan["vault_id"])
    original_bootstrap = bootstrap.read_bytes()
    bootstrap.unlink()  # The plugin consumes this one-use handoff after activation.
    assert transaction.verify(expected_plan)["state"] == "blocked"

    provisioning_before = layout.secure_provisioning.read_bytes()
    provisioning = json.loads(provisioning_before)
    ack = {"ack_schema": "claudian-remote.bridge-bootstrap-ack/v1", **{
        field: provisioning[field] for field in (
            "installation_id", "vault_id", "bridge_credential_id", "bootstrap_generation"
        )
    }}
    for field in ("bootstrap_generation", "vault_id", "installation_id", "bridge_credential_id"):
        layout.bridge_bootstrap_ack.write_text(json.dumps({**ack, field: "foreign-or-stale"}))
        assert transaction.verify(expected_plan)["state"] == "blocked"
    layout.bridge_bootstrap_ack.write_text(json.dumps(ack))
    assert transaction.verify(expected_plan)["code"] == "verification_ready"
    assert layout.ownership_receipt.read_bytes() == receipt_before

    # ACK acceptance does not waive any extant digest or other required file.
    bootstrap.write_bytes(original_bootstrap + b" ")
    assert transaction.verify(expected_plan)["state"] == "blocked"
    bootstrap.unlink()
    agent_before = layout.relay_launch_agent.read_bytes()
    layout.relay_launch_agent.unlink()
    assert transaction.verify(expected_plan)["state"] == "blocked"
    layout.relay_launch_agent.write_bytes(agent_before)
    layout.secure_provisioning.write_text(json.dumps({**provisioning, "bootstrap_generation": "forged"}))
    layout.bridge_bootstrap_ack.write_text(json.dumps({**ack, "bootstrap_generation": "forged"}))
    assert transaction.verify(expected_plan)["state"] == "blocked"
    layout.secure_provisioning.write_bytes(provisioning_before)
    layout.bridge_bootstrap_ack.write_text(json.dumps(ack))

    uninstaller = OwnershipUninstaller(
        layout, stop_owned_services=lambda: None, revoke_credentials=lambda: None,
    )
    assert uninstaller.preflight(require_present=True)["state"] == "ready"
    assert layout.ownership_receipt.read_bytes() == receipt_before
    assert uninstaller.uninstall()["code"] == "uninstall_completed"
    assert not bootstrap.exists()


def test_fresh_and_current_journeys_share_the_tail_without_legacy_calls_or_journals(
    tmp_path,
):
    devices = {"iphone-existing"}
    device_revocations = []
    deps, _ = dependencies(
        tmp_path,
        pairing_devices=devices,
        pairing_revocations=device_revocations,
    )
    forbidden = ForbiddenRetirementService()
    deps.legacy_credential_revoker = forbidden
    transaction = LocalTailscaleTransaction(deps)
    shared_phases = [
        "staging",
        "secure_provisioning",
        "plugin_activation",
        "launchd",
        "tailscale_serve",
        "verified",
        "paired",
    ]

    fresh_operation = "op-" + "a" * 32
    assert transaction.install(plan(), operation_id=fresh_operation)["state"] == "ready"

    preserve_operation = "op-" + "b" * 32
    preserve = current_update_plan(policy="preserve", suffix="2")
    assert transaction.install(preserve, operation_id=preserve_operation)["state"] == "ready"

    rotate_operation = "op-" + "c" * 32
    rotate = current_update_plan(policy="rotate", suffix="3")
    waiting = transaction.install(rotate, operation_id=rotate_operation)
    assert waiting["code"] == "pairing_approval_required"
    assert device_revocations == [("iphone-existing", "profile_changed")]
    devices.add("iphone-replacement")
    assert transaction.install(rotate, operation_id=rotate_operation)["state"] == "ready"

    assert forbidden.authority_calls == []
    for operation_id in (fresh_operation, preserve_operation, rotate_operation):
        assert not (deps.layout.state / f"{operation_id}.legacy-plugin.json").exists()
        journal = json.loads(
            (deps.layout.state / f"{operation_id}.transaction.json").read_text()
        )
        assert journal["operation_id"] == operation_id
        assert journal["phase"] == "ready"
        assert journal["completed_phases"] == shared_phases


@pytest.mark.parametrize(
    "corruption",
    [
        "invalid_schema",
        "wrong_operation",
        "wrong_plan",
        "wrong_compatibility_set",
        "wrong_plugin_root",
        "wrong_resource_digest",
    ],
)
def test_ready_fails_closed_when_ownership_receipt_is_invalid_or_misbound(tmp_path, corruption):
    deps, _ = dependencies(tmp_path)
    transaction = LocalTailscaleTransaction(deps)
    operation_id = "op-" + "1" * 32
    expected_plan = plan()
    assert transaction.install(expected_plan, operation_id=operation_id)["state"] == "ready"
    assert transaction.verify(expected_plan)["code"] == "verification_ready"

    receipt_path = deps.layout.ownership_receipt
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    if corruption == "invalid_schema":
        receipt["receipt_schema"] = "claudian-remote.ownership/unknown"
    elif corruption == "wrong_operation":
        receipt["operation_id"] = "op-" + "f" * 32
    elif corruption == "wrong_plan":
        receipt["plan_id"] = "plan-" + "f" * 64
    elif corruption == "wrong_compatibility_set":
        receipt["compatibility_set_id"] = "claudian-remote-0.2.0-beta.other"
    elif corruption == "wrong_plugin_root":
        receipt["plugin_root"] = str(tmp_path / "Other" / ".obsidian" / "plugins" / "claudian-remote")
    elif corruption == "wrong_resource_digest":
        next(item for item in receipt["resources"] if item.get("digest"))["digest"] = "0" * 64
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")

    assert transaction.verify(expected_plan) == {
        "state": "blocked",
        "code": "verification_failed",
        "mutation_performed": False,
    }


def test_current_update_preserve_survives_activation_and_restart_without_repair(tmp_path):
    devices = {"iphone-existing"}
    revocations = []
    deps, _ = dependencies(
        tmp_path,
        pairing_devices=devices,
        pairing_revocations=revocations,
    )
    transaction = LocalTailscaleTransaction(deps)
    assert transaction.install(plan(), operation_id="op-" + "1" * 32)["state"] == "ready"
    deps.revoke_pairing_device = None

    update = current_update_plan(policy="preserve", suffix="2")
    operation_id = "op-" + "2" * 32
    result = transaction.install(update, operation_id=operation_id)

    assert result["state"] == "ready"
    assert devices == {"iphone-existing"}
    assert revocations == []
    restarted = LocalTailscaleTransaction(deps).install(update, operation_id=operation_id)
    assert restarted["state"] == "ready"
    assert restarted["code"] == "already_ready"
    assert revocations == []


def test_current_update_rotate_waits_until_verified_then_repairs_in_the_same_operation(tmp_path):
    devices = {"iphone-old"}
    revocations = []
    deps, _ = dependencies(
        tmp_path,
        pairing_devices=devices,
        pairing_revocations=revocations,
    )
    transaction = LocalTailscaleTransaction(deps)
    transaction.install(plan(), operation_id="op-" + "3" * 32)

    update = current_update_plan(policy="rotate", suffix="9")
    operation_id = "op-" + "4" * 32
    waiting = transaction.install(update, operation_id=operation_id)

    assert waiting["state"] == "blocked"
    assert waiting["code"] == "pairing_approval_required"
    assert waiting["re_pair_required"] is True
    assert devices == set()
    assert revocations == [("iphone-old", "profile_changed")]
    assert transaction.rollback(update, operation_id=operation_id) == {
        "state": "blocked",
        "code": "rollback_unavailable_after_pairing_rotation",
        "mutation_performed": False,
        "recovery_action": "resume",
    }

    devices.add("iphone-new")
    ready = transaction.install(update, operation_id=operation_id)
    assert ready["state"] == "ready"
    assert ready["code"] == "installation_ready"
    assert revocations == [("iphone-old", "profile_changed")]


def test_current_update_rotate_precommit_health_failure_restores_old_release_and_identity(tmp_path):
    devices = {"iphone-old"}
    revocations = []
    deps, _ = dependencies(
        tmp_path,
        pairing_devices=devices,
        pairing_revocations=revocations,
    )
    transaction = LocalTailscaleTransaction(deps)
    transaction.install(plan(), operation_id="op-" + "5" * 32)
    prior = deps.layout.current.resolve()
    deps.health_probe = lambda: False

    failed = transaction.install(
        current_update_plan(policy="rotate", suffix="6"),
        operation_id="op-" + "6" * 32,
    )

    assert failed["state"] == "rolled_back"
    assert deps.layout.current.resolve() == prior
    assert devices == {"iphone-old"}
    assert revocations == []


def test_current_update_rotate_resumes_after_rotation_interruption_without_double_revoke(tmp_path):
    devices = {"iphone-old"}
    revocations = []
    deps, _ = dependencies(
        tmp_path,
        pairing_devices=devices,
        pairing_revocations=revocations,
    )
    transaction = LocalTailscaleTransaction(deps)
    transaction.install(plan(), operation_id="op-" + "7" * 32)
    update = current_update_plan(policy="rotate", suffix="8")
    operation_id = "op-" + "8" * 32
    deps.interruption_probe = lambda phase: phase == "after_pairing_identity_rotation"

    with pytest.raises(LifecycleInterrupted, match="after_pairing_identity_rotation"):
        transaction.install(update, operation_id=operation_id)

    assert revocations == [("iphone-old", "profile_changed")]
    deps.interruption_probe = lambda _phase: False
    devices.add("iphone-new")
    ready = LocalTailscaleTransaction(deps).install(update, operation_id=operation_id)
    assert ready["state"] == "ready"
    assert revocations == [("iphone-old", "profile_changed")]


@pytest.mark.parametrize("phase", ["before_staging", "before_activation", "after_activation"])
def test_current_update_preserve_resumes_the_same_operation_across_shared_tail_interruptions(
    tmp_path, phase
):
    devices = {"iphone-existing"}
    legacy_calls = []
    deps, _ = dependencies(
        tmp_path,
        pairing_devices=devices,
        revoked=legacy_calls,
    )
    transaction = LocalTailscaleTransaction(deps)
    assert transaction.install(plan(), operation_id="op-" + "1" * 32)["state"] == "ready"
    update = current_update_plan(policy="preserve", suffix="4")
    operation_id = "op-" + "4" * 32
    deps.interruption_probe = lambda candidate: candidate == phase

    with pytest.raises(LifecycleInterrupted, match=phase):
        transaction.install(update, operation_id=operation_id)

    deps.interruption_probe = lambda _candidate: False
    resumed = LocalTailscaleTransaction(deps).install(
        update, operation_id=operation_id
    )

    assert resumed["state"] == "ready"
    assert devices == {"iphone-existing"}
    assert legacy_calls == []
    assert not (deps.layout.state / f"{operation_id}.legacy-plugin.json").exists()
    journal = json.loads(
        (deps.layout.state / f"{operation_id}.transaction.json").read_text()
    )
    assert journal["operation_id"] == operation_id
    assert journal["phase"] == "ready"


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


@pytest.mark.parametrize("phase", ["before_staging", "before_activation"])
def test_pre_activation_rollback_preserves_the_operation_specific_active_release(tmp_path, phase):
    deps, _ = dependencies(tmp_path)
    transaction = LocalTailscaleTransaction(deps)
    transaction.install(plan(), operation_id="op-" + "1" * 32)
    second = dict(
        plan(),
        plan_id="plan-" + "2" * 64,
        compatibility_set_id="claudian-remote-0.2.0-beta.2",
    )
    transaction.install(second, operation_id="op-" + "2" * 32)
    active_before = deps.layout.current.resolve()
    plugin = deps.vault_path("vault-a") / ".obsidian/plugins/claudian-remote/manifest.json"
    plugin_before = plugin.read_text()

    third = dict(
        plan(),
        plan_id="plan-" + "3" * 64,
        compatibility_set_id="claudian-remote-0.2.0-beta.4",
    )
    deps.interruption_probe = lambda candidate: candidate == phase
    operation_id = "op-" + "3" * 32
    with pytest.raises(LifecycleInterrupted, match=phase):
        transaction.install(third, operation_id=operation_id)

    deps.interruption_probe = lambda _phase: False
    result = transaction.rollback(third, operation_id=operation_id)

    assert result == {
        "state": "rolled_back",
        "code": "rollback_completed",
        "mutation_performed": False,
        "restored_previous": False,
    }
    assert deps.layout.current.resolve() == active_before
    assert plugin.read_text() == plugin_before
    assert deps.launchd.status()["ready"] is True


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


def test_compensation_restores_prior_availability_only_when_prior_release_supports_it(tmp_path):
    deps, launchctl = dependencies(tmp_path)
    transaction = LocalTailscaleTransaction(deps)
    transaction.install(plan(), operation_id="op-" + "a" * 32)
    prior = deps.layout.current.resolve()
    capability = (
        prior / "installer" / "installer" / "claudian_remote_lifecycle" / "availability.py"
    )
    capability.parent.mkdir(parents=True)
    capability.write_text("# availability capability\n")

    changed = dict(plan(), compatibility_set_id="claudian-remote-0.2.0-beta.2")
    deps.health_probe = lambda: False
    failed = transaction.install(changed, operation_id="op-" + "b" * 32)

    assert failed["state"] == "rolled_back"
    assert deps.layout.current.resolve() == prior
    assert deps.launchd.availability_vault_name() == "vault-vault-a"
    assert len(launchctl.loaded) == 3


def test_compensation_omits_availability_for_prior_release_without_capability(tmp_path):
    deps, launchctl = dependencies(tmp_path)
    transaction = LocalTailscaleTransaction(deps)
    transaction.install(plan(), operation_id="op-" + "7" * 32)
    prior = deps.layout.current.resolve()
    assert not LocalTailscaleTransaction._supports_availability(prior)

    changed = dict(
        plan(),
        plan_id="plan-" + "d" * 64,
        compatibility_set_id="claudian-remote-0.2.0-beta.2",
        vault_id="vault-b",
    )
    deps.health_probe = lambda: False
    failed = transaction.install(changed, operation_id="op-" + "8" * 32)

    assert failed["state"] == "rolled_back"
    assert deps.layout.current.resolve() == prior
    assert deps.launchd.availability_vault_name() is None
    assert not deps.layout.availability_launch_agent.exists()
    assert len(launchctl.loaded) == 2


def test_explicit_rollback_restores_prior_availability_capability(tmp_path):
    deps, launchctl = dependencies(tmp_path)
    transaction = LocalTailscaleTransaction(deps)
    transaction.install(plan(), operation_id="op-" + "c" * 32)
    prior = deps.layout.current.resolve()
    capability = (
        prior / "installer" / "installer" / "claudian_remote_lifecycle" / "availability.py"
    )
    capability.parent.mkdir(parents=True)
    capability.write_text("# availability capability\n")
    changed = dict(
        plan(),
        plan_id="plan-" + "b" * 64,
        compatibility_set_id="claudian-remote-0.2.0-beta.2",
        vault_id="vault-b",
    )
    transaction.install(changed, operation_id="op-" + "d" * 32)

    assert deps.launchd.availability_vault_name() == "vault-vault-b"

    result = transaction.rollback(changed, operation_id="op-" + "d" * 32)

    assert result["state"] == "rolled_back"
    assert deps.layout.current.resolve() == prior
    assert deps.launchd.availability_vault_name() == "vault-vault-a"
    assert len(launchctl.loaded) == 3


def test_resume_compensation_preserves_prior_availability_binding(tmp_path):
    deps, _launchctl = dependencies(tmp_path)
    transaction = LocalTailscaleTransaction(deps)
    transaction.install(plan(), operation_id="op-" + "1" * 32)
    prior = deps.layout.current.resolve()
    capability = (
        prior / "installer" / "installer" / "claudian_remote_lifecycle" / "availability.py"
    )
    capability.parent.mkdir(parents=True)
    capability.write_text("# availability capability\n")

    changed = dict(
        plan(),
        plan_id="plan-" + "c" * 64,
        compatibility_set_id="claudian-remote-0.2.0-beta.2",
        vault_id="vault-b",
    )
    deps.bridge_ready_probe = lambda: False
    blocked = transaction.install(changed, operation_id="op-" + "2" * 32)
    assert blocked["code"] == "desktop_plugin_bootstrap_required"
    assert deps.launchd.availability_vault_name() == "vault-vault-b"

    deps.bridge_ready_probe = lambda: True
    deps.health_probe = lambda: False
    failed = transaction.install(changed, operation_id="op-" + "2" * 32)

    assert failed["state"] == "rolled_back"
    assert deps.layout.current.resolve() == prior
    assert deps.launchd.availability_vault_name() == "vault-vault-a"


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


def test_failure_after_retirement_requires_finish_forward_and_never_restores_legacy(tmp_path):
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

    transaction = LocalTailscaleTransaction(deps)
    operation_id = "op-" + "f" * 32
    result = transaction.install(legacy_plan(), operation_id=operation_id)

    assert result["state"] == "recovery_required"
    assert result["code"] == "post_retirement_finish_forward_required"
    assert result["recovery_action"] == "finish_forward"
    assert revoked == ["retire-me"]
    assert not legacy.exists()
    assert json.loads(enabled.read_text()) == []
    assert transaction.recovery_action(operation_id, legacy_plan()["plan_id"]) == "finish_forward"

    rollback = transaction.rollback(legacy_plan(), operation_id=operation_id)
    assert rollback == {
        "state": "blocked",
        "code": "rollback_unavailable_after_retirement",
        "mutation_performed": False,
        "recovery_action": "finish_forward",
    }


@pytest.mark.parametrize(
    ("reconciliation", "expected_state", "expected_code"),
    [
        (
            "retired",
            "recovery_required",
            "post_retirement_finish_forward_required",
        ),
        ("not_applied", "rolled_back", "rollback_completed"),
    ],
)
def test_transaction_reconciliation_does_not_continue_plugin_migration(
    tmp_path,
    reconciliation,
    expected_state,
    expected_code,
):
    source = FixtureReleaseSource()
    deps, _ = dependencies(tmp_path, source=source)
    service = AmbiguousRetirementService(reconciliation=reconciliation)
    deps.legacy_credential_revoker = service
    vault = deps.vault_path("vault-a")
    legacy = vault / ".obsidian/plugins/whale-agent-bridge"
    legacy.mkdir(parents=True)
    (legacy / "manifest.json").write_text(
        json.dumps({"id": "whale-agent-bridge"})
    )
    (legacy / "data.json").write_text(
        json.dumps({"mobile_token": "legacy-secret"})
    )
    enabled = vault / ".obsidian/community-plugins.json"
    enabled.parent.mkdir(parents=True, exist_ok=True)
    enabled.write_text(json.dumps(["whale-agent-bridge"]))
    transaction = LocalTailscaleTransaction(deps)
    operation_id = "op-" + "9" * 32

    ambiguous = transaction.install(legacy_plan(), operation_id=operation_id)
    assert ambiguous["code"] == "legacy_retirement_outcome_unknown"
    assert legacy.is_dir()
    assert json.loads((legacy / "data.json").read_text())["mobile_token"] == (
        "legacy-secret"
    )

    result = transaction.reconcile_legacy_retirement(
        legacy_plan(), operation_id=operation_id
    )

    assert result["state"] == expected_state
    assert result["code"] == expected_code
    assert service.dispatches == 1
    assert service.reconciliations == 1
    assert legacy.is_dir()
    assert json.loads((legacy / "data.json").read_text())["mobile_token"] == (
        "legacy-secret"
    )
    assert json.loads(enabled.read_text()) == ["whale-agent-bridge"]


def test_legacy_install_requires_terminal_prior_operation_before_staging(tmp_path):
    source = FixtureReleaseSource()
    deps, _ = dependencies(tmp_path, source=source)
    vault = deps.vault_path("vault-a")
    legacy = vault / ".obsidian/plugins/whale-agent-bridge"
    legacy.mkdir(parents=True)
    (legacy / "manifest.json").write_text(json.dumps({"id": "whale-agent-bridge"}))
    (legacy / "data.json").write_text(json.dumps({"mobile_token": "still-active"}))
    enabled = vault / ".obsidian/community-plugins.json"
    enabled.parent.mkdir(parents=True, exist_ok=True)
    enabled.write_text(json.dumps(["whale-agent-bridge"]))

    result = LocalTailscaleTransaction(deps).install(
        legacy_plan(prior_operation_terminal=False),
        operation_id="op-" + "1" * 32,
    )

    assert result == {
        "state": "blocked",
        "code": "prior_operation_not_terminal",
        "mutation_performed": False,
        "recovery_action": "reconcile_prior_operation",
    }
    assert source.calls == 0
    assert json.loads((legacy / "data.json").read_text())["mobile_token"] == "still-active"


def test_failed_unverified_revocation_does_not_remove_uncreated_runtime(tmp_path):
    class FailIfInactiveTailscale(FakeTailscale):
        def remove_serve(self):
            if self.serve_calls == 0:
                raise RuntimeError("serve_was_never_created")
            super().remove_serve()

    tailscale = FailIfInactiveTailscale()
    deps, _ = dependencies(tmp_path, tailscale=tailscale)
    deps.legacy_credential_revoker = FixtureRetirementService(outcome={"verified": False})
    vault = deps.vault_path("vault-a")
    legacy = vault / ".obsidian/plugins/whale-agent-bridge"
    legacy.mkdir(parents=True)
    (legacy / "manifest.json").write_text(json.dumps({"id": "whale-agent-bridge"}))
    (legacy / "data.json").write_text(json.dumps({"mobile_token": "still-active"}))
    enabled = vault / ".obsidian/community-plugins.json"
    enabled.parent.mkdir(parents=True, exist_ok=True)
    enabled.write_text(json.dumps(["whale-agent-bridge"]))

    result = LocalTailscaleTransaction(deps).install(
        plan(), operation_id="op-" + "d" * 32
    )

    assert result["state"] == "blocked"
    assert result["code"] == "legacy_credential_revocation_required"
    assert result["recovery_action"] == "retire_legacy_credential_and_retry"
    assert tailscale.removed == 0
    assert json.loads((legacy / "data.json").read_text())["mobile_token"] == "still-active"
    assert json.loads(enabled.read_text()) == ["whale-agent-bridge"]
    assert not list(deps.layout.staging.glob("*.partial"))


def test_unavailable_legacy_revoker_blocks_before_staging_or_compensation(tmp_path):
    source = FixtureReleaseSource()
    tailscale = FakeTailscale()
    deps, _ = dependencies(tmp_path, source=source, tailscale=tailscale)
    deps.legacy_credential_revoker = None
    vault = deps.vault_path("vault-a")
    legacy = vault / ".obsidian/plugins/whale-agent-bridge"
    legacy.mkdir(parents=True)
    (legacy / "manifest.json").write_text(json.dumps({"id": "whale-agent-bridge"}))
    (legacy / "data.json").write_text(json.dumps({"mobile_token": "still-active"}))
    enabled = vault / ".obsidian/community-plugins.json"
    enabled.parent.mkdir(parents=True, exist_ok=True)
    enabled.write_text(json.dumps(["whale-agent-bridge"]))

    result = LocalTailscaleTransaction(deps).install(
        plan(), operation_id="op-" + "8" * 32
    )

    assert result == {
        "state": "blocked",
        "code": "legacy_credential_revocation_unavailable",
        "mutation_performed": False,
        "recovery_action": "retire_legacy_credential_and_retry",
    }
    assert source.calls == 0
    assert tailscale.removed == 0
    assert not deps.layout.base.exists()
    assert json.loads((legacy / "data.json").read_text())["mobile_token"] == "still-active"


def test_unavailable_revoker_does_not_block_legacy_plugin_without_a_credential(tmp_path):
    deps, _ = dependencies(tmp_path)
    deps.legacy_credential_revoker = None
    vault = deps.vault_path("vault-a")
    legacy = vault / ".obsidian/plugins/whale-agent-bridge"
    legacy.mkdir(parents=True)
    (legacy / "manifest.json").write_text(json.dumps({"id": "whale-agent-bridge"}))
    (legacy / "data.json").write_text(json.dumps({"notifications_enabled": True}))
    enabled = vault / ".obsidian/community-plugins.json"
    enabled.parent.mkdir(parents=True, exist_ok=True)
    enabled.write_text(json.dumps(["whale-agent-bridge"]))

    result = LocalTailscaleTransaction(deps).install(
        plan(), operation_id="op-" + "9" * 32
    )

    assert result["state"] == "ready"
    assert not legacy.exists()


def test_beta3_staging_only_recovery_rolls_back_without_touching_legacy_runtime(tmp_path):
    tailscale = FakeTailscale()
    deps, _ = dependencies(tmp_path, tailscale=tailscale)
    deps.legacy_credential_revoker = FixtureRetirementService(outcome={"verified": False})
    transaction = LocalTailscaleTransaction(deps)
    operation_id = "op-" + "e" * 32
    vault = deps.vault_path("vault-a")
    legacy = vault / ".obsidian/plugins/whale-agent-bridge"
    legacy.mkdir(parents=True)
    (legacy / "manifest.json").write_text(json.dumps({"id": "whale-agent-bridge"}))
    (legacy / "data.json").write_text(json.dumps({"mobile_token": "still-active"}))
    enabled = vault / ".obsidian/community-plugins.json"
    enabled.parent.mkdir(parents=True, exist_ok=True)
    enabled.write_text(json.dumps(["whale-agent-bridge"]))
    deps.layout.ensure()
    partial = deps.layout.staging / f"{operation_id}.partial"
    partial.mkdir(parents=True)

    with pytest.raises(ValueError, match="legacy_credential_revocation_unverified"):
        transaction._legacy_migration(
            "vault-a",
            plan_id=plan()["plan_id"],
            installation_id=plan()["installation_id"],
        ).prepare(operation_id=operation_id)
    operation_file = deps.layout.state / f"{operation_id}.transaction.json"
    operation_file.write_text(json.dumps({
        "transaction_schema": "claudian-remote.local-transaction/v1",
        "operation_id": operation_id,
        "plan_id": plan()["plan_id"],
        "phase": "recovery_required",
        "completed_phases": ["staging"],
        "prior_availability_vault": None,
        "prior_release_id": None,
        "activation_started": False,
        "plugin_activated": False,
    }))

    assert transaction.recovery_action(operation_id, plan()["plan_id"]) == "rollback"

    result = transaction.rollback(plan(), operation_id=operation_id)

    assert result == {
        "state": "rolled_back",
        "code": "rollback_completed",
        "mutation_performed": False,
        "restored_previous": False,
    }
    assert tailscale.removed == 0
    assert json.loads((legacy / "data.json").read_text()) == {
        "mobile_token": "still-active"
    }
    assert json.loads(enabled.read_text()) == ["whale-agent-bridge"]
    assert not partial.exists()
    assert json.loads(operation_file.read_text())["phase"] == "rolled_back"
    assert transaction.recovery_action(operation_id, plan()["plan_id"]) == "manual_recovery_required"


def test_legacy_retirement_requires_explicit_human_authorization_after_staging(
    tmp_path,
):
    source = FixtureReleaseSource()
    deps, _ = dependencies(tmp_path, source=source)
    deps.legacy_credential_revoker = AuthorizationRequiredRetirementService()
    vault = deps.vault_path("vault-a")
    legacy = vault / ".obsidian/plugins/whale-agent-bridge"
    legacy.mkdir(parents=True)
    (legacy / "manifest.json").write_text(json.dumps({"id": "whale-agent-bridge"}))
    (legacy / "data.json").write_text(json.dumps({"mobile_token": "still-active"}))
    enabled = vault / ".obsidian/community-plugins.json"
    enabled.parent.mkdir(parents=True, exist_ok=True)
    enabled.write_text(json.dumps(["whale-agent-bridge"]))

    result = LocalTailscaleTransaction(deps).install(
        legacy_plan(), operation_id="op-" + "4" * 32
    )

    assert result["state"] == "blocked"
    assert result["code"] == "legacy_authority_authorization_required"
    assert result["gate"]["gate_type"] == "legacy_authority_authorization_required"
    assert source.calls == 1
    journal = json.loads(
        (
            deps.layout.state / ("op-" + "4" * 32 + ".transaction.json")
        ).read_text()
    )
    assert journal["phase"] == "before_legacy_migration"
    assert journal["completed_phases"] == ["staging"]
    assert json.loads((legacy / "data.json").read_text())["mobile_token"] == "still-active"


def test_staging_failure_never_requests_legacy_retirement_authorization(tmp_path):
    class AuthorizationMustNotBeChecked(FixtureRetirementService):
        def authorized(self, *, operation_id, plan_id):
            raise AssertionError("authorization_checked_before_staging_completed")

    source = FixtureReleaseSource(stage_fail=True)
    deps, _ = dependencies(tmp_path, source=source)
    deps.legacy_credential_revoker = AuthorizationMustNotBeChecked()
    vault = deps.vault_path("vault-a")
    legacy = vault / ".obsidian/plugins/whale-agent-bridge"
    legacy.mkdir(parents=True)
    (legacy / "manifest.json").write_text(json.dumps({"id": "whale-agent-bridge"}))
    (legacy / "data.json").write_text(json.dumps({"mobile_token": "still-active"}))
    enabled = vault / ".obsidian/community-plugins.json"
    enabled.parent.mkdir(parents=True, exist_ok=True)
    enabled.write_text(json.dumps(["whale-agent-bridge"]))

    with pytest.raises(ReleaseValidationError, match="runtime_asset_digest_mismatch"):
        LocalTailscaleTransaction(deps).install(
            legacy_plan(), operation_id="op-" + "5" * 32
        )

    assert source.calls == 1
    assert json.loads((legacy / "data.json").read_text())["mobile_token"] == "still-active"


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


def test_install_waits_for_login_launch_agent_to_open_bound_obsidian_vault(tmp_path):
    bridge = {"checks": 0}
    deps, _ = dependencies(tmp_path, bridge_ready=False)
    deps.readiness_attempts = 2

    def bridge_ready():
        bridge["checks"] += 1
        return bridge["checks"] >= 2

    deps.bridge_ready_probe = bridge_ready

    result = LocalTailscaleTransaction(deps).install(
        plan(), operation_id="op-" + "8" * 32
    )

    assert result["state"] == "ready"
    assert bridge["checks"] == 2
    assert deps.layout.availability_config.is_file()


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


@pytest.mark.parametrize("healthy", [True, False])
def test_plugin_backup_and_restore_never_rename_across_the_synced_vault(tmp_path, monkeypatch, healthy):
    deps, _ = dependencies(tmp_path)
    vault = deps.vault_path("vault-a")
    destination = vault / ".obsidian/plugins/claudian-remote"
    destination.mkdir(parents=True)
    (destination / "manifest.json").write_text("old plugin")
    (destination / "data.json").write_text(json.dumps({"vault_id": "vault-a"}))
    original_replace = Path.replace

    def replace_within_storage_domain(path, target):
        if path.is_relative_to(vault) != Path(target).is_relative_to(vault):
            raise OSError("cross-domain iCloud directory rename unavailable")
        return original_replace(path, target)

    monkeypatch.setattr(Path, "replace", replace_within_storage_domain)
    deps.health_probe = lambda: healthy
    operation_id = "op-" + "d" * 32
    result = LocalTailscaleTransaction(deps).install(plan(), operation_id=operation_id)

    assert result["state"] == ("ready" if healthy else "rolled_back")
    assert (deps.layout.backups / operation_id / "plugin/manifest.json").read_text() == "old plugin"
    assert ((destination / "manifest.json").read_text() == "old plugin") is (not healthy)
    assert json.loads((destination / "data.json").read_text())["vault_id"] == "vault-a"


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


def test_install_migrates_old_plugin_id_and_post_retirement_health_failure_finishes_forward(tmp_path):
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

    ready = LocalTailscaleTransaction(deps).install(legacy_plan(), operation_id="op-" + "9" * 32)
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

    recovery = LocalTailscaleTransaction(failed_deps).install(
        legacy_plan(), operation_id="op-" + "0" * 32
    )
    assert recovery["state"] == "recovery_required"
    assert recovery["recovery_action"] == "finish_forward"
    assert not failed_legacy.exists()
    assert json.loads(failed_enabled.read_text()) == ["claudian-remote"]


def test_legacy_upgrade_retires_then_resumes_deliberate_pairing_under_original_operation(
    tmp_path,
):
    retired = []
    devices = set()
    deps, _ = dependencies(
        tmp_path,
        pairing_ready=False,
        pairing_devices=devices,
        revoked=retired,
    )
    deps.pairing_probe = lambda: bool(devices)
    vault = deps.vault_path("vault-a")
    legacy = vault / ".obsidian/plugins/whale-agent-bridge"
    legacy.mkdir(parents=True)
    (legacy / "manifest.json").write_text(json.dumps({"id": "whale-agent-bridge"}))
    (legacy / "data.json").write_text(json.dumps({
        "mobile_token": "legacy-secret",
        "vault_id": "vault-a",
        "connection_mode": "remote_vps",
        "notifications_enabled": False,
        "haptics_enabled": False,
        "relay_url": "https://private.example.invalid",
        "local_path": "/Users/example/private-vault",
    }))
    enabled = vault / ".obsidian/community-plugins.json"
    enabled.parent.mkdir(parents=True, exist_ok=True)
    enabled.write_text(json.dumps(["whale-agent-bridge"]))
    operation_id = "op-" + "e" * 32
    selected_plan = legacy_plan()

    waiting = LocalTailscaleTransaction(deps).install(
        selected_plan, operation_id=operation_id
    )

    assert waiting["state"] == "blocked"
    assert waiting["code"] == "pairing_approval_required"
    assert waiting["gate"]["resume_reference"] == operation_id
    assert retired == ["legacy-secret"]
    assert not legacy.exists()
    assert json.loads(enabled.read_text()) == ["claudian-remote"]
    migrated = json.loads(
        (vault / ".obsidian/plugins/claudian-remote/data.json").read_text()
    )
    assert migrated == {
        "schema_version": 2,
        "vault_id": "vault-a",
        "connection_mode": "local_tailscale",
        "notifications_enabled": False,
        "haptics_enabled": False,
    }
    migration_journal = json.loads(
        (deps.layout.state / f"{operation_id}.legacy-plugin.json").read_text()
    )
    assert migration_journal["operation_id"] == operation_id
    assert migration_journal["phase"] == "committed"
    assert migration_journal["re_pair_required"] is True
    assert "legacy-secret" not in json.dumps(migration_journal)
    waiting_journal = json.loads(
        (deps.layout.state / f"{operation_id}.transaction.json").read_text()
    )
    assert waiting_journal["operation_id"] == operation_id
    assert waiting_journal["phase"] == "await_pairing"

    devices.add("iphone-new")
    ready = LocalTailscaleTransaction(deps).install(
        selected_plan, operation_id=operation_id
    )

    assert ready["state"] == "ready"
    assert ready["code"] == "installation_ready"
    assert retired == ["legacy-secret"]
    final_journal = json.loads(
        (deps.layout.state / f"{operation_id}.transaction.json").read_text()
    )
    assert final_journal["operation_id"] == operation_id
    assert final_journal["phase"] == "ready"
    assert final_journal["completed_phases"] == [
        "staging",
        "legacy_plugin_migration",
        "secure_provisioning",
        "plugin_activation",
        "launchd",
        "tailscale_serve",
        "verified",
        "paired",
    ]


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


def test_failed_plugin_activation_and_failed_restore_require_recovery(tmp_path, monkeypatch):
    import shutil

    deps, _ = dependencies(tmp_path)
    destination = deps.vault_path("vault-a") / ".obsidian/plugins/claudian-remote"
    destination.mkdir(parents=True)
    original = {"manifest.json": "old plugin", "data.json": json.dumps({"vault_id": "vault-a"})}
    for name, contents in original.items():
        (destination / name).write_text(contents)
    operation_id = "op-" + "e" * 32
    backup = deps.layout.backups / operation_id / "plugin"
    original_replace = Path.replace
    original_copytree = shutil.copytree

    def fail_activation_replace(path, target):
        if path.name.endswith(".next") and Path(target) == destination:
            raise OSError("iCloud activation rename failed")
        return original_replace(path, target)

    def fail_restore_copy(source, target, *args, **kwargs):
        if Path(source) == backup:
            raise OSError("disk full while restoring plugin")
        return original_copytree(source, target, *args, **kwargs)

    monkeypatch.setattr(Path, "replace", fail_activation_replace)
    monkeypatch.setattr(shutil, "copytree", fail_restore_copy)
    result = LocalTailscaleTransaction(deps).install(plan(), operation_id=operation_id)

    assert not destination.exists()
    assert {path.name: path.read_text() for path in backup.iterdir()} == original
    assert result["state"] == "recovery_required"


class FixtureCommunityReleaseSource(FixtureReleaseSource):
    """A verified fixture whose installed-plugin check uses production code."""

    verify_installed_plugin = BootstrapVerifiedReleaseSource.verify_installed_plugin

    def __init__(self, directory):
        super().__init__()
        self.directory = directory
        self.files = {
            "manifest.json": json.dumps({"id": "claudian-remote", "version": COMMUNITY_VERSION}).encode(),
            "main.js": b"community plugin code\n",
            "styles.css": b".community { color: inherit; }\n",
        }
        (directory / "assets").mkdir(parents=True)
        archive = directory / "assets" / "plugin.tar.gz"
        with tarfile.open(archive, "w:gz") as bundle:
            for name, contents in self.files.items():
                member = tarfile.TarInfo(name)
                member.size = len(contents)
                bundle.addfile(member, io.BytesIO(contents))
        self._manifest = {"release_version": COMMUNITY_VERSION,
            "distribution_channel": "community", "plugin_update_owner": "obsidian",
            "assets": [{"component": "plugin", "name": archive.name,
                "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(), "size": archive.stat().st_size}]}

    def verify(self, _plan):
        return {"verified": True, "release_version": COMMUNITY_VERSION,
            "plugin_update_owner": "obsidian"}

    def stage(self, plan, destination, runtime_root):
        staged = super().stage(plan, destination, runtime_root)
        for name, contents in self.files.items():
            (destination / "plugin" / name).write_bytes(contents)
        return staged

    def install_market_plugin(self, deps):
        plugin = deps.vault_path("vault-a") / ".obsidian/plugins/claudian-remote"
        plugin.mkdir(parents=True)
        for name, contents in self.files.items():
            (plugin / name).write_bytes(contents)
        (plugin / "data.json").write_text(json.dumps({"vault_id": "vault-a", "notifications_enabled": False}))
        (plugin.parent.parent / "community-plugins.json").write_text('["claudian-remote"]')
        return plugin


def community_plan(*, journey="fresh_install"):
    return {**plan(), "compatibility_set_id": COMMUNITY_SET_ID, "journey": journey,
        "pairing_identity_policy": "preserve" if journey == "current_update" else "not_applicable"}


def plugin_bytes(plugin):
    return {file.name: file.read_bytes() for file in plugin.iterdir() if file.is_file()}


def test_community_service_install_leaves_market_plugin_unowned_and_unchanged(tmp_path):
    from installer.claudian_remote_lifecycle.uninstall import OwnershipUninstaller
    from installer.claudian_remote_lifecycle.operation_arbitration import _read_transaction_companion
    source = FixtureCommunityReleaseSource(tmp_path / "release")
    deps, _ = dependencies(tmp_path, source=source)
    plugin = source.install_market_plugin(deps)
    before = plugin_bytes(plugin)
    op = "op-" + "e" * 32
    result = LocalTailscaleTransaction(deps).install(community_plan(), operation_id=op)
    assert result["state"] == "ready"
    journal = _read_transaction_companion(deps.layout.state / f"{op}.transaction.json",
        operation_id=op, plan_id=community_plan()["plan_id"], journey="fresh_install")
    assert journal["plugin_update_owner"] == "obsidian"
    assert journal["plugin_activated"] is False
    assert "plugin_activation" not in journal["completed_phases"]
    assert plugin_bytes(plugin) == before
    assert not (deps.layout.backups / op / "plugin").exists()
    receipt = json.loads(deps.layout.ownership_receipt.read_text())
    assert receipt["plugin_update_owner"] == "obsidian"
    assert not any(item["resource_id"].startswith("plugin_") for item in receipt["resources"])
    outcome = OwnershipUninstaller(deps.layout, stop_owned_services=lambda: None,
        revoke_credentials=lambda: None).uninstall()
    assert outcome["state"] == "ready"
    assert plugin_bytes(plugin) == before


@pytest.mark.parametrize("damage,code", [
    ("missing", "community_plugin_install_required"),
    ("old", "community_plugin_update_required"),
    ("modified", "community_plugin_assets_mismatch"),
    ("disabled", "community_plugin_enable_required"),
])
def test_community_missing_or_wrong_plugin_refuses_before_any_service_mutation(tmp_path, damage, code):
    source = FixtureCommunityReleaseSource(tmp_path / "release")
    deps, launchctl = dependencies(tmp_path, source=source)
    plugin = source.install_market_plugin(deps)
    if damage == "missing":
        (plugin / "main.js").unlink()
    elif damage == "old":
        (plugin / "manifest.json").write_text('{"id":"claudian-remote","version":"0.2.0-beta.6.7"}')
    elif damage == "modified":
        (plugin / "styles.css").write_text("modified")
    else:
        (plugin.parent.parent / "community-plugins.json").write_text("[]")
    before = plugin_bytes(plugin)
    result = LocalTailscaleTransaction(deps).install(community_plan(), operation_id="op-" + "d" * 32)
    assert result["state"] == "blocked"
    assert result["code"] == code
    assert result["mutation_performed"] is False
    assert plugin_bytes(plugin) == before
    assert source.calls == 0
    assert not deps.layout.base.exists()
    assert not launchctl.loaded


@pytest.mark.parametrize("bootstrap_consumed", [False, True])
def test_community_beta67_update_preserves_pairing_and_market_assets_through_rollback(tmp_path, bootstrap_consumed):
    from installer.claudian_remote_lifecycle.inspect import LocalInspectionProbe
    from installer.claudian_remote_lifecycle.private_io import write_private_json
    from installer.claudian_remote_lifecycle.provisioning import SecureInputFile
    deps, _ = dependencies(tmp_path)
    tx = LocalTailscaleTransaction(deps)
    old = {**plan(), "compatibility_set_id": "claudian-remote-0.2.0-beta.6.7"}
    assert tx.install(old, operation_id="op-" + "1" * 32)["state"] == "ready"
    old_target = deps.layout.current.resolve()
    if bootstrap_consumed:
        provisioning = json.loads(deps.layout.secure_provisioning.read_text())
        write_private_json(deps.layout.bridge_bootstrap_ack, {
            "ack_schema": "claudian-remote.bridge-bootstrap-ack/v1",
            **{key: provisioning[key] for key in ("bootstrap_generation", "installation_id", "vault_id", "bridge_credential_id")},
        })
        SecureInputFile(deps.layout.bridge_bootstrap_for("vault-a")).discard()
    old_receipt = deps.layout.ownership_receipt.read_bytes()
    source = FixtureCommunityReleaseSource(tmp_path / "release")
    deps.release_source = source
    plugin = deps.vault_path("vault-a") / ".obsidian/plugins/claudian-remote"
    for name, contents in source.files.items():
        (plugin / name).write_bytes(contents)
    before = plugin_bytes(plugin)
    original_devices = set(deps.active_pairing_device_ids())
    op = "op-" + "2" * 32
    update = community_plan(journey="current_update")
    assert tx.install(update, operation_id=op)["state"] == "ready"
    assert set(deps.active_pairing_device_ids()) == original_devices
    assert plugin_bytes(plugin) == before
    assert tx.rollback(update, operation_id=op)["state"] == "rolled_back"
    assert deps.layout.current.resolve() == old_target
    restored = json.loads(deps.layout.ownership_receipt.read_text())
    assert all(restored[key] == json.loads(old_receipt)[key] for key in ("operation_id", "plan_id", "compatibility_set_id"))
    assert LocalInspectionProbe(home=tmp_path)._verified_managed_version(deps.layout, old_target) == "0.2.0-beta.6.7"
    assert set(deps.active_pairing_device_ids()) == original_devices
    assert plugin_bytes(plugin) == before
    from installer.claudian_remote_lifecycle.uninstall import OwnershipUninstaller
    assert deps.layout.bridge_bootstrap_for("vault-a").exists() is (not bootstrap_consumed)
    uninstall = OwnershipUninstaller(deps.layout, stop_owned_services=lambda: None, revoke_credentials=lambda: None)
    assert uninstall.preflight()["state"] == "ready"
    assert uninstall.uninstall()["state"] == "ready"
    assert plugin_bytes(plugin) == before


def test_community_failed_activation_rolls_back_services_without_restoring_plugin(tmp_path):
    from installer.claudian_remote_lifecycle.inspect import LocalInspectionProbe
    deps, _ = dependencies(tmp_path)
    tx = LocalTailscaleTransaction(deps)
    assert tx.install(plan(), operation_id="op-" + "4" * 32)["state"] == "ready"
    prior = deps.layout.current.resolve()
    source = FixtureCommunityReleaseSource(tmp_path / "release")
    deps.release_source = source
    plugin = deps.vault_path("vault-a") / ".obsidian/plugins/claudian-remote"
    for name, contents in source.files.items():
        (plugin / name).write_bytes(contents)
    before = plugin_bytes(plugin)
    deps.health_probe = lambda: False
    result = tx.install(community_plan(journey="current_update"), operation_id="op-" + "5" * 32)
    assert result["state"] == "rolled_back"
    assert deps.layout.current.resolve() == prior
    assert plugin_bytes(plugin) == before
    assert LocalInspectionProbe(home=tmp_path)._verified_managed_version(deps.layout, prior) == BETA4_VERSION
    assert deps.active_pairing_device_ids() == {"iphone-a"}
    from installer.claudian_remote_lifecycle.uninstall import OwnershipUninstaller
    assert OwnershipUninstaller(deps.layout, stop_owned_services=lambda: None,
        revoke_credentials=lambda: None).preflight()["state"] == "ready"


def test_community_incomplete_plugin_does_not_query_or_change_existing_pairing(tmp_path):
    source = FixtureCommunityReleaseSource(tmp_path / "release")
    deps, _ = dependencies(tmp_path, source=source)
    source.install_market_plugin(deps).joinpath("main.js").unlink()
    def forbidden_inventory():
        raise AssertionError("queried pairing before plugin preflight")
    deps.active_pairing_device_ids = forbidden_inventory
    outcome = LocalTailscaleTransaction(deps).install(community_plan(journey="current_update"), operation_id="op-" + "6" * 32)
    assert outcome["code"] == "community_plugin_install_required"
    assert "Obsidian" in outcome["human_action"]
    assert not deps.layout.base.exists()


@pytest.mark.parametrize("final_phase", ["ready", "await_plugin_bootstrap", "await_pairing", "rolled_back", "recovery_required"])
def test_community_actual_journal_stays_readable_through_wait_and_compensation(tmp_path, monkeypatch, final_phase):
    from installer.claudian_remote_lifecycle import transaction as transaction_module
    from installer.claudian_remote_lifecycle.operation_arbitration import _read_transaction_companion
    source = FixtureCommunityReleaseSource(tmp_path / "release")
    deps, _ = dependencies(tmp_path, source=source)
    plugin = source.install_market_plugin(deps)
    before = plugin_bytes(plugin)
    deps.bridge_ready_probe = lambda: final_phase != "await_plugin_bootstrap"
    deps.pairing_probe = lambda: final_phase != "await_pairing"
    deps.health_probe = lambda: final_phase not in {"rolled_back", "recovery_required"}
    if final_phase == "recovery_required":
        def fail_cleanup():
            raise RuntimeError("fixture cleanup failed")
        deps.launchd.remove_local_agents = fail_cleanup
    snapshots = []
    op = "op-" + "7" * 32
    original_write = transaction_module.write_private_json
    def capture(path, value, **kwargs):
        original_write(path, value, **kwargs)
        if path.name == f"{op}.transaction.json":
            snapshots.append(json.loads(path.read_text()))
    monkeypatch.setattr(transaction_module, "write_private_json", capture)
    tx = LocalTailscaleTransaction(deps)
    tx.install(community_plan(), operation_id=op)
    assert snapshots[-1]["phase"] == final_phase
    assert {"activation_started", "secure_provisioned", "after_activation"} <= {item["phase"] for item in snapshots}
    captured = tmp_path / "captured.json"
    for journal in snapshots:
        captured.write_text(json.dumps(journal))
        assert _read_transaction_companion(captured, operation_id=op,
            plan_id=community_plan()["plan_id"], journey="fresh_install", plugin_update_owner="obsidian") == journal
        with pytest.raises(ValueError, match="invalid_transaction_companion_owner"):
            _read_transaction_companion(captured, operation_id=op,
                plan_id=community_plan()["plan_id"], journey="fresh_install", plugin_update_owner="lifecycle_manager")
    if final_phase in {"await_plugin_bootstrap", "await_pairing"}:
        deps.bridge_ready_probe = deps.pairing_probe = lambda: True
        assert tx.install(community_plan(), operation_id=op)["state"] == "ready"
        assert source.calls == 1
    assert plugin_bytes(plugin) == before


def test_shared_vault_identity_installs_services_waits_and_resumes_without_plugin_writes(tmp_path):
    from installer.claudian_remote_lifecycle.inspect import Inspector, LocalInspectionProbe
    from installer.claudian_remote_lifecycle.plan import PlanBuilder
    from installer.tests.test_inspect import FakeProbe
    local = LocalInspectionProbe(home=tmp_path)
    source = FixtureCommunityReleaseSource(tmp_path / "release")
    deps, launchctl = dependencies(tmp_path, source=source, bridge_ready=False)
    deps.layout = RuntimeLayout(tmp_path / "Library/Application Support/Claudian Remote", tmp_path / "Library/LaunchAgents")
    deps.launchd = LaunchAgentManager(deps.layout, runner=launchctl)
    vault = tmp_path / "Notes"
    plugin = vault / ".obsidian/plugins/claudian-remote"
    plugin.mkdir(parents=True)
    for name, data in source.files.items():
        (plugin / name).write_bytes(data)
    (plugin / "data.json").write_text('{"vault_id":"vault-shared-phone-uuid"}')
    (vault / ".obsidian/community-plugins.json").write_text('["claudian", "claudian-remote"]')
    claudian = vault / ".obsidian/plugins/claudian"
    claudian.mkdir()
    (claudian / "manifest.json").write_text('{"id":"claudian","version":"2.2.7"}')
    registry = tmp_path / "Library/Application Support/obsidian/obsidian.json"
    registry.parent.mkdir(parents=True)
    registry.write_text(json.dumps({"vaults": {"different-local-registration": {"path": str(vault)}}}))
    fake = FakeProbe(claudian_version="2.2.7")
    fake.vaults = local.vaults
    fake.installation = local.installation
    local._secure_provisioning_status = lambda: {"secure_provisioning_available": True, "secure_provisioning_probe": "fixture"}
    deps.vault_path = local.resolve_vault
    before = plugin_bytes(plugin)
    snapshot = Inspector(fake).snapshot()
    target = PlanBuilder().build(snapshot, mode="local_tailscale")
    assert target["journey"] == "fresh_install"
    assert target["vault_id"] == "vault-shared-phone-uuid"
    assert target["blockers"] == []
    tx = LocalTailscaleTransaction(deps)
    op = "op-" + "8" * 32
    assert tx.install(target, operation_id=op)["code"] == "desktop_plugin_bootstrap_required"
    pending = Inspector(fake).snapshot()
    assert pending["installation"]["managed_runtime_state"] == "verified"
    deps.bridge_ready_probe = lambda: True
    assert tx.install(target, operation_id=op)["state"] == "ready"
    assert tx.verify(target)["state"] == "ready"
    profile = json.loads(deps.layout.connection_profile.read_text())
    assert profile["vault_id"] == "vault-shared-phone-uuid"
    assert source.calls == 1
    assert plugin_bytes(plugin) == before


def test_community_update_refuses_modified_existing_runtime_before_extending_receipt_ownership(tmp_path):
    deps, _ = dependencies(tmp_path)
    tx = LocalTailscaleTransaction(deps)
    assert tx.install(plan(), operation_id="op-" + "a" * 32)["state"] == "ready"
    (deps.layout.runtime / "foreign-file").write_text("user-owned content")
    source = FixtureCommunityReleaseSource(tmp_path / "release")
    deps.release_source = source
    plugin = deps.vault_path("vault-a") / ".obsidian/plugins/claudian-remote"
    for name, contents in source.files.items():
        (plugin / name).write_bytes(contents)
    before = plugin_bytes(plugin)
    result = tx.install(community_plan(journey="current_update"), operation_id="op-" + "b" * 32)
    assert result["code"] == "owned_resource_modified"
    assert result["mutation_performed"] is False
    assert source.calls == 0
    assert plugin_bytes(plugin) == before
    assert (deps.layout.runtime / "foreign-file").read_text() == "user-owned content"
