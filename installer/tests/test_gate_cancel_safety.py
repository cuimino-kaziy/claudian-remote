"""Beta 5 U2 safety contracts for gated resume and operation cancellation.

These tests intentionally describe the smallest public/internal interfaces
needed to make gate verification and cancellation crash-safe.  They are kept
separate from the older lifecycle tests so an implementation can turn each
boundary green independently.
"""

from __future__ import annotations

import io
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import installer.claudian_remote_lifecycle.cli as lifecycle_cli
from installer.claudian_remote_lifecycle.checkpoint import CheckpointStore
from installer.claudian_remote_lifecycle.cli import (
    LifecycleServices,
    build_parser,
    main,
)
from installer.claudian_remote_lifecycle.human_gates import HumanGateController
from installer.claudian_remote_lifecycle.legacy_authority import (
    RetirementCommit,
    RetirementIntent,
)
from installer.claudian_remote_lifecycle.model import (
    AmbiguityState,
    CredentialEffect,
    EffectDisposition,
    EffectSummary,
    Journey,
    PairingIdentityPolicy,
    RecoveryPolicy,
)
from installer.claudian_remote_lifecycle.operation_arbitration import (
    OperationArbitration,
)
from installer.claudian_remote_lifecycle.provisioning import SecureInputFile
from installer.claudian_remote_lifecycle.runtime import RuntimeLayout
from installer.tests.test_inspect import FakeProbe
from installer.tests.test_operation_arbitration import (
    _cancel_action,
    _create_v2_operation,
    _resume_action,
)


def _blocked_gate(store: CheckpointStore, *, probe=lambda: True) -> dict:
    checkpoint = store.create(
        command="install",
        plan_id="plan-" + "a" * 64,
        phase="authorization",
        journey=Journey.LEGACY_UPGRADE,
        irreversible_boundary_crossed=False,
        ambiguity_state=AmbiguityState.NOT_DISPATCHED,
        recovery_policy=RecoveryPolicy.RETRY_SAME_OPERATION,
        effect_summary=EffectSummary(
            local_effect=EffectDisposition.UNCHANGED,
            remote_effect=EffectDisposition.UNCHANGED,
            credential_effect=CredentialEffect.NOT_DISPATCHED,
            mutation_performed=False,
            owned_resource_count=0,
        ),
        next_actions=(_resume_action(), _cancel_action()),
        cancellation_available=True,
        pairing_identity_policy=PairingIdentityPolicy.NOT_APPLICABLE,
        prior_operation_terminal=True,
    )
    HumanGateController(store, {"external_ready": probe}).require(
        checkpoint["operation_id"],
        gate_type="external_action_required",
        explanation="Complete the external action.",
        exact_action="Complete it, then resume the same operation.",
        verification_probe="external_ready",
    )
    return store.read(checkpoint["operation_id"])


def test_resume_uses_one_lock_for_arbitration_gate_verification_and_mutation(
    tmp_path, monkeypatch
):
    """No resume decision may escape the lock that owns its mutation."""

    state = tmp_path / "lifecycle"
    checkpoint = _blocked_gate(CheckpointStore(state))
    operation_id = checkpoint["operation_id"]
    lock_state = {"depth": 0, "entries": 0}
    calls = {"mutation": 0}

    class TrackingLock:
        def __init__(self, _state_dir: Path) -> None:
            pass

        def acquire(self):
            assert lock_state["depth"] == 0, "resume acquired a nested second lock"
            lock_state["depth"] = 1
            lock_state["entries"] += 1
            return self

        def release(self) -> None:
            assert lock_state["depth"] == 1
            lock_state["depth"] = 0

        def __enter__(self):
            return self.acquire()

        def __exit__(self, *_args) -> None:
            self.release()

    class TrackingArbitrator:
        def __init__(self, _state_dir: Path) -> None:
            pass

        def inspect(self):
            assert lock_state["depth"] == 1, "resume arbitration ran outside OperationLock"
            return OperationArbitration(
                state="blocked",
                reason_code="operation_requires_resume",
                prior_operation_terminal=False,
                operation_id=operation_id,
                recommended_action="resume",
                checkpoint=CheckpointStore(state).read(operation_id),
            )

    class ReadOnlyGateController:
        def __init__(self, _checkpoints, _probes) -> None:
            pass

        def verify(self, target_operation_id: str):
            assert lock_state["depth"] == 1, "gate verification ran outside OperationLock"
            assert target_operation_id == operation_id
            return {
                "verified": True,
                "checkpoint": CheckpointStore(state).read(operation_id),
            }

        # Kept only to make the failure about lock scope on the old API rather
        # than about the future method rename.
        verify_and_resume = verify

    sentinel = object()

    def run_mutation(**kwargs):
        assert lock_state["depth"] == 1, "mutation ran outside the resume lock"
        assert kwargs.get("lock_held") is True, "resume attempted to acquire a second lock"
        calls["mutation"] += 1
        return sentinel

    monkeypatch.setattr(lifecycle_cli, "OperationLock", TrackingLock)
    monkeypatch.setattr(lifecycle_cli, "OperationArbitrator", TrackingArbitrator)
    monkeypatch.setattr(lifecycle_cli, "HumanGateController", ReadOnlyGateController)
    monkeypatch.setattr(lifecycle_cli, "_run_mutation", run_mutation)

    result = lifecycle_cli.dispatch(
        SimpleNamespace(
            command="resume",
            operation_id=operation_id,
            state_dir=state,
        ),
        services=LifecycleServices(FakeProbe(), {"external_ready": lambda: True}),
    )

    assert result is sentinel
    assert calls["mutation"] == 1
    assert lock_state == {"depth": 0, "entries": 1}


def test_successful_gate_verification_is_read_only_until_mutation_commits(tmp_path):
    """A crash after verification must still leave the resumable gate intact."""

    state = tmp_path / "lifecycle"
    store = CheckpointStore(state)
    checkpoint = _blocked_gate(store)
    operation_id = checkpoint["operation_id"]
    before = store.read(operation_id)
    verify = getattr(HumanGateController(store, {"external_ready": lambda: True}), "verify", None)

    assert callable(verify), "HumanGateController.verify read-only API is missing"
    outcome = verify(operation_id)

    assert outcome["verified"] is True
    assert store.read(operation_id) == before
    assert outcome["checkpoint"]["active_gate"] == before["active_gate"]
    assert outcome["checkpoint"]["state"] == "blocked"


class _CancelableTransaction:
    def __init__(self, layout: RuntimeLayout) -> None:
        self.layout = layout
        self.calls: list[str] = []

    def completed_phases(self, _operation_id: str) -> list[str]:
        return []

    def cancel_pre_boundary(self, _plan, *, operation_id: str) -> dict:
        self.calls.append(operation_id)
        partial = self.layout.staging / f"{operation_id}.partial"
        if partial.is_dir():
            for child in partial.iterdir():
                if child.is_file():
                    child.unlink()
            partial.rmdir()
        return {
            "state": "rolled_back",
            "code": "operation_cancelled",
            "mutation_performed": True,
        }


def _run_cancel(state: Path, operation_id: str, services: LifecycleServices):
    output = io.StringIO()
    exit_code = main(
        ["--state-dir", str(state), "cancel", "--operation-id", operation_id],
        stdout=output,
        services=services,
    )
    return exit_code, json.loads(output.getvalue())


def test_cancel_command_is_parseable_and_pre_dispatch_cancel_is_idempotent(tmp_path):
    """Only the operation's inert staging and secure companion are discarded."""

    layout = RuntimeLayout(tmp_path / "app", tmp_path / "LaunchAgents")
    state = layout.base / "lifecycle"
    _plan, checkpoint = _create_v2_operation(state, journey="legacy_upgrade")
    operation_id = checkpoint["operation_id"]
    partial = layout.staging / f"{operation_id}.partial"
    partial.mkdir(parents=True)
    (partial / "staged.txt").write_text("owned staging\n", encoding="utf-8")
    secure_path = state / f"{operation_id}.diagnostic-destination.json"
    SecureInputFile.create(secure_path, {"destination": "/private/tmp/export.json"})
    transaction = _CancelableTransaction(layout)
    services = LifecycleServices(
        FakeProbe(), {}, transaction=transaction, layout=layout
    )

    parsed = build_parser().parse_args(
        ["--state-dir", str(state), "cancel", "--operation-id", operation_id]
    )
    assert parsed.command == "cancel"

    first_exit, first = _run_cancel(state, operation_id, services)
    assert first_exit == 0
    assert first["state"] == "rolled_back"
    assert first["code"] == "operation_cancelled"
    assert first["data"]["mutation_performed"] is True
    assert not partial.exists()
    assert not secure_path.exists()
    persisted = CheckpointStore(state).read(operation_id)
    assert persisted["state"] == "rolled_back"
    assert persisted["active_gate"] is None
    assert persisted["cancellation_available"] is False

    second_exit, second = _run_cancel(state, operation_id, services)
    assert second_exit == 0
    assert second["state"] == "rolled_back"
    assert second["code"] == "operation_already_cancelled"
    assert second["data"]["mutation_performed"] is False
    assert transaction.calls == [operation_id]


def test_post_dispatch_cancel_is_rejected_without_any_side_effect(tmp_path):
    layout = RuntimeLayout(tmp_path / "app", tmp_path / "LaunchAgents")
    state = layout.base / "lifecycle"
    _plan, checkpoint = _create_v2_operation(state, journey="legacy_upgrade")
    operation_id = checkpoint["operation_id"]
    store = CheckpointStore(state)
    commit = RetirementCommit(
        authority_instance_id="authority-a",
        authority_origin_digest="a" * 64,
        runtime_key_id="runtime-key-a",
        owner_id="owner-a",
        installation_id="installation-a",
        mac_id="mac-a",
        vault_id="vault-a",
        role="mobile",
        slot_id="slot-a",
        old_generation=1,
        target_generation=2,
        operation_id=operation_id,
        plan_id=checkpoint["plan_id"],
        release_digest="b" * 64,
        helper_digest="c" * 64,
        nonce_digest="d" * 64,
        idempotency_digest="e" * 64,
        proof_digest="f" * 64,
        consumed_at_epoch=1_800_000_000,
    )
    store.update(
        operation_id,
        state="recovery_required",
        phase="retirement_reconciliation",
        recorded_answers={
            "retirement_intent": RetirementIntent(
                profile_id="profile-a",
                protocol_version="legacy-retirement/v1",
                authority_instance_id=commit.authority_instance_id,
                authority_origin_digest=commit.authority_origin_digest,
                runtime_key_id=commit.runtime_key_id,
                owner_id=commit.owner_id,
                installation_id=commit.installation_id,
                mac_id=commit.mac_id,
                vault_id=commit.vault_id,
                role=commit.role,
                slot_id=commit.slot_id,
                old_generation=commit.old_generation,
                target_generation=commit.target_generation,
                operation_id=commit.operation_id,
                plan_id=commit.plan_id,
                release_digest=commit.release_digest,
                helper_digest=commit.helper_digest,
                nonce_digest=commit.nonce_digest,
                idempotency_digest=commit.idempotency_digest,
            ).to_mapping(),
            "retirement_commit": commit.to_mapping(),
        },
        irreversible_boundary_crossed=True,
        ambiguity_state=AmbiguityState.RETIRED,
        recovery_policy=RecoveryPolicy.FINISH_FORWARD,
        effect_summary=EffectSummary(
            local_effect=EffectDisposition.CHANGED,
            remote_effect=EffectDisposition.CHANGED,
            credential_effect=CredentialEffect.RETIRED,
            mutation_performed=True,
            owned_resource_count=2,
            effect_codes=("retirement_dispatched",),
        ),
        next_actions=(_resume_action(),),
        cancellation_available=False,
    )
    partial = layout.staging / f"{operation_id}.partial"
    partial.mkdir(parents=True)
    marker = partial / "must-remain.txt"
    marker.write_text("do not delete\n", encoding="utf-8")
    secure_path = state / f"{operation_id}.diagnostic-destination.json"
    SecureInputFile.create(secure_path, {"destination": "/private/tmp/export.json"})
    checkpoint_before = store.read(operation_id)
    secure_before = secure_path.read_bytes()
    transaction = _CancelableTransaction(layout)

    exit_code, result = _run_cancel(
        state,
        operation_id,
        LifecycleServices(FakeProbe(), {}, transaction=transaction, layout=layout),
    )

    assert exit_code == 2
    assert result["state"] == "blocked"
    assert result["code"] == "cancellation_unavailable_after_dispatch"
    assert result["data"]["mutation_performed"] is False
    assert transaction.calls == []
    assert store.read(operation_id) == checkpoint_before
    assert marker.read_text(encoding="utf-8") == "do not delete\n"
    assert secure_path.read_bytes() == secure_before


def test_expired_gate_refreshes_in_place_for_the_same_operation(tmp_path):
    """Expiry never approves a gate; refresh never creates a replacement operation."""

    state = tmp_path / "lifecycle"
    store = CheckpointStore(state)
    checkpoint = store.create(
        command="install",
        plan_id="plan-" + "b" * 64,
        phase="authorization",
    )
    now = {"value": 1_000}
    controller = HumanGateController(
        store,
        {"external_ready": lambda: True},
        now=lambda: now["value"],
        gate_ttl_seconds=60,
    )
    gate = controller.require(
        checkpoint["operation_id"],
        gate_type="external_action_required",
        explanation="Complete the external action.",
        exact_action="Complete it, then resume.",
        verification_probe="external_ready",
    )
    first = gate.to_dict()
    assert first["created_at_epoch"] == 1_000
    assert first["expires_at_epoch"] == 1_060
    assert first["refresh_generation"] == 0

    now["value"] = 1_061
    expired = controller.verify(checkpoint["operation_id"])
    assert expired["verified"] is False
    assert expired["code"] == "human_gate_refreshed"
    assert store.read(checkpoint["operation_id"])["state"] == "blocked"

    refreshed_value = expired["gate"]
    assert refreshed_value["gate_id"] != first["gate_id"]
    assert refreshed_value["resume_reference"] == checkpoint["operation_id"]
    assert refreshed_value["created_at_epoch"] == 1_061
    assert refreshed_value["expires_at_epoch"] == 1_121
    assert refreshed_value["refresh_generation"] == 1
    assert store.read(checkpoint["operation_id"])["active_gate"] == refreshed_value

    now["value"] = 1_062
    verified = controller.verify(checkpoint["operation_id"])
    assert verified["verified"] is True
    # Verification remains read-only; only the mutation commit may clear it.
    assert store.read(checkpoint["operation_id"])["active_gate"] == refreshed_value
