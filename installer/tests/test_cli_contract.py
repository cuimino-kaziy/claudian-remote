import io
import json
import shutil
from types import SimpleNamespace

import pytest

from installer.claudian_remote_lifecycle.cli import (
    LifecycleArgumentError,
    LifecycleServices,
    _run_mutation,
    build_parser,
    main,
)
from installer.claudian_remote_lifecycle.checkpoint import CheckpointStore
from installer.claudian_remote_lifecycle.diagnostics import DiagnosticService
from installer.claudian_remote_lifecycle.legacy_authority import (
    CapabilityAwareLegacyRetirementService,
    RetirementCommit,
    RetirementIntent,
)
from installer.claudian_remote_lifecycle.inspect import Inspector
from installer.claudian_remote_lifecycle.model import COMMANDS, RESULT_SCHEMA
from installer.claudian_remote_lifecycle.operation_arbitration import OperationArbitrator
from installer.claudian_remote_lifecycle.plan import PlanStore
from installer.claudian_remote_lifecycle.transaction import LocalTailscaleTransaction
from installer.tests.test_compatibility_decode import _artifact_set
from installer.tests.test_inspect import FakeProbe
from installer.tests.test_operation_arbitration import (
    _create_v2_operation,
    _write_transaction,
)
from installer.tests.test_runtime_transaction import dependencies


def test_every_contract_command_is_parseable_and_unimplemented_mutations_fail_closed(tmp_path):
    parser = build_parser()
    invocations = {
        "inspect": ["inspect"],
        "plan": ["plan", "--mode", "local_tailscale"],
        "status": ["status", "--operation-id", "op-" + "a" * 32],
        "resume": ["resume", "--operation-id", "op-" + "a" * 32],
        "cancel": ["cancel", "--operation-id", "op-" + "a" * 32],
        "install": ["install", "--plan-id", "plan-a"],
        "verify": ["verify"],
        "update": ["update", "--plan-id", "plan-a"],
        "rollback": ["rollback", "--operation-id", "op-" + "a" * 32],
        "uninstall": ["uninstall", "--plan-id", "plan-a"],
        "purge": ["purge", "--plan-id", "plan-a"],
        "revoke-device": ["revoke-device", "--device-id", "device-a"],
        "diagnose": ["diagnose"],
        "export-diagnostics": ["export-diagnostics", "--destination", str((tmp_path / "diagnostics.json").resolve())],
    }
    assert set(invocations) == set(COMMANDS)
    for command, argv in invocations.items():
        assert parser.parse_args(["--state-dir", str(tmp_path), *argv]).command == command

    for command in ("uninstall", "purge"):
        output = io.StringIO()
        exit_code = main(
            ["--state-dir", str(tmp_path), command, "--plan-id", "plan-a"],
            stdout=output,
            services=LifecycleServices(FakeProbe(), {}),
        )
        result = json.loads(output.getvalue())
        assert exit_code == 2
        assert result["result_schema"] == RESULT_SCHEMA
        assert result["code"] == "operation_not_implemented"
        assert result["data"]["mutation_performed"] is False

    output = io.StringIO()
    exit_code = main(
        ["--state-dir", str(tmp_path), "update", "--plan-id", "plan-a"],
        stdout=output,
        services=LifecycleServices(FakeProbe(), {}),
    )
    assert exit_code == 2
    assert json.loads(output.getvalue())["code"] == "plan_not_found"

    output = io.StringIO()
    exit_code = main(
        ["--state-dir", str(tmp_path), "install", "--plan-id", "plan-a"],
        stdout=output,
        services=LifecycleServices(FakeProbe(), {}),
    )
    assert exit_code == 2
    assert json.loads(output.getvalue())["code"] == "plan_not_found"


class FakeUninstaller:
    def __init__(self):
        self.calls = []

    def uninstall(self):
        self.calls.append("uninstall")
        return {"state": "ready", "code": "uninstall_completed", "mutation_performed": True}

    def purge(self, *, confirmation_verified):
        assert confirmation_verified is True
        self.calls.append("purge")
        return {"state": "ready", "code": "purge_completed", "mutation_performed": True}


def _prepare_plan(tmp_path, services):
    output = io.StringIO()
    assert main(
        ["--state-dir", str(tmp_path), "plan", "--mode", "local_tailscale", "--vault-id", "vault-a"],
        stdout=output,
        services=services,
    ) == 0
    return json.loads(output.getvalue())["plan_id"]


def test_local_support_commands_are_wired_and_human_gates_resume(tmp_path):
    uninstaller = FakeUninstaller()
    revoked = []
    services = LifecycleServices(
        FakeProbe(),
        {
            "purge_confirmation_verified": lambda: True,
            "diagnostic_export_confirmation_verified": lambda: True,
        },
        diagnostics=DiagnosticService(),
        uninstaller=uninstaller,
        revoke_device=lambda device_id: (
            revoked.append(device_id)
            or {"state": "ready", "code": "device_revoked", "mutation_performed": True, "device_id": device_id}
        ),
    )
    plan_id = _prepare_plan(tmp_path, services)

    output = io.StringIO()
    assert main(
        ["--state-dir", str(tmp_path), "uninstall", "--plan-id", plan_id],
        stdout=output,
        services=services,
    ) == 0
    assert json.loads(output.getvalue())["code"] == "uninstall_completed"

    output = io.StringIO()
    assert main(
        ["--state-dir", str(tmp_path), "revoke-device", "--device-id", "iphone-a"],
        stdout=output,
        services=services,
    ) == 0
    assert revoked == ["iphone-a"]

    output = io.StringIO()
    assert main(["--state-dir", str(tmp_path), "diagnose"], stdout=output, services=services) == 0
    diagnosis = json.loads(output.getvalue())
    assert diagnosis["code"] == "diagnostic_summary_ready"
    assert diagnosis["data"]["uploaded"] is False

    output = io.StringIO()
    assert main(
        ["--state-dir", str(tmp_path), "purge", "--plan-id", plan_id],
        stdout=output,
        services=services,
    ) == 2
    purge_gate = json.loads(output.getvalue())
    assert purge_gate["code"] == "human_action_required"
    output = io.StringIO()
    assert main(
        ["--state-dir", str(tmp_path), "resume", "--operation-id", purge_gate["operation_id"]],
        stdout=output,
        services=services,
    ) == 0
    assert json.loads(output.getvalue())["code"] == "purge_completed"

    destination = (tmp_path / "export.json").resolve()
    output = io.StringIO()
    assert main(
        ["--state-dir", str(tmp_path), "export-diagnostics", "--destination", str(destination)],
        stdout=output,
        services=services,
    ) == 2
    export_gate = json.loads(output.getvalue())
    assert export_gate["data"]["preview"]["uploaded"] is False
    output = io.StringIO()
    assert main(
        ["--state-dir", str(tmp_path), "resume", "--operation-id", export_gate["operation_id"]],
        stdout=output,
        services=services,
    ) == 0
    assert json.loads(output.getvalue())["code"] == "diagnostic_export_ready"
    assert destination.stat().st_mode & 0o777 == 0o600


def test_partial_uninstall_returns_an_operation_that_resume_can_finish(tmp_path):
    class InterruptedUninstaller(FakeUninstaller):
        def uninstall(self):
            self.calls.append("uninstall")
            if len(self.calls) == 1:
                return {
                    "state": "recovery_required",
                    "code": "uninstall_precondition_incomplete",
                    "mutation_performed": True,
                }
            return {
                "state": "ready",
                "code": "uninstall_completed",
                "mutation_performed": True,
            }

    uninstaller = InterruptedUninstaller()
    services = LifecycleServices(FakeProbe(), {}, uninstaller=uninstaller)
    plan_id = _prepare_plan(tmp_path, services)

    output = io.StringIO()
    assert main(
        ["--state-dir", str(tmp_path), "uninstall", "--plan-id", plan_id],
        stdout=output,
        services=services,
    ) == 2
    interrupted = json.loads(output.getvalue())
    assert interrupted["code"] == "uninstall_precondition_incomplete"
    assert interrupted["state"] == "recovery_required"
    assert interrupted["operation_id"].startswith("op-")

    output = io.StringIO()
    assert main(
        ["--state-dir", str(tmp_path), "resume", "--operation-id", interrupted["operation_id"]],
        stdout=output,
        services=services,
    ) == 0
    completed = json.loads(output.getvalue())
    assert completed["code"] == "uninstall_completed"
    assert completed["operation_id"] == interrupted["operation_id"]
    assert uninstaller.calls == ["uninstall", "uninstall"]


def test_recovery_status_exposes_rollback_and_resume_does_not_guess(tmp_path):
    class VerifiedRecoveryTransaction:
        @staticmethod
        def recovery_action(operation_id, plan_id):
            assert operation_id.startswith("op-")
            assert plan_id.startswith("plan-")
            return "rollback"

    _plan, checkpoint = _create_v2_operation(tmp_path)
    _write_transaction(
        tmp_path,
        checkpoint,
        phase="recovery_required",
        completed=("staging",),
    )
    services = LifecycleServices(
        FakeProbe(), {}, transaction=VerifiedRecoveryTransaction()
    )

    output = io.StringIO()
    assert main(
        [
            "--state-dir", str(tmp_path), "status",
            "--operation-id", checkpoint["operation_id"],
        ],
        stdout=output,
        services=services,
    ) == 2
    status = json.loads(output.getvalue())
    assert status["state"] == "recovery_required"
    assert status["data"]["recovery_action"] == "rollback"

    output = io.StringIO()
    assert main(
        [
            "--state-dir", str(tmp_path), "resume",
            "--operation-id", checkpoint["operation_id"],
        ],
        stdout=output,
        services=services,
    ) == 2
    resumed = json.loads(output.getvalue())
    assert resumed["state"] == "recovery_required"
    assert resumed["data"]["recovery_action"] == "rollback"


def test_recovery_status_requires_manual_review_without_a_validated_transaction(tmp_path):
    checkpoints = CheckpointStore(tmp_path)
    checkpoint = checkpoints.create(
        command="install",
        plan_id="plan-" + "c" * 64,
    )
    checkpoints.update(
        checkpoint["operation_id"],
        state="recovery_required",
        phase="installation_compensation_failed",
        completed_phases=["staging"],
    )

    output = io.StringIO()
    assert main(
        [
            "--state-dir", str(tmp_path), "status",
            "--operation-id", checkpoint["operation_id"],
        ],
        stdout=output,
        services=LifecycleServices(FakeProbe(), {}),
    ) == 2

    status = json.loads(output.getvalue())
    assert status["state"] == "blocked"
    assert status["code"] == "prior_operation_artifact_invalid"
    assert status["data"]["recovery_action"] == "manual_recovery_required"


def test_ready_v2_operation_cannot_be_rolled_back_after_commit(tmp_path):
    class RollbackMustNotRun:
        def __init__(self):
            self.calls = []

        def rollback(self, plan, *, operation_id):
            self.calls.append((plan, operation_id))
            raise AssertionError("closed ready operation must not invoke rollback")

    _plan, checkpoint = _create_v2_operation(tmp_path)
    completed = (
        "staging",
        "legacy_plugin_migration",
        "secure_provisioning",
        "plugin_activation",
        "launchd",
        "tailscale_serve",
        "verified",
        "paired",
    )
    _write_transaction(
        tmp_path,
        checkpoint,
        phase="ready",
        completed=completed,
        activation_started=True,
        plugin_activated=True,
    )
    CheckpointStore(tmp_path).update(
        checkpoint["operation_id"],
        state="ready",
        phase="complete",
        completed_phases=list(completed),
        recovery_policy="not_applicable",
        next_actions=[],
        cancellation_available=False,
        active_gate=None,
    )
    transaction = RollbackMustNotRun()
    output = io.StringIO()

    assert main(
        [
            "--state-dir",
            str(tmp_path),
            "rollback",
            "--operation-id",
            checkpoint["operation_id"],
        ],
        stdout=output,
        services=LifecycleServices(FakeProbe(), {}, transaction=transaction),
    ) == 2

    result = json.loads(output.getvalue())
    assert result["state"] == "blocked"
    assert result["code"] == "rollback_not_available"
    assert result["operation_id"] == checkpoint["operation_id"]
    assert transaction.calls == []


def test_exact_beta4_staging_failure_status_and_rollback_close_the_original_operation(
    tmp_path,
):
    deps, _events = dependencies(tmp_path)
    deps.layout.ensure()
    state_dir = deps.layout.state
    paths, values = _artifact_set(state_dir, migration=False)
    operation_id = values["checkpoint"]["operation_id"]
    vault = deps.vault_path("vault-a")
    legacy = vault / ".obsidian" / "plugins" / "whale-agent-bridge"
    legacy.mkdir(parents=True)
    (legacy / "manifest.json").write_text(
        json.dumps({"id": "whale-agent-bridge", "version": "recognized-dogfood-lineage"}),
        encoding="utf-8",
    )
    (legacy / "data.json").write_text(
        json.dumps({"mobile_token": "fixture-secret-never-returned"}),
        encoding="utf-8",
    )
    (vault / ".obsidian" / "community-plugins.json").write_text(
        json.dumps(["whale-agent-bridge"]),
        encoding="utf-8",
    )
    partial = deps.layout.staging / f"{operation_id}.partial"
    partial.mkdir(parents=True)
    saved_plan_before = paths["saved_plan_path"].read_bytes()
    services = LifecycleServices(
        FakeProbe(),
        {},
        transaction=LocalTailscaleTransaction(deps),
    )

    output = io.StringIO()
    assert main(
        [
            "--state-dir",
            str(state_dir),
            "status",
            "--operation-id",
            operation_id,
        ],
        stdout=output,
        services=services,
    ) == 2
    status = json.loads(output.getvalue())
    assert status["code"] == "prior_operation_recovery_required"
    assert status["operation_id"] == operation_id
    assert status["next_actions"] == [
        {
            "action_id": "rollback-original-operation",
            "action_type": "lifecycle_command",
            "owner": "agent",
            "recommended": True,
            "executable": True,
            "command": "rollback",
            "parameters": {"operation_id_ref": "result.operation_id"},
        }
    ]

    output = io.StringIO()
    assert main(
        [
            "--state-dir",
            str(state_dir),
            "rollback",
            "--operation-id",
            operation_id,
        ],
        stdout=output,
        services=services,
    ) == 0
    rolled_back = json.loads(output.getvalue())
    assert rolled_back["state"] == "rolled_back"
    assert rolled_back["code"] == "rollback_completed"
    assert rolled_back["operation_id"] == operation_id
    assert not partial.exists()
    assert paths["saved_plan_path"].read_bytes() == saved_plan_before
    assert json.loads(paths["checkpoint_path"].read_text())["state"] == "rolled_back"
    assert json.loads(paths["local_transaction_path"].read_text())["phase"] == "rolled_back"
    assert OperationArbitrator(state_dir).inspect().state == "clear"

    output = io.StringIO()
    assert main(
        [
            "--state-dir",
            str(state_dir),
            "rollback",
            "--operation-id",
            operation_id,
        ],
        stdout=output,
        services=services,
    ) == 0
    repeated = json.loads(output.getvalue())
    assert repeated["state"] == "rolled_back"
    assert repeated["code"] == "rollback_already_completed"
    assert repeated["data"]["mutation_performed"] is False


def test_successful_purge_does_not_recreate_deleted_lifecycle_state(tmp_path):
    class StateDeletingUninstaller(FakeUninstaller):
        def purge(self, *, confirmation_verified):
            assert confirmation_verified is True
            shutil.rmtree(tmp_path)
            return {"state": "ready", "code": "purge_completed", "mutation_performed": True}

    services = LifecycleServices(
        FakeProbe(),
        {"purge_confirmation_verified": lambda: True},
        uninstaller=StateDeletingUninstaller(),
    )
    plan_id = _prepare_plan(tmp_path, services)
    output = io.StringIO()
    assert main(
        ["--state-dir", str(tmp_path), "purge", "--plan-id", plan_id],
        stdout=output,
        services=services,
    ) == 2
    operation_id = json.loads(output.getvalue())["operation_id"]

    output = io.StringIO()
    assert main(
        ["--state-dir", str(tmp_path), "resume", "--operation-id", operation_id],
        stdout=output,
        services=services,
    ) == 0
    assert json.loads(output.getvalue())["code"] == "purge_completed"
    assert not tmp_path.exists()


def test_stdout_is_exactly_one_json_result(tmp_path):
    output = io.StringIO()
    code = main(
        ["--state-dir", str(tmp_path), "inspect"],
        stdout=output,
        services=LifecycleServices(FakeProbe(), {}),
    )
    lines = output.getvalue().splitlines()
    assert code == 0
    assert len(lines) == 1
    assert json.loads(lines[0])["code"] == "inspection_ready"


def test_invalid_arguments_and_agent_unsafe_result_fields_fail_closed_to_json(tmp_path):
    output = io.StringIO()
    code = main(["--state-dir", str(tmp_path), "plan"], stdout=output)
    result = json.loads(output.getvalue())
    assert code == 2
    assert result["code"] == "invalid_lifecycle_input"

    from installer.claudian_remote_lifecycle.model import LifecycleResult

    unsafe = LifecycleResult(
        command="diagnose",
        state="blocked",
        code="test",
        message="safe",
        data={"access_token": "must-not-print"},
    )
    with pytest.raises(ValueError, match="agent_unsafe_result_field"):
        unsafe.to_dict()


def test_production_services_reject_an_arbitrary_state_directory_that_could_expand_purge_scope(tmp_path):
    with pytest.raises(LifecycleArgumentError, match="state_directory_not_supported"):
        LifecycleServices.local(state_dir=tmp_path / "state")


def test_unknown_runtime_exception_is_normalized_in_result_and_checkpoint(tmp_path):
    class FailingTransaction:
        def install(self, _plan, *, operation_id):
            raise RuntimeError("looks_stable_but_contains_private_context")

        def completed_phases(self, _operation_id):
            return []

    services = LifecycleServices(FakeProbe(), {}, transaction=FailingTransaction())
    plan_id = _prepare_plan(tmp_path, services)
    output = io.StringIO()
    assert main(
        ["--state-dir", str(tmp_path), "install", "--plan-id", plan_id],
        stdout=output,
        services=services,
    ) == 2
    result = json.loads(output.getvalue())
    assert result["code"] == "operation_failed"
    checkpoint = json.loads((tmp_path / f"{result['operation_id']}.json").read_text())
    assert checkpoint["phase"] == "preparation"
    assert checkpoint["effect_summary"]["effect_codes"] == ["operation_failed"]
    assert "private_context" not in json.dumps(result)


def test_install_transition_reloads_authority_checkpoint_after_retirement_proof(
    tmp_path,
    monkeypatch,
):
    _plan, checkpoint = _create_v2_operation(tmp_path, journey="legacy_upgrade")
    store = CheckpointStore(tmp_path)
    commit = RetirementCommit(
        authority_instance_id="authority-a",
        authority_origin_digest="1" * 64,
        runtime_key_id="runtime-key-a",
        owner_id="owner-a",
        installation_id="installation-a",
        mac_id="mac-a",
        vault_id="vault-a",
        role="mobile",
        slot_id="slot-a",
        old_generation=1,
        target_generation=2,
        operation_id=checkpoint["operation_id"],
        plan_id=checkpoint["plan_id"],
        release_digest="2" * 64,
        helper_digest="3" * 64,
        nonce_digest="4" * 64,
        idempotency_digest="5" * 64,
        proof_digest="6" * 64,
        consumed_at_epoch=2_000_000_000,
    )

    class ProofAdvancingTransaction:
        def install(self, _plan, *, operation_id):
            store.update(
                operation_id,
                state="recovery_required",
                phase="retirement_reconciliation",
                irreversible_boundary_crossed=True,
                ambiguity_state="retired",
                recovery_policy="finish_forward",
                effect_summary={
                    "local_effect": "staged",
                    "remote_effect": "changed",
                    "credential_effect": "retired",
                    "mutation_performed": True,
                    "owned_resource_count": 2,
                    "effect_codes": ["retirement_committed"],
                },
                next_actions=[checkpoint["next_actions"][0]],
                cancellation_available=False,
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
                        nonce_digest="4" * 64,
                        idempotency_digest="5" * 64,
                    ).to_mapping(),
                    "retirement_commit": commit.to_mapping(),
                },
            )
            return {
                "state": "recovery_required",
                "code": "post_retirement_finish_forward_required",
                "mutation_performed": True,
            }

        def completed_phases(self, _operation_id):
            return []

        def recovery_action(self, _operation_id, _plan_id):
            return "finish_forward"

    monkeypatch.setattr(
        "installer.claudian_remote_lifecycle.cli.validate_mutation_environment",
        lambda *_args, **_kwargs: None,
    )
    result = _run_mutation(
        command="install",
        operation_id=checkpoint["operation_id"],
        plan_id=checkpoint["plan_id"],
        args=SimpleNamespace(state_dir=str(tmp_path)),
        inspector=Inspector(FakeProbe()),
        plans=PlanStore(tmp_path),
        checkpoints=store,
        services=LifecycleServices(
            FakeProbe(), {}, transaction=ProofAdvancingTransaction()
        ),
    )

    persisted = store.read(checkpoint["operation_id"])
    assert result.code == "post_retirement_finish_forward_required"
    assert persisted["irreversible_boundary_crossed"] is True
    assert persisted["ambiguity_state"] == "retired"
    assert persisted["recovery_policy"] == "finish_forward"
    assert persisted["cancellation_available"] is False
    assert persisted["recorded_answers"]["retirement_commit"] == commit.to_mapping()


def test_resume_reconciles_before_environment_drift_validation(tmp_path, monkeypatch):
    _plan, checkpoint = _create_v2_operation(tmp_path, journey="legacy_upgrade")
    store = CheckpointStore(tmp_path)
    reconcile_action = {
        "action_id": "reconcile-original-operation",
        "action_type": "lifecycle_command",
        "owner": "agent",
        "recommended": True,
        "executable": True,
        "command": "resume",
        "parameters": {"operation_id_ref": "checkpoint.operation_id"},
    }
    store.update(
        checkpoint["operation_id"],
        state="recovery_required",
        phase="retirement_reconciliation",
        ambiguity_state="retirement_outcome_unknown",
        recovery_policy="reconcile_same_operation",
        effect_summary={
            "local_effect": "staged",
            "remote_effect": "unknown",
            "credential_effect": "outcome_unknown",
            "mutation_performed": True,
            "owned_resource_count": 1,
            "effect_codes": ["retirement_dispatched"],
        },
        next_actions=[reconcile_action],
        recorded_answers={
            "retirement_intent": RetirementIntent(
                profile_id="profile-a",
                protocol_version="legacy-retirement/v1",
                authority_instance_id="authority-a",
                authority_origin_digest="1" * 64,
                runtime_key_id="runtime-key-a",
                owner_id="owner-a",
                installation_id="installation-a",
                mac_id="mac-a",
                vault_id="vault-a",
                role="mobile",
                slot_id="slot-a",
                old_generation=1,
                target_generation=2,
                operation_id=checkpoint["operation_id"],
                plan_id=checkpoint["plan_id"],
                release_digest="2" * 64,
                helper_digest="3" * 64,
                nonce_digest="4" * 64,
                idempotency_digest="5" * 64,
            ).to_mapping()
        },
        cancellation_available=False,
    )

    class ReconciliationOnlyTransaction:
        def __init__(self):
            self.reconciled = 0
            self.installed = 0

        def recovery_action(self, _operation_id, _plan_id):
            return "reconcile_retirement_outcome"

        def reconcile_legacy_retirement(self, _plan, *, operation_id):
            assert operation_id == checkpoint["operation_id"]
            self.reconciled += 1
            return {
                "state": "rolled_back",
                "code": "rollback_completed",
                "mutation_performed": True,
            }

        def install(self, _plan, *, operation_id):
            self.installed += 1
            pytest.fail("reconciliation must not continue installation")

        def completed_phases(self, _operation_id):
            return []

    transaction = ReconciliationOnlyTransaction()
    monkeypatch.setattr(
        "installer.claudian_remote_lifecycle.cli.validate_mutation_environment",
        lambda *_args, **_kwargs: pytest.fail(
            "read-only reconciliation must not be blocked by environment drift"
        ),
    )
    result = _run_mutation(
        command="resume",
        operation_id=checkpoint["operation_id"],
        plan_id=checkpoint["plan_id"],
        args=SimpleNamespace(state_dir=str(tmp_path)),
        inspector=Inspector(FakeProbe()),
        plans=PlanStore(tmp_path),
        checkpoints=store,
        services=LifecycleServices(FakeProbe(), {}, transaction=transaction),
    )

    assert result.state == "rolled_back"
    assert transaction.reconciled == 1
    assert transaction.installed == 0


@pytest.mark.parametrize(
    ("blocking_code", "probe_name"),
    [
        ("tailscale_https_consent_required", "tailscale_https_ready"),
        ("desktop_plugin_bootstrap_required", "desktop_plugin_authenticated"),
        ("pairing_approval_required", "pairing_credential_active"),
    ],
)
def test_transaction_gates_use_one_canonical_human_gate_and_resume_contract(
    tmp_path, blocking_code, probe_name,
):
    ready = False

    class GatedTransaction:
        def install(self, _plan, *, operation_id):
            if ready:
                return {"state": "ready", "code": "installation_ready", "mutation_performed": True}
            return {
                "state": "blocked",
                "code": blocking_code,
                "mutation_performed": blocking_code != "tailscale_https_consent_required",
                "gate": {
                    "gate_type": blocking_code,
                    "explanation": "A verified external action is required.",
                    "exact_action": "Complete the external action, then resume.",
                    "verification_probe": probe_name,
                    "operator_options": ({
                        "id": "agent_continue",
                        "label": "由 Agent 继续操作",
                        "instructions": "Continue through the external action.",
                        "recommended": True,
                    },),
                },
            }

        def completed_phases(self, _operation_id):
            return []

    services = LifecycleServices(
        FakeProbe(),
        {probe_name: lambda: ready},
        transaction=GatedTransaction(),
    )
    plan_id = _prepare_plan(tmp_path, services)
    output = io.StringIO()
    assert main(
        ["--state-dir", str(tmp_path), "install", "--plan-id", plan_id],
        stdout=output,
        services=services,
    ) == 2
    waiting = json.loads(output.getvalue())
    assert waiting["code"] == "human_action_required"
    assert waiting["data"]["blocking_code"] == blocking_code
    assert waiting["gate"]["verification_probe"] == probe_name
    assert waiting["gate"]["operator_options"][0]["id"] == "agent_continue"
    operation_id = waiting["operation_id"]

    output = io.StringIO()
    assert main(
        ["--state-dir", str(tmp_path), "resume", "--operation-id", operation_id],
        stdout=output,
        services=services,
    ) == 2
    assert json.loads(output.getvalue())["code"] == "human_action_required"

    ready = True
    output = io.StringIO()
    assert main(
        ["--state-dir", str(tmp_path), "resume", "--operation-id", operation_id],
        stdout=output,
        services=services,
    ) == 0
    assert json.loads(output.getvalue())["code"] == "installation_ready"


def test_legacy_retirement_requires_explicit_operation_bound_authorization(tmp_path):
    store = CheckpointStore(tmp_path)
    available = False
    operator_confirmed = False

    class AuthorizationGatedTransaction:
        def install(self, plan, *, operation_id):
            checkpoint = store.read(operation_id)
            marker = checkpoint["recorded_answers"].get(
                "legacy_authority_authorization"
            )
            if marker != {
                "operation_id": operation_id,
                "plan_id": plan["plan_id"],
                "authorized": True,
            }:
                return {
                    "state": "blocked",
                    "code": "legacy_authority_authorization_required",
                    "mutation_performed": False,
                    "gate": {
                        "gate_type": "legacy_authority_authorization_required",
                        "explanation": "Retirement requires explicit approval.",
                        "exact_action": "Review the impact and explicitly authorize retirement.",
                        "verification_probe": "legacy_authority_available",
                    },
                }
            return {
                "state": "ready",
                "code": "installation_ready",
                "mutation_performed": True,
            }

        def completed_phases(self, _operation_id):
            return []

    services = LifecycleServices(
        FakeProbe(),
        {
            "legacy_authority_available": lambda: available,
            "legacy_retirement_operator_confirmation": lambda: operator_confirmed,
        },
        transaction=AuthorizationGatedTransaction(),
    )
    plan_id = _prepare_plan(tmp_path, services)
    output = io.StringIO()
    assert main(
        ["--state-dir", str(tmp_path), "install", "--plan-id", plan_id],
        stdout=output,
        services=services,
    ) == 2
    operation_id = json.loads(output.getvalue())["operation_id"]

    available = True
    output = io.StringIO()
    assert main(
        ["--state-dir", str(tmp_path), "resume", "--operation-id", operation_id],
        stdout=output,
        services=services,
    ) == 2
    assert json.loads(output.getvalue())["code"] == "human_action_required"
    assert "legacy_authority_authorization" not in store.read(operation_id)[
        "recorded_answers"
    ]

    output = io.StringIO()
    assert main(
        [
            "--state-dir",
            str(tmp_path),
            "resume",
            "--operation-id",
            operation_id,
            "--authorize-legacy-retirement",
        ],
        stdout=output,
        services=services,
    ) == 2
    assert json.loads(output.getvalue())["code"] == "human_action_required"
    assert "legacy_authority_authorization" not in store.read(operation_id)[
        "recorded_answers"
    ]

    operator_confirmed = True
    output = io.StringIO()
    assert main(
        [
            "--state-dir",
            str(tmp_path),
            "resume",
            "--operation-id",
            operation_id,
            "--authorize-legacy-retirement",
        ],
        stdout=output,
        services=services,
    ) == 0
    assert json.loads(output.getvalue())["code"] == "installation_ready"
    assert store.read(operation_id)["recorded_answers"][
        "legacy_authority_authorization"
    ] == {
        "operation_id": operation_id,
        "plan_id": plan_id,
        "authorized": True,
    }


def test_production_local_services_wire_a_real_legacy_retirement_adapter(
    tmp_path,
    monkeypatch,
):
    import installer.claudian_remote_lifecycle.cli as cli_module

    state = tmp_path / "lifecycle"
    monkeypatch.setattr(cli_module, "DEFAULT_STATE_DIR", state)
    services = LifecycleServices.local(state_dir=state)

    assert isinstance(
        services.transaction.dependencies.legacy_credential_revoker,
        CapabilityAwareLegacyRetirementService,
    )
