import json

from installer.claudian_remote_lifecycle.checkpoint import CheckpointStore
from installer.claudian_remote_lifecycle.inspect import Inspector
from installer.claudian_remote_lifecycle.model import (
    ActionOwner,
    AmbiguityState,
    CredentialEffect,
    EffectDisposition,
    EffectSummary,
    Journey,
    NextAction,
    NextActionType,
    PairingIdentityPolicy,
    RecoveryPolicy,
)
from installer.claudian_remote_lifecycle.operation_arbitration import (
    OperationArbitrator,
)
from installer.claudian_remote_lifecycle.plan import PlanBuilder, PlanStore
from installer.claudian_remote_lifecycle.provisioning import SecureInputFile
from installer.claudian_remote_lifecycle.human_gates import HumanGateController
from installer.claudian_remote_lifecycle.legacy_authority import (
    RetirementCommit,
    RetirementIntent,
)
from installer.tests.test_compatibility_decode import _artifact_set
from installer.tests.test_inspect import FakeProbe


def _rewrite(path, value):
    path.write_text(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def _retirement_intent(checkpoint):
    return RetirementIntent(
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


def _retirement_commit(checkpoint):
    return RetirementCommit(
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
    ).to_mapping()


def _write_v2_plan(state, *, journey="fresh_install", pairing_policy="preserve"):
    probe = FakeProbe()
    if journey == "current_update":
        installation = {
            **probe.installation(),
            "installed": True,
            "plugin_lineage": {
                "current": {"present": True, "enabled": True, "recognized": True},
                "legacy": {"present": False, "enabled": False, "recognized": True},
            },
            "legacy_authority_capability": "not_applicable",
        }
        probe.installation = lambda: installation
    elif journey == "legacy_upgrade":
        installation = {
            **probe.installation(),
            "installed": False,
            "plugin_lineage": {
                "current": {"present": False, "enabled": False, "recognized": True},
                "legacy": {"present": True, "enabled": True, "recognized": True},
            },
            "legacy_authority_adapter": "verified_test_adapter",
            "legacy_authority_capability": "available",
        }
        probe.installation = lambda: installation
    snapshot = Inspector(probe).snapshot()
    plan = PlanBuilder(
        current_update_pairing_identity_policy=pairing_policy
    ).build(snapshot, mode="local_tailscale")
    PlanStore(state).write(plan, snapshot)
    return plan


def _resume_action():
    return NextAction(
        action_id="resume-original-operation",
        action_type=NextActionType.LIFECYCLE_COMMAND,
        owner=ActionOwner.AGENT,
        recommended=True,
        executable=True,
        command="resume",
        parameters={"operation_id_ref": "checkpoint.operation_id"},
    )


def _cancel_action():
    return NextAction(
        action_id="cancel-original-operation",
        action_type=NextActionType.LIFECYCLE_COMMAND,
        owner=ActionOwner.AGENT,
        recommended=False,
        executable=True,
        command="cancel",
        parameters={"operation_id_ref": "result.operation_id"},
    )


def _lifecycle_action(
    command,
    *,
    action_id=None,
    owner=ActionOwner.AGENT,
    operation_id_ref="checkpoint.operation_id",
):
    return NextAction(
        action_id=action_id or f"{command}-original-operation",
        action_type=NextActionType.LIFECYCLE_COMMAND,
        owner=owner,
        recommended=True,
        executable=True,
        command=command,
        parameters={"operation_id_ref": operation_id_ref},
    )


def _manual_action():
    return NextAction(
        action_id="contact-maintainer-with-diagnostics",
        action_type=NextActionType.MANUAL_INSTRUCTION,
        owner=ActionOwner.MAINTAINER,
        recommended=True,
        executable=True,
        parameters={"instruction_code": "manual_recovery_required"},
    )


def _write_transaction(
    state,
    checkpoint,
    *,
    phase="before_staging",
    completed=(),
    operation_id=None,
    plan_id=None,
    activation_started=False,
    plugin_activated=False,
):
    value = {
        "transaction_schema": "claudian-remote.local-transaction/v1",
        "operation_id": operation_id or checkpoint["operation_id"],
        "plan_id": plan_id or checkpoint["plan_id"],
        "phase": phase,
        "completed_phases": list(completed),
        "prior_availability_vault": None,
        "prior_release_id": None,
        "activation_started": activation_started,
        "plugin_activated": plugin_activated,
    }
    _rewrite(
        state / f"{checkpoint['operation_id']}.transaction.json",
        value,
    )
    return value


def _create_v2_operation(
    state,
    *,
    journey="fresh_install",
    plan_pairing="preserve",
    checkpoint_pairing=PairingIdentityPolicy.NOT_APPLICABLE,
):
    plan = _write_v2_plan(
        state, journey=journey, pairing_policy=plan_pairing
    )
    checkpoint = CheckpointStore(state).create(
        command="update" if journey == "current_update" else "install",
        plan_id=plan["plan_id"],
        phase="preparation",
        journey=Journey(journey),
        irreversible_boundary_crossed=False,
        ambiguity_state=(
            AmbiguityState.NOT_DISPATCHED
            if journey == "legacy_upgrade"
            else AmbiguityState.NOT_APPLICABLE
        ),
        recovery_policy=RecoveryPolicy.RETRY_SAME_OPERATION,
        effect_summary=EffectSummary(
            local_effect=EffectDisposition.STAGED,
            remote_effect=EffectDisposition.NOT_APPLICABLE,
            credential_effect=(
                CredentialEffect.NOT_DISPATCHED
                if journey == "legacy_upgrade"
                else CredentialEffect.NOT_APPLICABLE
            ),
            mutation_performed=True,
            owned_resource_count=1,
            effect_codes=("operation_staged",),
        ),
        next_actions=(_resume_action(), _cancel_action()),
        cancellation_available=True,
        pairing_identity_policy=checkpoint_pairing,
        prior_operation_terminal=True,
    )
    return plan, checkpoint


def _create_diagnostic_export_gate(state):
    store = CheckpointStore(state)
    checkpoint = store.create(
        command="export-diagnostics",
        plan_id="diagnostic-export",
        phase="diagnostics",
        journey=Journey.UNCLASSIFIED,
        irreversible_boundary_crossed=False,
        ambiguity_state=AmbiguityState.NOT_APPLICABLE,
        recovery_policy=RecoveryPolicy.RETRY_SAME_OPERATION,
        effect_summary=EffectSummary(
            local_effect=EffectDisposition.STAGED,
            remote_effect=EffectDisposition.NOT_APPLICABLE,
            credential_effect=CredentialEffect.NOT_APPLICABLE,
            mutation_performed=False,
            owned_resource_count=0,
            effect_codes=(),
        ),
        next_actions=(_resume_action(), _cancel_action()),
        cancellation_available=True,
        pairing_identity_policy=PairingIdentityPolicy.UNCLASSIFIED,
        prior_operation_terminal=True,
    )
    HumanGateController(
        store,
        {"diagnostic_export_confirmation_verified": lambda: False},
    ).require(
        checkpoint["operation_id"],
        gate_type="diagnostic_export_confirmation_required",
        explanation="Review the local diagnostic export preview.",
        exact_action="Confirm the macOS-owned dialog, then resume.",
        verification_probe="diagnostic_export_confirmation_verified",
    )
    return store.read(checkpoint["operation_id"])


def test_empty_state_has_no_prior_operation_and_allows_classification(tmp_path):
    result = OperationArbitrator(tmp_path).inspect()

    assert result.state == "clear"
    assert result.prior_operation_terminal is True
    assert result.recommended_action is None
    assert result.operation_id is None


def test_diagnostic_destination_companion_is_bound_to_its_waiting_gate(tmp_path):
    checkpoint = _create_diagnostic_export_gate(tmp_path)
    SecureInputFile.create(
        tmp_path
        / f"{checkpoint['operation_id']}.diagnostic-destination.json",
        {"destination": str((tmp_path / "diagnostics.json").resolve())},
    )

    result = OperationArbitrator(tmp_path).inspect()

    assert result.state == "reconciliation_required"
    assert result.operation_id == checkpoint["operation_id"]
    assert result.recommended_action == "resume"


def test_diagnostic_destination_companion_with_unsafe_permissions_is_rejected(
    tmp_path,
):
    checkpoint = _create_diagnostic_export_gate(tmp_path)
    path = (
        tmp_path
        / f"{checkpoint['operation_id']}.diagnostic-destination.json"
    )
    SecureInputFile.create(path, {"destination": "/tmp/diagnostics.json"})
    path.chmod(0o644)

    result = OperationArbitrator(tmp_path).inspect()

    assert result.state == "blocked"
    assert result.reason_code == "prior_operation_artifact_invalid"


def test_pre_mutation_blocked_v1_operation_is_verified_terminal(tmp_path):
    paths, values = _artifact_set(tmp_path, migration=False)
    paths["local_transaction_path"].unlink()
    values["checkpoint"].update(
        state="blocked",
        phase="legacy_credential_revocation_unavailable",
        completed_phases=[],
    )
    _rewrite(paths["checkpoint_path"], values["checkpoint"])

    result = OperationArbitrator(tmp_path).inspect()

    assert result.state == "clear"
    assert result.prior_operation_terminal is True
    assert result.terminal_operation_ids == (values["checkpoint"]["operation_id"],)


def test_waiting_v1_human_gate_owns_resume_and_blocks_a_new_operation(tmp_path):
    paths, values = _artifact_set(tmp_path, migration=False)
    paths["local_transaction_path"].unlink()
    checkpoint = values["checkpoint"]
    checkpoint.update(
        state="blocked",
        phase="tailscale_login_required",
        completed_phases=[],
        active_gate={
            "gate_id": "gate-" + "b" * 24,
            "gate_type": "tailscale_login_required",
            "explanation": "Sign in to Tailscale.",
            "exact_action": "Complete sign in and resume.",
            "verification_probe": "tailscale_logged_in",
            "resume_reference": checkpoint["operation_id"],
            "operator_options": [],
            "status": "waiting",
        },
    )
    _rewrite(paths["checkpoint_path"], checkpoint)

    result = OperationArbitrator(tmp_path).inspect()

    assert result.state == "reconciliation_required"
    assert result.prior_operation_terminal is False
    assert result.operation_id == checkpoint["operation_id"]
    assert result.reason_code == "prior_operation_gate_waiting"
    assert result.recommended_action == "resume"


def test_recovery_required_v1_operation_owns_the_only_rollback_action(tmp_path):
    paths, values = _artifact_set(tmp_path, migration=False)

    result = OperationArbitrator(tmp_path).inspect()

    assert result.state == "reconciliation_required"
    assert result.prior_operation_terminal is False
    assert result.operation_id == values["checkpoint"]["operation_id"]
    assert result.recommended_action == "rollback"
    assert result.reason_code == "prior_operation_recovery_required"


def test_beta4_legacy_migration_journal_cannot_be_treated_as_authoritative_rollback_proof(
    tmp_path,
):
    paths, values = _artifact_set(tmp_path)
    values["checkpoint"].update(state="rolled_back", phase="rollback_completed")
    values["legacy_migration"]["phase"] = "rolled_back"
    _rewrite(paths["checkpoint_path"], values["checkpoint"])
    _rewrite(paths["legacy_migration_path"], values["legacy_migration"])

    result = OperationArbitrator(tmp_path).inspect()

    assert result.state == "reconciliation_required"
    assert result.recommended_action == "manual_recovery_required"
    assert result.reason_code == "prior_operation_legacy_effect_inconclusive"


def test_consistent_rolled_back_operation_is_terminal_without_deleting_sources(tmp_path):
    paths, values = _artifact_set(tmp_path, migration=False)
    values["checkpoint"].update(state="rolled_back", phase="rollback_completed")
    values["local_transaction"]["phase"] = "rolled_back"
    _rewrite(paths["checkpoint_path"], values["checkpoint"])
    _rewrite(paths["local_transaction_path"], values["local_transaction"])
    before = {name: path.read_bytes() for name, path in paths.items()}

    result = OperationArbitrator(tmp_path).inspect()

    assert result.state == "clear"
    assert result.prior_operation_terminal is True
    assert result.terminal_operation_ids == (values["checkpoint"]["operation_id"],)
    assert {name: path.read_bytes() for name, path in paths.items()} == before


def test_multiple_unfinished_operations_fail_closed_without_mtime_selection(tmp_path):
    first_paths, first_values = _artifact_set(tmp_path / "first", migration=False)
    second_paths, second_values = _artifact_set(tmp_path / "second", migration=False)
    second_operation = "op-" + "b" * 32
    second_values["checkpoint"]["operation_id"] = second_operation
    second_values["local_transaction"]["operation_id"] = second_operation
    state = tmp_path / "state"
    (state / "plans").mkdir(parents=True)
    for paths, values in ((first_paths, first_values), (second_paths, second_values)):
        operation = values["checkpoint"]["operation_id"]
        _rewrite(state / f"{operation}.json", values["checkpoint"])
        _rewrite(state / f"{operation}.transaction.json", values["local_transaction"])
        plan_id = values["saved_plan"]["plan"]["plan_id"]
        _rewrite(state / "plans" / f"{plan_id}.json", values["saved_plan"])

    result = OperationArbitrator(state).inspect()

    assert result.state == "blocked"
    assert result.reason_code == "multiple_unfinished_operations"
    assert result.recommended_action == "manual_recovery_required"


def test_orphan_or_invalid_v1_artifact_blocks_new_operations(tmp_path):
    orphan = tmp_path / ("op-" + "c" * 32 + ".transaction.json")
    orphan.write_text("{}\n", encoding="utf-8")

    result = OperationArbitrator(tmp_path).inspect()

    assert result.state == "blocked"
    assert result.reason_code == "prior_operation_artifact_invalid"
    assert result.prior_operation_terminal is False


def test_prepared_v2_operation_owns_typed_resume_action(tmp_path):
    _plan, checkpoint = _create_v2_operation(tmp_path)

    result = OperationArbitrator(tmp_path).inspect()

    assert result.state == "reconciliation_required"
    assert result.operation_id == checkpoint["operation_id"]
    assert result.reason_code == "prior_operation_incomplete"
    assert result.recommended_action == "resume"
    assert result.checkpoint == checkpoint
    assert result.to_summary()["journey"] == "fresh_install"

    snapshot = Inspector(FakeProbe()).snapshot(
        operation_arbitration=result.to_summary()
    )
    assert snapshot["journey"]["journey"] == "unclassified"
    assert snapshot["operation_arbitration"]["phase"] == "preparation"


def test_ready_v2_operation_is_terminal_and_keeps_evidence(tmp_path):
    _plan, checkpoint = _create_v2_operation(tmp_path)
    path = CheckpointStore(tmp_path).path_for(checkpoint["operation_id"])
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
    transaction = _write_transaction(
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
        irreversible_boundary_crossed=True,
        recovery_policy=RecoveryPolicy.NOT_APPLICABLE,
        effect_summary=EffectSummary(
            local_effect=EffectDisposition.CHANGED,
            remote_effect=EffectDisposition.NOT_APPLICABLE,
            credential_effect=CredentialEffect.NOT_APPLICABLE,
            mutation_performed=True,
            owned_resource_count=1,
            effect_codes=("operation_ready",),
        ),
        next_actions=(),
        cancellation_available=False,
    )
    transaction_path = tmp_path / f"{checkpoint['operation_id']}.transaction.json"
    before = (path.read_bytes(), transaction_path.read_bytes())

    result = OperationArbitrator(tmp_path).inspect()

    assert result.state == "clear"
    assert result.prior_operation_terminal is True
    assert result.terminal_operation_ids == (checkpoint["operation_id"],)
    assert (path.read_bytes(), transaction_path.read_bytes()) == before


def test_semantically_invalid_v2_checkpoint_blocks_instead_of_guessing(tmp_path):
    _plan, checkpoint = _create_v2_operation(tmp_path)
    path = CheckpointStore(tmp_path).path_for(checkpoint["operation_id"])
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["irreversible_boundary_crossed"] = True
    raw["recovery_policy"] = "rollback_pre_boundary"
    _rewrite(path, raw)

    result = OperationArbitrator(tmp_path).inspect()

    assert result.state == "blocked"
    assert result.reason_code == "prior_operation_artifact_invalid"
    assert result.recommended_action == "manual_recovery_required"


def test_current_update_checkpoint_must_match_signed_pairing_policy(tmp_path):
    _create_v2_operation(
        tmp_path,
        journey="current_update",
        plan_pairing="preserve",
        checkpoint_pairing=PairingIdentityPolicy.ROTATE,
    )

    result = OperationArbitrator(tmp_path).inspect()

    assert result.state == "blocked"
    assert result.reason_code == "prior_operation_artifact_invalid"


def test_checkpoint_command_must_match_signed_plan_action(tmp_path):
    _plan, checkpoint = _create_v2_operation(
        tmp_path,
        journey="current_update",
        plan_pairing="preserve",
        checkpoint_pairing=PairingIdentityPolicy.PRESERVE,
    )
    path = CheckpointStore(tmp_path).path_for(checkpoint["operation_id"])
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["command"] = "install"
    _rewrite(path, raw)

    result = OperationArbitrator(tmp_path).inspect()

    assert result.state == "blocked"
    assert result.reason_code == "prior_operation_artifact_invalid"


def test_active_gate_never_classifies_as_terminal_no_effect(tmp_path):
    _plan, checkpoint = _create_v2_operation(tmp_path)
    CheckpointStore(tmp_path).update(
        checkpoint["operation_id"],
        state="blocked",
        active_gate={
            "gate_id": "gate-" + "a" * 24,
            "gate_type": "tailscale_login_required",
            "explanation": "Sign in to Tailscale.",
            "exact_action": "Complete sign in and resume.",
            "verification_probe": "tailscale_logged_in",
            "resume_reference": checkpoint["operation_id"],
            "operator_options": [],
            "status": "waiting",
            "created_at_epoch": 100,
            "expires_at_epoch": 200,
            "refresh_generation": 0,
        },
        effect_summary=EffectSummary(
            local_effect=EffectDisposition.UNCHANGED,
            remote_effect=EffectDisposition.NOT_APPLICABLE,
            credential_effect=CredentialEffect.NOT_APPLICABLE,
            mutation_performed=False,
            owned_resource_count=0,
        ),
        recovery_policy=RecoveryPolicy.NOT_APPLICABLE,
        next_actions=(),
        cancellation_available=False,
    )

    result = OperationArbitrator(tmp_path).inspect()

    assert result.state == "blocked"
    assert result.reason_code == "prior_operation_artifact_invalid"


def test_crossed_boundary_rejects_available_cancellation(tmp_path):
    _plan, checkpoint = _create_v2_operation(tmp_path)
    path = CheckpointStore(tmp_path).path_for(checkpoint["operation_id"])
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw.update(
        irreversible_boundary_crossed=True,
        cancellation_available=True,
        recovery_policy="finish_forward",
    )
    _rewrite(path, raw)

    result = OperationArbitrator(tmp_path).inspect()

    assert result.state == "blocked"
    assert result.reason_code == "prior_operation_artifact_invalid"


def test_no_effect_terminal_requires_pre_boundary_and_no_gate(tmp_path):
    _plan, checkpoint = _create_v2_operation(tmp_path)
    path = CheckpointStore(tmp_path).path_for(checkpoint["operation_id"])
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw.update(
        state="blocked",
        irreversible_boundary_crossed=True,
        recovery_policy="not_applicable",
        next_actions=[],
        cancellation_available=False,
    )
    raw["effect_summary"].update(
        mutation_performed=False,
        owned_resource_count=0,
        effect_codes=[],
    )
    _rewrite(path, raw)

    result = OperationArbitrator(tmp_path).inspect()

    assert result.state == "blocked"
    assert result.reason_code == "prior_operation_artifact_invalid"


def test_classified_v2_requires_known_boundary_and_cancellation_booleans(tmp_path):
    for field in ("irreversible_boundary_crossed", "cancellation_available"):
        state = tmp_path / field
        _plan, checkpoint = _create_v2_operation(state)
        path = CheckpointStore(state).path_for(checkpoint["operation_id"])
        raw = json.loads(path.read_text(encoding="utf-8"))
        raw[field] = None
        _rewrite(path, raw)

        result = OperationArbitrator(state).inspect()

        assert result.state == "blocked"
        assert result.reason_code == "prior_operation_artifact_invalid"


def test_legacy_retired_rejects_retry_resume(tmp_path):
    _plan, checkpoint = _create_v2_operation(tmp_path, journey="legacy_upgrade")
    path = CheckpointStore(tmp_path).path_for(checkpoint["operation_id"])
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw.update(
        ambiguity_state="retired",
        irreversible_boundary_crossed=True,
        cancellation_available=False,
    )
    raw["effect_summary"]["credential_effect"] = "retired"
    _rewrite(path, raw)

    result = OperationArbitrator(tmp_path).inspect()

    assert result.state == "blocked"
    assert result.reason_code == "prior_operation_artifact_invalid"


def test_retirement_outcome_unknown_only_allows_reconcile_or_manual(tmp_path):
    _plan, checkpoint = _create_v2_operation(tmp_path, journey="legacy_upgrade")
    path = CheckpointStore(tmp_path).path_for(checkpoint["operation_id"])
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw.update(
        ambiguity_state="retirement_outcome_unknown",
        cancellation_available=False,
    )
    raw["effect_summary"]["credential_effect"] = "outcome_unknown"
    _rewrite(path, raw)

    result = OperationArbitrator(tmp_path).inspect()

    assert result.state == "blocked"
    assert result.reason_code == "prior_operation_artifact_invalid"


def test_bound_retirement_reconciliation_uses_resume_as_the_only_action(tmp_path):
    _plan, checkpoint = _create_v2_operation(tmp_path, journey="legacy_upgrade")
    store = CheckpointStore(tmp_path)
    store.update(
        checkpoint["operation_id"],
        state="recovery_required",
        phase="retirement_reconciliation",
        ambiguity_state=AmbiguityState.RETIREMENT_OUTCOME_UNKNOWN,
        recovery_policy=RecoveryPolicy.RECONCILE_SAME_OPERATION,
        effect_summary=EffectSummary(
            local_effect=EffectDisposition.STAGED,
            remote_effect=EffectDisposition.UNKNOWN,
            credential_effect=CredentialEffect.OUTCOME_UNKNOWN,
            mutation_performed=True,
            owned_resource_count=1,
            effect_codes=("retirement_dispatched",),
        ),
        next_actions=(
            _lifecycle_action("resume", action_id="reconcile-original-operation"),
        ),
        recorded_answers={"retirement_intent": _retirement_intent(checkpoint)},
        cancellation_available=False,
    )
    _write_transaction(
        tmp_path,
        checkpoint,
        phase="recovery_required",
        completed=("staging",),
    )
    _rewrite(
        tmp_path / f"{checkpoint['operation_id']}.legacy-plugin.json",
        {
            "migration_schema": "claudian-remote.legacy-plugin/v2",
            "operation_id": checkpoint["operation_id"],
            "plan_id": checkpoint["plan_id"],
            "installation_id": "installation-a",
            "vault_id": "vault-a",
            "connection_mode": "local_tailscale",
            "phase": "retirement_outcome_unknown",
            "legacy_present": True,
            "legacy_was_enabled": True,
            "current_was_enabled": False,
            "re_pair_required": True,
            "synchronized": {
                "schema_version": 2,
                "vault_id": "vault-a",
                "connection_mode": "local_tailscale",
                "notifications_enabled": True,
                "haptics_enabled": True,
            },
        },
    )

    result = OperationArbitrator(tmp_path).inspect()

    assert result.state == "reconciliation_required"
    assert result.recommended_action == "reconcile_retirement_outcome"
    assert result.checkpoint["next_actions"] == [
        {
            "action_id": "reconcile-original-operation",
            "action_type": "lifecycle_command",
            "owner": "agent",
            "recommended": True,
            "executable": True,
            "command": "resume",
            "parameters": {"operation_id_ref": "checkpoint.operation_id"},
        }
    ]


def test_proof_checkpoint_and_unknown_migration_split_reconciles_before_forward(
    tmp_path,
):
    _plan, checkpoint = _create_v2_operation(tmp_path, journey="legacy_upgrade")
    store = CheckpointStore(tmp_path)
    store.update(
        checkpoint["operation_id"],
        state="recovery_required",
        phase="retirement_reconciliation",
        irreversible_boundary_crossed=True,
        ambiguity_state=AmbiguityState.RETIRED,
        recovery_policy=RecoveryPolicy.FINISH_FORWARD,
        effect_summary=EffectSummary(
            local_effect=EffectDisposition.STAGED,
            remote_effect=EffectDisposition.CHANGED,
            credential_effect=CredentialEffect.RETIRED,
            mutation_performed=True,
            owned_resource_count=1,
            effect_codes=("retirement_committed",),
        ),
        next_actions=(_lifecycle_action("resume"),),
        recorded_answers={
            "retirement_intent": _retirement_intent(checkpoint),
            "retirement_commit": _retirement_commit(checkpoint),
        },
        cancellation_available=False,
    )
    _write_transaction(
        tmp_path,
        checkpoint,
        phase="recovery_required",
        completed=("staging",),
    )
    _rewrite(
        tmp_path / f"{checkpoint['operation_id']}.legacy-plugin.json",
        {
            "migration_schema": "claudian-remote.legacy-plugin/v2",
            "operation_id": checkpoint["operation_id"],
            "plan_id": checkpoint["plan_id"],
            "installation_id": "installation-a",
            "vault_id": "vault-a",
            "connection_mode": "local_tailscale",
            "phase": "retirement_outcome_unknown",
            "legacy_present": True,
            "legacy_was_enabled": True,
            "current_was_enabled": False,
            "re_pair_required": True,
            "synchronized": {
                "schema_version": 2,
                "vault_id": "vault-a",
                "connection_mode": "local_tailscale",
                "notifications_enabled": True,
                "haptics_enabled": True,
            },
        },
    )

    result = OperationArbitrator(tmp_path).inspect()

    assert result.state == "reconciliation_required"
    assert result.recommended_action == "reconcile_retirement_outcome"
    assert result.checkpoint["ambiguity_state"] == "retired"
    assert result.checkpoint["recovery_policy"] == "reconcile_same_operation"
    assert result.checkpoint["next_actions"][0]["command"] == "resume"


def test_inconclusive_only_allows_manual_recovery(tmp_path):
    _plan, checkpoint = _create_v2_operation(tmp_path, journey="legacy_upgrade")
    CheckpointStore(tmp_path).update(
        checkpoint["operation_id"],
        ambiguity_state=AmbiguityState.INCONCLUSIVE,
        recovery_policy=RecoveryPolicy.RECONCILE_SAME_OPERATION,
        effect_summary=EffectSummary(
            local_effect=EffectDisposition.STAGED,
            remote_effect=EffectDisposition.UNKNOWN,
            credential_effect=CredentialEffect.INCONCLUSIVE,
            mutation_performed=True,
            owned_resource_count=1,
            effect_codes=("retirement_outcome_inconclusive",),
        ),
        next_actions=(
            _lifecycle_action("status", action_id="reconcile-original-operation"),
        ),
        recorded_answers={"retirement_intent": _retirement_intent(checkpoint)},
        cancellation_available=False,
    )

    result = OperationArbitrator(tmp_path).inspect()

    assert result.state == "blocked"
    assert result.reason_code == "prior_operation_artifact_invalid"


def test_finish_forward_requires_crossed_boundary(tmp_path):
    _plan, checkpoint = _create_v2_operation(tmp_path, journey="legacy_upgrade")
    CheckpointStore(tmp_path).update(
        checkpoint["operation_id"],
        ambiguity_state=AmbiguityState.NOT_APPLIED,
        recovery_policy=RecoveryPolicy.FINISH_FORWARD,
        effect_summary=EffectSummary(
            local_effect=EffectDisposition.STAGED,
            remote_effect=EffectDisposition.UNCHANGED,
            credential_effect=CredentialEffect.NOT_APPLIED,
            mutation_performed=True,
            owned_resource_count=1,
            effect_codes=("retirement_not_applied",),
        ),
        next_actions=(_resume_action(),),
        recorded_answers={"retirement_intent": _retirement_intent(checkpoint)},
        cancellation_available=False,
    )

    result = OperationArbitrator(tmp_path).inspect()

    assert result.state == "blocked"
    assert result.reason_code == "prior_operation_artifact_invalid"


def test_lifecycle_recovery_action_requires_agent_owner_and_current_operation_ref(
    tmp_path,
):
    cases = (
        {"owner": ActionOwner.HUMAN},
        {"operation_id_ref": "checkpoint.other_operation_id"},
    )
    for index, override in enumerate(cases):
        state = tmp_path / str(index)
        _plan, checkpoint = _create_v2_operation(state)
        CheckpointStore(state).update(
            checkpoint["operation_id"],
            next_actions=(
                _lifecycle_action("resume", **override),
                _cancel_action(),
            ),
        )

        result = OperationArbitrator(state).inspect()

        assert result.state == "blocked"
        assert result.reason_code == "prior_operation_artifact_invalid"


def test_valid_v2_transaction_bridge_keeps_original_resume_owner(tmp_path):
    _plan, checkpoint = _create_v2_operation(tmp_path)
    _write_transaction(tmp_path, checkpoint)

    result = OperationArbitrator(tmp_path).inspect()

    assert result.state == "reconciliation_required"
    assert result.operation_id == checkpoint["operation_id"]
    assert result.recommended_action == "resume"


def test_v2_recovery_required_transaction_projects_owned_rollback(tmp_path):
    _plan, checkpoint = _create_v2_operation(tmp_path)
    _write_transaction(
        tmp_path,
        checkpoint,
        phase="recovery_required",
        completed=("staging",),
    )

    result = OperationArbitrator(tmp_path).inspect()

    assert result.state == "reconciliation_required"
    assert result.operation_id == checkpoint["operation_id"]
    assert result.recommended_action == "rollback"
    assert result.reason_code == "prior_operation_recovery_required"


def test_v2_transaction_operation_or_plan_mismatch_blocks(tmp_path):
    cases = (
        {"operation_id": "op-" + "f" * 32},
        {"plan_id": "plan-mismatched"},
    )
    for index, override in enumerate(cases):
        state = tmp_path / str(index)
        _plan, checkpoint = _create_v2_operation(state)
        _write_transaction(state, checkpoint, **override)

        result = OperationArbitrator(state).inspect()

        assert result.state == "blocked"
        assert result.reason_code == "prior_operation_artifact_invalid"


def test_malformed_v2_companion_blocks(tmp_path):
    _plan, checkpoint = _create_v2_operation(tmp_path)
    _write_transaction(
        tmp_path,
        checkpoint,
        phase="after_activation",
        completed=("staging", "secure_provisioning"),
        activation_started=True,
        plugin_activated=True,
    )

    result = OperationArbitrator(tmp_path).inspect()

    assert result.state == "blocked"
    assert result.reason_code == "prior_operation_artifact_invalid"


def test_fresh_v2_rejects_legacy_migration_companion(tmp_path):
    _plan, checkpoint = _create_v2_operation(tmp_path)
    _rewrite(
        tmp_path / f"{checkpoint['operation_id']}.legacy-plugin.json",
        {
            "migration_schema": "claudian-remote.legacy-plugin/v1",
            "phase": "committed",
            "legacy_present": True,
            "legacy_was_enabled": True,
            "current_was_enabled": False,
            "re_pair_required": True,
            "synchronized": {
                "schema_version": 2,
                "vault_id": "vault-a",
                "connection_mode": "local_tailscale",
                "notifications_enabled": True,
                "haptics_enabled": True,
            },
        },
    )

    result = OperationArbitrator(tmp_path).inspect()

    assert result.state == "blocked"
    assert result.reason_code == "prior_operation_artifact_invalid"
