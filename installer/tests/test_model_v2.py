import pytest

from installer.claudian_remote_lifecycle.model import (
    CHECKPOINT_SCHEMA,
    CHECKPOINT_SCHEMA_V1,
    PLAN_SCHEMA,
    PLAN_SCHEMA_V1,
    RESULT_SCHEMA,
    RESULT_SCHEMA_V1,
    SNAPSHOT_SCHEMA,
    SNAPSHOT_SCHEMA_V1,
    ActionOwner,
    AmbiguityState,
    CredentialEffect,
    EffectDisposition,
    EffectSummary,
    Journey,
    LifecyclePhase,
    LifecycleResult,
    NextAction,
    NextActionType,
    PairingIdentityPolicy,
    RecoveryPolicy,
    normalize_strict_result,
    validate_strict_result,
)


def _running_result(**overrides):
    values = {
        "command": "status",
        "state": "running",
        "code": "operation_running",
        "message": "The original operation is still running.",
        "journey": Journey.LEGACY_UPGRADE,
        "phase": LifecyclePhase.RETIREMENT_RECONCILIATION,
        "irreversible_boundary_crossed": False,
        "ambiguity_state": AmbiguityState.RETIREMENT_OUTCOME_UNKNOWN,
        "recovery_policy": RecoveryPolicy.RECONCILE_SAME_OPERATION,
        "effect_summary": EffectSummary(
            local_effect=EffectDisposition.STAGED,
            remote_effect=EffectDisposition.UNKNOWN,
            credential_effect=CredentialEffect.OUTCOME_UNKNOWN,
            mutation_performed=None,
            owned_resource_count=2,
            effect_codes=("local_stage_present", "retirement_dispatch_recorded"),
        ),
        "next_actions": (
            NextAction(
                action_id="status-original-operation",
                action_type=NextActionType.LIFECYCLE_COMMAND,
                owner=ActionOwner.AGENT,
                command="status",
                recommended=True,
                executable=True,
                parameters={"operation_id_ref": "result.operation_id"},
            ),
        ),
        "cancellation_available": False,
        "pairing_identity_policy": PairingIdentityPolicy.NOT_APPLICABLE,
        "operation_id": "op-" + "a" * 32,
    }
    values.update(overrides)
    return LifecycleResult(**values)


def test_v2_is_the_write_schema_and_v1_names_remain_explicit_for_decoders():
    assert RESULT_SCHEMA == "claudian-remote.lifecycle-result/v2"
    assert SNAPSHOT_SCHEMA == "claudian-remote.inspection/v2"
    assert PLAN_SCHEMA == "claudian-remote.plan/v2"
    assert CHECKPOINT_SCHEMA == "claudian-remote.checkpoint/v2"

    assert RESULT_SCHEMA_V1 == "claudian-remote.lifecycle-result/v1"
    assert SNAPSHOT_SCHEMA_V1 == "claudian-remote.inspection/v1"
    assert PLAN_SCHEMA_V1 == "claudian-remote.plan/v1"
    assert CHECKPOINT_SCHEMA_V1 == "claudian-remote.checkpoint/v1"


def test_legacy_callers_receive_an_explicit_safe_unclassified_projection():
    result = LifecycleResult(
        command="inspect",
        state="ready",
        code="inspection_ready",
        message="Inspection completed.",
    ).to_dict()

    assert result["result_schema"] == RESULT_SCHEMA
    assert result["journey"] == "unclassified"
    assert result["phase"] == "unclassified"
    assert result["irreversible_boundary_crossed"] is None
    assert result["ambiguity_state"] == "unclassified"
    assert result["recovery_policy"] == "unclassified"
    assert result["effect_summary"] == {
        "local_effect": "unknown",
        "remote_effect": "unknown",
        "credential_effect": "unknown",
        "mutation_performed": None,
        "owned_resource_count": 0,
        "effect_codes": [],
    }
    assert result["next_actions"] == []
    assert result["cancellation_available"] is None
    assert result["pairing_identity_policy"] == "unclassified"


def test_typed_v2_result_serializes_without_agent_having_to_parse_message():
    result = validate_strict_result(_running_result()).to_dict()

    assert result["journey"] == "legacy_upgrade"
    assert result["phase"] == "retirement_reconciliation"
    assert result["ambiguity_state"] == "retirement_outcome_unknown"
    assert result["recovery_policy"] == "reconcile_same_operation"
    assert result["effect_summary"]["credential_effect"] == "outcome_unknown"
    assert result["next_actions"] == [
        {
            "action_id": "status-original-operation",
            "action_type": "lifecycle_command",
            "owner": "agent",
            "recommended": True,
            "executable": True,
            "command": "status",
            "parameters": {"operation_id_ref": "result.operation_id"},
        }
    ]


def test_public_strict_normalizer_emits_only_classified_non_null_control_fields():
    result = normalize_strict_result(_running_result())

    assert result["result_schema"] == RESULT_SCHEMA
    assert result["journey"] != "unclassified"
    assert result["phase"] != "unclassified"
    assert result["irreversible_boundary_crossed"] is not None
    assert result["ambiguity_state"] != "unclassified"
    assert result["recovery_policy"] != "unclassified"
    assert result["effect_summary"] is not None
    assert result["next_actions"] is not None
    assert result["cancellation_available"] is not None
    assert result["pairing_identity_policy"] != "unclassified"


@pytest.mark.parametrize(
    ("field", "value", "error"),
    [
        ("journey", Journey.UNCLASSIFIED, "classified_journey_required"),
        ("phase", LifecyclePhase.UNCLASSIFIED, "classified_phase_required"),
        (
            "ambiguity_state",
            AmbiguityState.UNCLASSIFIED,
            "classified_ambiguity_state_required",
        ),
        (
            "recovery_policy",
            RecoveryPolicy.UNCLASSIFIED,
            "classified_recovery_policy_required",
        ),
        (
            "pairing_identity_policy",
            PairingIdentityPolicy.UNCLASSIFIED,
            "classified_pairing_identity_policy_required",
        ),
        (
            "irreversible_boundary_crossed",
            None,
            "known_irreversible_boundary_state_required",
        ),
        (
            "cancellation_available",
            None,
            "known_cancellation_availability_required",
        ),
    ],
)
def test_public_strict_normalizer_rejects_unclassified_or_null_control_fields(
    field, value, error
):
    with pytest.raises(ValueError, match=error):
        normalize_strict_result(_running_result(**{field: value}))


def test_manual_recovery_fallback_remains_fully_typed_and_agent_safe():
    result = LifecycleResult(
        command="status",
        state="recovery_required",
        code="manual_recovery_required",
        message="The operation needs maintainer review; no mutation was inferred.",
        journey=Journey.LEGACY_UPGRADE,
        phase=LifecyclePhase.RECONCILIATION,
        irreversible_boundary_crossed=False,
        ambiguity_state=AmbiguityState.INCONCLUSIVE,
        recovery_policy=RecoveryPolicy.MANUAL_RECOVERY_REQUIRED,
        effect_summary=EffectSummary(
            local_effect=EffectDisposition.UNKNOWN,
            remote_effect=EffectDisposition.UNKNOWN,
            credential_effect=CredentialEffect.INCONCLUSIVE,
            mutation_performed=None,
            owned_resource_count=0,
            effect_codes=("authority_effect_inconclusive",),
        ),
        next_actions=(
            NextAction(
                action_id="follow-maintainer-recovery-runbook",
                action_type=NextActionType.MANUAL_INSTRUCTION,
                owner=ActionOwner.MAINTAINER,
                recommended=True,
                executable=True,
                parameters={"instruction_ref": "support.manual_recovery"},
            ),
        ),
        cancellation_available=False,
        pairing_identity_policy=PairingIdentityPolicy.NOT_APPLICABLE,
        operation_id="op-" + "b" * 32,
    )

    normalized = normalize_strict_result(result)

    assert normalized["recovery_policy"] == "manual_recovery_required"
    assert normalized["ambiguity_state"] == "inconclusive"
    assert normalized["effect_summary"]["credential_effect"] == "inconclusive"
    assert normalized["next_actions"] == [
        {
            "action_id": "follow-maintainer-recovery-runbook",
            "action_type": "manual_instruction",
            "owner": "maintainer",
            "recommended": True,
            "executable": True,
            "parameters": {"instruction_ref": "support.manual_recovery"},
        }
    ]


def test_manual_recovery_fallback_requires_one_typed_recommended_action():
    with pytest.raises(
        ValueError, match="exactly_one_recommended_executable_action_required"
    ):
        normalize_strict_result(
            _running_result(
                state="recovery_required",
                ambiguity_state=AmbiguityState.INCONCLUSIVE,
                recovery_policy=RecoveryPolicy.MANUAL_RECOVERY_REQUIRED,
                effect_summary=EffectSummary(
                    local_effect=EffectDisposition.UNKNOWN,
                    remote_effect=EffectDisposition.UNKNOWN,
                    credential_effect=CredentialEffect.INCONCLUSIVE,
                    mutation_performed=None,
                    owned_resource_count=0,
                ),
                next_actions=(),
            )
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("journey", "guessed_upgrade"),
        ("phase", "maybe_finished"),
        ("ambiguity_state", "probably_retired"),
        ("recovery_policy", "delete_checkpoint"),
        ("pairing_identity_policy", "guess"),
    ],
)
def test_result_rejects_unknown_control_enum_values(field, value):
    with pytest.raises(ValueError, match=f"unknown_{field}"):
        LifecycleResult(
            command="status",
            state="ready",
            code="ok",
            message="Safe.",
            **{field: value},
        )


def test_next_action_is_typed_and_rejects_unknown_or_non_executable_recommendations():
    with pytest.raises(ValueError, match="unknown_next_action_command"):
        NextAction(
            action_id="unsafe",
            action_type=NextActionType.LIFECYCLE_COMMAND,
            owner=ActionOwner.AGENT,
            command="delete-checkpoint",
            recommended=True,
            executable=True,
        )

    with pytest.raises(ValueError, match="recommended_action_must_be_executable"):
        NextAction(
            action_id="manual",
            action_type=NextActionType.MANUAL_INSTRUCTION,
            owner=ActionOwner.MAINTAINER,
            recommended=True,
            executable=False,
        )


def test_non_terminal_strict_result_requires_exactly_one_recommended_executable_action():
    with pytest.raises(ValueError, match="exactly_one_recommended_executable_action_required"):
        validate_strict_result(_running_result(next_actions=()))

    action = _running_result().next_actions[0]
    with pytest.raises(ValueError, match="exactly_one_recommended_executable_action_required"):
        validate_strict_result(_running_result(next_actions=(action, action)))


def test_actionable_blocked_or_recovery_result_also_requires_one_machine_action():
    with pytest.raises(ValueError, match="exactly_one_recommended_executable_action_required"):
        validate_strict_result(
            _running_result(
                state="recovery_required",
                recovery_policy=RecoveryPolicy.RECONCILE_SAME_OPERATION,
                next_actions=(),
            )
        )


def test_strict_validation_rejects_rollback_or_cancellation_after_dispatch_boundary():
    with pytest.raises(ValueError, match="cancellation_unavailable_after_dispatch"):
        validate_strict_result(_running_result(cancellation_available=True))

    with pytest.raises(ValueError, match="rollback_forbidden_after_irreversible_boundary"):
        validate_strict_result(
            _running_result(
                irreversible_boundary_crossed=True,
                ambiguity_state=AmbiguityState.RETIRED,
                recovery_policy=RecoveryPolicy.ROLLBACK_PRE_BOUNDARY,
                effect_summary=EffectSummary(
                    local_effect=EffectDisposition.STAGED,
                    remote_effect=EffectDisposition.CHANGED,
                    credential_effect=CredentialEffect.RETIRED,
                    mutation_performed=True,
                    owned_resource_count=2,
                ),
            )
        )


def test_current_update_requires_signed_preserve_or_rotate_pairing_policy():
    base = _running_result(
        journey=Journey.CURRENT_UPDATE,
        phase=LifecyclePhase.ACTIVATION,
        ambiguity_state=AmbiguityState.NOT_APPLICABLE,
        recovery_policy=RecoveryPolicy.RETRY_SAME_OPERATION,
        effect_summary=EffectSummary(
            local_effect=EffectDisposition.CHANGED,
            remote_effect=EffectDisposition.NOT_APPLICABLE,
            credential_effect=CredentialEffect.NOT_APPLICABLE,
            mutation_performed=True,
            owned_resource_count=1,
        ),
    )
    with pytest.raises(ValueError, match="current_update_pairing_policy_required"):
        validate_strict_result(base)

    validate_strict_result(
        _running_result(
            journey=Journey.CURRENT_UPDATE,
            phase=LifecyclePhase.ACTIVATION,
            ambiguity_state=AmbiguityState.NOT_APPLICABLE,
            recovery_policy=RecoveryPolicy.RETRY_SAME_OPERATION,
            pairing_identity_policy=PairingIdentityPolicy.PRESERVE,
            effect_summary=EffectSummary(
                local_effect=EffectDisposition.CHANGED,
                remote_effect=EffectDisposition.NOT_APPLICABLE,
                credential_effect=CredentialEffect.NOT_APPLICABLE,
                mutation_performed=True,
                owned_resource_count=1,
            ),
        )
    )


def test_nested_action_parameters_remain_subject_to_agent_safe_field_rules():
    result = _running_result(
        next_actions=(
            NextAction(
                action_id="status-original-operation",
                action_type=NextActionType.LIFECYCLE_COMMAND,
                owner=ActionOwner.AGENT,
                command="status",
                recommended=True,
                executable=True,
                parameters={"access_token": "must-not-print"},
            ),
        )
    )
    with pytest.raises(ValueError, match="agent_unsafe_result_field"):
        result.to_dict()
