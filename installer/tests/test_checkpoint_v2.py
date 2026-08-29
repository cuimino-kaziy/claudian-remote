import json

import pytest

from installer.claudian_remote_lifecycle.checkpoint import CheckpointStore
from installer.claudian_remote_lifecycle.model import (
    CHECKPOINT_SCHEMA,
    CHECKPOINT_SCHEMA_V1,
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


PLAN_ID = "plan-" + "a" * 64


def test_v2_create_uses_complete_safe_nonterminal_defaults(tmp_path):
    store = CheckpointStore(tmp_path / "state")

    checkpoint = store.create(command="install", plan_id=PLAN_ID)

    assert checkpoint == store.read(checkpoint["operation_id"])
    assert checkpoint["checkpoint_schema"] == CHECKPOINT_SCHEMA
    assert checkpoint["state"] == "prepared"
    assert checkpoint["journey"] == "unclassified"
    assert checkpoint["phase"] == "unclassified"
    assert checkpoint["irreversible_boundary_crossed"] is None
    assert checkpoint["ambiguity_state"] == "unclassified"
    assert checkpoint["recovery_policy"] == "unclassified"
    assert checkpoint["effect_summary"] == {
        "local_effect": "unknown",
        "remote_effect": "unknown",
        "credential_effect": "unknown",
        "mutation_performed": False,
        "owned_resource_count": 0,
        "effect_codes": [],
    }
    assert checkpoint["next_actions"] == []
    assert checkpoint["cancellation_available"] is None
    assert checkpoint["pairing_identity_policy"] == "unclassified"
    assert checkpoint["prior_operation_terminal"] is None


def test_v2_control_fields_round_trip_as_canonical_json(tmp_path):
    store = CheckpointStore(tmp_path / "state")
    action = NextAction(
        action_id="resume-original-operation",
        action_type=NextActionType.LIFECYCLE_COMMAND,
        owner=ActionOwner.AGENT,
        recommended=True,
        executable=True,
        command="resume",
        parameters={"operation_ref": "same-operation"},
    )
    cancel_action = NextAction(
        action_id="cancel-original-operation",
        action_type=NextActionType.LIFECYCLE_COMMAND,
        owner=ActionOwner.AGENT,
        recommended=False,
        executable=True,
        command="cancel",
        parameters={"operation_id_ref": "result.operation_id"},
    )
    effect = EffectSummary(
        local_effect=EffectDisposition.STAGED,
        remote_effect=EffectDisposition.UNCHANGED,
        credential_effect=CredentialEffect.NOT_DISPATCHED,
        mutation_performed=True,
        owned_resource_count=1,
        effect_codes=("local_staging_complete",),
    )

    checkpoint = store.create(
        command="update",
        plan_id=PLAN_ID,
        phase="reconciliation",
        journey=Journey.LEGACY_UPGRADE,
        irreversible_boundary_crossed=False,
        ambiguity_state=AmbiguityState.NOT_DISPATCHED,
        recovery_policy=RecoveryPolicy.RETRY_SAME_OPERATION,
        effect_summary=effect,
        next_actions=(action, cancel_action),
        cancellation_available=True,
        pairing_identity_policy=PairingIdentityPolicy.NOT_APPLICABLE,
        prior_operation_terminal=True,
    )

    raw = json.loads(store.path_for(checkpoint["operation_id"]).read_text())
    assert raw == checkpoint
    assert raw["journey"] == "legacy_upgrade"
    assert raw["effect_summary"]["credential_effect"] == "not_dispatched"
    assert raw["next_actions"][0]["command"] == "resume"
    assert raw["next_actions"][1]["command"] == "cancel"


def test_record_and_read_reject_non_exact_duplicate_and_secret_fields(tmp_path):
    store = CheckpointStore(tmp_path / "state")
    checkpoint = store.create(command="install", plan_id=PLAN_ID)
    path = store.path_for(checkpoint["operation_id"])

    with pytest.raises(ValueError, match="invalid_checkpoint_fields"):
        store.record({**checkpoint, "invented": True})
    with pytest.raises(ValueError, match="checkpoint_forbidden_field"):
        store.record(
            {
                **checkpoint,
                "recorded_answers": {"maintenance_token": "synthetic-canary"},
            }
        )

    encoded = path.read_text()
    path.write_text(encoded.replace('"state":"prepared"', '"state":"prepared","state":"ready"'))
    with pytest.raises(ValueError, match="checkpoint_duplicate_field"):
        store.read(checkpoint["operation_id"])


def test_update_only_allows_mutable_fields_and_revalidates_before_write(tmp_path):
    store = CheckpointStore(tmp_path / "state")
    checkpoint = store.create(command="install", plan_id=PLAN_ID)
    original = store.path_for(checkpoint["operation_id"]).read_bytes()

    with pytest.raises(ValueError, match="immutable_or_unknown_checkpoint_field"):
        store.update(checkpoint["operation_id"], journey="fresh_install")
    with pytest.raises(ValueError, match="invalid_checkpoint_ambiguity_state"):
        store.update(checkpoint["operation_id"], ambiguity_state="probably_retired")
    assert store.path_for(checkpoint["operation_id"]).read_bytes() == original

    updated = store.update(
        checkpoint["operation_id"],
        phase="staging",
        completed_phases=["preparation"],
        effect_summary={
            "local_effect": "staged",
            "remote_effect": "unchanged",
            "credential_effect": "not_applicable",
            "mutation_performed": True,
            "owned_resource_count": 1,
            "effect_codes": ["local_staging_complete"],
        },
    )
    assert updated["effect_summary"]["mutation_performed"] is True
    assert store.read(checkpoint["operation_id"]) == updated


def test_inventory_separates_supported_v1_from_current_v2_without_rewriting(tmp_path):
    store = CheckpointStore(tmp_path / "state")
    current = store.create(command="install", plan_id=PLAN_ID)
    legacy_id = "op-" + "b" * 32
    legacy_path = store.path_for(legacy_id)
    legacy = {
        "checkpoint_schema": CHECKPOINT_SCHEMA_V1,
        "operation_id": legacy_id,
        "command": "install",
        "plan_id": "plan-" + "b" * 64,
        "phase": "staging",
        "state": "recovery_required",
        "completed_phases": ["staging"],
        "recorded_answers": {"connection_mode": "local_tailscale"},
        "active_gate": None,
    }
    legacy_path.write_text(json.dumps(legacy, sort_keys=True) + "\n")
    legacy_bytes = legacy_path.read_bytes()

    checkpoints, invalid_count = store.inventory()

    assert [item["operation_id"] for item in checkpoints] == [current["operation_id"]]
    assert invalid_count == 0
    assert legacy_path.read_bytes() == legacy_bytes


def test_inventory_counts_unknown_or_malformed_schema_as_invalid(tmp_path):
    store = CheckpointStore(tmp_path / "state")
    state_dir = tmp_path / "state"
    state_dir.mkdir(parents=True)
    bad_id = "op-" + "c" * 32
    (state_dir / f"{bad_id}.json").write_text(
        json.dumps({"checkpoint_schema": "claudian-remote.checkpoint/v99"})
    )

    checkpoints, invalid_count = store.inventory()

    assert checkpoints == []
    assert invalid_count == 1
