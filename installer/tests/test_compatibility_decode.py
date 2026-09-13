import copy
import hashlib
import json

import pytest

from installer.claudian_remote_lifecycle import compatibility_decode
from installer.claudian_remote_lifecycle.compatibility_decode import (
    ArtifactKind,
    CompatibilityDecodeError,
    LegacyCredentialEffect,
    decode_v1_compatibility_set,
    load_supported_v1_checkpoint,
    load_supported_v1_saved_plan,
    mark_supported_v1_checkpoint_rolled_back,
)


OPERATION_ID = "op-" + "a" * 32


def _content_id(prefix, value):
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return f"{prefix}-{hashlib.sha256(encoded.encode('utf-8')).hexdigest()}"


def _frozen_v1_snapshot_and_plan():
    snapshot = {
        "snapshot_schema": "claudian-remote.inspection/v1",
        "macos": {"platform": "Darwin", "version": "15.5", "architecture": "arm64"},
        "obsidian": {"installed": True, "version": "1.12.3", "running": True},
        "claudian": {"installed": True, "enabled": True, "version": "2.0.4"},
        "vaults": [{"vault_id": "vault-a", "display_name": "Notes"}],
        "installation": {
            "installed": False,
            "compatibility_set_id": None,
            "operation_id": None,
            "secure_provisioning_available": True,
            "secure_provisioning_probe": "verified_test_adapter",
        },
        "network": {"tailscale_installed": True, "tailscale_logged_in": True},
        "read_only": True,
        "support": {
            "supported": True,
            "required_claudian_version": "2.0.4",
            "reason_codes": [],
        },
    }
    snapshot["snapshot_id"] = _content_id("inspection", snapshot)
    installation_seed = "Darwin|arm64|vault-a"
    plan = {
        "plan_schema": "claudian-remote.plan/v1",
        "inspection_snapshot_id": snapshot["snapshot_id"],
        "environment_fingerprint": snapshot["snapshot_id"],
        "compatibility_set_id": "claudian-remote-0.2.0-beta.4",
        "vault_id": "vault-a",
        "installation_id": "installation-"
        + hashlib.sha256(installation_seed.encode()).hexdigest()[:24],
        "endpoint_audience": None,
        "topology": {
            "mode": "local_tailscale",
            "relay_location": "mac_loopback",
            "exposure": "tailscale_serve",
            "silent_fallback": False,
        },
        "gates": [
            {"gate_type": "pairing_approval_required", "probe": "pairing_credential_active"}
        ],
        "blockers": [],
        "affected_resources": [
            "device_local_state",
            "mac_companion",
            "obsidian_plugin:claudian-remote",
            "pairing_identity",
            "relay_runtime",
        ],
        "rollback_boundary": "previous_locally_coherent_compatibility_set",
        "mutation_performed": False,
    }
    plan["plan_id"] = _content_id("plan", plan)
    return snapshot, plan


def _write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n",
        encoding="utf-8",
    )
    return path


def _artifact_set(tmp_path, *, migration=True):
    snapshot, plan = _frozen_v1_snapshot_and_plan()
    checkpoint = {
        "checkpoint_schema": "claudian-remote.checkpoint/v1",
        "operation_id": OPERATION_ID,
        "command": "install",
        "plan_id": plan["plan_id"],
        "phase": "installation_compensation_failed",
        "state": "recovery_required",
        "completed_phases": ["staging"],
        "recorded_answers": {},
        "active_gate": None,
    }
    transaction = {
        "transaction_schema": "claudian-remote.local-transaction/v1",
        "operation_id": OPERATION_ID,
        "plan_id": plan["plan_id"],
        "phase": "recovery_required",
        "completed_phases": ["staging"],
        "prior_availability_vault": None,
        "prior_release_id": None,
        "activation_started": False,
        "plugin_activated": False,
    }
    migration_value = {
        "migration_schema": "claudian-remote.legacy-plugin/v1",
        "phase": "pending_revocation",
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
    }
    paths = {
        "checkpoint_path": _write(tmp_path / f"{OPERATION_ID}.json", checkpoint),
        "saved_plan_path": _write(tmp_path / "plans" / f"{plan['plan_id']}.json", {
            "plan": plan,
            "snapshot": snapshot,
        }),
        "local_transaction_path": _write(
            tmp_path / f"{OPERATION_ID}.transaction.json", transaction
        ),
    }
    values = {
        "checkpoint": checkpoint,
        "saved_plan": {"plan": plan, "snapshot": snapshot},
        "local_transaction": transaction,
    }
    if migration:
        paths["legacy_migration_path"] = _write(
            tmp_path / f"{OPERATION_ID}.legacy-plugin.json", migration_value
        )
        values["legacy_migration"] = migration_value
    return paths, values


def test_exact_v1_operation_set_decodes_read_only_with_source_digests(tmp_path):
    paths, _values = _artifact_set(tmp_path)
    before = {name: path.read_bytes() for name, path in paths.items()}

    result = decode_v1_compatibility_set(**paths)

    assert result.operation_id == OPERATION_ID
    assert result.command == "install"
    assert result.checkpoint_state == "recovery_required"
    assert result.completed_phases == ("staging",)
    assert result.active_gate_present is False
    assert result.transaction_phase == "recovery_required"
    assert result.migration_phase == "pending_revocation"
    assert result.legacy_credential_effect is LegacyCredentialEffect.INCONCLUSIVE
    assert result.mutation_may_have_started is True
    assert [source.artifact for source in result.sources] == [
        ArtifactKind.CHECKPOINT,
        ArtifactKind.SAVED_PLAN,
        ArtifactKind.LOCAL_TRANSACTION,
        ArtifactKind.LEGACY_MIGRATION,
    ]
    for name, path in paths.items():
        assert path.read_bytes() == before[name]
    for source in result.sources:
        matching = next(path for path in paths.values() if path.name == source.source_name)
        assert source.sha256 == hashlib.sha256(matching.read_bytes()).hexdigest()
        assert source.byte_length == len(matching.read_bytes())
        assert "/" not in source.source_name


def test_v1_pre_mutation_checkpoint_can_decode_without_transaction(tmp_path):
    paths, values = _artifact_set(tmp_path, migration=False)
    checkpoint = values["checkpoint"]
    checkpoint.update(
        state="blocked",
        phase="legacy_credential_revocation_unavailable",
        completed_phases=[],
    )
    _write(paths["checkpoint_path"], checkpoint)

    result = decode_v1_compatibility_set(
        checkpoint_path=paths["checkpoint_path"],
        saved_plan_path=paths["saved_plan_path"],
    )

    assert result.transaction_phase is None
    assert result.migration_phase is None
    assert result.legacy_credential_effect is LegacyCredentialEffect.NOT_APPLIED
    assert result.mutation_may_have_started is False


def test_v1_waiting_gate_is_projected_without_copying_gate_content(tmp_path):
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
    _write(paths["checkpoint_path"], checkpoint)

    result = decode_v1_compatibility_set(
        checkpoint_path=paths["checkpoint_path"],
        saved_plan_path=paths["saved_plan_path"],
    )

    assert result.active_gate_present is True
    assert not hasattr(result, "active_gate")


@pytest.mark.parametrize(
    ("artifact", "mutate"),
    [
        ("checkpoint", lambda value: value.update(checkpoint_schema="claudian-remote.checkpoint/v2")),
        ("checkpoint", lambda value: value.update(mobile_token="must-not-be-accepted")),
        ("saved_plan", lambda value: value["plan"].update(plan_schema="claudian-remote.plan/v2")),
        ("saved_plan", lambda value: value.update(maintenance_credential_ref="unexpected")),
        (
            "local_transaction",
            lambda value: value.update(transaction_schema="claudian-remote.local-transaction/v2"),
        ),
        ("local_transaction", lambda value: value.update(credential_effect="retired")),
        (
            "legacy_migration",
            lambda value: value.update(migration_schema="claudian-remote.legacy-plugin/v2"),
        ),
        ("legacy_migration", lambda value: value.update(authority_id="unexpected")),
    ],
)
def test_unknown_schema_or_extra_field_fails_closed(tmp_path, artifact, mutate):
    paths, values = _artifact_set(tmp_path)
    altered = copy.deepcopy(values[artifact])
    mutate(altered)
    key = {
        "checkpoint": "checkpoint_path",
        "saved_plan": "saved_plan_path",
        "local_transaction": "local_transaction_path",
        "legacy_migration": "legacy_migration_path",
    }[artifact]
    _write(paths[key], altered)

    with pytest.raises(CompatibilityDecodeError):
        decode_v1_compatibility_set(**paths)


def test_recovery_checkpoint_requires_its_transaction_companion(tmp_path):
    paths, _values = _artifact_set(tmp_path, migration=False)

    with pytest.raises(CompatibilityDecodeError, match="v1_companion_missing"):
        decode_v1_compatibility_set(
            checkpoint_path=paths["checkpoint_path"],
            saved_plan_path=paths["saved_plan_path"],
        )


def test_migration_without_transaction_and_mixed_operation_set_fail_closed(tmp_path):
    paths, values = _artifact_set(tmp_path)
    with pytest.raises(CompatibilityDecodeError, match="v1_companion_missing"):
        decode_v1_compatibility_set(
            checkpoint_path=paths["checkpoint_path"],
            saved_plan_path=paths["saved_plan_path"],
            legacy_migration_path=paths["legacy_migration_path"],
        )

    values["local_transaction"]["operation_id"] = "op-" + "b" * 32
    _write(paths["local_transaction_path"], values["local_transaction"])
    with pytest.raises(CompatibilityDecodeError, match="v1_companion_identity_mismatch"):
        decode_v1_compatibility_set(**paths)


def test_operationless_migration_is_bound_only_by_exact_validated_filename(tmp_path):
    paths, _values = _artifact_set(tmp_path)
    wrong_name = paths["legacy_migration_path"].with_name("legacy-plugin.json")
    paths["legacy_migration_path"].rename(wrong_name)
    paths["legacy_migration_path"] = wrong_name

    with pytest.raises(CompatibilityDecodeError, match="v1_filename_binding_invalid"):
        decode_v1_compatibility_set(**paths)


def test_checkpoint_and_transaction_phase_sets_must_match(tmp_path):
    paths, values = _artifact_set(tmp_path)
    values["local_transaction"]["completed_phases"] = []
    values["local_transaction"]["phase"] = "before_staging"
    _write(paths["local_transaction_path"], values["local_transaction"])

    with pytest.raises(CompatibilityDecodeError, match="v1_companion_phase_mismatch"):
        decode_v1_compatibility_set(**paths)


@pytest.mark.parametrize("invalid", [None, "field", "phase", "progress", "identity", "migration"])
def test_beta2_compact_transaction_is_narrowly_decoded_without_invented_fields(tmp_path, invalid):
    paths, values = _artifact_set(tmp_path, migration=invalid == "migration")
    values["checkpoint"].update(state="blocked", phase="release_archive_unsafe_member", completed_phases=[])
    transaction = {key: values["local_transaction"][key] for key in (
        "transaction_schema", "operation_id", "plan_id", "phase", "completed_phases"
    )}
    transaction.update(phase="before_staging", completed_phases=[])
    if invalid == "field":
        transaction["activation_started"] = False
    elif invalid == "phase":
        transaction["phase"] = "activation_started"
    elif invalid == "progress":
        transaction["completed_phases"] = ["staging"]
    elif invalid == "identity":
        transaction["operation_id"] = "op-" + "b" * 32
    _write(paths["checkpoint_path"], values["checkpoint"])
    _write(paths["local_transaction_path"], transaction)
    before = paths["local_transaction_path"].read_bytes()
    if invalid:
        with pytest.raises(CompatibilityDecodeError):
            decode_v1_compatibility_set(**paths)
    else:
        result = decode_v1_compatibility_set(**paths)
        assert result.mutation_may_have_started is True
        assert compatibility_decode.load_supported_v1_transaction(paths["local_transaction_path"]) == transaction
    assert paths["local_transaction_path"].read_bytes() == before


@pytest.mark.parametrize(
    ("field", "value"),
    [("vault_id", "other-vault"), ("connection_mode", "remote_vps")],
)
def test_migration_projection_must_match_its_saved_plan(tmp_path, field, value):
    paths, values = _artifact_set(tmp_path)
    values["legacy_migration"]["synchronized"][field] = value
    _write(paths["legacy_migration_path"], values["legacy_migration"])

    with pytest.raises(CompatibilityDecodeError, match="v1_companion_identity_mismatch"):
        decode_v1_compatibility_set(**paths)


def test_duplicate_json_field_is_rejected_instead_of_last_value_winning(tmp_path):
    paths, _values = _artifact_set(tmp_path)
    raw = paths["checkpoint_path"].read_text(encoding="utf-8")
    paths["checkpoint_path"].write_text(
        raw.replace(
            '"checkpoint_schema":"claudian-remote.checkpoint/v1",',
            '"checkpoint_schema":"claudian-remote.checkpoint/v1",'
            '"checkpoint_schema":"claudian-remote.checkpoint/v1",',
            1,
        ),
        encoding="utf-8",
    )

    with pytest.raises(CompatibilityDecodeError, match="v1_artifact_duplicate_field"):
        decode_v1_compatibility_set(**paths)


def test_supported_v1_checkpoint_loader_binds_operation_and_returns_detached_value(
    tmp_path,
):
    paths, values = _artifact_set(tmp_path)

    checkpoint, evidence = load_supported_v1_checkpoint(
        paths["checkpoint_path"], expected_operation_id=OPERATION_ID
    )

    assert checkpoint == values["checkpoint"]
    assert evidence.artifact is ArtifactKind.CHECKPOINT
    assert evidence.sha256 == hashlib.sha256(
        paths["checkpoint_path"].read_bytes()
    ).hexdigest()
    checkpoint["recorded_answers"]["connection_mode"] = "local_tailscale"
    persisted = json.loads(paths["checkpoint_path"].read_text(encoding="utf-8"))
    assert persisted["recorded_answers"] == {}


def test_supported_v1_checkpoint_loader_rejects_wrong_operation_and_extra_fields(
    tmp_path,
):
    paths, values = _artifact_set(tmp_path)
    before = paths["checkpoint_path"].read_bytes()

    with pytest.raises(CompatibilityDecodeError, match="v1_filename_binding_invalid"):
        load_supported_v1_checkpoint(
            paths["checkpoint_path"],
            expected_operation_id="op-" + "b" * 32,
        )
    assert paths["checkpoint_path"].read_bytes() == before

    values["checkpoint"]["credential_effect"] = "retired"
    _write(paths["checkpoint_path"], values["checkpoint"])
    with pytest.raises(CompatibilityDecodeError, match="v1_artifact_fields_invalid"):
        load_supported_v1_checkpoint(
            paths["checkpoint_path"], expected_operation_id=OPERATION_ID
        )


def test_supported_v1_saved_plan_loader_is_strict_bound_and_detached(tmp_path):
    paths, values = _artifact_set(tmp_path)
    plan_id = values["saved_plan"]["plan"]["plan_id"]

    plan, snapshot = load_supported_v1_saved_plan(
        paths["saved_plan_path"], expected_plan_id=plan_id
    )

    assert plan == values["saved_plan"]["plan"]
    assert snapshot == values["saved_plan"]["snapshot"]
    plan["topology"]["mode"] = "remote_vps"
    snapshot["network"]["tailscale_logged_in"] = False
    persisted = json.loads(paths["saved_plan_path"].read_text(encoding="utf-8"))
    assert persisted == values["saved_plan"]


def test_supported_v1_saved_plan_loader_rejects_wrong_identity_and_unknown_field(
    tmp_path,
):
    paths, values = _artifact_set(tmp_path)

    with pytest.raises(CompatibilityDecodeError, match="v1_filename_binding_invalid"):
        load_supported_v1_saved_plan(
            paths["saved_plan_path"],
            expected_plan_id="plan-" + "b" * 64,
        )

    values["saved_plan"]["maintenance_credential_ref"] = "unexpected"
    _write(paths["saved_plan_path"], values["saved_plan"])
    with pytest.raises(CompatibilityDecodeError, match="v1_artifact_fields_invalid"):
        load_supported_v1_saved_plan(
            paths["saved_plan_path"],
            expected_plan_id=values["saved_plan"]["plan"]["plan_id"],
        )


def test_supported_v1_checkpoint_is_atomically_marked_rolled_back_and_retained(
    tmp_path,
):
    paths, values = _artifact_set(tmp_path)
    original_checkpoint = copy.deepcopy(values["checkpoint"])
    retained = {
        name: path.read_bytes()
        for name, path in paths.items()
        if name != "checkpoint_path"
    }
    _checkpoint, before = load_supported_v1_checkpoint(
        paths["checkpoint_path"], expected_operation_id=OPERATION_ID
    )

    after = mark_supported_v1_checkpoint_rolled_back(
        paths["checkpoint_path"],
        expected_operation_id=OPERATION_ID,
        expected_checkpoint_sha256=before.sha256,
    )

    persisted = json.loads(paths["checkpoint_path"].read_text(encoding="utf-8"))
    assert persisted == {
        **original_checkpoint,
        "phase": "rollback_completed",
        "state": "rolled_back",
        "active_gate": None,
    }
    assert after.sha256 == hashlib.sha256(
        paths["checkpoint_path"].read_bytes()
    ).hexdigest()
    assert paths["checkpoint_path"].stat().st_mode & 0o777 == 0o600
    assert not list(tmp_path.glob(f".{OPERATION_ID}.json.*"))
    for name, raw in retained.items():
        assert paths[name].read_bytes() == raw

    # The exact terminal checkpoint is idempotent and is not rewritten.
    terminal_bytes = paths["checkpoint_path"].read_bytes()
    repeated = mark_supported_v1_checkpoint_rolled_back(
        paths["checkpoint_path"],
        expected_operation_id=OPERATION_ID,
        expected_checkpoint_sha256=after.sha256,
    )
    assert repeated.sha256 == after.sha256
    assert paths["checkpoint_path"].read_bytes() == terminal_bytes


def test_v1_checkpoint_mark_rejects_stale_digest_without_overwriting_new_bytes(
    tmp_path,
):
    paths, values = _artifact_set(tmp_path)
    _checkpoint, observed = load_supported_v1_checkpoint(
        paths["checkpoint_path"], expected_operation_id=OPERATION_ID
    )
    values["checkpoint"]["recorded_answers"] = {
        "connection_mode": "local_tailscale"
    }
    _write(paths["checkpoint_path"], values["checkpoint"])
    drifted = paths["checkpoint_path"].read_bytes()

    with pytest.raises(CompatibilityDecodeError, match="v1_checkpoint_drift_detected"):
        mark_supported_v1_checkpoint_rolled_back(
            paths["checkpoint_path"],
            expected_operation_id=OPERATION_ID,
            expected_checkpoint_sha256=observed.sha256,
        )

    assert paths["checkpoint_path"].read_bytes() == drifted


def test_v1_checkpoint_mark_detects_drift_during_atomic_staging(
    tmp_path, monkeypatch
):
    paths, values = _artifact_set(tmp_path)
    _checkpoint, observed = load_supported_v1_checkpoint(
        paths["checkpoint_path"], expected_operation_id=OPERATION_ID
    )
    original_mkstemp = compatibility_decode.tempfile.mkstemp

    def mkstemp_with_drift(*args, **kwargs):
        descriptor_and_name = original_mkstemp(*args, **kwargs)
        drifted = copy.deepcopy(values["checkpoint"])
        drifted["recorded_answers"] = {"connection_mode": "local_tailscale"}
        _write(paths["checkpoint_path"], drifted)
        return descriptor_and_name

    monkeypatch.setattr(
        compatibility_decode.tempfile, "mkstemp", mkstemp_with_drift
    )

    with pytest.raises(CompatibilityDecodeError, match="v1_checkpoint_drift_detected"):
        mark_supported_v1_checkpoint_rolled_back(
            paths["checkpoint_path"],
            expected_operation_id=OPERATION_ID,
            expected_checkpoint_sha256=observed.sha256,
        )

    persisted = json.loads(paths["checkpoint_path"].read_text(encoding="utf-8"))
    assert persisted["state"] == "recovery_required"
    assert persisted["recorded_answers"] == {"connection_mode": "local_tailscale"}
    assert not list(tmp_path.glob(f".{OPERATION_ID}.json.*"))


def test_v1_checkpoint_mark_rejects_non_recovery_and_unknown_schema(tmp_path):
    paths, values = _artifact_set(tmp_path)
    values["checkpoint"].update(
        state="blocked", phase="tailscale_login_required", completed_phases=[]
    )
    _write(paths["checkpoint_path"], values["checkpoint"])
    _checkpoint, evidence = load_supported_v1_checkpoint(
        paths["checkpoint_path"], expected_operation_id=OPERATION_ID
    )
    blocked_bytes = paths["checkpoint_path"].read_bytes()
    with pytest.raises(CompatibilityDecodeError, match="v1_checkpoint_not_recoverable"):
        mark_supported_v1_checkpoint_rolled_back(
            paths["checkpoint_path"],
            expected_operation_id=OPERATION_ID,
            expected_checkpoint_sha256=evidence.sha256,
        )
    assert paths["checkpoint_path"].read_bytes() == blocked_bytes

    values["checkpoint"]["checkpoint_schema"] = "claudian-remote.checkpoint/v2"
    _write(paths["checkpoint_path"], values["checkpoint"])
    unknown_bytes = paths["checkpoint_path"].read_bytes()
    with pytest.raises(CompatibilityDecodeError, match="unsupported_or_mixed_schema_set"):
        mark_supported_v1_checkpoint_rolled_back(
            paths["checkpoint_path"],
            expected_operation_id=OPERATION_ID,
            expected_checkpoint_sha256=hashlib.sha256(unknown_bytes).hexdigest(),
        )
    assert paths["checkpoint_path"].read_bytes() == unknown_bytes
