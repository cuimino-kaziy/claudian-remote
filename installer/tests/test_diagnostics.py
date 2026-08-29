from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from installer.claudian_remote_lifecycle.checkpoint import CheckpointStore
from installer.claudian_remote_lifecycle.cli import LifecycleServices, _diagnostic_observation
from installer.claudian_remote_lifecycle.diagnostics import DiagnosticService
from installer.claudian_remote_lifecycle.inspect import Inspector
from installer.claudian_remote_lifecycle.legacy_authority import RetirementCommit
from installer.claudian_remote_lifecycle.model import (
    CHECKPOINT_SCHEMA,
    RESULT_SCHEMA,
    RESULT_SCHEMA_V1,
    ActionOwner,
    AmbiguityState,
    CredentialEffect,
    EffectDisposition,
    EffectSummary,
    Journey,
    LifecyclePhase,
    NextAction,
    NextActionType,
    PairingIdentityPolicy,
    RecoveryPolicy,
)
from installer.claudian_remote_lifecycle.operation_arbitration import (
    OperationArbitration,
)
from installer.claudian_remote_lifecycle.plan import PlanBuilder, PlanStore
from installer.claudian_remote_lifecycle.runtime import RuntimeLayout
from installer.tests.test_inspect import FakeProbe


def unsafe_observation(secret: str) -> dict:
    return {
        "components": {"plugin": "0.2.0-beta.1", "relay": "0.2.0-beta.1", "extra": secret},
        "lifecycle": {"state": "blocked", "phase": "verify", "raw_path": f"/Users/{secret}"},
        "reason_codes": ["relay_offline", secret],
        "connection": {
            "mode": "local_tailscale",
            "transport_status": "disconnected",
            "endpoint": f"https://{secret}.invalid/path",
            "pairing_state": secret,
        },
        "counters": {"failed_checks": 2},
        "argv": ["--password", secret],
        "environment": {"TOKEN": secret},
        "stack": f"trace: {secret}",
        "content": f"markdown {secret}",
    }


def test_agent_summary_is_typed_and_ignores_arbitrary_sensitive_fields():
    marker = "CANARY-SECRET-秘密"
    service = DiagnosticService(clock=lambda: datetime(2026, 7, 21, tzinfo=timezone.utc))
    encoded = json.dumps(service.agent_safe_summary(unsafe_observation(marker)), ensure_ascii=False)
    assert marker not in encoded
    assert "/Users/" not in encoded
    assert "https://" not in encoded
    assert "pairing_state" not in encoded
    assert "relay_offline" in encoded


def test_semantic_looking_ascii_secrets_cannot_cross_allowlisted_fields():
    marker = "sk_live_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnop"
    observation = unsafe_observation(marker)
    observation["components"]["plugin"] = marker
    observation["components"]["protocol"] = marker
    observation["lifecycle"]["phase"] = marker
    observation["reason_codes"] = [marker]
    observation["connection"]["mode"] = marker
    service = DiagnosticService(clock=lambda: datetime(2026, 7, 21, tzinfo=timezone.utc))

    encoded = json.dumps(service.agent_safe_summary(observation))

    assert marker not in encoded
    assert encoded.count("unknown") >= 5


def test_v2_control_and_typed_attention_are_allowlisted_without_parameters():
    marker = "CANARY-SECRET-parameter"
    observation = unsafe_observation(marker)
    observation["lifecycle"].update(
        {
            "result_schema": RESULT_SCHEMA,
            "journey": "legacy_upgrade",
            "phase": "retirement_reconciliation",
            "irreversible_boundary_crossed": False,
            "ambiguity_state": "retirement_outcome_unknown",
            "recovery_policy": "reconcile_same_operation",
            "cancellation_available": False,
            "pairing_identity_policy": "not_applicable",
            "effect_summary": {
                "local_effect": "staged",
                "remote_effect": "unknown",
                "credential_effect": "outcome_unknown",
                "mutation_performed": True,
                "owned_resource_count": 2,
                "effect_codes": [
                    "local_stage_present",
                    "operation_staged",
                    "retirement_dispatch_recorded",
                ],
                "private_url": f"https://{marker}.invalid",
            },
            "next_actions": [
                {
                    "action_id": "status-original-operation",
                    "action_type": "lifecycle_command",
                    "owner": "agent",
                    "recommended": True,
                    "executable": True,
                    "command": "status",
                    "parameters": {
                        "private_url": f"https://{marker}.invalid",
                        "token": marker,
                    },
                }
            ],
        }
    )
    service = DiagnosticService(clock=lambda: datetime(2026, 7, 22, tzinfo=timezone.utc))

    summary = service.agent_safe_summary(observation)
    encoded = json.dumps(summary, ensure_ascii=False)

    assert marker not in encoded
    assert "https://" not in encoded
    assert summary["result_schema"] == RESULT_SCHEMA
    assert summary["journey"] == "legacy_upgrade"
    assert summary["phase"] == "retirement_reconciliation"
    assert summary["irreversible_boundary_crossed"] is False
    assert summary["ambiguity_state"] == "retirement_outcome_unknown"
    assert summary["recovery_policy"] == "reconcile_same_operation"
    assert summary["effect_summary"] == {
        "local_effect": "staged",
        "remote_effect": "unknown",
        "credential_effect": "outcome_unknown",
        "mutation_performed": True,
        "owned_resource_count": 2,
        "effect_codes": [
            "local_stage_present",
            "operation_staged",
            "retirement_dispatch_recorded",
        ],
    }
    assert summary["attention"]["next_action_count"] == 1
    assert summary["attention"]["next_actions"] == [
        {
            "action_id": "status-original-operation",
            "action_type": "lifecycle_command",
            "owner": "agent",
            "command": "status",
            "recommended": True,
            "executable": True,
        }
    ]


def test_retirement_diagnostics_expose_only_non_replayable_commit_facts():
    marker = "CANARY-RETIREMENT-SECRET"
    observation = unsafe_observation(marker)
    observation["lifecycle"].update(
        {
            "result_schema": RESULT_SCHEMA,
            "journey": "legacy_upgrade",
            "phase": "retirement_reconciliation",
            "irreversible_boundary_crossed": True,
            "ambiguity_state": "retired",
            "recovery_policy": "finish_forward",
            "cancellation_available": False,
            "pairing_identity_policy": "not_applicable",
            "effect_summary": {
                "local_effect": "staged",
                "remote_effect": "changed",
                "credential_effect": "retired",
                "mutation_performed": True,
                "owned_resource_count": 2,
                "effect_codes": ["retirement_proof_consumed"],
            },
            "retirement_commit": RetirementCommit(
                authority_instance_id="authority-instance-a",
                authority_origin_digest="a" * 64,
                runtime_key_id="runtime-key-a",
                owner_id="owner-a",
                installation_id="installation-a",
                mac_id="mac-a",
                vault_id="vault-a",
                role="mobile",
                slot_id="slot-a",
                old_generation=7,
                target_generation=8,
                operation_id="op-" + "a" * 32,
                plan_id="plan-beta5",
                release_digest="b" * 64,
                helper_digest="c" * 64,
                nonce_digest="d" * 64,
                idempotency_digest="e" * 64,
                proof_digest="f" * 64,
                consumed_at_epoch=2_000_000_000,
            ).to_mapping(),
            "private_endpoint": f"https://{marker}.invalid",
            "runtime_evidence": marker,
        }
    )
    summary = DiagnosticService(
        clock=lambda: datetime(2026, 7, 22, tzinfo=timezone.utc)
    ).agent_safe_summary(observation)
    encoded = json.dumps(summary, ensure_ascii=False)

    assert marker not in encoded
    assert "https://" not in encoded
    assert summary["retirement_commit"] == {
        "present": True,
        "authority_instance_id": "authority-instance-a",
        "target_generation": 8,
        "consumed_at_epoch": 2_000_000_000,
    }
    assert summary["effect_summary"]["effect_codes"] == [
        "retirement_proof_consumed"
    ]


def test_v2_recovery_actions_and_current_effect_codes_remain_machine_selectable():
    service = DiagnosticService(clock=lambda: datetime(2026, 7, 22, tzinfo=timezone.utc))
    observation = unsafe_observation("not-exported")
    observation["lifecycle"].update(
        {
            "result_schema": RESULT_SCHEMA,
            "journey": "legacy_upgrade",
            "phase": "retirement_reconciliation",
            "irreversible_boundary_crossed": False,
            "ambiguity_state": "retirement_outcome_unknown",
            "recovery_policy": "reconcile_same_operation",
            "cancellation_available": False,
            "pairing_identity_policy": "not_applicable",
            "effect_summary": {
                "local_effect": "staged",
                "remote_effect": "unknown",
                "credential_effect": "outcome_unknown",
                "mutation_performed": True,
                "owned_resource_count": 1,
                "effect_codes": [
                    "operation_failed",
                    "installation_ready",
                    "rollback_completed",
                    "uninstall_completed",
                    "purge_completed",
                    "diagnostic_export_ready",
                    "device_revoked",
                    "operation_interrupted",
                ],
            },
            "next_actions": [
                {
                    "action_id": "rollback-original-operation",
                    "action_type": "lifecycle_command",
                    "owner": "agent",
                    "recommended": True,
                    "executable": True,
                    "command": "rollback",
                    "parameters": {},
                },
                {
                    "action_id": "reconcile-original-operation",
                    "action_type": "lifecycle_command",
                    "owner": "agent",
                    "recommended": False,
                    "executable": True,
                    "command": "status",
                    "parameters": {},
                },
                {
                    "action_id": "contact-maintainer-with-diagnostics",
                    "action_type": "manual_instruction",
                    "owner": "maintainer",
                    "recommended": False,
                    "executable": True,
                    "command": None,
                    "parameters": {},
                },
            ],
        }
    )
    operation_id = "op-" + "d" * 32

    for recovery_action in ("finish_forward", "reconcile_retirement_outcome"):
        observation["attention"] = {
            "operation_id": operation_id,
            "command": "status",
            "recovery_action": recovery_action,
        }
        summary = service.agent_safe_summary(observation)

        assert summary["attention"]["recovery_action"] == recovery_action
        assert [
            item["action_id"] for item in summary["attention"]["next_actions"]
        ] == [
            "rollback-original-operation",
            "reconcile-original-operation",
            "contact-maintainer-with-diagnostics",
        ]
        assert summary["effect_summary"]["effect_codes"] == observation[
            "lifecycle"
        ]["effect_summary"]["effect_codes"]


def test_unknown_schema_or_v2_enum_downgrades_to_unknown_without_inference():
    service = DiagnosticService(clock=lambda: datetime(2026, 7, 22, tzinfo=timezone.utc))
    observation = unsafe_observation("not-exported")
    observation["lifecycle"].update(
        {
            "result_schema": "claudian-remote.lifecycle-result/v99",
            "journey": "legacy_upgrade",
            # This deliberately overlaps the legacy allowlist. An explicit
            # unknown schema must still make the phase unknown.
            "phase": "ready",
            "irreversible_boundary_crossed": True,
            "ambiguity_state": "retired",
            "recovery_policy": "finish_forward",
            "effect_summary": {
                "local_effect": "changed",
                "remote_effect": "changed",
                "credential_effect": "retired",
            },
        }
    )

    summary = service.agent_safe_summary(observation)

    assert summary["result_schema"] == "unknown"
    assert summary["journey"] == "unknown"
    assert summary["phase"] == "unknown"
    assert summary["irreversible_boundary_crossed"] is None
    assert summary["ambiguity_state"] == "unknown"
    assert summary["recovery_policy"] == "unknown"
    assert summary["effect_summary"] == {
        "local_effect": "unknown",
        "remote_effect": "unknown",
        "credential_effect": "unknown",
        "mutation_performed": None,
        "owned_resource_count": None,
        "effect_codes": [],
    }

    observation["lifecycle"] = {
        "result_schema": RESULT_SCHEMA_V1,
        "state": "recovery_required",
        "phase": "installation_compensation_failed",
    }
    legacy = service.agent_safe_summary(observation)
    assert legacy["result_schema"] == RESULT_SCHEMA_V1
    assert legacy["phase"] == "installation_compensation_failed"

    observation["lifecycle"].update(
        {
            "result_schema": RESULT_SCHEMA,
            "journey": "probably_upgrade",
            "phase": "maybe_finished",
            "ambiguity_state": "probably_retired",
            "recovery_policy": "delete_checkpoint",
            "pairing_identity_policy": "guess",
        }
    )
    downgraded = service.agent_safe_summary(observation)
    assert downgraded["journey"] == "unknown"
    assert downgraded["phase"] == "unknown"
    assert downgraded["ambiguity_state"] == "unknown"
    assert downgraded["recovery_policy"] == "unknown"
    assert downgraded["pairing_identity_policy"] == "unknown"


def test_operation_arbitration_observation_projects_only_codes_ids_and_count():
    marker = "CANARY-SECRET-arbitration"
    observation = unsafe_observation(marker)
    arbitration = OperationArbitration(
        state="reconciliation_required",
        reason_code="prior_operation_recovery_required",
        prior_operation_terminal=False,
        operation_id="op-" + "a" * 32,
        recommended_action="rollback",
        terminal_operation_ids=("op-" + "b" * 32,),
        checkpoint={
            "checkpoint_schema": CHECKPOINT_SCHEMA,
            "journey": "legacy_upgrade",
            "phase": "retirement_reconciliation",
            "irreversible_boundary_crossed": False,
            "ambiguity_state": "retirement_outcome_unknown",
            "recovery_policy": "reconcile_same_operation",
            "cancellation_available": False,
            "pairing_identity_policy": "not_applicable",
            "effect_summary": {
                "local_effect": "staged",
                "remote_effect": "unknown",
                "credential_effect": "outcome_unknown",
                "mutation_performed": True,
                "owned_resource_count": 2,
                "effect_codes": ["retirement_dispatch_recorded"],
            },
        },
    )
    observation["operation_arbitration"] = {
        **arbitration.to_summary(),
        "checkpoint_path": f"/Users/{marker}/checkpoint.json",
        "private_url": f"https://{marker}.invalid",
        "credential": marker,
    }
    service = DiagnosticService(clock=lambda: datetime(2026, 7, 22, tzinfo=timezone.utc))

    summary = service.agent_safe_summary(observation)
    encoded = json.dumps(summary, ensure_ascii=False)

    assert marker not in encoded
    assert "/Users/" not in encoded
    assert "https://" not in encoded
    assert summary["operation_arbitration"] == {
        "state": "reconciliation_required",
        "reason_code": "prior_operation_recovery_required",
        "prior_operation_terminal": False,
        "operation_id": "op-" + "a" * 32,
        "recommended_action": "rollback",
        "terminal_operation_count": 1,
        "operation_schema": CHECKPOINT_SCHEMA,
        "journey": "legacy_upgrade",
        "phase": "retirement_reconciliation",
        "irreversible_boundary_crossed": False,
        "ambiguity_state": "retirement_outcome_unknown",
        "recovery_policy": "reconcile_same_operation",
        "cancellation_available": False,
        "pairing_identity_policy": "not_applicable",
        "effect_summary": {
            "local_effect": "staged",
            "remote_effect": "unknown",
            "credential_effect": "outcome_unknown",
            "mutation_performed": True,
            "owned_resource_count": 2,
            "effect_codes": ["retirement_dispatch_recorded"],
        },
    }

    observation["operation_arbitration"].update(
        {
            "state": marker,
            "reason_code": marker,
            "operation_id": marker,
            "recommended_action": marker,
            "terminal_operation_ids": [marker],
            "operation_schema": "claudian-remote.checkpoint/v99",
        }
    )
    unknown = service.agent_safe_summary(observation)["operation_arbitration"]
    assert unknown == {
        "state": "unknown",
        "reason_code": "unknown",
        "prior_operation_terminal": False,
        "operation_id": None,
        "recommended_action": "unknown",
        "terminal_operation_count": None,
        "operation_schema": "unknown",
        "journey": "unknown",
        "phase": "unknown",
        "irreversible_boundary_crossed": None,
        "ambiguity_state": "unknown",
        "recovery_policy": "unknown",
        "cancellation_available": None,
        "pairing_identity_policy": "unknown",
        "effect_summary": {
            "local_effect": "unknown",
            "remote_effect": "unknown",
            "credential_effect": "unknown",
            "mutation_performed": None,
            "owned_resource_count": None,
            "effect_codes": [],
        },
    }


def test_export_requires_verified_confirmation_and_writes_private_local_file(tmp_path):
    marker = "CANARY-SECRET-秘密"
    service = DiagnosticService(clock=lambda: datetime(2026, 7, 21, tzinfo=timezone.utc))
    destination = (tmp_path / "diagnostics.json").resolve()
    blocked = service.export(unsafe_observation(marker), destination, confirmation_verified=False)
    assert blocked["code"] == "diagnostic_export_confirmation_required"
    assert not destination.exists()

    ready = service.export(unsafe_observation(marker), destination, confirmation_verified=True)
    assert ready["code"] == "diagnostic_export_ready"
    assert ready["uploaded"] is False
    assert os.stat(destination).st_mode & 0o777 == 0o600
    text = destination.read_text(encoding="utf-8")
    assert marker not in text
    assert "/Users/" not in text
    assert "https://" not in text
    assert service.delete_export(destination) is True
    assert not destination.exists()


def test_diagnose_reports_recovery_checkpoint_instead_of_hardcoded_zero(tmp_path):
    layout = RuntimeLayout(tmp_path / "app", tmp_path / "LaunchAgents")
    checkpoints = CheckpointStore(layout.base / "lifecycle")
    snapshot = Inspector(FakeProbe()).snapshot()
    plan = PlanBuilder().build(snapshot, mode="local_tailscale")
    PlanStore(layout.base / "lifecycle").write(plan, snapshot)
    rollback = NextAction(
        action_id="rollback-original-operation",
        action_type=NextActionType.LIFECYCLE_COMMAND,
        owner=ActionOwner.AGENT,
        recommended=True,
        executable=True,
        command="rollback",
        parameters={"operation_id_ref": "checkpoint.operation_id"},
    )
    checkpoint = checkpoints.create(
        command="install",
        plan_id=plan["plan_id"],
        phase=LifecyclePhase.ROLLBACK.value,
        journey=Journey.FRESH_INSTALL,
        irreversible_boundary_crossed=False,
        ambiguity_state=AmbiguityState.NOT_APPLICABLE,
        recovery_policy=RecoveryPolicy.ROLLBACK_PRE_BOUNDARY,
        effect_summary=EffectSummary(
            local_effect=EffectDisposition.STAGED,
            remote_effect=EffectDisposition.NOT_APPLICABLE,
            credential_effect=CredentialEffect.NOT_APPLICABLE,
            mutation_performed=True,
            owned_resource_count=1,
            effect_codes=("operation_failed",),
        ),
        next_actions=(rollback,),
        cancellation_available=False,
        pairing_identity_policy=PairingIdentityPolicy.NOT_APPLICABLE,
        prior_operation_terminal=True,
    )
    checkpoints.update(
        checkpoint["operation_id"],
        state="recovery_required",
        completed_phases=["staging"],
    )
    transaction_path = (
        layout.base
        / "lifecycle"
        / f"{checkpoint['operation_id']}.transaction.json"
    )
    transaction_path.write_text(
        json.dumps(
            {
                "transaction_schema": "claudian-remote.local-transaction/v1",
                "operation_id": checkpoint["operation_id"],
                "plan_id": plan["plan_id"],
                "phase": "recovery_required",
                "completed_phases": ["staging"],
                "prior_availability_vault": None,
                "prior_release_id": None,
                "activation_started": False,
                "plugin_activated": False,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )
    services = LifecycleServices(object(), {}, layout=layout)

    observation = _diagnostic_observation(snapshot, services)
    summary = DiagnosticService().agent_safe_summary(observation)

    assert summary["state"] == "recovery_required"
    assert summary["phase"] == "rollback"
    assert summary["counters"]["pending_operations"] == 1
    assert summary["attention"] == {
        "operation_id": checkpoint["operation_id"],
        "command": "rollback",
        "recovery_action": "rollback",
        "next_action_count": 1,
        "next_actions": [
            {
                "action_id": "rollback-original-operation",
                "action_type": "lifecycle_command",
                "owner": "agent",
                "command": "rollback",
                "recommended": True,
                "executable": True,
            }
        ],
    }


def test_diagnose_fails_closed_when_a_checkpoint_is_unreadable(tmp_path):
    layout = RuntimeLayout(tmp_path / "app", tmp_path / "LaunchAgents")
    lifecycle = layout.base / "lifecycle"
    lifecycle.mkdir(parents=True)
    (lifecycle / ("op-" + "b" * 32 + ".json")).write_text("{truncated", encoding="utf-8")
    services = LifecycleServices(object(), {}, layout=layout)
    snapshot = {
        "installation": {"plugin_versions": []},
        "support": {"reason_codes": []},
        "claudian": {"version": "2.0.4"},
        "network": {"tailscale_logged_in": True},
        "obsidian": {"running": False},
    }

    summary = DiagnosticService().agent_safe_summary(
        _diagnostic_observation(snapshot, services)
    )

    assert summary["state"] == "blocked"
    assert summary["phase"] == "reconciliation"
    assert summary["reason_codes"] == ["lifecycle_checkpoint_invalid"]
    assert summary["counters"]["pending_operations"] == 1
    assert summary["counters"]["failed_checks"] == 1
