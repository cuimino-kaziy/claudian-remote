"""Allowlisted, local-only lifecycle diagnostics.

The diagnostic service deliberately does not serialize arbitrary runtime
objects.  Callers provide structured observations, but only stable codes,
versions, booleans, and counters cross the Agent/export boundary.  This keeps
paths, endpoints, credentials, content, argv/environment, stacks, and pairing
state out of both the short summary and the optional bundle.
"""

from __future__ import annotations

import json
import os
import platform
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from .legacy_authority import RetirementCommit
from .model import (
    CHECKPOINT_SCHEMA,
    COMMANDS,
    RESULT_SCHEMA,
    RESULT_SCHEMA_V1,
    ActionOwner,
    AmbiguityState,
    CredentialEffect,
    EffectDisposition,
    Journey,
    LifecyclePhase,
    NextActionType,
    PairingIdentityPolicy,
    RecoveryPolicy,
)

DIAGNOSTIC_SCHEMA = "claudian-remote.diagnostics/v2"
AGENT_SAFE_SUMMARY_SCHEMA = "claudian-remote.agent-safe-summary/v2"
DIAGNOSTIC_PREVIEW_SCHEMA = "claudian-remote.diagnostic-preview/v2"
SEMVER = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
LIFECYCLE_STATES = frozenset(
    {"ready", "prepared", "running", "blocked", "rolled_back", "recovery_required"}
)
LIFECYCLE_PHASES = frozenset({
    "inspection", "created", "install_prepared", "update_prepared", "before_staging",
    "before_legacy_migration", "before_activation", "after_activation", "await_pairing",
    "awaiting_purge_confirmation", "awaiting_diagnostic_export_confirmation", "verify", "ready",
    "rolled_back", "recovery_required", "installation_compensation_failed",
    "legacy_credential_revocation_required", "legacy_credential_revocation_unavailable",
    "rollback_completed", "checkpoint_invalid",
})
V2_LIFECYCLE_PHASES = frozenset(item.value for item in LifecyclePhase)
JOURNEYS = frozenset(item.value for item in Journey)
AMBIGUITY_STATES = frozenset(item.value for item in AmbiguityState)
RECOVERY_POLICIES = frozenset(item.value for item in RecoveryPolicy)
PAIRING_IDENTITY_POLICIES = frozenset(item.value for item in PairingIdentityPolicy)
LOCAL_REMOTE_EFFECTS = frozenset(item.value for item in EffectDisposition)
CREDENTIAL_EFFECTS = frozenset(item.value for item in CredentialEffect)
NEXT_ACTION_TYPES = frozenset(item.value for item in NextActionType)
NEXT_ACTION_OWNERS = frozenset(item.value for item in ActionOwner)
NEXT_ACTION_COMMANDS = frozenset(COMMANDS)
NEXT_ACTION_IDS = frozenset({
    "execute_install_plan",
    "resolve_plan_blocker",
    "rollback-original-operation",
    "reconcile-original-operation",
    "contact-maintainer-with-diagnostics",
    "resume-original-operation",
    "status-original-operation",
    "finish-forward-original-operation",
})
EFFECT_CODES = frozenset({
    "diagnostic_export_ready",
    "device_revoked",
    "installation_ready",
    "local_stage_present",
    "local_staging_complete",
    "operation_failed",
    "operation_interrupted",
    "operation_ready",
    "operation_staged",
    "purge_completed",
    "retirement_dispatch_recorded",
    "retirement_proof_consumed",
    "rollback_completed",
    "uninstall_completed",
})
REASON_CODES = frozenset({
    "unsupported_desktop_os", "unsupported_claudian_version", "claudian_not_enabled",
    "secure_provisioning_missing", "vault_not_found", "vault_selection_required",
    "tailscale_install_required", "tailscale_login_required", "tailscale_update_required",
    "tailscale_https_consent_required", "pairing_approval_required",
    "trusted_lan_not_release_eligible", "environment_drift", "owned_resource_modified",
    "device_revocation_unavailable", "device_revocation_unverified",
    "relay_offline", "lifecycle_checkpoint_invalid",
    "operation_reconciliation_required", "unsupported_current_lineage",
    "unsupported_legacy_lineage", "legacy_and_current_plugin_enabled",
    "plugin_lineage_ambiguous", "journey_classification_failed",
})
CONNECTION_MODES = frozenset({"local_tailscale", "remote_vps", "local_lan"})
TRANSPORT_STATES = frozenset({"connected", "disconnected"})
MAC_STATES = frozenset({"online", "offline"})
COMPATIBILITY_STATES = frozenset({"compatible", "blocked"})
ARCHITECTURES = frozenset({"arm64", "aarch64", "x86_64"})
ATTENTION_COMMANDS = frozenset({"status", "resume", "rollback"})
RECOVERY_ACTIONS = frozenset({
    "resume",
    "rollback",
    "finish_forward",
    "reconcile_retirement_outcome",
    "manual_recovery_required",
})
ARBITRATION_STATES = frozenset({"clear", "reconciliation_required", "blocked"})
ARBITRATION_ACTIONS = frozenset({
    "resume",
    "rollback",
    "finish_forward",
    "reconcile_retirement_outcome",
    "manual_recovery_required",
})
ARBITRATION_REASON_CODES = frozenset({
    "no_prior_operation",
    "prior_operations_terminal",
    "multiple_unfinished_operations",
    "prior_operation_artifact_invalid",
    "prior_operation_ready",
    "prior_operation_gate_waiting",
    "prior_operation_no_effect",
    "prior_operation_rolled_back",
    "prior_operation_terminal_journal_mismatch",
    "prior_operation_recovery_required",
    "prior_operation_incomplete",
    "prior_operation_ambiguous",
    "prior_operation_finish_forward_required",
    "prior_operation_retirement_reconciliation_required",
    "prior_operation_manual_recovery_required",
})
OPERATION_ID = re.compile(r"^op-[0-9a-f]{32}$")


def _enum(value: Any, allowed: frozenset[str], fallback: str = "unknown") -> str:
    candidate = str(value or "").strip().lower()
    return candidate if candidate in allowed else fallback


def _version(key: str, value: Any) -> str:
    candidate = str(value or "").strip()
    if key == "protocol":
        return candidate if candidate == "claudian.remote.v2" else "unknown"
    return candidate if SEMVER.fullmatch(candidate) else "unknown"


def _count(value: Any) -> int:
    try:
        return max(0, min(int(value), 1_000_000_000))
    except (TypeError, ValueError):
        return 0


def _optional_bool(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def _optional_count(value: Any) -> int | None:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value > 1_000_000_000
    ):
        return None
    return value


def _operation_id(value: Any) -> str | None:
    candidate = str(value or "")
    return candidate if OPERATION_ID.fullmatch(candidate) else None


def _effect_projection(value: Any) -> dict[str, Any]:
    effect = value if isinstance(value, Mapping) else {}
    codes = effect.get("effect_codes")
    safe_codes = (
        [_enum(item, EFFECT_CODES) for item in codes[:32]]
        if isinstance(codes, (list, tuple))
        else []
    )
    return {
        "local_effect": _enum(effect.get("local_effect"), LOCAL_REMOTE_EFFECTS),
        "remote_effect": _enum(effect.get("remote_effect"), LOCAL_REMOTE_EFFECTS),
        "credential_effect": _enum(effect.get("credential_effect"), CREDENTIAL_EFFECTS),
        "mutation_performed": _optional_bool(effect.get("mutation_performed")),
        "owned_resource_count": _optional_count(effect.get("owned_resource_count")),
        "effect_codes": safe_codes,
    }


def _next_actions_projection(value: Any) -> tuple[list[dict[str, Any]], int | None]:
    if not isinstance(value, (list, tuple)):
        return [], None
    actions: list[dict[str, Any]] = []
    for raw_action in value[:32]:
        action = raw_action if isinstance(raw_action, Mapping) else {}
        command = action.get("command")
        actions.append(
            {
                "action_id": _enum(action.get("action_id"), NEXT_ACTION_IDS),
                "action_type": _enum(action.get("action_type"), NEXT_ACTION_TYPES),
                "owner": _enum(action.get("owner"), NEXT_ACTION_OWNERS),
                "command": (
                    _enum(command, NEXT_ACTION_COMMANDS)
                    if command is not None
                    else None
                ),
                "recommended": _optional_bool(action.get("recommended")),
                "executable": _optional_bool(action.get("executable")),
            }
        )
    return actions, len(value)


def _arbitration_projection(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    terminal_ids = value.get("terminal_operation_ids")
    terminal_count: int | None = None
    if isinstance(terminal_ids, (list, tuple)) and all(
        _operation_id(item) is not None for item in terminal_ids
    ):
        terminal_count = len(terminal_ids)
    action = value.get("recommended_action")
    operation_schema = (
        CHECKPOINT_SCHEMA
        if value.get("operation_schema") == CHECKPOINT_SCHEMA
        else "unknown"
    )
    v2_control = operation_schema == CHECKPOINT_SCHEMA
    return {
        "state": _enum(value.get("state"), ARBITRATION_STATES),
        "reason_code": _enum(value.get("reason_code"), ARBITRATION_REASON_CODES),
        "prior_operation_terminal": _optional_bool(
            value.get("prior_operation_terminal")
        ),
        "operation_id": _operation_id(value.get("operation_id")),
        "recommended_action": (
            _enum(action, ARBITRATION_ACTIONS) if action is not None else None
        ),
        "terminal_operation_count": terminal_count,
        "operation_schema": operation_schema,
        "journey": (
            _enum(value.get("journey"), JOURNEYS) if v2_control else "unknown"
        ),
        "phase": (
            _enum(value.get("phase"), V2_LIFECYCLE_PHASES)
            if v2_control
            else "unknown"
        ),
        "irreversible_boundary_crossed": (
            _optional_bool(value.get("irreversible_boundary_crossed"))
            if v2_control
            else None
        ),
        "ambiguity_state": (
            _enum(value.get("ambiguity_state"), AMBIGUITY_STATES)
            if v2_control
            else "unknown"
        ),
        "recovery_policy": (
            _enum(value.get("recovery_policy"), RECOVERY_POLICIES)
            if v2_control
            else "unknown"
        ),
        "cancellation_available": (
            _optional_bool(value.get("cancellation_available"))
            if v2_control
            else None
        ),
        "pairing_identity_policy": (
            _enum(value.get("pairing_identity_policy"), PAIRING_IDENTITY_POLICIES)
            if v2_control
            else "unknown"
        ),
        "effect_summary": _effect_projection(
            value.get("effect_summary") if v2_control else None
        ),
    }


def _retirement_commit_projection(value: Any) -> dict[str, Any] | None:
    """Expose only non-replayable retirement facts to Agent diagnostics."""

    try:
        commit = RetirementCommit.from_mapping(value)
    except (TypeError, ValueError):
        return None
    return {
        "present": True,
        "authority_instance_id": commit.authority_instance_id,
        "target_generation": commit.target_generation,
        "consumed_at_epoch": commit.consumed_at_epoch,
    }


class DiagnosticService:
    """Build and optionally export a non-sensitive diagnostic projection."""

    EXPORT_FIELDS = (
        "schema",
        "created_at",
        "system",
        "components",
        "lifecycle",
        "connection",
        "counters",
        "attention",
        "operation_arbitration",
    )

    def __init__(self, *, clock: Any | None = None) -> None:
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def _projection(self, observation: Mapping[str, Any]) -> dict[str, Any]:
        components = observation.get("components") if isinstance(observation.get("components"), Mapping) else {}
        lifecycle = observation.get("lifecycle") if isinstance(observation.get("lifecycle"), Mapping) else {}
        connection = observation.get("connection") if isinstance(observation.get("connection"), Mapping) else {}
        counters = observation.get("counters") if isinstance(observation.get("counters"), Mapping) else {}
        attention = observation.get("attention") if isinstance(observation.get("attention"), Mapping) else {}
        reasons = observation.get("reason_codes") if isinstance(observation.get("reason_codes"), (list, tuple)) else []
        operation_id = str(attention.get("operation_id") or "")
        command = _enum(attention.get("command"), ATTENTION_COMMANDS, fallback="")
        recovery_action = _enum(
            attention.get("recovery_action"), RECOVERY_ACTIONS, fallback=""
        )
        observed_schema = lifecycle.get("result_schema")
        control_schema = (
            observed_schema
            if observed_schema in {RESULT_SCHEMA, RESULT_SCHEMA_V1}
            else "unknown"
        )
        v2_control = control_schema == RESULT_SCHEMA
        next_actions, next_action_count = _next_actions_projection(
            lifecycle.get("next_actions") if v2_control else None
        )
        safe_attention = None
        if OPERATION_ID.fullmatch(operation_id) and command and recovery_action:
            safe_attention = {
                "operation_id": operation_id,
                "command": command,
                "recovery_action": recovery_action,
            }
        if v2_control and next_action_count is not None:
            safe_attention = dict(safe_attention or {})
            safe_attention.update(
                {
                    "next_action_count": next_action_count,
                    "next_actions": next_actions,
                }
            )
        legacy_control = observed_schema is None or control_schema == RESULT_SCHEMA_V1
        phase_allowlist = (
            V2_LIFECYCLE_PHASES
            if v2_control
            else LIFECYCLE_PHASES if legacy_control else frozenset()
        )
        return {
            "schema": DIAGNOSTIC_SCHEMA,
            "created_at": self.clock().astimezone(timezone.utc).isoformat(),
            "system": {
                "platform": "macos" if platform.system() == "Darwin" else "unsupported",
                "architecture": _enum(platform.machine(), ARCHITECTURES),
            },
            "components": {
                key: _version(key, components.get(key))
                for key in ("plugin", "companion", "relay", "protocol", "claudian")
            },
            "lifecycle": {
                "state": _enum(lifecycle.get("state"), LIFECYCLE_STATES),
                "result_schema": control_schema,
                "journey": (
                    _enum(lifecycle.get("journey"), JOURNEYS)
                    if v2_control
                    else "unknown"
                ),
                "phase": _enum(lifecycle.get("phase"), phase_allowlist),
                "irreversible_boundary_crossed": (
                    _optional_bool(lifecycle.get("irreversible_boundary_crossed"))
                    if v2_control
                    else None
                ),
                "ambiguity_state": (
                    _enum(lifecycle.get("ambiguity_state"), AMBIGUITY_STATES)
                    if v2_control
                    else "unknown"
                ),
                "recovery_policy": (
                    _enum(lifecycle.get("recovery_policy"), RECOVERY_POLICIES)
                    if v2_control
                    else "unknown"
                ),
                "cancellation_available": (
                    _optional_bool(lifecycle.get("cancellation_available"))
                    if v2_control
                    else None
                ),
                "pairing_identity_policy": (
                    _enum(
                        lifecycle.get("pairing_identity_policy"),
                        PAIRING_IDENTITY_POLICIES,
                    )
                    if v2_control
                    else "unknown"
                ),
                "effect_summary": _effect_projection(
                    lifecycle.get("effect_summary") if v2_control else None
                ),
                "reason_codes": [_enum(item, REASON_CODES) for item in reasons[:32]],
                "ownership_receipt_present": lifecycle.get("ownership_receipt_present") is True,
                "retirement_commit": (
                    _retirement_commit_projection(lifecycle.get("retirement_commit"))
                    if v2_control
                    else None
                ),
            },
            "connection": {
                "mode": _enum(connection.get("mode"), CONNECTION_MODES),
                "transport_status": _enum(connection.get("transport_status"), TRANSPORT_STATES),
                "mac_status": _enum(connection.get("mac_status"), MAC_STATES),
                "compatibility_status": _enum(connection.get("compatibility_status"), COMPATIBILITY_STATES),
            },
            "counters": {
                key: _count(counters.get(key))
                for key in ("pending_operations", "failed_checks", "owned_resources")
            },
            "attention": safe_attention,
            "operation_arbitration": _arbitration_projection(
                observation.get("operation_arbitration")
            ),
        }

    def agent_safe_summary(self, observation: Mapping[str, Any]) -> dict[str, Any]:
        projection = self._projection(observation)
        summary = {
            "summary_schema": AGENT_SAFE_SUMMARY_SCHEMA,
            "state": projection["lifecycle"]["state"],
            "phase": projection["lifecycle"]["phase"],
            "result_schema": projection["lifecycle"]["result_schema"],
            "journey": projection["lifecycle"]["journey"],
            "irreversible_boundary_crossed": projection["lifecycle"][
                "irreversible_boundary_crossed"
            ],
            "ambiguity_state": projection["lifecycle"]["ambiguity_state"],
            "recovery_policy": projection["lifecycle"]["recovery_policy"],
            "cancellation_available": projection["lifecycle"][
                "cancellation_available"
            ],
            "pairing_identity_policy": projection["lifecycle"][
                "pairing_identity_policy"
            ],
            "effect_summary": projection["lifecycle"]["effect_summary"],
            "reason_codes": projection["lifecycle"]["reason_codes"],
            "connection": projection["connection"],
            "components": projection["components"],
            "counters": projection["counters"],
        }
        if projection["attention"] is not None:
            summary["attention"] = projection["attention"]
        if projection["lifecycle"]["retirement_commit"] is not None:
            summary["retirement_commit"] = projection["lifecycle"][
                "retirement_commit"
            ]
        if projection["operation_arbitration"] is not None:
            summary["operation_arbitration"] = projection["operation_arbitration"]
        return summary

    def preview_export(self) -> dict[str, Any]:
        return {
            "preview_schema": DIAGNOSTIC_PREVIEW_SCHEMA,
            "fields": list(self.EXPORT_FIELDS),
            "excluded": [
                "credentials", "pairing_state", "content", "paths", "urls",
                "network_identity", "argv", "environment", "stacks",
            ],
            "uploaded": False,
        }

    def export(
        self,
        observation: Mapping[str, Any],
        destination: Path,
        *,
        confirmation_verified: bool,
    ) -> dict[str, Any]:
        if confirmation_verified is not True:
            return {
                "state": "blocked",
                "code": "diagnostic_export_confirmation_required",
                "mutation_performed": False,
                "preview": self.preview_export(),
            }
        destination = Path(destination)
        if not destination.is_absolute() or destination.suffix.lower() != ".json":
            return {
                "state": "blocked",
                "code": "diagnostic_export_destination_invalid",
                "mutation_performed": False,
            }
        destination.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(prefix=destination.name + ".", dir=destination.parent)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(self._projection(observation), handle, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, destination)
        finally:
            Path(temporary).unlink(missing_ok=True)
        return {
            "state": "ready",
            "code": "diagnostic_export_ready",
            "mutation_performed": True,
            "uploaded": False,
            "field_names": list(self.EXPORT_FIELDS),
        }

    @staticmethod
    def delete_export(path: Path) -> bool:
        path = Path(path)
        if not path.is_file():
            return False
        path.unlink()
        return True
