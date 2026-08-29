"""Read-only arbitration of prior lifecycle operations before journey selection."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
import stat
from typing import Any, Mapping, NoReturn, Sequence

from .checkpoint import CheckpointStore
from .compatibility_decode import (
    CompatibilityDecodeError,
    V1Reconciliation,
    decode_v1_compatibility_set,
)
from .model import CHECKPOINT_SCHEMA, CHECKPOINT_SCHEMA_V1, LifecyclePhase
from .migrations import inspect_legacy_retirement_journal
from .plan import PlanStore


_CHECKPOINT_NAME = re.compile(r"(op-[0-9a-f]{32})\.json")
_TRANSACTION_NAME = re.compile(r"(op-[0-9a-f]{32})\.transaction\.json")
_MIGRATION_NAME = re.compile(r"(op-[0-9a-f]{32})\.legacy-plugin\.json")
_DIAGNOSTIC_DESTINATION_NAME = re.compile(
    r"(op-[0-9a-f]{32})\.diagnostic-destination\.json"
)
_TRANSACTION_FIELDS = frozenset(
    {
        "transaction_schema",
        "operation_id",
        "plan_id",
        "phase",
        "completed_phases",
        "prior_availability_vault",
        "prior_release_id",
        "activation_started",
        "plugin_activated",
    }
)
_TRANSACTION_COMPLETED_PHASES = (
    "staging",
    "legacy_plugin_migration",
    "secure_provisioning",
    "plugin_activation",
    "launchd",
    "tailscale_serve",
    "verified",
    "paired",
)
_TRANSACTION_PHASE_PREFIXES = {
    "before_staging": 0,
    "before_legacy_migration": 1,
    "before_activation": 2,
    "activation_started": 2,
    "plugin_activated": 3,
    "after_activation": 6,
    "await_plugin_bootstrap": 6,
    "await_pairing": 7,
    "ready": 8,
}


@dataclass(frozen=True)
class OperationArbitration:
    state: str
    reason_code: str
    prior_operation_terminal: bool
    operation_id: str | None = None
    recommended_action: str | None = None
    terminal_operation_ids: tuple[str, ...] = ()
    reconciliation: V1Reconciliation | None = None
    checkpoint: Mapping[str, Any] | None = None

    def to_summary(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "state": self.state,
            "reason_code": self.reason_code,
            "prior_operation_terminal": self.prior_operation_terminal,
            "terminal_operation_ids": list(self.terminal_operation_ids),
        }
        if self.operation_id is not None:
            value["operation_id"] = self.operation_id
        if self.recommended_action is not None:
            value["recommended_action"] = self.recommended_action
        if self.checkpoint is not None:
            for field in (
                "checkpoint_schema",
                "journey",
                "phase",
                "irreversible_boundary_crossed",
                "ambiguity_state",
                "recovery_policy",
                "effect_summary",
                "cancellation_available",
                "pairing_identity_policy",
            ):
                if field in self.checkpoint:
                    item = self.checkpoint[field]
                    value["operation_schema" if field == "checkpoint_schema" else field] = item
        return value


@dataclass(frozen=True)
class _ClassifiedOperation:
    operation_id: str
    terminal: bool
    reason_code: str
    action: str | None
    reconciliation: V1Reconciliation | None = None
    checkpoint: Mapping[str, Any] | None = None


class OperationArbitrator:
    """Reconcile supported v1/v2 operations without selecting by file mtime."""

    def __init__(self, state_dir: Path) -> None:
        self.state_dir = Path(state_dir)

    def inspect(self) -> OperationArbitration:
        if not self.state_dir.exists():
            return OperationArbitration("clear", "no_prior_operation", True)
        if not self.state_dir.is_dir() or self.state_dir.is_symlink():
            return self._invalid()

        checkpoint_paths: dict[str, Path] = {}
        transaction_ids: set[str] = set()
        migration_ids: set[str] = set()
        diagnostic_destination_ids: set[str] = set()
        try:
            entries = tuple(self.state_dir.iterdir())
        except OSError:
            return self._invalid()
        for path in entries:
            if path.is_symlink():
                if path.name.startswith("op-"):
                    return self._invalid()
                continue
            checkpoint = _CHECKPOINT_NAME.fullmatch(path.name)
            transaction = _TRANSACTION_NAME.fullmatch(path.name)
            migration = _MIGRATION_NAME.fullmatch(path.name)
            diagnostic_destination = _DIAGNOSTIC_DESTINATION_NAME.fullmatch(
                path.name
            )
            if checkpoint:
                checkpoint_paths[checkpoint.group(1)] = path
            elif transaction:
                transaction_ids.add(transaction.group(1))
            elif migration:
                migration_ids.add(migration.group(1))
            elif diagnostic_destination:
                diagnostic_destination_ids.add(diagnostic_destination.group(1))
            elif path.name.startswith("op-") and path.suffix == ".json":
                return self._invalid()

        companion_ids = (
            transaction_ids | migration_ids | diagnostic_destination_ids
        )
        if companion_ids - set(checkpoint_paths):
            return self._invalid()

        classified: list[_ClassifiedOperation] = []
        for operation_id in sorted(checkpoint_paths):
            checkpoint = checkpoint_paths[operation_id]
            identity = self._checkpoint_identity(checkpoint)
            if identity is None:
                return self._invalid()
            schema, plan_id = identity
            if schema == CHECKPOINT_SCHEMA:
                try:
                    current = CheckpointStore(self.state_dir).read(operation_id)
                    plan = self._validate_v2_plan_binding(current, plan_id)
                    current = self._validate_v2_companions(
                        current,
                        plan=plan,
                        transaction_path=(
                            self.state_dir / f"{operation_id}.transaction.json"
                            if operation_id in transaction_ids
                            else None
                        ),
                        migration_path=(
                            self.state_dir / f"{operation_id}.legacy-plugin.json"
                            if operation_id in migration_ids
                            else None
                        ),
                        diagnostic_destination_path=(
                            self.state_dir
                            / f"{operation_id}.diagnostic-destination.json"
                            if operation_id in diagnostic_destination_ids
                            else None
                        ),
                    )
                    classified.append(self._classify_v2(current))
                except (OSError, ValueError):
                    return self._invalid()
                continue
            saved_plan = self.state_dir / "plans" / f"{plan_id}.json"
            transaction = self.state_dir / f"{operation_id}.transaction.json"
            migration = self.state_dir / f"{operation_id}.legacy-plugin.json"
            try:
                reconciliation = decode_v1_compatibility_set(
                    checkpoint_path=checkpoint,
                    saved_plan_path=saved_plan,
                    local_transaction_path=transaction if transaction.is_file() else None,
                    legacy_migration_path=migration if migration.is_file() else None,
                )
            except (CompatibilityDecodeError, OSError):
                return self._invalid()
            classified.append(self._classify_v1(reconciliation))

        unfinished = [item for item in classified if not item.terminal]
        terminal_ids = tuple(
            item.operation_id for item in classified if item.terminal
        )
        if not unfinished:
            return OperationArbitration(
                "clear",
                "prior_operations_terminal" if classified else "no_prior_operation",
                True,
                terminal_operation_ids=terminal_ids,
            )
        if len(unfinished) != 1:
            return OperationArbitration(
                "blocked",
                "multiple_unfinished_operations",
                False,
                recommended_action="manual_recovery_required",
                terminal_operation_ids=terminal_ids,
            )
        item = unfinished[0]
        return OperationArbitration(
            "reconciliation_required",
            item.reason_code,
            False,
            operation_id=item.operation_id,
            recommended_action=item.action,
            terminal_operation_ids=terminal_ids,
            reconciliation=item.reconciliation,
            checkpoint=item.checkpoint,
        )

    @staticmethod
    def _checkpoint_identity(path: Path) -> tuple[str, str] | None:
        # The strict decoder/store performs authoritative validation. This scan
        # only locates the immutable companion and rejects duplicate keys.
        try:
            value = json.loads(
                path.read_text(encoding="utf-8"),
                object_pairs_hook=_object_without_duplicates,
                parse_constant=_reject_json_constant,
            )
        except (OSError, ValueError, TypeError):
            return None
        schema = value.get("checkpoint_schema") if isinstance(value, dict) else None
        plan_id = value.get("plan_id") if isinstance(value, dict) else None
        if schema == CHECKPOINT_SCHEMA_V1:
            if not isinstance(plan_id, str) or re.fullmatch(r"plan-[0-9a-f]{64}", plan_id) is None:
                return None
        elif schema == CHECKPOINT_SCHEMA:
            if not isinstance(plan_id, str) or re.fullmatch(
                r"(?:plan-[A-Za-z0-9._:-]{1,194}|diagnostic-export)", plan_id
            ) is None:
                return None
        else:
            return None
        return schema, plan_id

    def _validate_v2_plan_binding(
        self, checkpoint: Mapping[str, Any], plan_id: str
    ) -> Mapping[str, Any] | None:
        command = str(checkpoint.get("command") or "")
        if plan_id == "diagnostic-export":
            if command != "export-diagnostics":
                raise ValueError("invalid_checkpoint_plan_binding")
            return None
        plan, _snapshot = PlanStore(self.state_dir).read(plan_id)
        if command in {"install", "update"}:
            signed_action = plan.get("recommended_next_action")
            expected_command = (
                "update" if plan.get("journey") == "current_update" else "install"
            )
            if (
                checkpoint.get("journey") != plan.get("journey")
                or checkpoint.get("pairing_identity_policy")
                != plan.get("pairing_identity_policy")
                or checkpoint.get("prior_operation_terminal") is not True
                or command != expected_command
                or not isinstance(signed_action, Mapping)
                or signed_action.get("action_type") != "lifecycle_command"
                or signed_action.get("owner") != "agent"
                or signed_action.get("command") != command
            ):
                raise ValueError("invalid_checkpoint_plan_binding")
        return plan

    @staticmethod
    def _validate_v2_companions(
        checkpoint: Mapping[str, Any],
        *,
        plan: Mapping[str, Any] | None,
        transaction_path: Path | None,
        migration_path: Path | None,
        diagnostic_destination_path: Path | None,
    ) -> dict[str, Any]:
        current = dict(checkpoint)
        command = str(current.get("command") or "")
        split_retirement_reconciliation = False
        if migration_path is not None:
            if current.get("journey") != "legacy_upgrade":
                raise ValueError("unexpected_legacy_migration_companion")
            retirement = inspect_legacy_retirement_journal(
                migration_path,
                operation_id=str(current["operation_id"]),
                plan_id=str(current["plan_id"]),
            )
            expected = {
                "not_dispatched": (False, "not_dispatched"),
                "retirement_outcome_unknown": (
                    False,
                    "retirement_outcome_unknown",
                ),
                "not_applied": (False, "not_applied"),
                "inconclusive": (False, "inconclusive"),
                "retired": (True, "retired"),
            }[retirement]
            checkpoint_ambiguity = current.get("ambiguity_state")
            transitional_unknown = retirement == "retirement_outcome_unknown" and (
                checkpoint_ambiguity
                in {"retirement_outcome_unknown", "not_applied", "inconclusive", "retired"}
            )
            if current.get("irreversible_boundary_crossed") != (
                checkpoint_ambiguity == "retired"
            ) or (not transitional_unknown and checkpoint_ambiguity != expected[1]):
                raise ValueError("checkpoint_migration_boundary_mismatch")
            if transitional_unknown and checkpoint_ambiguity != (
                "retirement_outcome_unknown"
            ):
                # The authority checkpoint may have consumed a proof just
                # before the process died, while the local migration companion
                # still says outcome unknown.  Reconcile the same request first;
                # never jump directly into forward mutation from this split.
                current.update(
                    state="recovery_required",
                    phase=LifecyclePhase.RECONCILIATION.value,
                    recovery_policy="reconcile_same_operation",
                    next_actions=[_projected_lifecycle_action("resume")],
                    cancellation_available=False,
                    active_gate=None,
                )
                split_retirement_reconciliation = True
            elif (
                retirement != "retirement_outcome_unknown"
                and current.get("recovery_policy") == "reconcile_same_operation"
            ):
                raise ValueError("retirement_reconciliation_policy_invalid")
        OperationArbitrator._validate_diagnostic_destination_companion(
            current,
            diagnostic_destination_path,
        )
        if transaction_path is None:
            if command in {"install", "update"} and current.get("state") in {
                "ready",
                "rolled_back",
                "recovery_required",
            }:
                raise ValueError("missing_transaction_companion")
            return current
        if command not in {"install", "update"} or plan is None:
            raise ValueError("unexpected_transaction_companion")

        transaction = _read_transaction_companion(
            transaction_path,
            operation_id=str(current["operation_id"]),
            plan_id=str(current["plan_id"]),
        )
        transaction_phase = str(transaction["phase"])
        checkpoint_state = str(current["state"])
        checkpoint_completed = current.get("completed_phases")
        transaction_completed = transaction["completed_phases"]
        if not isinstance(checkpoint_completed, list) or checkpoint_completed != transaction_completed[
            : len(checkpoint_completed)
        ]:
            raise ValueError("checkpoint_transaction_progress_mismatch")

        gate = current.get("active_gate")
        if gate is not None:
            expected_phase = {
                "desktop_plugin_bootstrap_required": "await_plugin_bootstrap",
                "pairing_approval_required": "await_pairing",
            }.get(str(gate.get("gate_type") or ""))
            if expected_phase is not None and transaction_phase != expected_phase:
                raise ValueError("checkpoint_transaction_gate_mismatch")

        if checkpoint_state == "ready" and transaction_phase != "ready":
            raise ValueError("checkpoint_transaction_terminal_mismatch")
        if checkpoint_state == "rolled_back" and transaction_phase != "rolled_back":
            raise ValueError("checkpoint_transaction_terminal_mismatch")

        if transaction_phase == "recovery_required":
            if split_retirement_reconciliation:
                if current.get("recovery_policy") != "reconcile_same_operation":
                    raise ValueError("retirement_reconciliation_policy_required")
            elif current.get("irreversible_boundary_crossed") is True:
                if current.get("recovery_policy") != "finish_forward":
                    raise ValueError("finish_forward_policy_required")
            elif current.get("ambiguity_state") == "retirement_outcome_unknown":
                if current.get("recovery_policy") != "reconcile_same_operation":
                    raise ValueError("retirement_reconciliation_policy_required")
            elif current.get("ambiguity_state") == "inconclusive":
                if current.get("recovery_policy") != "manual_recovery_required":
                    raise ValueError("retirement_manual_recovery_policy_required")
            elif current.get("ambiguity_state") == "not_applied":
                if current.get("recovery_policy") != "rollback_pre_boundary":
                    raise ValueError("retirement_rollback_policy_required")
            else:
                current.update(
                    state="recovery_required",
                    phase=LifecyclePhase.ROLLBACK.value,
                    recovery_policy="rollback_pre_boundary",
                    next_actions=[_projected_lifecycle_action("rollback")],
                    cancellation_available=False,
                    active_gate=None,
                )
        elif transaction_phase == "rolled_back" and checkpoint_state != "rolled_back":
            current.update(
                state="recovery_required",
                phase=LifecyclePhase.ROLLBACK.value,
                recovery_policy="rollback_pre_boundary",
                next_actions=[_projected_lifecycle_action("rollback")],
                cancellation_available=False,
                active_gate=None,
            )
        elif transaction_phase == "ready" and checkpoint_state != "ready":
            # The transaction reached a coherent installation, but the outer
            # checkpoint still owns the idempotent finish-forward update.
            if current.get("irreversible_boundary_crossed") is True:
                current.update(
                    state="recovery_required",
                    phase=LifecyclePhase.VERIFICATION.value,
                    recovery_policy="finish_forward",
                    next_actions=[_projected_lifecycle_action("resume")],
                    cancellation_available=False,
                    active_gate=None,
                )
            else:
                current.update(
                    state="prepared",
                    phase=LifecyclePhase.VERIFICATION.value,
                    recovery_policy="retry_same_operation",
                    next_actions=[_projected_lifecycle_action("resume")],
                    cancellation_available=False,
                    active_gate=None,
                )
        return current

    @staticmethod
    def _validate_diagnostic_destination_companion(
        checkpoint: Mapping[str, Any],
        path: Path | None,
    ) -> None:
        """Bind the opaque 0600 export destination to its owning human gate.

        The destination itself is intentionally not decoded here: arbitration
        only proves that the lifecycle-owned secret envelope is present and
        belongs to this exact operation.  ``SecureInputFile.consume`` remains
        the sole reader and one-shot remover of its contents.
        """

        command = str(checkpoint.get("command") or "")
        state = str(checkpoint.get("state") or "")
        gate = checkpoint.get("active_gate")
        if command != "export-diagnostics":
            if path is not None:
                raise ValueError("unexpected_diagnostic_destination_companion")
            return

        waiting_for_confirmation = (
            state == "blocked"
            and isinstance(gate, Mapping)
            and gate.get("gate_type")
            == "diagnostic_export_confirmation_required"
            and gate.get("resume_reference") == checkpoint.get("operation_id")
        )
        if not waiting_for_confirmation:
            if path is not None:
                raise ValueError("stale_diagnostic_destination_companion")
            return
        if path is None:
            raise ValueError("missing_diagnostic_destination_companion")

        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_mode & 0o077
            or metadata.st_size <= 0
            or metadata.st_size > 64 * 1024
        ):
            raise ValueError("invalid_diagnostic_destination_companion")

    @staticmethod
    def _classify_v2(value: Mapping[str, Any]) -> _ClassifiedOperation:
        operation_id = str(value["operation_id"])
        command = str(value["command"])
        state = str(value["state"])
        journey = str(value["journey"])
        ambiguity = str(value["ambiguity_state"])
        recovery = str(value["recovery_policy"])
        boundary = value["irreversible_boundary_crossed"]
        cancellation = value["cancellation_available"]
        pairing_policy = str(value["pairing_identity_policy"])
        effect = value["effect_summary"]

        if str(value.get("phase") or "") not in {
            item.value for item in LifecyclePhase
        }:
            return _invalid_v2(value, "v2_phase_invalid")
        if not isinstance(boundary, bool):
            return _invalid_v2(value, "v2_boundary_state_unknown")
        if not isinstance(cancellation, bool):
            return _invalid_v2(value, "v2_cancellation_state_unknown")
        if boundary and cancellation:
            return _invalid_v2(value, "v2_cancellation_state_invalid")

        if command in {"install", "update"}:
            if journey not in {"fresh_install", "current_update", "legacy_upgrade"}:
                return _invalid_v2(value, "v2_operation_journey_invalid")
            if value.get("prior_operation_terminal") is not True:
                return _invalid_v2(value, "v2_prior_operation_not_terminal")
            if journey == "current_update":
                if pairing_policy not in {"preserve", "rotate"}:
                    return _invalid_v2(value, "v2_pairing_policy_invalid")
            elif pairing_policy != "not_applicable":
                return _invalid_v2(value, "v2_pairing_policy_invalid")
            if journey in {"fresh_install", "current_update"} and ambiguity != "not_applicable":
                return _invalid_v2(value, "v2_ambiguity_state_invalid")

        dispatched = {
            "retirement_outcome_unknown",
            "not_applied",
            "retired",
            "inconclusive",
        }
        if ambiguity in dispatched and cancellation is not False:
            return _invalid_v2(value, "v2_cancellation_state_invalid")
        if boundary is True and recovery == "rollback_pre_boundary":
            return _invalid_v2(value, "v2_recovery_policy_invalid")
        if journey == "legacy_upgrade":
            if ambiguity == "retired" and boundary is not True:
                return _invalid_v2(value, "v2_boundary_state_invalid")
            if boundary is True and ambiguity != "retired":
                return _invalid_v2(value, "v2_boundary_state_invalid")
            allowed_legacy_recovery = {
                "not_dispatched": {
                    "retry_same_operation",
                    "rollback_pre_boundary",
                    "manual_recovery_required",
                    "not_applicable",
                },
                "retirement_outcome_unknown": {
                    "reconcile_same_operation",
                    "manual_recovery_required",
                },
                "not_applied": {
                    "retry_same_operation",
                    "rollback_pre_boundary",
                    "manual_recovery_required",
                },
                "retired": {
                    "finish_forward",
                    "reconcile_same_operation",
                    "manual_recovery_required",
                    "not_applicable",
                },
                "inconclusive": {"manual_recovery_required"},
            }.get(ambiguity)
            if allowed_legacy_recovery is None or recovery not in allowed_legacy_recovery:
                return _invalid_v2(value, "v2_legacy_recovery_policy_invalid")
        expected_credential = {
            "not_dispatched": "not_dispatched",
            "retirement_outcome_unknown": "outcome_unknown",
            "not_applied": "not_applied",
            "retired": "retired",
            "inconclusive": "inconclusive",
        }.get(ambiguity)
        if expected_credential is not None and effect.get("credential_effect") != expected_credential:
            return _invalid_v2(value, "v2_effect_summary_invalid")

        action = _v2_recovery_action(value)
        if action == "invalid":
            return _invalid_v2(value, "v2_next_action_invalid")
        if state == "ready":
            if action is not None or value.get("active_gate") is not None:
                return _invalid_v2(value, "v2_terminal_state_invalid")
            return _ClassifiedOperation(
                operation_id, True, "prior_operation_ready", None, checkpoint=value
            )
        if state == "rolled_back":
            if boundary is True or action is not None or value.get("active_gate") is not None:
                return _invalid_v2(value, "v2_terminal_state_invalid")
            return _ClassifiedOperation(
                operation_id,
                True,
                "prior_operation_rolled_back",
                None,
                checkpoint=value,
            )
        active_gate = value.get("active_gate")
        if active_gate is not None and not (
            state == "blocked"
            and action == "resume"
            and recovery == "retry_same_operation"
        ):
            return _invalid_v2(value, "v2_active_gate_invalid")
        if (
            state == "blocked"
            and action is None
            and active_gate is None
            and boundary is False
            and effect.get("mutation_performed") is False
            and effect.get("owned_resource_count") == 0
            and effect.get("effect_codes") == []
            and recovery == "not_applicable"
        ):
            return _ClassifiedOperation(
                operation_id,
                True,
                "prior_operation_no_effect",
                None,
                checkpoint=value,
            )
        if action is None:
            return _invalid_v2(value, "v2_next_action_required")
        return _ClassifiedOperation(
            operation_id,
            False,
            {
                "resume": "prior_operation_incomplete",
                "rollback": "prior_operation_recovery_required",
                "finish_forward": "prior_operation_finish_forward_required",
                "reconcile_retirement_outcome": "prior_operation_retirement_reconciliation_required",
                "manual_recovery_required": "prior_operation_manual_recovery_required",
            }[action],
            action,
            checkpoint=value,
        )

    @staticmethod
    def _classify_v1(value: V1Reconciliation) -> _ClassifiedOperation:
        state = value.checkpoint_state
        transaction = value.transaction_phase
        migration = value.migration_phase

        # A v1 legacy migration journal is local-only and has no authority,
        # credential-slot, operation proof, or not-applied receipt.  Once it
        # exists, Beta 5 cannot safely infer that the old credential was never
        # retired.  U3 supplies the first authoritative reconciliation path;
        # until then this exact original operation remains maintainer-owned.
        if migration is not None:
            return _ClassifiedOperation(
                value.operation_id,
                False,
                "prior_operation_legacy_effect_inconclusive",
                "manual_recovery_required",
                value,
            )

        if state == "ready" and transaction == "ready":
            return _ClassifiedOperation(
                value.operation_id, True, "prior_operation_ready", None, value
            )
        if state == "blocked" and value.active_gate_present:
            return _ClassifiedOperation(value.operation_id, False, "prior_operation_gate_waiting", "resume", value)
        if state == "blocked" and not value.mutation_may_have_started and transaction in {
            None,
            "before_staging",
        }:
            return _ClassifiedOperation(value.operation_id, True, "prior_operation_no_effect", None, value)
        if state == "rolled_back" and transaction == "rolled_back" and migration in {
            None,
            "rolled_back",
        }:
            return _ClassifiedOperation(value.operation_id, True, "prior_operation_rolled_back", None, value)
        if state == "rolled_back" and transaction == "recovery_required":
            return _ClassifiedOperation(
                value.operation_id,
                False,
                "prior_operation_terminal_journal_mismatch",
                "rollback",
                value,
            )
        if state == "recovery_required" and transaction == "recovery_required":
            return _ClassifiedOperation(value.operation_id, False, "prior_operation_recovery_required", "rollback", value)
        if state == "prepared":
            return _ClassifiedOperation(value.operation_id, False, "prior_operation_incomplete", "resume", value)
        return _ClassifiedOperation(
            value.operation_id, False, "prior_operation_ambiguous", "manual_recovery_required", value
        )

    @staticmethod
    def _invalid() -> OperationArbitration:
        return OperationArbitration(
            "blocked",
            "prior_operation_artifact_invalid",
            False,
            recommended_action="manual_recovery_required",
        )


def _object_without_duplicates(
    pairs: Sequence[tuple[str, Any]],
) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate_operation_artifact_field")
        value[key] = item
    return value


def _reject_json_constant(_value: str) -> NoReturn:
    raise ValueError("invalid_operation_artifact_json")


def _invalid_v2(_value: Mapping[str, Any], reason_code: str) -> NoReturn:
    """Fail the entire arbitration closed for an invalid current artifact."""

    raise ValueError(reason_code)


def _v2_recovery_action(value: Mapping[str, Any]) -> str | None:
    actions = value.get("next_actions")
    if not isinstance(actions, list):
        return "invalid"
    recommended = [
        action
        for action in actions
        if isinstance(action, Mapping)
        and action.get("recommended") is True
        and action.get("executable") is True
    ]
    if len(recommended) > 1:
        return "invalid"

    recovery = str(value.get("recovery_policy") or "")
    if not recommended:
        if recovery in {
            "retry_same_operation",
            "reconcile_same_operation",
            "rollback_pre_boundary",
            "finish_forward",
            "manual_recovery_required",
        }:
            return "invalid"
        return None

    action = recommended[0]
    command = action.get("command")
    action_type = action.get("action_type")
    owner = action.get("owner")
    parameters = action.get("parameters")
    expected = {
        "retry_same_operation": ("resume", "resume"),
        "reconcile_same_operation": (
            "resume",
            "reconcile_retirement_outcome",
        ),
        "rollback_pre_boundary": ("rollback", "rollback"),
        "finish_forward": ("resume", "finish_forward"),
    }.get(recovery)
    if expected is not None:
        expected_command, projection = expected
        if (
            action_type != "lifecycle_command"
            or owner != "agent"
            or command != expected_command
            or not _current_operation_reference(parameters)
        ):
            return "invalid"
        return projection
    if recovery == "manual_recovery_required":
        if (
            action_type != "manual_instruction"
            or command is not None
            or owner != "maintainer"
            or parameters != {"instruction_code": "manual_recovery_required"}
        ):
            return "invalid"
        return "manual_recovery_required"
    if recovery != "not_applicable":
        return "invalid"

    # A non-recovery support operation may still expose its one ordinary
    # continuation. Keep the public arbitration vocabulary deliberately small.
    command_projection = {
        "resume": "resume",
        "rollback": "rollback",
    }
    if (
        action_type != "lifecycle_command"
        or owner != "agent"
        or command not in command_projection
        or not _current_operation_reference(parameters)
    ):
        return "invalid"
    return command_projection[str(command)]


def _current_operation_reference(value: Any) -> bool:
    return isinstance(value, Mapping) and dict(value) in (
        {"operation_id_ref": "checkpoint.operation_id"},
        {"operation_id_ref": "result.operation_id"},
    )


def _projected_lifecycle_action(command: str) -> dict[str, Any]:
    action_id = {
        "resume": "resume-original-operation",
        "rollback": "rollback-original-operation",
    }[command]
    return {
        "action_id": action_id,
        "action_type": "lifecycle_command",
        "owner": "agent",
        "recommended": True,
        "executable": True,
        "command": command,
        "parameters": {"operation_id_ref": "checkpoint.operation_id"},
    }


def _read_transaction_companion(
    path: Path,
    *,
    operation_id: str,
    plan_id: str,
) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_json_constant,
        )
    except (OSError, ValueError, TypeError) as exc:
        raise ValueError("invalid_transaction_companion") from exc
    if not isinstance(value, Mapping) or set(value) != _TRANSACTION_FIELDS:
        raise ValueError("invalid_transaction_companion")
    transaction = dict(value)
    if (
        transaction.get("transaction_schema")
        != "claudian-remote.local-transaction/v1"
        or transaction.get("operation_id") != operation_id
        or transaction.get("plan_id") != plan_id
    ):
        raise ValueError("invalid_transaction_companion_binding")
    phase = transaction.get("phase")
    if phase not in set(_TRANSACTION_PHASE_PREFIXES) | {
        "rolled_back",
        "recovery_required",
    }:
        raise ValueError("invalid_transaction_companion_phase")
    completed = transaction.get("completed_phases")
    if (
        not isinstance(completed, list)
        or completed != list(_TRANSACTION_COMPLETED_PHASES[: len(completed)])
    ):
        raise ValueError("invalid_transaction_companion_progress")
    if phase in _TRANSACTION_PHASE_PREFIXES and len(completed) != _TRANSACTION_PHASE_PREFIXES[phase]:
        raise ValueError("invalid_transaction_companion_progress")
    activation_started = transaction.get("activation_started")
    plugin_activated = transaction.get("plugin_activated")
    if not isinstance(activation_started, bool) or not isinstance(plugin_activated, bool):
        raise ValueError("invalid_transaction_companion_activation")
    if plugin_activated and not activation_started:
        raise ValueError("invalid_transaction_companion_activation")
    if phase in {"before_staging", "before_legacy_migration", "before_activation"} and (
        activation_started or plugin_activated
    ):
        raise ValueError("invalid_transaction_companion_activation")
    if phase == "activation_started" and (
        activation_started is not True or plugin_activated
    ):
        raise ValueError("invalid_transaction_companion_activation")
    if phase in {
        "plugin_activated",
        "after_activation",
        "await_plugin_bootstrap",
        "await_pairing",
        "ready",
    } and (activation_started is not True or plugin_activated is not True):
        raise ValueError("invalid_transaction_companion_activation")
    availability = transaction.get("prior_availability_vault")
    if availability is not None and (
        not isinstance(availability, str)
        or not availability
        or len(availability) > 255
        or any(character in availability for character in ("/", "\x00"))
    ):
        raise ValueError("invalid_transaction_companion_vault")
    release_id = transaction.get("prior_release_id")
    if release_id is not None and (
        not isinstance(release_id, str)
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,194}", release_id) is None
    ):
        raise ValueError("invalid_transaction_companion_release")
    return transaction
