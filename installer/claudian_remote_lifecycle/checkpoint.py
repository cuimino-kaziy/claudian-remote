"""Private atomic checkpoints and one-process lifecycle operation lock."""

from __future__ import annotations

import fcntl
import json
import math
import os
import re
import secrets
import tempfile
from pathlib import Path
from typing import Any, Iterable, Mapping

from .model import (
    CHECKPOINT_SCHEMA,
    CHECKPOINT_SCHEMA_V1,
    COMMANDS,
    RESULT_STATES,
    AmbiguityState,
    EffectSummary,
    Journey,
    NextAction,
    PairingIdentityPolicy,
    RecoveryPolicy,
)


_CHECKPOINT_FIELDS = frozenset(
    {
        "checkpoint_schema",
        "operation_id",
        "command",
        "plan_id",
        "phase",
        "state",
        "completed_phases",
        "recorded_answers",
        "active_gate",
        "journey",
        "irreversible_boundary_crossed",
        "ambiguity_state",
        "recovery_policy",
        "effect_summary",
        "next_actions",
        "cancellation_available",
        "pairing_identity_policy",
        "prior_operation_terminal",
    }
)
_MUTABLE_CHECKPOINT_FIELDS = frozenset(
    {
        "phase",
        "state",
        "completed_phases",
        "recorded_answers",
        "active_gate",
        "irreversible_boundary_crossed",
        "ambiguity_state",
        "recovery_policy",
        "effect_summary",
        "next_actions",
        "cancellation_available",
    }
)
_EFFECT_SUMMARY_FIELDS = frozenset(
    {
        "local_effect",
        "remote_effect",
        "credential_effect",
        "mutation_performed",
        "owned_resource_count",
        "effect_codes",
    }
)
_NEXT_ACTION_FIELDS = frozenset(
    {
        "action_id",
        "action_type",
        "owner",
        "recommended",
        "executable",
        "command",
        "parameters",
    }
)
_GATE_FIELDS = frozenset(
    {
        "gate_id",
        "gate_type",
        "explanation",
        "exact_action",
        "verification_probe",
        "resume_reference",
        "operator_options",
        "status",
        "created_at_epoch",
        "expires_at_epoch",
        "refresh_generation",
    }
)
_OPERATOR_OPTION_REQUIRED_FIELDS = frozenset(
    {"id", "label", "instructions", "recommended"}
)
_OPERATOR_OPTION_OPTIONAL_FIELDS = frozenset({"url", "requires_capability"})
_SAFE_CODE = re.compile(r"[a-z][a-z0-9_.:-]{0,127}")
_OPERATION_ID = re.compile(r"op-[0-9a-f]{32}")
_PLAN_ID = re.compile(r"(?:plan-[A-Za-z0-9._:-]{1,194}|diagnostic-export)")


def _mapping_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("checkpoint_duplicate_field")
        value[key] = item
    return value


def _reject_json_constant(_value: str) -> None:
    raise ValueError("invalid_checkpoint_json")


def _load_json_mapping(path: Path) -> dict[str, Any]:
    value = json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=_mapping_without_duplicates,
        parse_constant=_reject_json_constant,
    )
    if not isinstance(value, Mapping):
        raise ValueError("invalid_checkpoint_shape")
    return dict(value)


def _assert_exact_fields(
    value: Mapping[str, Any],
    expected: frozenset[str],
    *,
    code: str,
) -> None:
    if set(value) != expected:
        raise ValueError(code)


def _assert_json_safe(value: Any, path: str = "checkpoint") -> None:
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"checkpoint_non_finite_number:{path}")
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"checkpoint_non_string_key:{path}")
            _assert_json_safe(item, f"{path}.{key}")
        return
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _assert_json_safe(item, f"{path}[{index}]")
        return
    raise ValueError(f"checkpoint_non_json_value:{path}")


class OperationBusy(RuntimeError):
    pass


def _assert_secret_free(value: Any, path: str = "root") -> None:
    forbidden_keys = ("password", "secret", "token", "credential", "claim")
    safe_contract_keys = {"credential_effect"}
    if isinstance(value, Mapping):
        for key, item in value.items():
            lowered = str(key).lower()
            if (
                any(part in lowered for part in forbidden_keys)
                and not lowered.endswith(("_ref", "_id"))
                and lowered not in safe_contract_keys
            ):
                raise ValueError(f"checkpoint_forbidden_field:{path}.{key}")
            _assert_secret_free(item, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _assert_secret_free(item, f"{path}[{index}]")


def _enum_value(value: Any, enum_type: type[Any], code: str) -> str:
    try:
        return (value if isinstance(value, enum_type) else enum_type(value)).value
    except (TypeError, ValueError) as exc:
        raise ValueError(code) from exc


def _effect_summary_dict(value: EffectSummary | Mapping[str, Any] | None) -> dict[str, Any]:
    if value is None:
        summary = EffectSummary(mutation_performed=False)
    elif isinstance(value, EffectSummary):
        summary = value
    elif isinstance(value, Mapping):
        _assert_exact_fields(
            value,
            _EFFECT_SUMMARY_FIELDS,
            code="invalid_checkpoint_effect_summary_fields",
        )
        effect_codes = value["effect_codes"]
        if isinstance(effect_codes, (str, bytes, Mapping)):
            raise ValueError("invalid_checkpoint_effect_summary")
        try:
            summary = EffectSummary(
                local_effect=value["local_effect"],
                remote_effect=value["remote_effect"],
                credential_effect=value["credential_effect"],
                mutation_performed=value["mutation_performed"],
                owned_resource_count=value["owned_resource_count"],
                effect_codes=tuple(effect_codes),
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("invalid_checkpoint_effect_summary") from exc
    else:
        raise ValueError("invalid_checkpoint_effect_summary")
    return {
        "local_effect": summary.local_effect.value,
        "remote_effect": summary.remote_effect.value,
        "credential_effect": summary.credential_effect.value,
        "mutation_performed": summary.mutation_performed,
        "owned_resource_count": summary.owned_resource_count,
        "effect_codes": list(summary.effect_codes),
    }


def _next_action_dict(value: NextAction | Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(value, NextAction):
        action = value
    elif isinstance(value, Mapping):
        _assert_exact_fields(
            value,
            _NEXT_ACTION_FIELDS,
            code="invalid_checkpoint_next_action_fields",
        )
        try:
            action = NextAction(
                action_id=value["action_id"],
                action_type=value["action_type"],
                owner=value["owner"],
                recommended=value["recommended"],
                executable=value["executable"],
                command=value["command"],
                parameters=value["parameters"],
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("invalid_checkpoint_next_action") from exc
    else:
        raise ValueError("invalid_checkpoint_next_action")
    parameters = dict(action.parameters)
    _assert_json_safe(parameters, "checkpoint.next_actions.parameters")
    _assert_secret_free(parameters, "checkpoint.next_actions.parameters")
    return {
        "action_id": action.action_id,
        "action_type": action.action_type.value,
        "owner": action.owner.value,
        "recommended": action.recommended,
        "executable": action.executable,
        "command": action.command,
        "parameters": parameters,
    }


def _next_action_list(
    values: Iterable[NextAction | Mapping[str, Any]] | None,
) -> list[dict[str, Any]]:
    if values is None:
        return []
    if isinstance(values, (str, bytes, Mapping)):
        raise ValueError("invalid_checkpoint_next_actions")
    actions = [_next_action_dict(value) for value in values]
    if len(actions) > 32:
        raise ValueError("too_many_checkpoint_next_actions")
    identifiers = [str(action["action_id"]) for action in actions]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("duplicate_checkpoint_next_action")
    return actions


def _validate_gate(value: Any, operation_id: str, state: str) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise ValueError("invalid_checkpoint_gate")
    _assert_exact_fields(value, _GATE_FIELDS, code="invalid_checkpoint_gate_fields")
    gate = dict(value)
    if (
        state != "blocked"
        or not isinstance(gate["gate_id"], str)
        or not re.fullmatch(r"gate-[0-9a-f]{24}", gate["gate_id"])
        or not isinstance(gate["gate_type"], str)
        or not _SAFE_CODE.fullmatch(gate["gate_type"])
        or not isinstance(gate["verification_probe"], str)
        or not _SAFE_CODE.fullmatch(gate["verification_probe"])
        or not isinstance(gate["explanation"], str)
        or not gate["explanation"]
        or len(gate["explanation"]) > 2000
        or not isinstance(gate["exact_action"], str)
        or not gate["exact_action"]
        or len(gate["exact_action"]) > 2000
        or gate["resume_reference"] != operation_id
        or gate["status"] != "waiting"
        or isinstance(gate["created_at_epoch"], bool)
        or not isinstance(gate["created_at_epoch"], int)
        or gate["created_at_epoch"] < 0
        or isinstance(gate["expires_at_epoch"], bool)
        or not isinstance(gate["expires_at_epoch"], int)
        or gate["expires_at_epoch"] <= gate["created_at_epoch"]
        or isinstance(gate["refresh_generation"], bool)
        or not isinstance(gate["refresh_generation"], int)
        or gate["refresh_generation"] < 0
        or not isinstance(gate["operator_options"], list)
        or len(gate["operator_options"]) > 8
    ):
        raise ValueError("invalid_checkpoint_gate")
    options: list[dict[str, Any]] = []
    for raw_option in gate["operator_options"]:
        if not isinstance(raw_option, Mapping):
            raise ValueError("invalid_checkpoint_gate_option")
        keys = set(raw_option)
        if not _OPERATOR_OPTION_REQUIRED_FIELDS.issubset(keys) or not keys.issubset(
            _OPERATOR_OPTION_REQUIRED_FIELDS | _OPERATOR_OPTION_OPTIONAL_FIELDS
        ):
            raise ValueError("invalid_checkpoint_gate_option_fields")
        option = dict(raw_option)
        if (
            not isinstance(option["id"], str)
            or not re.fullmatch(r"[a-z][a-z0-9_]{1,31}", option["id"])
            or not isinstance(option["label"], str)
            or not option["label"]
            or len(option["label"]) > 80
            or not isinstance(option["instructions"], str)
            or not option["instructions"]
            or len(option["instructions"]) > 1000
            or not isinstance(option["recommended"], bool)
        ):
            raise ValueError("invalid_checkpoint_gate_option")
        for optional in _OPERATOR_OPTION_OPTIONAL_FIELDS:
            if optional in option and (
                not isinstance(option[optional], str)
                or not option[optional]
                or len(option[optional]) > 2048
            ):
                raise ValueError("invalid_checkpoint_gate_option")
        options.append(option)
    gate["operator_options"] = options
    return gate


def _validate_retirement_commit(
    value: Any,
    *,
    operation_id: str,
    plan_id: str,
) -> dict[str, Any]:
    # Import lazily because legacy_authority imports CheckpointStore.
    from .legacy_authority import RetirementCommit

    try:
        parsed = RetirementCommit.from_mapping(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid_checkpoint_retirement_commit") from exc
    if parsed.operation_id != operation_id or parsed.plan_id != plan_id:
        raise ValueError("invalid_checkpoint_retirement_commit_binding")
    return parsed.to_mapping()


def _validate_retirement_intent(
    value: Any,
    *,
    operation_id: str,
    plan_id: str,
) -> dict[str, Any]:
    # Import lazily because legacy_authority imports CheckpointStore.
    from .legacy_authority import RetirementIntent

    try:
        parsed = RetirementIntent.from_mapping(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid_checkpoint_retirement_intent") from exc
    if parsed.operation_id != operation_id or parsed.plan_id != plan_id:
        raise ValueError("invalid_checkpoint_retirement_intent_binding")
    return parsed.to_mapping()


def _validate_v2_checkpoint(value: Mapping[str, Any]) -> dict[str, Any]:
    _assert_exact_fields(value, _CHECKPOINT_FIELDS, code="invalid_checkpoint_fields")
    checkpoint = dict(value)
    if checkpoint["checkpoint_schema"] != CHECKPOINT_SCHEMA:
        raise ValueError("invalid_checkpoint_schema")
    if not isinstance(checkpoint["operation_id"], str) or not _OPERATION_ID.fullmatch(
        checkpoint["operation_id"]
    ):
        raise ValueError("invalid_checkpoint_identity")
    if not isinstance(checkpoint["command"], str) or checkpoint["command"] not in COMMANDS:
        raise ValueError("invalid_checkpoint_identity")
    if not isinstance(checkpoint["plan_id"], str) or not _PLAN_ID.fullmatch(
        checkpoint["plan_id"]
    ):
        raise ValueError("invalid_checkpoint_identity")
    if not isinstance(checkpoint["phase"], str) or not _SAFE_CODE.fullmatch(
        checkpoint["phase"]
    ):
        raise ValueError("invalid_checkpoint_phase")
    if not isinstance(checkpoint["state"], str) or checkpoint["state"] not in RESULT_STATES:
        raise ValueError("invalid_checkpoint_state")
    completed = checkpoint["completed_phases"]
    if (
        not isinstance(completed, list)
        or any(not isinstance(item, str) or not _SAFE_CODE.fullmatch(item) for item in completed)
        or len(completed) != len(set(completed))
    ):
        raise ValueError("invalid_checkpoint_completed_phases")
    if not isinstance(checkpoint["recorded_answers"], Mapping):
        raise ValueError("invalid_checkpoint_recorded_answers")
    checkpoint["recorded_answers"] = dict(checkpoint["recorded_answers"])
    retirement_commit = checkpoint["recorded_answers"].get("retirement_commit")
    retirement_intent = checkpoint["recorded_answers"].get("retirement_intent")
    if retirement_intent is not None:
        checkpoint["recorded_answers"]["retirement_intent"] = (
            _validate_retirement_intent(
                retirement_intent,
                operation_id=checkpoint["operation_id"],
                plan_id=checkpoint["plan_id"],
            )
        )
    if retirement_commit is not None:
        checkpoint["recorded_answers"]["retirement_commit"] = (
            _validate_retirement_commit(
                retirement_commit,
                operation_id=checkpoint["operation_id"],
                plan_id=checkpoint["plan_id"],
            )
        )
    checkpoint["active_gate"] = _validate_gate(
        checkpoint["active_gate"], checkpoint["operation_id"], checkpoint["state"]
    )
    checkpoint["journey"] = _enum_value(
        checkpoint["journey"], Journey, "invalid_checkpoint_journey"
    )
    for field in (
        "irreversible_boundary_crossed",
        "cancellation_available",
        "prior_operation_terminal",
    ):
        if checkpoint[field] is not None and not isinstance(checkpoint[field], bool):
            raise ValueError(f"invalid_checkpoint_{field}")
    checkpoint["ambiguity_state"] = _enum_value(
        checkpoint["ambiguity_state"],
        AmbiguityState,
        "invalid_checkpoint_ambiguity_state",
    )
    checkpoint["recovery_policy"] = _enum_value(
        checkpoint["recovery_policy"],
        RecoveryPolicy,
        "invalid_checkpoint_recovery_policy",
    )
    checkpoint["pairing_identity_policy"] = _enum_value(
        checkpoint["pairing_identity_policy"],
        PairingIdentityPolicy,
        "invalid_checkpoint_pairing_identity_policy",
    )
    checkpoint["effect_summary"] = _effect_summary_dict(checkpoint["effect_summary"])
    checkpoint["next_actions"] = _next_action_list(checkpoint["next_actions"])
    commit_present = retirement_commit is not None
    intent_present = retirement_intent is not None
    retired_boundary = (
        checkpoint["journey"] == "legacy_upgrade"
        and checkpoint["irreversible_boundary_crossed"] is True
        and checkpoint["ambiguity_state"] == "retired"
    )
    if commit_present and not (
        retired_boundary
        and (
            checkpoint["recovery_policy"]
            in {"finish_forward", "manual_recovery_required"}
            or (
                checkpoint["state"] == "ready"
                and checkpoint["recovery_policy"] == "not_applicable"
            )
        )
        and checkpoint["effect_summary"]["credential_effect"] == "retired"
        and checkpoint["cancellation_available"] is False
    ):
        raise ValueError("invalid_checkpoint_retirement_commit_state")
    if retired_boundary and not commit_present:
        raise ValueError("retired_boundary_requires_retirement_commit")
    if (
        checkpoint["journey"] == "legacy_upgrade"
        and checkpoint["ambiguity_state"]
        in {"retirement_outcome_unknown", "not_applied", "retired", "inconclusive"}
        and not intent_present
    ):
        raise ValueError("dispatched_retirement_requires_intent")
    cancel_actions = [
        action
        for action in checkpoint["next_actions"]
        if action["action_type"] == "lifecycle_command"
        and action["command"] == "cancel"
        and action["executable"]
    ]
    if checkpoint["cancellation_available"] is True:
        if (
            len(cancel_actions) != 1
            or cancel_actions[0]["recommended"]
            or cancel_actions[0]["parameters"]
            != {"operation_id_ref": "result.operation_id"}
        ):
            raise ValueError("available_cancellation_requires_one_cancel_action")
    elif checkpoint["cancellation_available"] is False and cancel_actions:
        raise ValueError("cancel_action_forbidden_when_unavailable")
    _assert_json_safe(checkpoint)
    _assert_secret_free(checkpoint)
    return checkpoint


def _is_supported_v1_checkpoint(value: Mapping[str, Any], operation_id: str) -> bool:
    fields = _CHECKPOINT_FIELDS - {
        "journey",
        "irreversible_boundary_crossed",
        "ambiguity_state",
        "recovery_policy",
        "effect_summary",
        "next_actions",
        "cancellation_available",
        "pairing_identity_policy",
        "prior_operation_terminal",
    }
    if set(value) != fields or value.get("checkpoint_schema") != CHECKPOINT_SCHEMA_V1:
        return False
    if value.get("operation_id") != operation_id or value.get("command") not in {
        "install",
        "update",
    }:
        return False
    if not isinstance(value.get("plan_id"), str) or not re.fullmatch(
        r"plan-[0-9a-f]{64}", value["plan_id"]
    ):
        return False
    if value.get("state") not in {
        "ready",
        "prepared",
        "blocked",
        "rolled_back",
        "recovery_required",
    }:
        return False
    if not isinstance(value.get("phase"), str) or not _SAFE_CODE.fullmatch(value["phase"]):
        return False
    completed = value.get("completed_phases")
    if (
        not isinstance(completed, list)
        or any(
            not isinstance(item, str) or not _SAFE_CODE.fullmatch(item)
            for item in completed
        )
        or len(completed) != len(set(completed))
    ):
        return False
    answers = value.get("recorded_answers")
    if not isinstance(answers, Mapping) or not set(answers).issubset(
        {"connection_mode"}
    ):
        return False
    if answers.get("connection_mode") not in {
        None,
        "local_tailscale",
        "remote_vps",
        "local_lan",
    }:
        return False
    try:
        _validate_gate(value.get("active_gate"), operation_id, str(value.get("state")))
        _assert_json_safe(value)
        _assert_secret_free(value)
    except ValueError:
        return False
    return True


class PrivateStateDirectory:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    def ensure(self) -> Path:
        self.path.mkdir(parents=True, exist_ok=True)
        os.chmod(self.path, 0o700)
        return self.path

    def atomic_write_json(
        self,
        path: Path,
        value: Mapping[str, Any],
        *,
        validate_secret_free: bool = True,
    ) -> None:
        self.ensure()
        _assert_json_safe(value)
        if validate_secret_free:
            _assert_secret_free(value)
        descriptor, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=self.path)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(
                    value,
                    handle,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                )
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, path)
            directory = os.open(self.path, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            Path(temporary).unlink(missing_ok=True)


class OperationLock:
    def __init__(self, state_dir: Path) -> None:
        self.directory = PrivateStateDirectory(state_dir)
        self.path = Path(state_dir) / "operation.lock"
        self._handle: Any = None

    def acquire(self) -> "OperationLock":
        self.directory.ensure()
        handle = self.path.open("a+", encoding="utf-8")
        os.chmod(self.path, 0o600)
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            handle.close()
            raise OperationBusy("lifecycle_operation_busy") from exc
        self._handle = handle
        return self

    def release(self) -> None:
        if self._handle is not None:
            fcntl.flock(self._handle.fileno(), fcntl.LOCK_UN)
            self._handle.close()
            self._handle = None

    def __enter__(self) -> "OperationLock":
        return self.acquire()

    def __exit__(self, *_args: Any) -> None:
        self.release()


class CheckpointStore:
    def __init__(self, state_dir: Path) -> None:
        self.directory = PrivateStateDirectory(state_dir)

    def create(
        self,
        *,
        command: str,
        plan_id: str,
        phase: str = "unclassified",
        journey: Journey | str = Journey.UNCLASSIFIED,
        irreversible_boundary_crossed: bool | None = None,
        ambiguity_state: AmbiguityState | str = AmbiguityState.UNCLASSIFIED,
        recovery_policy: RecoveryPolicy | str = RecoveryPolicy.UNCLASSIFIED,
        effect_summary: EffectSummary | Mapping[str, Any] | None = None,
        next_actions: Iterable[NextAction | Mapping[str, Any]] = (),
        cancellation_available: bool | None = None,
        pairing_identity_policy: PairingIdentityPolicy | str = (
            PairingIdentityPolicy.UNCLASSIFIED
        ),
        prior_operation_terminal: bool | None = None,
    ) -> dict[str, Any]:
        if command not in COMMANDS:
            raise ValueError("unknown_lifecycle_command")
        checkpoint = {
            "checkpoint_schema": CHECKPOINT_SCHEMA,
            "operation_id": "op-" + secrets.token_hex(16),
            "command": command,
            "plan_id": plan_id,
            "phase": phase,
            "state": "prepared",
            "completed_phases": [],
            "recorded_answers": {},
            "active_gate": None,
            "journey": journey,
            "irreversible_boundary_crossed": irreversible_boundary_crossed,
            "ambiguity_state": ambiguity_state,
            "recovery_policy": recovery_policy,
            "effect_summary": effect_summary,
            "next_actions": next_actions,
            "cancellation_available": cancellation_available,
            "pairing_identity_policy": pairing_identity_policy,
            "prior_operation_terminal": prior_operation_terminal,
        }
        return self.record(checkpoint)

    def path_for(self, operation_id: str) -> Path:
        if not _OPERATION_ID.fullmatch(operation_id):
            raise ValueError("invalid_operation_id")
        return self.directory.path / f"{operation_id}.json"

    def record(self, checkpoint: Mapping[str, Any]) -> dict[str, Any]:
        """Strictly validate and atomically persist one schema-v2 checkpoint."""

        normalized = _validate_v2_checkpoint(checkpoint)
        self.directory.atomic_write_json(
            self.path_for(normalized["operation_id"]), normalized
        )
        return normalized

    def write(self, checkpoint: Mapping[str, Any]) -> None:
        """Compatibility wrapper for the pre-v2 internal writer API."""

        self.record(checkpoint)

    def read(self, operation_id: str) -> dict[str, Any]:
        value = _load_json_mapping(self.path_for(operation_id))
        if value.get("checkpoint_schema") != CHECKPOINT_SCHEMA:
            raise ValueError("invalid_checkpoint_schema")
        checkpoint = _validate_v2_checkpoint(value)
        if checkpoint["operation_id"] != operation_id:
            raise ValueError("invalid_checkpoint_identity")
        return checkpoint

    def update(self, operation_id: str, **changes: Any) -> dict[str, Any]:
        _assert_secret_free(changes, "checkpoint.update")
        illegal = set(changes) - _MUTABLE_CHECKPOINT_FIELDS
        if illegal:
            raise ValueError("immutable_or_unknown_checkpoint_field")
        checkpoint = self.read(operation_id)
        checkpoint.update(changes)
        return self.record(checkpoint)

    def inventory(self) -> tuple[list[dict[str, Any]], int]:
        """Return valid checkpoints plus the number of unreadable entries.

        A corrupt lifecycle record is itself pending operator attention.  The
        diagnostic path therefore stays available, but it must not silently
        turn an unreadable recovery operation into a healthy zero count.
        """

        if not self.directory.path.is_dir():
            return [], 0
        paths: list[tuple[int, str, Path]] = []
        invalid_count = 0
        for path in self.directory.path.glob("op-*.json"):
            if path.is_symlink() or not path.is_file():
                invalid_count += 1
                continue
            try:
                modified = path.stat().st_mtime_ns
            except OSError:
                invalid_count += 1
                continue
            paths.append((modified, path.name, path))
        checkpoints: list[dict[str, Any]] = []
        for _modified, _name, path in sorted(paths):
            try:
                raw = _load_json_mapping(path)
                schema = raw.get("checkpoint_schema")
                if schema == CHECKPOINT_SCHEMA:
                    checkpoints.append(self.read(path.stem))
                elif schema == CHECKPOINT_SCHEMA_V1 and _is_supported_v1_checkpoint(
                    raw, path.stem
                ):
                    # v1 remains immutable compatibility evidence.  It is not
                    # a current v2 checkpoint and is reconciled separately.
                    continue
                else:
                    invalid_count += 1
            except (OSError, ValueError, json.JSONDecodeError):
                invalid_count += 1
        return checkpoints, invalid_count

    def list_all(self) -> list[dict[str, Any]]:
        """Return valid checkpoints in filesystem creation/update order."""

        checkpoints, _invalid_count = self.inventory()
        return checkpoints
