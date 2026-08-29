"""Versioned, machine-readable lifecycle command and result contracts."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Mapping, TypeVar


# New writers use v2.  The explicit v1 names are intentionally retained for the
# bounded compatibility decoder; callers must never infer a legacy schema by
# trimming or rewriting a current schema string.
RESULT_SCHEMA_V1 = "claudian-remote.lifecycle-result/v1"
SNAPSHOT_SCHEMA_V1 = "claudian-remote.inspection/v1"
PLAN_SCHEMA_V1 = "claudian-remote.plan/v1"
CHECKPOINT_SCHEMA_V1 = "claudian-remote.checkpoint/v1"

RESULT_SCHEMA = "claudian-remote.lifecycle-result/v2"
SNAPSHOT_SCHEMA = "claudian-remote.inspection/v2"
PLAN_SCHEMA = "claudian-remote.plan/v2"
CHECKPOINT_SCHEMA = "claudian-remote.checkpoint/v2"

COMMANDS = (
    "inspect",
    "plan",
    "status",
    "resume",
    "cancel",
    "install",
    "verify",
    "update",
    "rollback",
    "uninstall",
    "purge",
    "revoke-device",
    "diagnose",
    "export-diagnostics",
)

TERMINAL_STATES = frozenset(
    {"ready", "prepared", "blocked", "rolled_back", "recovery_required"}
)
RESULT_STATES = TERMINAL_STATES | {"running"}


class Journey(str, Enum):
    UNCLASSIFIED = "unclassified"
    NOT_APPLICABLE = "not_applicable"
    FRESH_INSTALL = "fresh_install"
    CURRENT_UPDATE = "current_update"
    LEGACY_UPGRADE = "legacy_upgrade"
    COEXISTENCE_CONFLICT = "coexistence_conflict"


class LifecyclePhase(str, Enum):
    UNCLASSIFIED = "unclassified"
    INSPECTION = "inspection"
    RECONCILIATION = "reconciliation"
    PLANNING = "planning"
    PREPARATION = "preparation"
    AUTHORIZATION = "authorization"
    RETIREMENT_STAGING = "retirement_staging"
    RETIREMENT_DISPATCH = "retirement_dispatch"
    RETIREMENT_RECONCILIATION = "retirement_reconciliation"
    ACTIVATION = "activation"
    PAIRING = "pairing"
    VERIFICATION = "verification"
    ROLLBACK = "rollback"
    UNINSTALL = "uninstall"
    DIAGNOSTICS = "diagnostics"
    COMPLETE = "complete"


class AmbiguityState(str, Enum):
    UNCLASSIFIED = "unclassified"
    NOT_APPLICABLE = "not_applicable"
    NOT_DISPATCHED = "not_dispatched"
    RETIREMENT_OUTCOME_UNKNOWN = "retirement_outcome_unknown"
    NOT_APPLIED = "not_applied"
    RETIRED = "retired"
    INCONCLUSIVE = "inconclusive"


class RecoveryPolicy(str, Enum):
    UNCLASSIFIED = "unclassified"
    NOT_APPLICABLE = "not_applicable"
    RETRY_SAME_OPERATION = "retry_same_operation"
    RECONCILE_SAME_OPERATION = "reconcile_same_operation"
    ROLLBACK_PRE_BOUNDARY = "rollback_pre_boundary"
    FINISH_FORWARD = "finish_forward"
    MANUAL_RECOVERY_REQUIRED = "manual_recovery_required"


class PairingIdentityPolicy(str, Enum):
    UNCLASSIFIED = "unclassified"
    NOT_APPLICABLE = "not_applicable"
    PRESERVE = "preserve"
    ROTATE = "rotate"


class EffectDisposition(str, Enum):
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"
    UNCHANGED = "unchanged"
    STAGED = "staged"
    CHANGED = "changed"
    RESTORED = "restored"
    REMOVED = "removed"


class CredentialEffect(str, Enum):
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"
    ACTIVE = "active"
    NOT_DISPATCHED = "not_dispatched"
    OUTCOME_UNKNOWN = "outcome_unknown"
    NOT_APPLIED = "not_applied"
    RETIRED = "retired"
    INCONCLUSIVE = "inconclusive"


class NextActionType(str, Enum):
    LIFECYCLE_COMMAND = "lifecycle_command"
    HUMAN_GATE = "human_gate"
    AGENT_NAVIGATION = "agent_navigation"
    MANUAL_INSTRUCTION = "manual_instruction"


class ActionOwner(str, Enum):
    AGENT = "agent"
    HUMAN = "human"
    MAINTAINER = "maintainer"


EnumType = TypeVar("EnumType", bound=Enum)


def _coerce_enum(value: Any, enum_type: type[EnumType], field_name: str) -> EnumType:
    try:
        return value if isinstance(value, enum_type) else enum_type(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f"unknown_{field_name}") from error


def _assert_agent_safe(value: Any, path: str = "result") -> None:
    forbidden = ("password", "secret", "private_key", "token", "claim")
    if isinstance(value, Mapping):
        for key, item in value.items():
            lowered = str(key).lower()
            if any(part in lowered for part in forbidden) and not lowered.endswith("_ref"):
                raise ValueError(f"agent_unsafe_result_field:{path}.{key}")
            _assert_agent_safe(item, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _assert_agent_safe(item, f"{path}[{index}]")


def _json_value(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    return value


@dataclass(frozen=True)
class EffectSummary:
    """Non-secret, bounded projection of effects owned by one operation."""

    local_effect: EffectDisposition | str = EffectDisposition.UNKNOWN
    remote_effect: EffectDisposition | str = EffectDisposition.UNKNOWN
    credential_effect: CredentialEffect | str = CredentialEffect.UNKNOWN
    mutation_performed: bool | None = None
    owned_resource_count: int = 0
    effect_codes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "local_effect",
            _coerce_enum(self.local_effect, EffectDisposition, "local_effect"),
        )
        object.__setattr__(
            self,
            "remote_effect",
            _coerce_enum(self.remote_effect, EffectDisposition, "remote_effect"),
        )
        object.__setattr__(
            self,
            "credential_effect",
            _coerce_enum(self.credential_effect, CredentialEffect, "credential_effect"),
        )
        if self.mutation_performed is not None and not isinstance(
            self.mutation_performed, bool
        ):
            raise ValueError("invalid_mutation_performed")
        if (
            isinstance(self.owned_resource_count, bool)
            or not isinstance(self.owned_resource_count, int)
            or self.owned_resource_count < 0
        ):
            raise ValueError("invalid_owned_resource_count")
        if isinstance(self.effect_codes, (str, bytes)):
            raise ValueError("invalid_effect_code")
        codes = tuple(self.effect_codes)
        if any(not isinstance(code, str) or not code for code in codes):
            raise ValueError("invalid_effect_code")
        if len(codes) != len(set(codes)):
            raise ValueError("duplicate_effect_code")
        object.__setattr__(self, "effect_codes", codes)


@dataclass(frozen=True)
class NextAction:
    """A machine-selectable action; prose is never the mutation selector."""

    action_id: str
    action_type: NextActionType | str
    owner: ActionOwner | str
    recommended: bool
    executable: bool
    command: str | None = None
    parameters: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.action_id, str) or not self.action_id:
            raise ValueError("invalid_next_action_id")
        object.__setattr__(
            self,
            "action_type",
            _coerce_enum(self.action_type, NextActionType, "next_action_type"),
        )
        object.__setattr__(
            self,
            "owner",
            _coerce_enum(self.owner, ActionOwner, "next_action_owner"),
        )
        if not isinstance(self.recommended, bool) or not isinstance(
            self.executable, bool
        ):
            raise ValueError("invalid_next_action_flags")
        if self.recommended and not self.executable:
            raise ValueError("recommended_action_must_be_executable")
        if self.action_type is NextActionType.LIFECYCLE_COMMAND:
            if self.command not in COMMANDS:
                raise ValueError("unknown_next_action_command")
        elif self.command is not None:
            raise ValueError("non_command_action_must_not_set_command")
        if not isinstance(self.parameters, Mapping):
            raise ValueError("invalid_next_action_parameters")


@dataclass(frozen=True)
class LifecycleResult:
    """The only shape emitted on lifecycle stdout.

    ``message`` must be safe to show to an installation Agent. Secrets and raw
    paths belong in secure OS-owned channels, never in this object.

    During the U2 migration, legacy call sites receive explicit ``unclassified``
    values rather than a guessed safety decision. New control paths must call
    :meth:`validate_strict` (or :func:`validate_strict_result`) before emitting.
    """

    command: str
    state: str
    code: str
    message: str
    data: Mapping[str, Any] = field(default_factory=dict)
    plan_id: str | None = None
    operation_id: str | None = None
    gate: Mapping[str, Any] | None = None
    journey: Journey | str = Journey.UNCLASSIFIED
    phase: LifecyclePhase | str = LifecyclePhase.UNCLASSIFIED
    irreversible_boundary_crossed: bool | None = None
    ambiguity_state: AmbiguityState | str = AmbiguityState.UNCLASSIFIED
    recovery_policy: RecoveryPolicy | str = RecoveryPolicy.UNCLASSIFIED
    effect_summary: EffectSummary = field(default_factory=EffectSummary)
    next_actions: tuple[NextAction, ...] = ()
    cancellation_available: bool | None = None
    pairing_identity_policy: PairingIdentityPolicy | str = (
        PairingIdentityPolicy.UNCLASSIFIED
    )
    result_schema: str = RESULT_SCHEMA

    def __post_init__(self) -> None:
        if self.command not in COMMANDS:
            raise ValueError("unknown_lifecycle_command")
        if self.state not in RESULT_STATES:
            raise ValueError("unknown_lifecycle_state")
        if not self.code or not self.message:
            raise ValueError("incomplete_lifecycle_result")
        if self.state == "blocked" and self.code == "ok":
            raise ValueError("blocked_result_requires_reason")
        if self.result_schema != RESULT_SCHEMA:
            raise ValueError("lifecycle_result_writer_requires_v2")

        object.__setattr__(
            self, "journey", _coerce_enum(self.journey, Journey, "journey")
        )
        object.__setattr__(
            self, "phase", _coerce_enum(self.phase, LifecyclePhase, "phase")
        )
        object.__setattr__(
            self,
            "ambiguity_state",
            _coerce_enum(self.ambiguity_state, AmbiguityState, "ambiguity_state"),
        )
        object.__setattr__(
            self,
            "recovery_policy",
            _coerce_enum(self.recovery_policy, RecoveryPolicy, "recovery_policy"),
        )
        object.__setattr__(
            self,
            "pairing_identity_policy",
            _coerce_enum(
                self.pairing_identity_policy,
                PairingIdentityPolicy,
                "pairing_identity_policy",
            ),
        )
        if self.irreversible_boundary_crossed is not None and not isinstance(
            self.irreversible_boundary_crossed, bool
        ):
            raise ValueError("invalid_irreversible_boundary_crossed")
        if self.cancellation_available is not None and not isinstance(
            self.cancellation_available, bool
        ):
            raise ValueError("invalid_cancellation_available")
        if not isinstance(self.effect_summary, EffectSummary):
            raise ValueError("effect_summary_must_be_typed")
        actions = tuple(self.next_actions)
        if any(not isinstance(action, NextAction) for action in actions):
            raise ValueError("next_actions_must_be_typed")
        object.__setattr__(self, "next_actions", actions)

    def validate_strict(self) -> LifecycleResult:
        """Validate the schema-driven control invariants for a v2 code path."""

        if self.journey is Journey.UNCLASSIFIED:
            raise ValueError("classified_journey_required")
        if self.phase is LifecyclePhase.UNCLASSIFIED:
            raise ValueError("classified_phase_required")
        if self.ambiguity_state is AmbiguityState.UNCLASSIFIED:
            raise ValueError("classified_ambiguity_state_required")
        if self.recovery_policy is RecoveryPolicy.UNCLASSIFIED:
            raise ValueError("classified_recovery_policy_required")
        if self.pairing_identity_policy is PairingIdentityPolicy.UNCLASSIFIED:
            raise ValueError("classified_pairing_identity_policy_required")
        if not isinstance(self.irreversible_boundary_crossed, bool):
            raise ValueError("known_irreversible_boundary_state_required")
        if not isinstance(self.cancellation_available, bool):
            raise ValueError("known_cancellation_availability_required")

        recommended = tuple(
            action
            for action in self.next_actions
            if action.recommended and action.executable
        )
        actionable_recovery_policies = {
            RecoveryPolicy.RETRY_SAME_OPERATION,
            RecoveryPolicy.RECONCILE_SAME_OPERATION,
            RecoveryPolicy.ROLLBACK_PRE_BOUNDARY,
            RecoveryPolicy.FINISH_FORWARD,
            RecoveryPolicy.MANUAL_RECOVERY_REQUIRED,
        }
        if (
            self.state not in TERMINAL_STATES
            or self.recovery_policy in actionable_recovery_policies
        ) and len(recommended) != 1:
            raise ValueError("exactly_one_recommended_executable_action_required")

        dispatched_states = {
            AmbiguityState.RETIREMENT_OUTCOME_UNKNOWN,
            AmbiguityState.NOT_APPLIED,
            AmbiguityState.RETIRED,
            AmbiguityState.INCONCLUSIVE,
        }
        if self.ambiguity_state in dispatched_states and self.cancellation_available:
            raise ValueError("cancellation_unavailable_after_dispatch")
        cancel_actions = tuple(
            action
            for action in self.next_actions
            if action.action_type is NextActionType.LIFECYCLE_COMMAND
            and action.command == "cancel"
            and action.executable
        )
        if self.cancellation_available:
            if (
                len(cancel_actions) != 1
                or cancel_actions[0].recommended
                or cancel_actions[0].parameters
                != {"operation_id_ref": "result.operation_id"}
            ):
                raise ValueError("available_cancellation_requires_one_cancel_action")
        elif cancel_actions:
            raise ValueError("cancel_action_forbidden_when_unavailable")
        if (
            self.irreversible_boundary_crossed
            and self.recovery_policy is RecoveryPolicy.ROLLBACK_PRE_BOUNDARY
        ):
            raise ValueError("rollback_forbidden_after_irreversible_boundary")
        if (
            self.recovery_policy is RecoveryPolicy.FINISH_FORWARD
            and not self.irreversible_boundary_crossed
        ):
            raise ValueError("finish_forward_requires_irreversible_boundary")

        if self.journey is Journey.CURRENT_UPDATE:
            allowed_pairing = (
                {PairingIdentityPolicy.NOT_APPLICABLE}
                if self.phase is LifecyclePhase.INSPECTION
                else {
                    PairingIdentityPolicy.PRESERVE,
                    PairingIdentityPolicy.ROTATE,
                }
            )
            if self.pairing_identity_policy not in allowed_pairing:
                raise ValueError("current_update_pairing_policy_required")
        elif self.pairing_identity_policy is not PairingIdentityPolicy.NOT_APPLICABLE:
            raise ValueError("pairing_policy_only_applies_to_current_update")

        if self.journey in {Journey.FRESH_INSTALL, Journey.CURRENT_UPDATE}:
            if self.ambiguity_state is not AmbiguityState.NOT_APPLICABLE:
                raise ValueError("retirement_ambiguity_not_applicable_for_journey")

        expected_credential_effect = {
            AmbiguityState.NOT_DISPATCHED: CredentialEffect.NOT_DISPATCHED,
            AmbiguityState.RETIREMENT_OUTCOME_UNKNOWN: CredentialEffect.OUTCOME_UNKNOWN,
            AmbiguityState.NOT_APPLIED: CredentialEffect.NOT_APPLIED,
            AmbiguityState.RETIRED: CredentialEffect.RETIRED,
            AmbiguityState.INCONCLUSIVE: CredentialEffect.INCONCLUSIVE,
        }.get(self.ambiguity_state)
        if (
            expected_credential_effect is not None
            and self.effect_summary.credential_effect is not expected_credential_effect
        ):
            raise ValueError("ambiguity_and_credential_effect_mismatch")
        if self.ambiguity_state is AmbiguityState.RETIRED:
            if not self.irreversible_boundary_crossed:
                raise ValueError("retired_state_requires_irreversible_boundary")
        elif self.irreversible_boundary_crossed and self.journey is Journey.LEGACY_UPGRADE:
            raise ValueError("legacy_boundary_requires_retired_state")

        return self

    def to_dict(self) -> dict[str, Any]:
        value = _json_value(asdict(self))
        value = {key: item for key, item in value.items() if item is not None}
        # Stable v2 control fields remain present even when their safe migration
        # projection is null.  Only legacy optional envelope fields are omitted.
        value["irreversible_boundary_crossed"] = self.irreversible_boundary_crossed
        value["cancellation_available"] = self.cancellation_available
        _assert_agent_safe(value)
        return value


def validate_strict_result(result: LifecycleResult) -> LifecycleResult:
    """Validate and return ``result`` for explicit writer pipelines."""

    if not isinstance(result, LifecycleResult):
        raise TypeError("lifecycle_result_required")
    return result.validate_strict()


def normalize_strict_result(result: LifecycleResult) -> dict[str, Any]:
    """Validate and normalize one lifecycle result for external v2 output.

    ``LifecycleResult.to_dict`` intentionally remains available as a migration
    projection for legacy call sites.  External stdout writers must use this
    function instead: it rejects unclassified or null schema-v2 control state
    and removes inapplicable nullable action members.  Evidence may still carry
    an explicit unknown value (for example ``mutation_performed=None``) because
    uncertainty about an effect is data, not an executable control decision.
    """

    value = validate_strict_result(result).to_dict()
    enum_control_fields = (
        "journey",
        "phase",
        "ambiguity_state",
        "recovery_policy",
        "pairing_identity_policy",
    )
    for field_name in enum_control_fields:
        if value.get(field_name) in {None, "unclassified"}:
            raise ValueError(f"unclassified_result_control_field:{field_name}")

    for field_name in (
        "irreversible_boundary_crossed",
        "effect_summary",
        "next_actions",
        "cancellation_available",
    ):
        if value.get(field_name) is None:
            raise ValueError(f"null_result_control_field:{field_name}")

    for action in value["next_actions"]:
        if action.get("command") is None:
            action.pop("command", None)

    _assert_agent_safe(value)
    return value


def blocked_not_implemented(command: str, *, plan_id: str | None = None) -> LifecycleResult:
    """Fail closed for a declared command whose mutator has not shipped yet."""

    return LifecycleResult(
        command=command,
        state="blocked",
        code="operation_not_implemented",
        message=(
            f"{command} is present in this lifecycle contract but is not available "
            "in this build; no system state was changed."
        ),
        plan_id=plan_id,
        journey=Journey.NOT_APPLICABLE,
        phase=LifecyclePhase.PREPARATION,
        irreversible_boundary_crossed=False,
        ambiguity_state=AmbiguityState.NOT_APPLICABLE,
        recovery_policy=RecoveryPolicy.NOT_APPLICABLE,
        effect_summary=EffectSummary(
            local_effect=EffectDisposition.UNCHANGED,
            remote_effect=EffectDisposition.NOT_APPLICABLE,
            credential_effect=CredentialEffect.NOT_APPLICABLE,
            mutation_performed=False,
            owned_resource_count=0,
            effect_codes=("operation_not_implemented",),
        ),
        next_actions=(),
        cancellation_available=False,
        pairing_identity_policy=PairingIdentityPolicy.NOT_APPLICABLE,
        data={
            "mutation_performed": False,
            "recovery_action": "install_a_newer_verified_release",
        },
    )
