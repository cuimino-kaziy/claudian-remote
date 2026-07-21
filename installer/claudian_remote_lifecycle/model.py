"""Versioned, machine-readable lifecycle command and result contracts."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Mapping


RESULT_SCHEMA = "claudian-remote.lifecycle-result/v1"
SNAPSHOT_SCHEMA = "claudian-remote.inspection/v1"
PLAN_SCHEMA = "claudian-remote.plan/v1"
CHECKPOINT_SCHEMA = "claudian-remote.checkpoint/v1"

COMMANDS = (
    "inspect",
    "plan",
    "status",
    "resume",
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


@dataclass(frozen=True)
class LifecycleResult:
    """The only shape emitted on lifecycle stdout.

    ``message`` must be safe to show to an installation Agent. Secrets and raw
    paths belong in secure OS-owned channels, never in this object.
    """

    command: str
    state: str
    code: str
    message: str
    data: Mapping[str, Any] = field(default_factory=dict)
    plan_id: str | None = None
    operation_id: str | None = None
    gate: Mapping[str, Any] | None = None
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

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value = {key: item for key, item in value.items() if item is not None}
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
        data={"mutation_performed": False, "recovery_action": "install_a_newer_verified_release"},
    )
