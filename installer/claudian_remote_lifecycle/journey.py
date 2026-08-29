"""Secret-free journey classification after lifecycle-operation arbitration."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Mapping


JOURNEYS = frozenset(
    {
        "fresh_install",
        "current_update",
        "legacy_upgrade",
        "coexistence_conflict",
        "unclassified",
    }
)
AUTHORITY_CAPABILITIES = frozenset({"available", "unavailable", "unknown", "not_applicable"})


@dataclass(frozen=True)
class JourneyDecision:
    journey: str
    reason_code: str
    blocked: bool
    re_pair_required: bool | None
    legacy_authority_capability: str
    prior_operation_terminal: bool
    existing_operation: Mapping[str, Any] | None = None

    def __post_init__(self) -> None:
        if self.journey not in JOURNEYS:
            raise ValueError("unknown_journey")
        if self.legacy_authority_capability not in AUTHORITY_CAPABILITIES:
            raise ValueError("unknown_authority_capability")
        if not self.reason_code:
            raise ValueError("journey_reason_required")

    def to_dict(self) -> dict[str, Any]:
        return {key: value for key, value in asdict(self).items() if value is not None}


def _plugin(value: Any) -> dict[str, bool]:
    if not isinstance(value, Mapping):
        raise ValueError("invalid_plugin_observation")
    required = {"present", "enabled", "recognized"}
    if set(value) != required or any(not isinstance(value[key], bool) for key in required):
        raise ValueError("invalid_plugin_observation")
    if value["enabled"] and not value["present"]:
        raise ValueError("invalid_plugin_observation")
    return {key: bool(value[key]) for key in required}


def _existing_operation(value: Mapping[str, Any] | None) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise ValueError("invalid_existing_operation")
    allowed = {"operation_id", "terminal", "recommended_action"}
    if set(value) != allowed:
        raise ValueError("invalid_existing_operation")
    operation_id = str(value.get("operation_id") or "")
    if not operation_id.startswith("op-") or not isinstance(value.get("terminal"), bool):
        raise ValueError("invalid_existing_operation")
    action = value.get("recommended_action")
    if action is not None and action not in {
        "rollback",
        "resume",
        "finish_forward",
        "reconcile_retirement_outcome",
        "manual_recovery_required",
    }:
        raise ValueError("invalid_existing_operation")
    return {
        "operation_id": operation_id,
        "terminal": bool(value["terminal"]),
        "recommended_action": action,
    }


def classify_journey(
    observation: Mapping[str, Any],
    *,
    prior_operation: Mapping[str, Any] | None = None,
    prior_operation_terminal: bool | None = None,
) -> JourneyDecision:
    """Classify a supported entry state without reading credential material.

    The caller must arbitrate any previous operation first.  An unresolved
    operation deliberately yields ``unclassified`` so no new lifecycle
    operation can be created from an otherwise plausible plugin layout.
    """

    if not isinstance(observation, Mapping):
        raise ValueError("invalid_journey_observation")
    current = _plugin(observation.get("current"))
    legacy = _plugin(observation.get("legacy"))
    existing = _existing_operation(prior_operation)
    if prior_operation_terminal is not None and not isinstance(
        prior_operation_terminal, bool
    ):
        raise ValueError("invalid_prior_operation_terminal")
    terminal = (
        prior_operation_terminal
        if prior_operation_terminal is not None
        else existing is None or bool(existing["terminal"])
    )
    if existing is not None and existing["terminal"] is not terminal:
        raise ValueError("prior_operation_terminal_mismatch")
    if not terminal:
        return JourneyDecision(
            journey="unclassified",
            reason_code="operation_reconciliation_required",
            blocked=True,
            re_pair_required=None,
            legacy_authority_capability="not_applicable",
            prior_operation_terminal=False,
            existing_operation=existing,
        )

    if current["present"] and not current["recognized"]:
        return JourneyDecision(
            "coexistence_conflict",
            "unsupported_current_lineage",
            True,
            None,
            "not_applicable",
            True,
            existing,
        )
    if legacy["present"] and not legacy["recognized"]:
        return JourneyDecision(
            "coexistence_conflict",
            "unsupported_legacy_lineage",
            True,
            None,
            "not_applicable",
            True,
            existing,
        )
    if current["enabled"] and legacy["enabled"]:
        return JourneyDecision(
            "coexistence_conflict",
            "legacy_and_current_plugin_enabled",
            True,
            None,
            "not_applicable",
            True,
            existing,
        )
    if current["present"] and legacy["present"] and not (
        current["enabled"] or legacy["enabled"]
    ):
        return JourneyDecision(
            "coexistence_conflict",
            "plugin_lineage_ambiguous",
            True,
            None,
            "not_applicable",
            True,
            existing,
        )
    if current["enabled"] or (current["present"] and not legacy["enabled"]):
        return JourneyDecision(
            "current_update",
            "recognized_current_installation",
            False,
            None,
            "not_applicable",
            True,
            existing,
        )
    if legacy["enabled"] or legacy["present"]:
        capability = str(observation.get("legacy_authority_capability") or "unknown")
        if capability not in AUTHORITY_CAPABILITIES - {"not_applicable"}:
            raise ValueError("unknown_authority_capability")
        return JourneyDecision(
            "legacy_upgrade",
            "recognized_legacy_installation",
            False,
            True,
            capability,
            True,
            existing,
        )
    return JourneyDecision(
        "fresh_install",
        "clean_installation",
        False,
        True,
        "not_applicable",
        True,
        existing,
    )
