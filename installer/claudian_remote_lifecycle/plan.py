"""Canonical, mutation-free lifecycle planning and drift validation."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Mapping

from .inspect import SUPPORTED_CLAUDIAN_VERSION, SUPPORTED_CLAUDIAN_VERSIONS, content_id, validate_snapshot
from .model import PLAN_SCHEMA, SNAPSHOT_SCHEMA


SUPPORTED_MODES = frozenset({"local_tailscale"})
PLANNABLE_JOURNEYS = frozenset({"fresh_install", "current_update", "legacy_upgrade"})
PAIRING_IDENTITY_POLICIES = frozenset({"preserve", "rotate"})


class PlanError(ValueError):
    pass


class EnvironmentDrift(PlanError):
    pass


def _vault_ids(snapshot: Mapping[str, Any]) -> set[str]:
    return {str(item.get("vault_id")) for item in snapshot.get("vaults", []) if item.get("vault_id")}


def _journey_context(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    value = snapshot.get("journey")
    if not isinstance(value, Mapping):
        raise PlanError("journey_classification_required")
    journey = str(value.get("journey") or "unclassified")
    prior_terminal = value.get("prior_operation_terminal")
    if prior_terminal is not True:
        existing = value.get("existing_operation")
        if isinstance(existing, Mapping) and not existing.get("terminal", False):
            raise PlanError("operation_reconciliation_required")
        raise PlanError("prior_operation_not_terminal")
    if journey == "coexistence_conflict":
        raise PlanError("coexistence_conflict")
    if journey not in PLANNABLE_JOURNEYS:
        raise PlanError("unclassified_journey")
    return {
        "journey": journey,
        "reason_code": str(value.get("reason_code") or ""),
        "prior_operation_terminal": True,
    }


def _authority_context(snapshot: Mapping[str, Any], journey: str) -> dict[str, str]:
    if journey != "legacy_upgrade":
        return {"adapter": "not_applicable", "capability": "not_applicable"}
    installation = snapshot.get("installation")
    decision = snapshot.get("journey")
    if not isinstance(installation, Mapping) or not isinstance(decision, Mapping):
        raise PlanError("invalid_legacy_authority_context")
    adapter = str(
        decision.get("legacy_authority_adapter")
        or installation.get("legacy_authority_adapter")
        or "unclassified"
    )
    capability = str(decision.get("legacy_authority_capability") or "unknown")
    if (
        not adapter
        or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789_-" for character in adapter)
    ):
        raise PlanError("invalid_legacy_authority_adapter")
    if capability not in {"available", "unavailable", "unknown"}:
        raise PlanError("invalid_legacy_authority_capability")
    return {"adapter": adapter, "capability": capability}


def _affected_resources(journey: str) -> list[str]:
    resources = [
        "device_local_state",
        "mac_companion",
        "obsidian_plugin:claudian-remote",
        "pairing_identity",
        "relay_runtime",
    ]
    if journey == "legacy_upgrade":
        resources.extend(
            (
                "legacy_credential_authority",
                "obsidian_plugin:whale-agent-bridge",
            )
        )
    return resources


def _irreversible_boundary(journey: str) -> dict[str, Any]:
    if journey == "legacy_upgrade":
        return {
            "boundary_id": "legacy_credential_retirement_proof",
            "crossed": False,
            "phase": "retirement_reconciliation",
        }
    return {
        "boundary_id": "local_activation_commit",
        "crossed": False,
        "phase": "activation",
    }


def _recommended_action(blockers: list[str], journey: str) -> dict[str, Any]:
    if blockers:
        return {
            "action_id": "resolve_plan_blocker",
            "action_type": "manual_instruction",
            "owner": "human",
            "recommended": True,
            "executable": True,
            "parameters": {"reason_codes": list(blockers)},
        }
    command = "update" if journey == "current_update" else "install"
    return {
        "action_id": f"execute_{command}_plan",
        "action_type": "lifecycle_command",
        "owner": "agent",
        "recommended": True,
        "executable": True,
        "command": command,
        "parameters": {},
    }


@dataclass(frozen=True)
class PlanBuilder:
    compatibility_set_id: str = "claudian-remote-0.2.0-beta.5"
    current_update_pairing_identity_policy: str = "preserve"

    def build(
        self,
        snapshot: Mapping[str, Any],
        *,
        mode: str,
        vault_id: str | None = None,
        endpoint_audience: str | None = None,
    ) -> dict[str, Any]:
        try:
            validate_snapshot(snapshot)
        except ValueError as exc:
            raise PlanError(str(exc)) from exc
        if mode not in SUPPORTED_MODES:
            raise PlanError("unsupported_connection_mode")
        journey_context = _journey_context(snapshot)
        journey = str(journey_context["journey"])
        if self.current_update_pairing_identity_policy not in PAIRING_IDENTITY_POLICIES:
            raise PlanError("invalid_current_update_pairing_identity_policy")
        pairing_identity_policy = (
            self.current_update_pairing_identity_policy
            if journey == "current_update"
            else "not_applicable"
        )
        legacy_authority = _authority_context(snapshot, journey)

        vaults = _vault_ids(snapshot)
        if vault_id is None and len(vaults) == 1:
            vault_id = next(iter(vaults))
        if vault_id not in vaults:
            raise PlanError("vault_selection_required" if vaults else "vault_not_found")

        support_reasons = tuple(snapshot.get("support", {}).get("reason_codes", ()))
        hard_blockers = [
            reason
            for reason in support_reasons
            if reason not in {"vault_selection_required", "secure_provisioning_missing"}
        ]
        selected_vault = next(item for item in snapshot.get("vaults", []) if str(item.get("vault_id")) == vault_id)
        if "claudian_version" in selected_vault:
            hard_blockers = [reason for reason in hard_blockers if reason != "unsupported_claudian_version"]
            if selected_vault.get("claudian_version") not in SUPPORTED_CLAUDIAN_VERSIONS:
                hard_blockers.append("unsupported_claudian_version")
        if "claudian_enabled" in selected_vault:
            hard_blockers = [reason for reason in hard_blockers if reason != "claudian_not_enabled"]
            if not selected_vault.get("claudian_enabled"):
                hard_blockers.append("claudian_not_enabled")
        if journey == "legacy_upgrade":
            if legacy_authority["adapter"] == "unclassified":
                hard_blockers.append("legacy_authority_adapter_unclassified")
            if legacy_authority["capability"] == "unavailable":
                hard_blockers.append("legacy_credential_revocation_unavailable")
            elif legacy_authority["capability"] == "unknown":
                hard_blockers.append("legacy_authority_capability_unknown")
        hard_blockers = sorted(set(hard_blockers))
        gates = self._gates(snapshot, journey, pairing_identity_policy, legacy_authority)
        topology = {
            "mode": mode,
            "relay_location": "mac_loopback",
            "exposure": "tailscale_serve",
            "silent_fallback": False,
        }
        installation_seed = "|".join(
            (
                str(snapshot.get("macos", {}).get("platform") or ""),
                str(snapshot.get("macos", {}).get("architecture") or ""),
                str(vault_id),
            )
        )
        installation_id = "installation-" + hashlib.sha256(installation_seed.encode()).hexdigest()[:24]
        target_compatibility_set = {
            "compatibility_set_id": self.compatibility_set_id,
            "final_topology": "local_tailscale",
            "required_claudian_version": SUPPORTED_CLAUDIAN_VERSION,
        }
        cancellation = {
            "available": True,
            "unavailable_after": (
                "retirement_dispatch" if journey == "legacy_upgrade" else "local_activation_commit"
            ),
            "scope": "operation_owned_staging_only",
        }
        recommended_next_action = _recommended_action(hard_blockers, journey)
        body = {
            "plan_schema": PLAN_SCHEMA,
            "inspection_snapshot_id": snapshot["snapshot_id"],
            "environment_fingerprint": snapshot["snapshot_id"],
            "compatibility_set_id": self.compatibility_set_id,
            "target_compatibility_set": target_compatibility_set,
            "vault_id": vault_id,
            "installation_id": installation_id,
            "endpoint_audience": endpoint_audience,
            "journey": journey,
            "journey_reason_code": journey_context["reason_code"],
            "prior_operation_terminal": True,
            "legacy_authority": legacy_authority,
            "topology": topology,
            "gates": gates,
            "human_gates": gates,
            "blockers": hard_blockers,
            "affected_resources": _affected_resources(journey),
            "irreversible_boundary": _irreversible_boundary(journey),
            "recovery_policy": "rollback_pre_boundary",
            "pairing_identity_policy": pairing_identity_policy,
            "cancellation": cancellation,
            "cancellation_available": True,
            "recommended_next_action": recommended_next_action,
            "next_actions": [recommended_next_action],
            "rollback_boundary": "previous_locally_coherent_compatibility_set",
            "mutation_performed": False,
        }
        body["plan_id"] = content_id("plan", body)
        return body

    @staticmethod
    def _gates(
        snapshot: Mapping[str, Any],
        journey: str,
        pairing_identity_policy: str,
        legacy_authority: Mapping[str, str],
    ) -> list[dict[str, str]]:
        gates: list[dict[str, str]] = []
        if not snapshot.get("installation", {}).get("secure_provisioning_available"):
            gates.append(
                {
                    "gate_type": "pairing_admin_bootstrap_required",
                    "probe": "companion_secure_provisioning_available",
                }
            )
        network = snapshot.get("network", {})
        if not network.get("tailscale_installed"):
            gates.append({"gate_type": "tailscale_install_required", "probe": "tailscale_installed"})
        elif not network.get("tailscale_logged_in"):
            gates.append({"gate_type": "tailscale_login_required", "probe": "tailscale_logged_in"})
        if journey == "legacy_upgrade":
            gates.append(
                {
                    "gate_type": "legacy_authority_authorization_required",
                    # This probe proves only that the authority can execute.
                    # Human approval is a separate operation-bound resume flag.
                    "probe": "legacy_authority_capability_available",
                }
            )
        if journey != "current_update" or pairing_identity_policy == "rotate":
            gates.append({"gate_type": "pairing_approval_required", "probe": "pairing_credential_active"})
        return gates


def _validate_plan_binding(plan: Mapping[str, Any], snapshot: Mapping[str, Any]) -> None:
    journey_context = _journey_context(snapshot)
    journey = str(journey_context["journey"])
    if plan.get("journey") != journey:
        raise PlanError("plan_journey_mismatch")
    if plan.get("journey_reason_code") != journey_context["reason_code"]:
        raise PlanError("plan_journey_mismatch")
    if plan.get("prior_operation_terminal") is not True:
        raise PlanError("prior_operation_not_terminal")
    if plan.get("legacy_authority") != _authority_context(snapshot, journey):
        raise PlanError("plan_authority_mismatch")

    compatibility_set_id = str(plan.get("compatibility_set_id") or "")
    expected_target = {
        "compatibility_set_id": compatibility_set_id,
        "final_topology": "local_tailscale",
        "required_claudian_version": SUPPORTED_CLAUDIAN_VERSION,
    }
    if plan.get("target_compatibility_set") != expected_target:
        raise PlanError("plan_target_compatibility_set_mismatch")
    if plan.get("topology") != {
        "mode": "local_tailscale",
        "relay_location": "mac_loopback",
        "exposure": "tailscale_serve",
        "silent_fallback": False,
    }:
        raise PlanError("invalid_plan_topology")

    pairing_policy = plan.get("pairing_identity_policy")
    if journey == "current_update":
        if pairing_policy not in PAIRING_IDENTITY_POLICIES:
            raise PlanError("current_update_pairing_identity_policy_required")
    elif pairing_policy != "not_applicable":
        raise PlanError("pairing_identity_policy_not_applicable")
    if plan.get("affected_resources") != _affected_resources(journey):
        raise PlanError("affected_resources_mismatch")
    if plan.get("irreversible_boundary") != _irreversible_boundary(journey):
        raise PlanError("irreversible_boundary_mismatch")
    if plan.get("recovery_policy") != "rollback_pre_boundary":
        raise PlanError("invalid_plan_recovery_policy")

    gates = plan.get("gates")
    if not isinstance(gates, list) or plan.get("human_gates") != gates:
        raise PlanError("human_gates_mismatch")
    expected_cancellation = {
        "available": True,
        "unavailable_after": (
            "retirement_dispatch" if journey == "legacy_upgrade" else "local_activation_commit"
        ),
        "scope": "operation_owned_staging_only",
    }
    if (
        plan.get("cancellation") != expected_cancellation
        or plan.get("cancellation_available") is not True
    ):
        raise PlanError("invalid_plan_cancellation_policy")

    actions = plan.get("next_actions")
    if not isinstance(actions, list):
        raise PlanError("invalid_plan_next_actions")
    recommended = [
        action
        for action in actions
        if isinstance(action, Mapping)
        and action.get("recommended") is True
        and action.get("executable") is True
    ]
    if len(recommended) != 1 or plan.get("recommended_next_action") != recommended[0]:
        raise PlanError("exactly_one_recommended_executable_action_required")
    blockers = plan.get("blockers")
    if not isinstance(blockers, list):
        raise PlanError("invalid_plan_blockers")
    if recommended[0] != _recommended_action(
        [str(item) for item in blockers], journey
    ):
        raise PlanError("recommended_next_action_mismatch")


def validate_plan_environment(plan: Mapping[str, Any], snapshot: Mapping[str, Any]) -> None:
    try:
        validate_snapshot(snapshot)
    except ValueError as exc:
        raise PlanError(str(exc)) from exc
    if plan.get("plan_schema") != PLAN_SCHEMA:
        raise PlanError("invalid_plan_schema")
    if plan.get("plan_id") != content_id("plan", {k: v for k, v in plan.items() if k != "plan_id"}):
        raise PlanError("plan_integrity_failed")
    if plan.get("environment_fingerprint") != snapshot.get("snapshot_id"):
        raise EnvironmentDrift("environment_drift")
    _validate_plan_binding(plan, snapshot)


def validate_mutation_environment(
    plan: Mapping[str, Any],
    planned_snapshot: Mapping[str, Any],
    current_snapshot: Mapping[str, Any],
    *,
    allow_plan_target: bool = False,
) -> None:
    """Reject material drift while allowing a declared human gate to resolve."""

    validate_plan_environment(plan, planned_snapshot)
    validate_snapshot(current_snapshot)
    selected = str(plan.get("vault_id") or "")
    planned_vault = next(
        (item for item in planned_snapshot.get("vaults", []) if str(item.get("vault_id")) == selected),
        None,
    )
    current_vault = next(
        (item for item in current_snapshot.get("vaults", []) if str(item.get("vault_id")) == selected),
        None,
    )
    if planned_vault is None or current_vault is None:
        raise EnvironmentDrift("environment_drift")
    try:
        planned_journey = _journey_context(planned_snapshot)
        current_journey = _journey_context(current_snapshot)
        planned_authority = _authority_context(
            planned_snapshot, str(planned_journey["journey"])
        )
        current_authority = _authority_context(
            current_snapshot, str(current_journey["journey"])
        )
    except PlanError as exc:
        raise EnvironmentDrift("environment_drift") from exc
    current_installation = current_snapshot.get("installation", {})
    own_fresh_activation = (
        allow_plan_target
        and planned_journey["journey"] == "fresh_install"
        and current_journey["journey"] == "current_update"
        and current_installation.get("installed") is True
        and current_installation.get("compatibility_set_id") == plan.get("compatibility_set_id")
        and current_installation.get("profile_mode") == plan.get("topology", {}).get("mode")
        and bool(current_installation.get("profile_generation_id"))
    )
    if (planned_journey != current_journey and not own_fresh_activation) or planned_authority != current_authority:
        raise EnvironmentDrift("environment_drift")
    stable_pairs = (
        (planned_snapshot.get("macos", {}).get("platform"), current_snapshot.get("macos", {}).get("platform")),
        (planned_snapshot.get("macos", {}).get("architecture"), current_snapshot.get("macos", {}).get("architecture")),
        (planned_snapshot.get("obsidian", {}).get("version"), current_snapshot.get("obsidian", {}).get("version")),
        (planned_vault.get("claudian_version"), current_vault.get("claudian_version")),
        (planned_vault.get("claudian_enabled"), current_vault.get("claudian_enabled")),
    )
    if any(left != right for left, right in stable_pairs):
        raise EnvironmentDrift("environment_drift")
    planned_installation = planned_snapshot.get("installation", {})
    current_installation = current_snapshot.get("installation", {})
    drifted_installation_fields: list[str] = []
    for field in ("compatibility_set_id", "profile_mode", "profile_generation_id"):
        planned_value = planned_installation.get(field)
        if planned_value is not None and planned_value != current_installation.get(field):
            drifted_installation_fields.append(field)
    if not drifted_installation_fields:
        return
    if allow_plan_target:
        target_mode = str(plan.get("topology", {}).get("mode") or "")
        if (
            current_installation.get("compatibility_set_id") == plan.get("compatibility_set_id")
            and current_installation.get("profile_mode") == target_mode
            and current_installation.get("profile_generation_id")
        ):
            # A resumed operation may have crossed its own activation
            # boundary. The transaction still verifies the exact profile,
            # endpoint, Serve mapping, and application health before commit.
            return
    raise EnvironmentDrift("environment_drift")


class PlanStore:
    """Private immutable plan/snapshot registry used by later CLI processes."""

    def __init__(self, state_dir: Path) -> None:
        self.directory = Path(state_dir) / "plans"

    def _path(self, plan_id: str) -> Path:
        if not str(plan_id).startswith("plan-") or len(str(plan_id)) != 69:
            raise ValueError("invalid_plan_id")
        return self.directory / f"{plan_id}.json"

    def write(self, plan: Mapping[str, Any], snapshot: Mapping[str, Any]) -> None:
        validate_plan_environment(plan, snapshot)
        self.directory.mkdir(parents=True, exist_ok=True)
        os.chmod(self.directory, 0o700)
        path = self._path(str(plan["plan_id"]))
        value = {"plan": dict(plan), "snapshot": dict(snapshot)}
        encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
        if path.exists():
            if path.read_text(encoding="utf-8") != encoded:
                raise ValueError("immutable_plan_collision")
            return
        descriptor, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=self.directory)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, path)
        finally:
            Path(temporary).unlink(missing_ok=True)

    def read(self, plan_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
        value = json.loads(self._path(plan_id).read_text(encoding="utf-8"))
        if not isinstance(value, Mapping):
            raise ValueError("invalid_saved_plan")
        plan = dict(value.get("plan") or {})
        snapshot = dict(value.get("snapshot") or {})
        validate_plan_environment(plan, snapshot)
        return plan, snapshot
