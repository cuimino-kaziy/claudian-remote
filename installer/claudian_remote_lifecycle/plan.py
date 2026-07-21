"""Canonical, mutation-free lifecycle planning and drift validation."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Mapping

from .inspect import SUPPORTED_CLAUDIAN_VERSION, content_id, validate_snapshot
from .model import PLAN_SCHEMA, SNAPSHOT_SCHEMA


SUPPORTED_MODES = frozenset({"local_tailscale", "remote_vps", "local_lan"})


class PlanError(ValueError):
    pass


class EnvironmentDrift(PlanError):
    pass


def _vault_ids(snapshot: Mapping[str, Any]) -> set[str]:
    return {str(item.get("vault_id")) for item in snapshot.get("vaults", []) if item.get("vault_id")}


@dataclass(frozen=True)
class PlanBuilder:
    compatibility_set_id: str = "claudian-remote-0.2.0-beta.2"

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
            if selected_vault.get("claudian_version") != SUPPORTED_CLAUDIAN_VERSION:
                hard_blockers.append("unsupported_claudian_version")
        if "claudian_enabled" in selected_vault:
            hard_blockers = [reason for reason in hard_blockers if reason != "claudian_not_enabled"]
            if not selected_vault.get("claudian_enabled"):
                hard_blockers.append("claudian_not_enabled")
        if mode == "local_lan":
            # KTD8 keeps LAN unavailable until the real-device, network-change,
            # and packet-capture release evidence exists.  A consent prompt is
            # not a substitute for that evidence.
            hard_blockers.append("trusted_lan_not_release_eligible")
        gates = self._gates(snapshot, mode)
        topology = {
            "mode": mode,
            "relay_location": "vps" if mode == "remote_vps" else "mac_loopback",
            "exposure": {
                "local_tailscale": "tailscale_serve",
                "remote_vps": "user_owned_https_wss",
                "local_lan": "approved_tls_lan_gateway",
            }[mode],
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
        body = {
            "plan_schema": PLAN_SCHEMA,
            "inspection_snapshot_id": snapshot["snapshot_id"],
            "environment_fingerprint": snapshot["snapshot_id"],
            "compatibility_set_id": self.compatibility_set_id,
            "vault_id": vault_id,
            "installation_id": installation_id,
            "endpoint_audience": endpoint_audience,
            "topology": topology,
            "gates": gates,
            "blockers": sorted(set(hard_blockers)),
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
        body["plan_id"] = content_id("plan", body)
        return body

    @staticmethod
    def _gates(snapshot: Mapping[str, Any], mode: str) -> list[dict[str, str]]:
        gates: list[dict[str, str]] = []
        if not snapshot.get("installation", {}).get("secure_provisioning_available"):
            gates.append(
                {
                    "gate_type": "pairing_admin_bootstrap_required",
                    "probe": "companion_secure_provisioning_available",
                }
            )
        if mode == "local_tailscale":
            network = snapshot.get("network", {})
            if not network.get("tailscale_installed"):
                gates.append({"gate_type": "tailscale_install_required", "probe": "tailscale_installed"})
            elif not network.get("tailscale_logged_in"):
                gates.append({"gate_type": "tailscale_login_required", "probe": "tailscale_logged_in"})
        elif mode == "remote_vps":
            gates.append({"gate_type": "vps_host_authorization_required", "probe": "vps_host_key_confirmed"})
        else:
            gates.append({"gate_type": "trusted_lan_consent_required", "probe": "trusted_lan_consent_recorded"})
        gates.append({"gate_type": "pairing_approval_required", "probe": "pairing_credential_active"})
        return gates


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
