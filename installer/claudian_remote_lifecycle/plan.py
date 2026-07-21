"""Canonical, mutation-free lifecycle planning and drift validation."""

from __future__ import annotations

from dataclasses import dataclass
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
    compatibility_set_id: str = "claudian-remote-0.2.0-beta.1"

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
        body = {
            "plan_schema": PLAN_SCHEMA,
            "inspection_snapshot_id": snapshot["snapshot_id"],
            "environment_fingerprint": snapshot["snapshot_id"],
            "compatibility_set_id": self.compatibility_set_id,
            "vault_id": vault_id,
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
