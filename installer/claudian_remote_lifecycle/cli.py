"""Structured command-line entry point for the Claudian Remote lifecycle."""

from __future__ import annotations

import argparse
from contextlib import nullcontext
import hashlib
import json
import re
import subprocess
import sys
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence, TextIO

from .checkpoint import CheckpointStore, OperationBusy, OperationLock
from .compatibility_decode import (
    ArtifactKind,
    CompatibilityDecodeError,
    load_supported_v1_checkpoint,
    load_supported_v1_saved_plan,
    mark_supported_v1_checkpoint_rolled_back,
)
from .credentials import CredentialRevocationService
from .diagnostics import DiagnosticService
from .human_gates import HumanGateController
from .inspect import Inspector, InspectionProbe, LocalInspectionProbe
from .legacy_authority import CapabilityAwareLegacyRetirementService
from .model import (
    COMMANDS,
    RESULT_SCHEMA,
    ActionOwner,
    AmbiguityState,
    CredentialEffect,
    EffectDisposition,
    EffectSummary,
    Journey,
    LifecyclePhase,
    LifecycleResult,
    NextAction,
    NextActionType,
    PairingIdentityPolicy,
    RecoveryPolicy,
    blocked_not_implemented,
    normalize_strict_result,
)
from .operation_arbitration import OperationArbitration, OperationArbitrator
from .launchd import LaunchAgentManager
from .keychain import MacOSKeychain
from .plan import PlanBuilder, PlanError, PlanStore, validate_mutation_environment
from .runtime import BootstrapVerifiedReleaseSource, RuntimeLayout, UnavailableReleaseSource
from .provisioning import SecureInputFile, verify_bridge_bootstrap_ack
from .tailscale import TailscaleController
from .transaction import LifecycleInterrupted, LocalTailscaleTransaction, TransactionDependencies
from .uninstall import OwnershipUninstaller


DEFAULT_STATE_DIR = (
    Path.home() / "Library" / "Application Support" / "Claudian Remote" / "lifecycle"
)


class LifecycleArgumentError(ValueError):
    pass


SAFE_MUTATION_ERROR_CODES = frozenset({
    "community_plugin_state_invalid",
    "environment_drift",
    "incomplete_install_plan",
    "invalid_plan_schema",
    "invalid_saved_plan",
    "legacy_and_current_plugin_enabled",
    "legacy_credential_revocation_unverified",
    "legacy_plugin_manifest_invalid",
    "legacy_plugin_migration_invalid",
    "legacy_plugin_quarantine_conflict",
    "legacy_plugin_state_invalid",
    "legacy_plugin_unsafe_path",
    "manifest_signature_unverified",
    "manifest_signing_key_invalid",
    "manifest_signing_key_untrusted",
    "plan_integrity_failed",
    "plugin_sync_preferences_invalid",
    "plugin_vault_binding_mismatch",
    "release_archive_path_escape",
    "release_archive_unsafe_member",
    "release_asset_descriptor_invalid",
    "release_asset_digest_mismatch",
    "release_asset_missing",
    "release_contract_mismatch",
    "release_plan_mismatch",
    "release_signature_verifier_unavailable",
    "release_trust_root_unavailable",
    "runtime_asset_descriptor_invalid",
    "runtime_asset_digest_mismatch",
    "runtime_asset_mismatch",
    "runtime_asset_redirect_untrusted",
    "runtime_asset_target_missing",
    "runtime_asset_url_untrusted",
    "runtime_dependency_lock_missing",
    "runtime_environment_install_failed",
    "runtime_environment_mismatch",
    "runtime_environment_missing",
    "runtime_environment_python_missing",
    "runtime_executable_missing",
    "vault_path_must_be_absolute",
    "verified_release_unavailable",
})


def _stable_mutation_error(error: BaseException) -> str:
    candidate = str(error)
    return candidate if candidate in SAFE_MUTATION_ERROR_CODES else "operation_failed"


def _completed_phases(services: "LifecycleServices", operation_id: str) -> list[str]:
    transaction = services.transaction
    if transaction is None:
        return []
    return transaction.completed_phases(operation_id)


class LifecycleArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise LifecycleArgumentError("invalid_lifecycle_arguments")


@dataclass
class LifecycleServices:
    inspection_probe: InspectionProbe
    gate_probes: Mapping[str, Any]
    transaction: LocalTailscaleTransaction | None = None
    layout: RuntimeLayout | None = None
    diagnostics: DiagnosticService | None = None
    uninstaller: OwnershipUninstaller | None = None
    revoke_device: Any | None = None

    @classmethod
    def local(cls, *, state_dir: Path, release_dir: Path | None = None) -> "LifecycleServices":
        requested_state = Path(state_dir).expanduser().resolve()
        supported_state = DEFAULT_STATE_DIR.expanduser().resolve()
        if requested_state != supported_state:
            # Runtime ownership is rooted at the fixed per-user Application
            # Support directory.  Accepting an arbitrary checkpoint directory
            # and then deriving `layout.base` from its parent could make purge
            # target an unrelated directory such as /tmp.
            raise LifecycleArgumentError("state_directory_not_supported")
        probe = LocalInspectionProbe()
        layout = RuntimeLayout(
            supported_state.parent,
            Path.home() / "Library" / "LaunchAgents",
        )
        keychain = MacOSKeychain()

        def relay_request(
            path: str,
            *,
            method: str = "GET",
            body: Mapping[str, Any] | None = None,
        ) -> dict[str, Any]:
            config = json.loads(layout.companion_config.read_text(encoding="utf-8"))
            reference = str(config.get("pairing_admin_credential_ref") or "")
            authorization = keychain.get(reference)
            endpoint = str(config.get("connection_profile_path") or "")
            profile = json.loads(Path(endpoint).read_text(encoding="utf-8"))
            payload = None if body is None else json.dumps(dict(body)).encode("utf-8")
            request = urllib.request.Request(
                str(profile["endpoint"]).rstrip("/") + path,
                data=payload,
                method=method,
                headers={
                    "Authorization": f"Bearer {authorization}",
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                value = json.loads(response.read().decode("utf-8"))
            return value if isinstance(value, dict) else {}

        def health(_endpoint: str | None = None) -> bool:
            try:
                relay_ready = relay_request("/health").get("ok") is True
                provisioning = probe.installation()
                return relay_ready and provisioning.get("secure_provisioning_available") is True
            except Exception:
                return False

        def active_pairing_device_ids() -> list[str]:
            try:
                devices = relay_request("/api/v2/pairing/devices").get("devices", [])
                if not isinstance(devices, list):
                    raise ValueError("pairing_device_inventory_invalid")
                result = [
                    str(item.get("device_id") or "")
                    for item in devices
                    if isinstance(item, dict)
                    and item.get("status") == "active"
                    and item.get("revoked") is not True
                ]
                if not all(re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", item) for item in result):
                    raise ValueError("pairing_device_inventory_invalid")
                return sorted(set(result))
            except Exception as exc:
                raise RuntimeError("pairing_device_inventory_unavailable") from exc

        def paired() -> bool:
            try:
                return bool(active_pairing_device_ids())
            except RuntimeError:
                return False

        def desktop_plugin_authenticated() -> bool:
            return verify_bridge_bootstrap_ack(layout)

        def revoke_device(device_id: str, *, reason: str = "revoked") -> dict[str, Any]:
            target = str(device_id or "")
            if not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", target):
                return {"state": "blocked", "code": "device_id_invalid", "mutation_performed": False}
            if reason not in {"revoked", "lost_device", "suspected_disclosure", "profile_changed", "legacy_migration"}:
                return {"state": "blocked", "code": "revocation_reason_invalid", "mutation_performed": False}
            try:
                relay_request(
                    f"/api/v2/pairing/devices/{urllib.parse.quote(target, safe='')}/revoke",
                    method="POST",
                    body={"reason": reason},
                )
            except Exception:
                return {"state": "blocked", "code": "device_revocation_failed", "mutation_performed": False}
            return {
                "state": "ready",
                "code": "device_revoked",
                "mutation_performed": True,
                "device_id": target,
            }

        launchd = LaunchAgentManager(layout)

        def stop_owned_services() -> None:
            launchd.remove_local_agents()
            tailscale.remove_serve()

        def credential_references() -> Mapping[str, Any]:
            try:
                value = json.loads(layout.companion_config.read_text(encoding="utf-8"))
            except (OSError, ValueError, TypeError) as exc:
                raise RuntimeError("credential_references_unavailable") from exc
            if not isinstance(value, Mapping):
                raise RuntimeError("credential_references_unavailable")
            return value

        revocation = CredentialRevocationService(
            list_devices=lambda: relay_request("/api/v2/pairing/devices"),
            revoke_device=revoke_device,
            credential_store=keychain,
            credential_references=credential_references,
        )

        def os_confirmation(message: str) -> bool:
            script = (
                f'display dialog {json.dumps(message)} buttons {{"Cancel", "Confirm"}} '
                'default button "Cancel" cancel button "Cancel" with icon caution'
            )
            try:
                result = subprocess.run(
                    ["/usr/bin/osascript", "-e", script],
                    text=True,
                    capture_output=True,
                    check=False,
                    timeout=120,
                )
            except (OSError, subprocess.TimeoutExpired):
                return False
            return result.returncode == 0 and "button returned:Confirm" in result.stdout

        tailscale = TailscaleController()
        release_source = (
            BootstrapVerifiedReleaseSource(release_dir)
            if release_dir is not None
            else UnavailableReleaseSource()
        )
        legacy_retirement = CapabilityAwareLegacyRetirementService(
            layout.state / "legacy-authority-profile.json",
            CheckpointStore(supported_state),
            lock_held_by_caller=True,
        )
        transaction = LocalTailscaleTransaction(TransactionDependencies(
            layout=layout,
            release_source=release_source,
            launchd=launchd,
            tailscale=tailscale,
            keychain=keychain,
            vault_path=probe.resolve_vault,
            health_probe=health,
            pairing_probe=paired,
            active_pairing_device_ids=active_pairing_device_ids,
            revoke_pairing_device=lambda device_id, reason: revoke_device(
                device_id, reason=reason
            ),
            bridge_ready_probe=desktop_plugin_authenticated,
            legacy_credential_revoker=legacy_retirement,
            migration_safe_probe=lambda: probe.obsidian().get("running") is not True,
        ))
        return cls(
            inspection_probe=probe,
            gate_probes={
                "tailscale_installed": tailscale.installed,
                "tailscale_logged_in": tailscale.logged_in,
                "tailscale_https_ready": tailscale.https_ready,
                "pairing_credential_active": paired,
                "desktop_plugin_authenticated": desktop_plugin_authenticated,
                "companion_secure_provisioning_available": lambda: probe.installation().get("secure_provisioning_available") is True,
                "obsidian_closed_for_migration": lambda: probe.obsidian().get("running") is not True,
                "legacy_authority_available": legacy_retirement.available,
                "legacy_authority_capability_available": legacy_retirement.available,
                "legacy_retirement_operator_confirmation": lambda: os_confirmation(
                    "Retire the legacy Claudian Remote mobile credential for this installation? The current iPhone must be paired again. This cannot be undone."
                ),
                "purge_confirmation_verified": lambda: os_confirmation(
                    "Permanently remove Claudian Remote credentials, cache, databases, logs, and backups? Vault notes and Claudian conversations are preserved."
                ),
                "diagnostic_export_confirmation_verified": lambda: os_confirmation(
                    "Export the previewed, redacted Claudian Remote diagnostic JSON to the selected local file? Nothing is uploaded."
                ),
            },
            transaction=transaction,
            layout=layout,
            diagnostics=DiagnosticService(),
            uninstaller=OwnershipUninstaller(
                layout,
                stop_owned_services=stop_owned_services,
                revoke_credentials=revocation.revoke_all,
            ),
            revoke_device=revoke_device,
        )


def build_parser() -> argparse.ArgumentParser:
    parser = LifecycleArgumentParser(prog="claudian-remote-lifecycle")
    parser.add_argument("--state-dir", type=Path, default=DEFAULT_STATE_DIR)
    parser.add_argument("--release-dir", type=Path)
    subcommands = parser.add_subparsers(dest="command", required=True)

    subcommands.add_parser("inspect")
    plan = subcommands.add_parser("plan")
    plan.add_argument("--snapshot", type=Path)
    plan.add_argument("--mode", choices=("local_tailscale", "remote_vps", "local_lan"), required=True)
    plan.add_argument("--vault-id")
    plan.add_argument("--endpoint-audience")

    status = subcommands.add_parser("status")
    status.add_argument("--operation-id", required=True)
    resume = subcommands.add_parser("resume")
    resume.add_argument("--operation-id", required=True)
    resume.add_argument(
        "--authorize-legacy-retirement",
        action="store_true",
        help=(
            "Request the operation-bound native macOS confirmation for "
            "retiring the legacy mobile credential. This flag does not "
            "itself grant approval."
        ),
    )
    cancel = subcommands.add_parser("cancel")
    cancel.add_argument("--operation-id", required=True)

    for name in ("install", "update", "uninstall", "purge"):
        command = subcommands.add_parser(name)
        command.add_argument("--plan-id", required=True)
    verify = subcommands.add_parser("verify")
    verify.add_argument("--plan-id")
    rollback = subcommands.add_parser("rollback")
    rollback.add_argument("--operation-id", required=True)
    revoke = subcommands.add_parser("revoke-device")
    revoke.add_argument("--device-id", required=True)
    subcommands.add_parser("diagnose")
    export = subcommands.add_parser("export-diagnostics")
    export.add_argument("--destination", type=Path, required=True)
    return parser


def _load_snapshot(path: Path | None, inspector: Inspector) -> dict[str, Any]:
    if path is None:
        return inspector.snapshot()
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise PlanError("invalid_inspection_snapshot")
    return value


def _resume_action() -> NextAction:
    return NextAction(
        action_id="resume-original-operation",
        action_type=NextActionType.LIFECYCLE_COMMAND,
        owner=ActionOwner.AGENT,
        recommended=True,
        executable=True,
        command="resume",
        parameters={"operation_id_ref": "result.operation_id"},
    )


def _cancel_action() -> NextAction:
    return NextAction(
        action_id="cancel-original-operation",
        action_type=NextActionType.LIFECYCLE_COMMAND,
        owner=ActionOwner.AGENT,
        recommended=False,
        executable=True,
        command="cancel",
        parameters={"operation_id_ref": "result.operation_id"},
    )


def _rollback_action() -> NextAction:
    return NextAction(
        action_id="rollback-original-operation",
        action_type=NextActionType.LIFECYCLE_COMMAND,
        owner=ActionOwner.AGENT,
        recommended=True,
        executable=True,
        command="rollback",
        parameters={"operation_id_ref": "result.operation_id"},
    )


def _manual_recovery_action() -> NextAction:
    return NextAction(
        action_id="contact-maintainer-with-diagnostics",
        action_type=NextActionType.MANUAL_INSTRUCTION,
        owner=ActionOwner.MAINTAINER,
        recommended=True,
        executable=True,
        parameters={"instruction_code": "manual_recovery_required"},
    )


def _checkpoint_effect(*, mutation_performed: bool = False) -> EffectSummary:
    return EffectSummary(
        local_effect=(
            EffectDisposition.STAGED
            if mutation_performed
            else EffectDisposition.UNCHANGED
        ),
        remote_effect=EffectDisposition.NOT_APPLICABLE,
        credential_effect=CredentialEffect.NOT_APPLICABLE,
        mutation_performed=mutation_performed,
        owned_resource_count=1 if mutation_performed else 0,
        effect_codes=("operation_staged",) if mutation_performed else (),
    )


def _checkpoint_controls(checkpoint: Mapping[str, Any]) -> dict[str, Any]:
    """Decode the complete typed control projection from a trusted v2 checkpoint."""

    raw_effect = checkpoint.get("effect_summary")
    effect = (
        raw_effect
        if isinstance(raw_effect, EffectSummary)
        else EffectSummary(**dict(raw_effect or {}))
    )
    actions = tuple(
        action
        if isinstance(action, NextAction)
        else NextAction(**dict(action))
        for action in checkpoint.get("next_actions", ())
    )
    return {
        "journey": checkpoint["journey"],
        "phase": checkpoint["phase"],
        "irreversible_boundary_crossed": checkpoint[
            "irreversible_boundary_crossed"
        ],
        "ambiguity_state": checkpoint["ambiguity_state"],
        "recovery_policy": checkpoint["recovery_policy"],
        "effect_summary": effect,
        "next_actions": actions,
        "cancellation_available": checkpoint["cancellation_available"],
        "pairing_identity_policy": checkpoint["pairing_identity_policy"],
    }


def _static_result(
    *,
    command: str,
    state: str,
    code: str,
    message: str,
    phase: LifecyclePhase,
    plan_id: str | None = None,
    operation_id: str | None = None,
    gate: Mapping[str, Any] | None = None,
    data: Mapping[str, Any] | None = None,
    effect_summary: EffectSummary | None = None,
) -> LifecycleResult:
    """Build a fully classified result for support/pre-operation outcomes."""

    mutation = bool((data or {}).get("mutation_performed", False))
    return LifecycleResult(
        command=command,
        state=state,
        code=code,
        message=message,
        plan_id=plan_id,
        operation_id=operation_id,
        gate=gate,
        journey=Journey.NOT_APPLICABLE,
        phase=phase,
        irreversible_boundary_crossed=False,
        ambiguity_state=AmbiguityState.NOT_APPLICABLE,
        recovery_policy=RecoveryPolicy.NOT_APPLICABLE,
        effect_summary=effect_summary
        or EffectSummary(
            local_effect=(
                EffectDisposition.CHANGED
                if mutation
                else EffectDisposition.UNCHANGED
            ),
            remote_effect=EffectDisposition.NOT_APPLICABLE,
            credential_effect=CredentialEffect.NOT_APPLICABLE,
            mutation_performed=mutation,
            owned_resource_count=1 if mutation else 0,
            effect_codes=(code,),
        ),
        next_actions=(),
        cancellation_available=False,
        pairing_identity_policy=PairingIdentityPolicy.NOT_APPLICABLE,
        data=dict(data or {}),
    )


def _arbitrated_snapshot(
    inspector: Inspector,
    state_dir: Path,
) -> tuple[dict[str, Any], OperationArbitration]:
    arbitration = OperationArbitrator(state_dir).inspect()
    return (
        inspector.snapshot(operation_arbitration=arbitration.to_summary()),
        arbitration,
    )


def _arbitration_result(
    command: str,
    arbitration: OperationArbitration,
    *,
    snapshot: Mapping[str, Any] | None = None,
) -> LifecycleResult:
    checkpoint = arbitration.checkpoint or {}
    action = arbitration.recommended_action
    next_action = {
        "resume": _resume_action,
        "rollback": _rollback_action,
        "finish_forward": _resume_action,
        "reconcile_retirement_outcome": lambda: NextAction(
            action_id="reconcile-original-operation",
            action_type=NextActionType.LIFECYCLE_COMMAND,
            owner=ActionOwner.AGENT,
            recommended=True,
            executable=True,
            command="resume",
            parameters={"operation_id_ref": "result.operation_id"},
        ),
        "manual_recovery_required": _manual_recovery_action,
    }.get(action or "")
    if checkpoint:
        journey = checkpoint["journey"]
        phase = checkpoint["phase"]
        boundary = checkpoint["irreversible_boundary_crossed"]
        ambiguity = checkpoint["ambiguity_state"]
        recovery = checkpoint["recovery_policy"]
        pairing = checkpoint["pairing_identity_policy"]
        effect_summary = EffectSummary(**dict(checkpoint["effect_summary"]))
        cancellation = checkpoint["cancellation_available"]
    elif arbitration.reconciliation is not None:
        journey = Journey.LEGACY_UPGRADE
        phase = LifecyclePhase.RECONCILIATION
        boundary = False
        legacy_effect = arbitration.reconciliation.legacy_credential_effect.value
        ambiguity = AmbiguityState(legacy_effect)
        recovery = {
            "rollback": RecoveryPolicy.ROLLBACK_PRE_BOUNDARY,
            "resume": RecoveryPolicy.RETRY_SAME_OPERATION,
            "finish_forward": RecoveryPolicy.FINISH_FORWARD,
            "reconcile_retirement_outcome": RecoveryPolicy.RECONCILE_SAME_OPERATION,
        }.get(action or "", RecoveryPolicy.MANUAL_RECOVERY_REQUIRED)
        pairing = PairingIdentityPolicy.NOT_APPLICABLE
        effect_summary = EffectSummary(
            local_effect=EffectDisposition.UNKNOWN,
            remote_effect=EffectDisposition.UNKNOWN,
            credential_effect=CredentialEffect(legacy_effect),
            mutation_performed=None,
            owned_resource_count=0,
            effect_codes=(arbitration.reason_code,),
        )
        cancellation = False
    else:
        journey = Journey.NOT_APPLICABLE
        phase = LifecyclePhase.RECONCILIATION
        boundary = True
        ambiguity = AmbiguityState.INCONCLUSIVE
        recovery = RecoveryPolicy.MANUAL_RECOVERY_REQUIRED
        pairing = PairingIdentityPolicy.NOT_APPLICABLE
        effect_summary = EffectSummary(
            local_effect=EffectDisposition.UNKNOWN,
            remote_effect=EffectDisposition.UNKNOWN,
            credential_effect=CredentialEffect.INCONCLUSIVE,
            mutation_performed=None,
            owned_resource_count=0,
            effect_codes=(arbitration.reason_code,),
        )
        cancellation = False
        next_action = _manual_recovery_action
    data: dict[str, Any] = {
        "mutation_performed": False,
        "operation_arbitration": arbitration.to_summary(),
    }
    if action is not None:
        data["recovery_action"] = action
    if snapshot is not None:
        data["snapshot"] = dict(snapshot)
    result_state = "blocked"
    if command in {"status", "resume", "rollback"}:
        candidate_state = checkpoint.get("state")
        if candidate_state is None and arbitration.reconciliation is not None:
            candidate_state = arbitration.reconciliation.checkpoint_state
        if candidate_state in {"prepared", "blocked", "recovery_required"}:
            result_state = str(candidate_state)
    return LifecycleResult(
        command=command,
        state=result_state,
        code=arbitration.reason_code,
        message=(
            "An earlier lifecycle operation must be reconciled before a new "
            "operation can start."
        ),
        operation_id=arbitration.operation_id,
        journey=journey,
        phase=phase,
        irreversible_boundary_crossed=boundary,
        ambiguity_state=ambiguity,
        recovery_policy=recovery,
        effect_summary=effect_summary,
        next_actions=(next_action(),) if next_action else (),
        cancellation_available=cancellation,
        pairing_identity_policy=pairing,
        data=data,
    )


def _v1_source_digest(
    arbitration: OperationArbitration,
    artifact: ArtifactKind,
) -> str:
    reconciliation = arbitration.reconciliation
    if reconciliation is None:
        raise CompatibilityDecodeError("v1_reconciliation_required")
    matches = [source.sha256 for source in reconciliation.sources if source.artifact is artifact]
    if len(matches) != 1:
        raise CompatibilityDecodeError("v1_companion_missing")
    return matches[0]


def _v1_terminal_result(
    command: str,
    checkpoint: Mapping[str, Any],
    *,
    code: str = "operation_status",
    mutation_performed: bool = False,
    known_staging_closure: bool = False,
) -> LifecycleResult:
    state = str(checkpoint["state"])
    return LifecycleResult(
        command=command,
        state=state,
        code=code,
        message="The supported Beta 4 operation is already terminal.",
        operation_id=str(checkpoint["operation_id"]),
        plan_id=str(checkpoint["plan_id"]),
        journey=Journey.LEGACY_UPGRADE,
        phase=(
            LifecyclePhase.ROLLBACK
            if state == "rolled_back"
            else LifecyclePhase.COMPLETE
        ),
        irreversible_boundary_crossed=False,
        ambiguity_state=(
            AmbiguityState.NOT_DISPATCHED
            if known_staging_closure
            else AmbiguityState.NOT_APPLICABLE
        ),
        recovery_policy=RecoveryPolicy.NOT_APPLICABLE,
        effect_summary=EffectSummary(
            local_effect=(
                EffectDisposition.RESTORED
                if known_staging_closure
                else EffectDisposition.UNKNOWN
            ),
            remote_effect=(
                EffectDisposition.UNCHANGED
                if known_staging_closure
                else EffectDisposition.UNKNOWN
            ),
            credential_effect=(
                CredentialEffect.NOT_DISPATCHED
                if known_staging_closure
                else CredentialEffect.UNKNOWN
            ),
            mutation_performed=mutation_performed,
            owned_resource_count=0,
            effect_codes=(
                ("v1_staging_only_rollback_verified",)
                if known_staging_closure
                else ("legacy_terminal_effect_not_reprobed",)
            ),
        ),
        next_actions=(),
        cancellation_available=False,
        pairing_identity_policy=PairingIdentityPolicy.NOT_APPLICABLE,
        data={
            "phase": checkpoint["phase"],
            "completed_phases": list(checkpoint["completed_phases"]),
            "mutation_performed": mutation_performed,
        },
    )


def _v1_recovery_probe_failed(
    command: str,
    *,
    operation_id: str,
    plan_id: str,
    code: str = "v1_recovery_effect_probe_failed",
) -> LifecycleResult:
    return LifecycleResult(
        command=command,
        state="recovery_required",
        code=code,
        message=(
            "The original Beta 4 operation remains locked because its live "
            "host effects could not be proven safe for automatic rollback."
        ),
        operation_id=operation_id,
        plan_id=plan_id,
        journey=Journey.LEGACY_UPGRADE,
        phase=LifecyclePhase.RECONCILIATION,
        irreversible_boundary_crossed=False,
        ambiguity_state=AmbiguityState.NOT_APPLIED,
        recovery_policy=RecoveryPolicy.MANUAL_RECOVERY_REQUIRED,
        effect_summary=EffectSummary(
            local_effect=EffectDisposition.UNKNOWN,
            remote_effect=EffectDisposition.UNKNOWN,
            credential_effect=CredentialEffect.NOT_APPLIED,
            mutation_performed=False,
            owned_resource_count=0,
            effect_codes=(code,),
        ),
        next_actions=(_manual_recovery_action(),),
        cancellation_available=False,
        pairing_identity_policy=PairingIdentityPolicy.NOT_APPLICABLE,
        data={"mutation_performed": False},
    )


def _create_plan_operation_checkpoint(
    checkpoints: CheckpointStore,
    *,
    command: str,
    plan: Mapping[str, Any],
    phase: LifecyclePhase,
) -> dict[str, Any]:
    journey = Journey(str(plan["journey"]))
    pairing = PairingIdentityPolicy(str(plan["pairing_identity_policy"]))
    return checkpoints.create(
        command=command,
        plan_id=str(plan["plan_id"]),
        phase=phase.value,
        journey=journey,
        irreversible_boundary_crossed=False,
        ambiguity_state=(
            AmbiguityState.NOT_DISPATCHED
            if journey is Journey.LEGACY_UPGRADE
            else AmbiguityState.NOT_APPLICABLE
        ),
        recovery_policy=RecoveryPolicy.RETRY_SAME_OPERATION,
        effect_summary=_checkpoint_effect(),
        next_actions=(_resume_action(), _cancel_action()),
        cancellation_available=True,
        pairing_identity_policy=pairing,
        prior_operation_terminal=True,
    )


def _create_support_operation_checkpoint(
    checkpoints: CheckpointStore,
    *,
    command: str,
    phase: LifecyclePhase,
) -> dict[str, Any]:
    return checkpoints.create(
        command=command,
        plan_id="diagnostic-export",
        phase=phase.value,
        journey=Journey.NOT_APPLICABLE,
        irreversible_boundary_crossed=False,
        ambiguity_state=AmbiguityState.NOT_APPLICABLE,
        recovery_policy=RecoveryPolicy.RETRY_SAME_OPERATION,
        effect_summary=_checkpoint_effect(),
        next_actions=(_resume_action(), _cancel_action()),
        cancellation_available=True,
        pairing_identity_policy=PairingIdentityPolicy.NOT_APPLICABLE,
        prior_operation_terminal=True,
    )


def _phase_for_outcome(
    original_command: str,
    outcome: Mapping[str, Any],
) -> LifecyclePhase:
    state = str(outcome.get("state") or "blocked")
    code = str(outcome.get("blocking_code") or outcome.get("code") or "")
    if state == "ready":
        return LifecyclePhase.COMPLETE
    if state == "rolled_back":
        return LifecyclePhase.ROLLBACK
    if original_command in {"uninstall", "purge"}:
        return LifecyclePhase.UNINSTALL
    if original_command == "export-diagnostics":
        return LifecyclePhase.DIAGNOSTICS
    if "pairing" in code:
        return LifecyclePhase.PAIRING
    if "verification" in code:
        return LifecyclePhase.VERIFICATION
    if "activation" in code or "plugin" in code or "launchd" in code:
        return LifecyclePhase.ACTIVATION
    if "legacy" in code or "retirement" in code:
        return LifecyclePhase.RETIREMENT_RECONCILIATION
    if outcome.get("gate"):
        return LifecyclePhase.AUTHORIZATION
    if state == "recovery_required":
        return LifecyclePhase.ROLLBACK
    return LifecyclePhase.PREPARATION


def _checkpoint_transition(
    checkpoint: Mapping[str, Any],
    outcome: Mapping[str, Any],
    services: LifecycleServices,
) -> dict[str, Any]:
    state = str(outcome.get("state") or "blocked")
    original_command = str(checkpoint.get("command") or "")
    mutation = bool(outcome.get("mutation_performed"))
    boundary = bool(checkpoint.get("irreversible_boundary_crossed"))
    ambiguity = str(checkpoint.get("ambiguity_state") or "not_applicable")
    gate = outcome.get("gate")

    if (
        checkpoint.get("journey") == Journey.LEGACY_UPGRADE.value
        and ambiguity == AmbiguityState.RETIRED.value
        and boundary is not True
    ):
        raise ValueError("retired_boundary_checkpoint_invalid")
    if ambiguity == AmbiguityState.RETIREMENT_OUTCOME_UNKNOWN.value:
        state = "recovery_required"
    elif boundary and ambiguity == AmbiguityState.RETIRED.value and state != "ready":
        state = "recovery_required"

    if state == "ready":
        recovery = RecoveryPolicy.NOT_APPLICABLE
        next_actions: tuple[NextAction, ...] = ()
        cancellation = False
    elif state == "rolled_back":
        boundary = False
        recovery = RecoveryPolicy.NOT_APPLICABLE
        next_actions = ()
        cancellation = False
    elif gate is not None or state == "prepared":
        recovery = RecoveryPolicy.RETRY_SAME_OPERATION
        cancellation = (
            not boundary
            and not mutation
            and ambiguity
            in {
                AmbiguityState.NOT_APPLICABLE.value,
                AmbiguityState.NOT_DISPATCHED.value,
            }
        )
        next_actions = (
            (_resume_action(), _cancel_action())
            if cancellation
            else (_resume_action(),)
        )
    elif state == "recovery_required":
        recovery_action = _checkpoint_recovery_action(
            {**dict(checkpoint), "state": state}, services
        )
        if recovery_action == "rollback" and not boundary:
            recovery = RecoveryPolicy.ROLLBACK_PRE_BOUNDARY
            next_actions = (_rollback_action(),)
        elif recovery_action in {"resume", "finish_forward"}:
            recovery = (
                RecoveryPolicy.FINISH_FORWARD
                if recovery_action == "finish_forward"
                else RecoveryPolicy.RETRY_SAME_OPERATION
            )
            next_actions = (_resume_action(),)
        elif recovery_action == "reconcile_retirement_outcome":
            recovery = RecoveryPolicy.RECONCILE_SAME_OPERATION
            next_actions = (
                NextAction(
                    action_id="reconcile-original-operation",
                    action_type=NextActionType.LIFECYCLE_COMMAND,
                    owner=ActionOwner.AGENT,
                    recommended=True,
                    executable=True,
                    command="resume",
                    parameters={"operation_id_ref": "result.operation_id"},
                ),
            )
        else:
            recovery = RecoveryPolicy.MANUAL_RECOVERY_REQUIRED
            next_actions = (_manual_recovery_action(),)
        cancellation = False
    elif mutation:
        recovery = RecoveryPolicy.MANUAL_RECOVERY_REQUIRED
        next_actions = (_manual_recovery_action(),)
        cancellation = False
    else:
        recovery = RecoveryPolicy.NOT_APPLICABLE
        next_actions = ()
        cancellation = False

    credential_effect = {
        AmbiguityState.NOT_DISPATCHED.value: CredentialEffect.NOT_DISPATCHED,
        AmbiguityState.RETIREMENT_OUTCOME_UNKNOWN.value: CredentialEffect.OUTCOME_UNKNOWN,
        AmbiguityState.NOT_APPLIED.value: CredentialEffect.NOT_APPLIED,
        AmbiguityState.RETIRED.value: CredentialEffect.RETIRED,
        AmbiguityState.INCONCLUSIVE.value: CredentialEffect.INCONCLUSIVE,
    }.get(ambiguity, CredentialEffect.NOT_APPLICABLE)
    if state == "rolled_back":
        local_effect = EffectDisposition.RESTORED
    elif state == "ready" and mutation:
        local_effect = EffectDisposition.CHANGED
    elif mutation:
        local_effect = EffectDisposition.STAGED
    else:
        local_effect = EffectDisposition.UNCHANGED
    effect_code = str(
        outcome.get("blocking_code") or outcome.get("code") or ""
    )
    effect_codes = (effect_code,) if effect_code else ()
    return {
        "state": state,
        "phase": _phase_for_outcome(original_command, outcome).value,
        "active_gate": gate,
        "irreversible_boundary_crossed": boundary,
        "ambiguity_state": ambiguity,
        "recovery_policy": recovery,
        "effect_summary": EffectSummary(
            local_effect=local_effect,
            remote_effect=EffectDisposition.NOT_APPLICABLE,
            credential_effect=credential_effect,
            mutation_performed=mutation,
            owned_resource_count=1 if mutation else 0,
            effect_codes=effect_codes,
        ),
        "next_actions": next_actions,
        "cancellation_available": cancellation,
    }


def _diagnostic_observation(
    snapshot: Mapping[str, Any],
    services: LifecycleServices,
    checkpoint_store: CheckpointStore | None = None,
) -> dict[str, Any]:
    installation = snapshot.get("installation") if isinstance(snapshot.get("installation"), Mapping) else {}
    versions = installation.get("plugin_versions") if isinstance(installation.get("plugin_versions"), list) else []
    network = snapshot.get("network") if isinstance(snapshot.get("network"), Mapping) else {}
    support = snapshot.get("support") if isinstance(snapshot.get("support"), Mapping) else {}
    claudian = snapshot.get("claudian") if isinstance(snapshot.get("claudian"), Mapping) else {}
    obsidian = snapshot.get("obsidian") if isinstance(snapshot.get("obsidian"), Mapping) else {}
    layout = services.layout
    owned_resources = 0
    if layout and layout.ownership_receipt.is_file():
        try:
            receipt = json.loads(layout.ownership_receipt.read_text(encoding="utf-8"))
            resources = receipt.get("resources") if isinstance(receipt, Mapping) else []
            owned_resources = len(resources) if isinstance(resources, list) else 0
        except (OSError, ValueError, TypeError):
            owned_resources = 0
    mode = "unknown"
    if layout and layout.connection_profile.is_file():
        try:
            profile = json.loads(layout.connection_profile.read_text(encoding="utf-8"))
            mode = str(profile.get("mode") or "unknown")
        except (OSError, ValueError, TypeError):
            mode = "unknown"
    source_reasons = support.get("reason_codes") if isinstance(support.get("reason_codes"), list) else []
    reasons = list(source_reasons)
    store = checkpoint_store or (
        CheckpointStore(layout.base / "lifecycle") if layout else None
    )
    arbitration = (
        OperationArbitrator(store.directory.path).inspect()
        if store is not None
        else OperationArbitration("clear", "no_prior_operation", True)
    )
    arbitration_summary = arbitration.to_summary()
    invalid_arbitration = (
        arbitration.state == "blocked"
        and arbitration.reason_code == "prior_operation_artifact_invalid"
    )
    if invalid_arbitration and "lifecycle_checkpoint_invalid" not in reasons:
        reasons.append("lifecycle_checkpoint_invalid")
    attention: dict[str, str] | None = None
    checkpoint = arbitration.checkpoint
    if arbitration.state != "clear":
        lifecycle_state = (
            str(checkpoint.get("state"))
            if isinstance(checkpoint, Mapping)
            else "blocked"
        )
        lifecycle_phase = (
            str(checkpoint.get("phase"))
            if isinstance(checkpoint, Mapping)
            else (
                arbitration.reconciliation.checkpoint_phase
                if arbitration.reconciliation is not None
                else "reconciliation"
            )
        )
        recovery_action = arbitration.recommended_action or "manual_recovery_required"
        command = {
            "resume": "resume",
            "rollback": "rollback",
            "finish_forward": "resume",
            "reconcile_retirement_outcome": "resume",
            "manual_recovery_required": "status",
        }.get(recovery_action, "status")
        attention = {
            "operation_id": str(arbitration.operation_id or ""),
            "command": command,
            "recovery_action": recovery_action,
        }
    else:
        lifecycle_state = "ready" if not reasons else "blocked"
        lifecycle_phase = "inspection"

    lifecycle_controls: dict[str, Any]
    if isinstance(checkpoint, Mapping):
        recorded_answers = checkpoint.get("recorded_answers")
        retirement_commit = (
            recorded_answers.get("retirement_commit")
            if isinstance(recorded_answers, Mapping)
            else None
        )
        lifecycle_controls = {
            "result_schema": RESULT_SCHEMA,
            "journey": checkpoint.get("journey"),
            "irreversible_boundary_crossed": checkpoint.get(
                "irreversible_boundary_crossed"
            ),
            "ambiguity_state": checkpoint.get("ambiguity_state"),
            "recovery_policy": checkpoint.get("recovery_policy"),
            "effect_summary": checkpoint.get("effect_summary"),
            "next_actions": checkpoint.get("next_actions"),
            "cancellation_available": checkpoint.get("cancellation_available"),
            "pairing_identity_policy": checkpoint.get(
                "pairing_identity_policy"
            ),
            "retirement_commit": retirement_commit,
        }
    elif arbitration.state != "clear":
        lifecycle_controls = {
            "result_schema": RESULT_SCHEMA,
            "journey": Journey.UNCLASSIFIED.value,
            "irreversible_boundary_crossed": False,
            "ambiguity_state": AmbiguityState.UNCLASSIFIED.value,
            "recovery_policy": RecoveryPolicy.MANUAL_RECOVERY_REQUIRED.value,
            "effect_summary": {
                "local_effect": "unknown",
                "remote_effect": "unknown",
                "credential_effect": "unknown",
                "mutation_performed": None,
                "owned_resource_count": 0,
                "effect_codes": [],
            },
            "next_actions": [],
            "cancellation_available": False,
            "pairing_identity_policy": PairingIdentityPolicy.UNCLASSIFIED.value,
        }
    else:
        snapshot_journey = snapshot.get("journey")
        journey = (
            str(snapshot_journey.get("journey") or Journey.UNCLASSIFIED.value)
            if isinstance(snapshot_journey, Mapping)
            else Journey.UNCLASSIFIED.value
        )
        lifecycle_controls = {
            "result_schema": RESULT_SCHEMA,
            "journey": journey,
            "irreversible_boundary_crossed": False,
            "ambiguity_state": (
                AmbiguityState.NOT_DISPATCHED.value
                if journey == Journey.LEGACY_UPGRADE.value
                else AmbiguityState.NOT_APPLICABLE.value
            ),
            "recovery_policy": RecoveryPolicy.NOT_APPLICABLE.value,
            "effect_summary": {
                "local_effect": "unchanged",
                "remote_effect": "not_applicable",
                "credential_effect": (
                    "not_dispatched"
                    if journey == Journey.LEGACY_UPGRADE.value
                    else "not_applicable"
                ),
                "mutation_performed": False,
                "owned_resource_count": 0,
                "effect_codes": [],
            },
            "next_actions": [],
            "cancellation_available": False,
            "pairing_identity_policy": PairingIdentityPolicy.UNCLASSIFIED.value,
        }
    observation = {
        "components": {
            "plugin": versions[0] if versions else "unknown",
            "claudian": str(claudian.get("version") or "unknown"),
        },
        "lifecycle": {
            "state": lifecycle_state,
            "phase": lifecycle_phase,
            "ownership_receipt_present": bool(layout and layout.ownership_receipt.is_file()),
            **lifecycle_controls,
        },
        "reason_codes": reasons,
        "connection": {
            "mode": mode,
            "transport_status": "connected" if network.get("tailscale_logged_in") is True else "disconnected",
            "mac_status": "online" if obsidian.get("running") is True else "offline",
            "compatibility_status": "compatible" if not reasons else "blocked",
        },
        "counters": {
            "owned_resources": owned_resources,
            "failed_checks": len(source_reasons) + int(invalid_arbitration),
            "pending_operations": int(arbitration.state != "clear"),
        },
        "operation_arbitration": arbitration_summary,
    }
    if attention is not None:
        observation["attention"] = attention
    return observation


def _checkpoint_recovery_action(
    checkpoint: Mapping[str, Any], services: LifecycleServices
) -> str | None:
    if checkpoint.get("state") != "recovery_required":
        return None
    if checkpoint.get("command") in {"install", "update"}:
        transaction = services.transaction
        recovery_probe = getattr(transaction, "recovery_action", None)
        if callable(recovery_probe):
            action = recovery_probe(
                str(checkpoint.get("operation_id") or ""),
                str(checkpoint.get("plan_id") or ""),
            )
            if action in {
                "rollback",
                "resume",
                "finish_forward",
                "reconcile_retirement_outcome",
                "manual_recovery_required",
            }:
                return action
        return "manual_recovery_required"
    if checkpoint.get("command") == "uninstall":
        return "resume"
    return "manual_recovery_required"


def _human_gate_result(
    command: str,
    checkpoint: Mapping[str, Any],
    gate: Any,
    *,
    data: Mapping[str, Any] | None = None,
) -> LifecycleResult:
    return LifecycleResult(
        command=command,
        state="blocked",
        code="human_action_required",
        message="A human-only confirmation is required before this operation can continue.",
        plan_id=str(checkpoint.get("plan_id") or "") or None,
        operation_id=str(checkpoint["operation_id"]),
        gate=gate.to_dict(),
        **_checkpoint_controls(checkpoint),
        data={"mutation_performed": False, **dict(data or {})},
    )


def dispatch(
    args: argparse.Namespace,
    *,
    services: LifecycleServices,
) -> LifecycleResult:
    command = str(args.command)
    inspector = Inspector(services.inspection_probe)
    checkpoints = CheckpointStore(args.state_dir)
    plans = PlanStore(args.state_dir)

    if command == "inspect":
        snapshot, arbitration = _arbitrated_snapshot(inspector, args.state_dir)
        if arbitration.state != "clear":
            return _arbitration_result(
                command, arbitration, snapshot=snapshot
            )
        reasons = snapshot["support"]["reason_codes"]
        blocking_reasons = [reason for reason in reasons if reason != "secure_provisioning_missing"]
        journey = Journey(str(snapshot["journey"]["journey"]))
        ambiguity = (
            AmbiguityState.NOT_DISPATCHED
            if journey is Journey.LEGACY_UPGRADE
            else AmbiguityState.NOT_APPLICABLE
        )
        return LifecycleResult(
            command=command,
            state="ready" if not blocking_reasons else "blocked",
            code="inspection_ready" if not blocking_reasons else blocking_reasons[0],
            message="Read-only inspection completed; no system state was changed.",
            journey=journey,
            phase=LifecyclePhase.INSPECTION,
            irreversible_boundary_crossed=False,
            ambiguity_state=ambiguity,
            recovery_policy=RecoveryPolicy.NOT_APPLICABLE,
            effect_summary=EffectSummary(
                local_effect=EffectDisposition.UNCHANGED,
                remote_effect=EffectDisposition.NOT_APPLICABLE,
                credential_effect=(
                    CredentialEffect.NOT_DISPATCHED
                    if ambiguity is AmbiguityState.NOT_DISPATCHED
                    else CredentialEffect.NOT_APPLICABLE
                ),
                mutation_performed=False,
                owned_resource_count=0,
                effect_codes=(),
            ),
            next_actions=(),
            cancellation_available=False,
            pairing_identity_policy=PairingIdentityPolicy.NOT_APPLICABLE,
            data={"snapshot": snapshot, "mutation_performed": False},
        )

    if command == "plan":
        live_snapshot, arbitration = _arbitrated_snapshot(
            inspector, args.state_dir
        )
        if arbitration.state != "clear":
            return _arbitration_result(
                command, arbitration, snapshot=live_snapshot
            )
        snapshot = (
            live_snapshot
            if args.snapshot is None
            else _load_snapshot(args.snapshot, inspector)
        )
        plan = PlanBuilder().build(
            snapshot,
            mode=args.mode,
            vault_id=args.vault_id,
            endpoint_audience=args.endpoint_audience,
        )
        plans.write(plan, snapshot)
        state = "blocked" if plan["blockers"] else "prepared"
        code = plan["blockers"][0] if plan["blockers"] else "plan_prepared"
        journey = Journey(str(plan["journey"]))
        ambiguity = (
            AmbiguityState.NOT_DISPATCHED
            if journey is Journey.LEGACY_UPGRADE
            else AmbiguityState.NOT_APPLICABLE
        )
        return LifecycleResult(
            command=command,
            state=state,
            code=code,
            message="Deterministic plan created without changing system state.",
            plan_id=plan["plan_id"],
            journey=journey,
            phase=LifecyclePhase.PLANNING,
            irreversible_boundary_crossed=False,
            ambiguity_state=ambiguity,
            recovery_policy=RecoveryPolicy.NOT_APPLICABLE,
            effect_summary=EffectSummary(
                local_effect=EffectDisposition.UNCHANGED,
                remote_effect=EffectDisposition.NOT_APPLICABLE,
                credential_effect=(
                    CredentialEffect.NOT_DISPATCHED
                    if ambiguity is AmbiguityState.NOT_DISPATCHED
                    else CredentialEffect.NOT_APPLICABLE
                ),
                mutation_performed=False,
                owned_resource_count=0,
                effect_codes=(),
            ),
            next_actions=(NextAction(**dict(plan["recommended_next_action"])),),
            cancellation_available=False,
            pairing_identity_policy=PairingIdentityPolicy(
                str(plan["pairing_identity_policy"])
            ),
            data={"plan": plan, "mutation_performed": False},
        )

    if command == "status":
        arbitration = OperationArbitrator(args.state_dir).inspect()
        if arbitration.state != "clear" and (
            arbitration.operation_id in {None, args.operation_id}
        ):
            return _arbitration_result(command, arbitration)
        if args.operation_id in arbitration.terminal_operation_ids:
            try:
                legacy_checkpoint, _evidence = load_supported_v1_checkpoint(
                    Path(args.state_dir) / f"{args.operation_id}.json",
                    expected_operation_id=args.operation_id,
                )
            except CompatibilityDecodeError:
                pass
            else:
                return _v1_terminal_result(command, legacy_checkpoint)
        try:
            checkpoint = checkpoints.read(args.operation_id)
        except (FileNotFoundError, ValueError):
            return _static_result(
                command=command,
                state="blocked",
                code="operation_not_found",
                message="No lifecycle checkpoint matches that operation reference.",
                operation_id=args.operation_id,
                phase=LifecyclePhase.RECONCILIATION,
                data={"mutation_performed": False},
            )
        status_data = {
            "phase": checkpoint["phase"],
            "completed_phases": checkpoint["completed_phases"],
        }
        recovery_action = _checkpoint_recovery_action(checkpoint, services)
        if recovery_action:
            status_data["recovery_action"] = recovery_action
        return LifecycleResult(
            command=command,
            state=checkpoint["state"],
            code="operation_status",
            message="Lifecycle checkpoint loaded.",
            operation_id=args.operation_id,
            plan_id=checkpoint["plan_id"],
            gate=checkpoint.get("active_gate"),
            **_checkpoint_controls(checkpoint),
            data={**status_data, "mutation_performed": False},
        )

    if command == "resume":
        try:
            with OperationLock(args.state_dir):
                arbitration = OperationArbitrator(args.state_dir).inspect()
                if arbitration.state != "clear" and (
                    arbitration.operation_id in {None, args.operation_id}
                ):
                    if arbitration.recommended_action not in {
                        "resume",
                        "finish_forward",
                        "reconcile_retirement_outcome",
                    }:
                        return _arbitration_result(command, arbitration)
                    if arbitration.reconciliation is not None:
                        # A v1 waiting gate remains owned by Beta 4.  Beta 5
                        # can report it, but cannot rewrite the older gate.
                        return _arbitration_result(command, arbitration)
                try:
                    checkpoint = checkpoints.read(args.operation_id)
                except (FileNotFoundError, ValueError):
                    return _static_result(
                        command=command,
                        state="blocked",
                        code="operation_not_found",
                        message="No resumable lifecycle checkpoint matches that operation reference.",
                        operation_id=args.operation_id,
                        phase=LifecyclePhase.RECONCILIATION,
                        data={"mutation_performed": False},
                    )
                original_command = str(checkpoint.get("command") or "")
                terminal_states = {"ready", "rolled_back"}
                recovery_action = _checkpoint_recovery_action(checkpoint, services)
                if (
                    checkpoint.get("state") == "recovery_required"
                    and original_command != "uninstall"
                    and recovery_action
                    not in {"finish_forward", "reconcile_retirement_outcome"}
                ):
                    terminal_states.add("recovery_required")
                if checkpoint.get("state") in terminal_states:
                    terminal_data = {
                        "phase": checkpoint.get("phase"),
                        "completed_phases": checkpoint.get("completed_phases", []),
                        "mutation_performed": False,
                    }
                    if recovery_action:
                        terminal_data["recovery_action"] = recovery_action
                    return LifecycleResult(
                        command=command,
                        state=str(checkpoint["state"]),
                        code="operation_status",
                        message="This lifecycle operation is already in a terminal state.",
                        operation_id=args.operation_id,
                        plan_id=str(checkpoint.get("plan_id") or "") or None,
                        **_checkpoint_controls(checkpoint),
                        data=terminal_data,
                    )
                if checkpoint.get("active_gate"):
                    controller = HumanGateController(checkpoints, services.gate_probes)
                    gate_outcome = controller.verify(args.operation_id)
                    if not gate_outcome["verified"]:
                        gate_checkpoint = gate_outcome.get("checkpoint", checkpoint)
                        return LifecycleResult(
                            command=command,
                            state="blocked",
                            code=str(gate_outcome.get("code") or "human_action_required"),
                            message=(
                                "The expired human gate was refreshed under the same operation."
                                if gate_outcome.get("code") == "human_gate_refreshed"
                                else "The required external action has not passed its verification probe."
                            ),
                            operation_id=args.operation_id,
                            gate=gate_outcome["gate"],
                            **_checkpoint_controls(gate_checkpoint),
                            data={"mutation_performed": False},
                        )
                    legacy_authorization_gate = (
                        checkpoint["active_gate"].get("gate_type")
                        == "legacy_authority_authorization_required"
                    )
                    if legacy_authorization_gate and not bool(
                        getattr(args, "authorize_legacy_retirement", False)
                    ):
                        return LifecycleResult(
                            command=command,
                            state="blocked",
                            code="human_action_required",
                            message=(
                                "Legacy credential retirement still requires explicit "
                                "operation-bound authorization."
                            ),
                            operation_id=args.operation_id,
                            plan_id=str(checkpoint.get("plan_id") or "") or None,
                            gate=checkpoint["active_gate"],
                            **_checkpoint_controls(checkpoint),
                            data={"mutation_performed": False},
                        )
                    if legacy_authorization_gate:
                        approval_probe = services.gate_probes.get(
                            "legacy_retirement_operator_confirmation"
                        )
                        try:
                            operator_confirmed = (
                                approval_probe is not None
                                and bool(approval_probe())
                            )
                        except Exception:
                            operator_confirmed = False
                        if not operator_confirmed:
                            return LifecycleResult(
                                command=command,
                                state="blocked",
                                code="human_action_required",
                                message=(
                                    "Legacy credential retirement was not approved "
                                    "in the native operator confirmation."
                                ),
                                operation_id=args.operation_id,
                                plan_id=str(checkpoint.get("plan_id") or "") or None,
                                gate=checkpoint["active_gate"],
                                **_checkpoint_controls(checkpoint),
                                data={"mutation_performed": False},
                            )
                        recorded = dict(checkpoint["recorded_answers"])
                        recorded["legacy_authority_authorization"] = {
                            "operation_id": args.operation_id,
                            "plan_id": str(checkpoint["plan_id"]),
                            "authorized": True,
                        }
                        checkpoint = checkpoints.update(
                            args.operation_id,
                            recorded_answers=recorded,
                            active_gate=None,
                            state="prepared",
                        )
                return _run_mutation(
                    command="resume",
                    operation_id=args.operation_id,
                    plan_id=str(checkpoint["plan_id"]),
                    args=args,
                    inspector=inspector,
                    plans=plans,
                    checkpoints=checkpoints,
                    services=services,
                    lock_held=True,
                )
        except OperationBusy:
            return _static_result(
                command=command,
                state="blocked",
                code="lifecycle_operation_busy",
                message="Another lifecycle mutation currently holds the installation lock.",
                operation_id=args.operation_id,
                phase=LifecyclePhase.RECONCILIATION,
                data={"mutation_performed": False},
            )

    if command == "cancel":
        try:
            with OperationLock(args.state_dir):
                arbitration = OperationArbitrator(args.state_dir).inspect()
                if arbitration.state != "clear" and (
                    arbitration.operation_id not in {None, args.operation_id}
                    or arbitration.reconciliation is not None
                ):
                    return _arbitration_result(command, arbitration)
                try:
                    checkpoint = checkpoints.read(args.operation_id)
                except (FileNotFoundError, ValueError):
                    return _static_result(
                        command=command,
                        state="blocked",
                        code="operation_not_found",
                        message="No cancellable lifecycle checkpoint matches that operation reference.",
                        operation_id=args.operation_id,
                        phase=LifecyclePhase.RECONCILIATION,
                        data={"mutation_performed": False},
                    )
                if checkpoint["state"] == "rolled_back":
                    return LifecycleResult(
                        command=command,
                        state="rolled_back",
                        code="operation_already_cancelled",
                        message="This lifecycle operation is already closed.",
                        operation_id=args.operation_id,
                        plan_id=checkpoint["plan_id"],
                        **_checkpoint_controls(checkpoint),
                        data={"mutation_performed": False},
                    )
                cancellable_ambiguity = checkpoint["ambiguity_state"] in {
                    AmbiguityState.NOT_APPLICABLE.value,
                    AmbiguityState.NOT_DISPATCHED.value,
                }
                if (
                    checkpoint.get("cancellation_available") is not True
                    or checkpoint.get("irreversible_boundary_crossed") is not False
                    or not cancellable_ambiguity
                ):
                    dispatched = (
                        checkpoint.get("irreversible_boundary_crossed") is True
                        or checkpoint.get("ambiguity_state")
                        in {
                            AmbiguityState.RETIREMENT_OUTCOME_UNKNOWN.value,
                            AmbiguityState.NOT_APPLIED.value,
                            AmbiguityState.RETIRED.value,
                            AmbiguityState.INCONCLUSIVE.value,
                        }
                    )
                    return LifecycleResult(
                        command=command,
                        state="blocked",
                        code=(
                            "cancellation_unavailable_after_dispatch"
                            if dispatched
                            else "cancellation_unavailable"
                        ),
                        message="Cancellation is unavailable at this lifecycle boundary.",
                        operation_id=args.operation_id,
                        plan_id=checkpoint["plan_id"],
                        **_checkpoint_controls(checkpoint),
                        data={"mutation_performed": False},
                    )

                original_command = str(checkpoint["command"])
                if original_command == "export-diagnostics":
                    secure_path = (
                        Path(args.state_dir)
                        / f"{args.operation_id}.diagnostic-destination.json"
                    )
                    try:
                        discarded = SecureInputFile(secure_path).discard()
                    except Exception:
                        outcome = {
                            "state": "blocked",
                            "code": "cancel_cleanup_unverified",
                            "mutation_performed": False,
                        }
                    else:
                        outcome = {
                            "state": "rolled_back",
                            "code": "operation_cancelled",
                            "mutation_performed": discarded,
                        }
                elif original_command == "purge":
                    outcome = {
                        "state": "rolled_back",
                        "code": "operation_cancelled",
                        "mutation_performed": False,
                    }
                elif original_command in {"install", "update", "uninstall"}:
                    if services.transaction is None:
                        return blocked_not_implemented(
                            command,
                            plan_id=checkpoint["plan_id"],
                        )
                    plan, _snapshot = plans.read(str(checkpoint["plan_id"]))
                    outcome = services.transaction.cancel_pre_boundary(
                        plan,
                        operation_id=args.operation_id,
                    )
                else:
                    outcome = {
                        "state": "blocked",
                        "code": "cancellation_unavailable",
                        "mutation_performed": False,
                    }

                if outcome["state"] != "rolled_back":
                    return LifecycleResult(
                        command=command,
                        state="blocked",
                        code=str(outcome["code"]),
                        message="Cancellation stopped because its cleanup boundary could not be proven.",
                        operation_id=args.operation_id,
                        plan_id=checkpoint["plan_id"],
                        **_checkpoint_controls(checkpoint),
                        data={"mutation_performed": bool(outcome.get("mutation_performed"))},
                    )
                secure_path = (
                    Path(args.state_dir)
                    / f"{args.operation_id}.diagnostic-destination.json"
                )
                if original_command != "export-diagnostics":
                    try:
                        secure_input_removed = SecureInputFile(secure_path).discard()
                    except Exception:
                        return LifecycleResult(
                            command=command,
                            state="recovery_required",
                            code="cancel_cleanup_unverified",
                            message="Cancellation removed staging but could not prove secure-input cleanup.",
                            operation_id=args.operation_id,
                            plan_id=checkpoint["plan_id"],
                            **_checkpoint_controls(checkpoint),
                            data={"mutation_performed": True},
                        )
                    if secure_input_removed:
                        outcome = {**dict(outcome), "mutation_performed": True}
                changes = _checkpoint_transition(checkpoint, outcome, services)
                updated = checkpoints.update(
                    args.operation_id,
                    **changes,
                    completed_phases=_completed_phases(services, args.operation_id),
                )
                return _result_from_outcome(
                    command,
                    outcome,
                    plan_id=checkpoint["plan_id"],
                    operation_id=args.operation_id,
                    checkpoint=updated,
                )
        except OperationBusy:
            return _static_result(
                command=command,
                state="blocked",
                code="lifecycle_operation_busy",
                message="Another lifecycle mutation currently holds the installation lock.",
                operation_id=args.operation_id,
                phase=LifecyclePhase.RECONCILIATION,
                data={"mutation_performed": False},
            )
        except (FileNotFoundError, ValueError):
            return _static_result(
                command=command,
                state="blocked",
                code="cancel_precondition_unverified",
                message="Cancellation stopped because the saved operation could not be verified.",
                operation_id=args.operation_id,
                phase=LifecyclePhase.RECONCILIATION,
                data={"mutation_performed": False},
            )

    if command in {"install", "update"}:
        try:
            with OperationLock(args.state_dir):
                arbitration = OperationArbitrator(args.state_dir).inspect()
                if arbitration.state != "clear":
                    return _arbitration_result(command, arbitration)
                plan, planned_snapshot = plans.read(args.plan_id)
                current_snapshot, current_arbitration = _arbitrated_snapshot(
                    inspector, args.state_dir
                )
                if current_arbitration.state != "clear":
                    return _arbitration_result(command, current_arbitration)
                validate_mutation_environment(
                    plan, planned_snapshot, current_snapshot
                )
                if services.transaction is None:
                    return blocked_not_implemented(command, plan_id=args.plan_id)
                checkpoint = _create_plan_operation_checkpoint(
                    checkpoints,
                    command=command,
                    plan=plan,
                    phase=LifecyclePhase.PREPARATION,
                )
                return _run_mutation(
                    command=command,
                    operation_id=checkpoint["operation_id"],
                    plan_id=args.plan_id,
                    args=args,
                    inspector=inspector,
                    plans=plans,
                    checkpoints=checkpoints,
                    services=services,
                    lock_held=True,
                )
        except OperationBusy:
            return _static_result(
                command=command,
                state="blocked",
                code="lifecycle_operation_busy",
                message="Another lifecycle mutation currently holds the installation lock.",
                plan_id=args.plan_id,
                phase=LifecyclePhase.PREPARATION,
                data={"mutation_performed": False},
            )
        except (FileNotFoundError, ValueError, PlanError) as exc:
            code = str(exc) if str(exc) in {
                "environment_drift", "verified_release_unavailable", "manifest_signature_unverified",
                "release_asset_missing", "release_asset_digest_mismatch",
            } else "plan_not_found"
            return _static_result(
                command=command,
                state="blocked",
                code=code,
                message="The saved plan or verified release could not be used; no product state was changed.",
                plan_id=args.plan_id,
                phase=LifecyclePhase.PREPARATION,
                data={"mutation_performed": False},
            )

    if command == "diagnose":
        if services.diagnostics is None:
            return blocked_not_implemented(command)
        summary = services.diagnostics.agent_safe_summary(
            _diagnostic_observation(inspector.snapshot(), services, checkpoints)
        )
        return _static_result(
            command=command,
            state="ready",
            code="diagnostic_summary_ready",
            message="A local allowlisted diagnostic summary was generated; nothing was uploaded.",
            phase=LifecyclePhase.DIAGNOSTICS,
            data={"agent_safe_summary": summary, "mutation_performed": False, "uploaded": False},
        )

    if command == "export-diagnostics":
        if services.diagnostics is None:
            return blocked_not_implemented(command)
        destination = Path(args.destination)
        if not destination.is_absolute() or destination.suffix.lower() != ".json":
            return _result_from_outcome(
                command,
                {"state": "blocked", "code": "diagnostic_export_destination_invalid", "mutation_performed": False},
                support_context=True,
            )
        try:
            with OperationLock(args.state_dir):
                arbitration = OperationArbitrator(args.state_dir).inspect()
                if arbitration.state != "clear":
                    return _arbitration_result(command, arbitration)
                checkpoint = _create_support_operation_checkpoint(
                    checkpoints,
                    command=command,
                    phase=LifecyclePhase.DIAGNOSTICS,
                )
                secure_path = Path(args.state_dir) / f"{checkpoint['operation_id']}.diagnostic-destination.json"
                SecureInputFile.create(secure_path, {"destination": str(destination)})
                gate = HumanGateController(checkpoints, services.gate_probes).require(
                    checkpoint["operation_id"],
                    gate_type="diagnostic_export_confirmation_required",
                    explanation="The redacted field preview must be confirmed in a macOS-owned dialog before a local file is written.",
                    exact_action="Run resume and click Confirm in the macOS dialog after reviewing the documented export fields.",
                    verification_probe="diagnostic_export_confirmation_verified",
                )
                return _human_gate_result(
                    command,
                    checkpoint,
                    gate,
                    data={"preview": services.diagnostics.preview_export(), "uploaded": False},
                )
        except OperationBusy:
            return _static_result(
                command=command,
                state="blocked",
                code="lifecycle_operation_busy",
                message="Another lifecycle mutation currently holds the installation lock.",
                phase=LifecyclePhase.DIAGNOSTICS,
                data={"mutation_performed": False},
            )

    if command == "revoke-device":
        if services.revoke_device is None:
            return blocked_not_implemented(command)
        try:
            with OperationLock(args.state_dir):
                arbitration = OperationArbitrator(args.state_dir).inspect()
                if arbitration.state != "clear":
                    return _arbitration_result(command, arbitration)
                outcome = services.revoke_device(args.device_id)
        except OperationBusy:
            outcome = {"state": "blocked", "code": "lifecycle_operation_busy", "mutation_performed": False}
        except Exception:
            outcome = {"state": "blocked", "code": "device_revocation_failed", "mutation_performed": False}
        return _result_from_outcome(command, outcome, support_context=True)

    if command == "uninstall":
        if services.uninstaller is None:
            return blocked_not_implemented(command, plan_id=args.plan_id)
        try:
            with OperationLock(args.state_dir):
                arbitration = OperationArbitrator(args.state_dir).inspect()
                if arbitration.state != "clear":
                    return _arbitration_result(command, arbitration)
                plan, _snapshot = plans.read(args.plan_id)
                checkpoint = _create_plan_operation_checkpoint(
                    checkpoints,
                    command=command,
                    plan=plan,
                    phase=LifecyclePhase.UNINSTALL,
                )
                return _run_mutation(
                    command=command,
                    operation_id=checkpoint["operation_id"],
                    plan_id=args.plan_id,
                    args=args,
                    inspector=inspector,
                    plans=plans,
                    checkpoints=checkpoints,
                    services=services,
                    lock_held=True,
                )
        except OperationBusy:
            return _static_result(
                command=command,
                state="blocked",
                code="lifecycle_operation_busy",
                message="Another lifecycle mutation currently holds the installation lock.",
                plan_id=args.plan_id,
                phase=LifecyclePhase.UNINSTALL,
                data={"mutation_performed": False},
            )
        except (FileNotFoundError, ValueError):
            return _static_result(
                command=command,
                state="blocked",
                code="plan_not_found",
                message="The saved plan could not be found; no product state was changed.",
                plan_id=args.plan_id,
                phase=LifecyclePhase.UNINSTALL,
                data={"mutation_performed": False},
            )

    if command == "purge":
        if services.uninstaller is None:
            return blocked_not_implemented(command, plan_id=args.plan_id)
        try:
            with OperationLock(args.state_dir):
                arbitration = OperationArbitrator(args.state_dir).inspect()
                if arbitration.state != "clear":
                    return _arbitration_result(command, arbitration)
                plan, _snapshot = plans.read(args.plan_id)
                checkpoint = _create_plan_operation_checkpoint(
                    checkpoints,
                    command=command,
                    plan=plan,
                    phase=LifecyclePhase.UNINSTALL,
                )
                gate = HumanGateController(checkpoints, services.gate_probes).require(
                    checkpoint["operation_id"],
                    gate_type="purge_confirmation_required",
                    explanation="Purge permanently removes all Claudian Remote local state but preserves Vault notes and Claudian conversations.",
                    exact_action="Run resume and click Confirm in the macOS warning dialog.",
                    verification_probe="purge_confirmation_verified",
                )
                return _human_gate_result(command, checkpoint, gate)
        except OperationBusy:
            return _static_result(
                command=command,
                state="blocked",
                code="lifecycle_operation_busy",
                message="Another lifecycle mutation currently holds the installation lock.",
                plan_id=args.plan_id,
                phase=LifecyclePhase.UNINSTALL,
                data={"mutation_performed": False},
            )
        except (FileNotFoundError, ValueError):
            return _static_result(
                command=command,
                state="blocked",
                code="plan_not_found",
                message="The saved plan could not be found; no product state was changed.",
                plan_id=args.plan_id,
                phase=LifecyclePhase.UNINSTALL,
                data={"mutation_performed": False},
            )

    if command == "verify":
        if not args.plan_id:
            return _static_result(
                command=command,
                state="blocked",
                code="plan_required",
                message="Verification requires the immutable plan reference used for installation.",
                phase=LifecyclePhase.VERIFICATION,
                data={"mutation_performed": False},
            )
        try:
            plan, _snapshot = plans.read(args.plan_id)
            outcome = services.transaction.verify(plan) if services.transaction else {"state": "blocked", "code": "operation_not_implemented"}
        except (FileNotFoundError, ValueError):
            return _static_result(
                command=command,
                state="blocked",
                code="plan_not_found",
                message="The saved plan could not be found; no product state was changed.",
                plan_id=args.plan_id,
                phase=LifecyclePhase.VERIFICATION,
                data={"mutation_performed": False},
            )
        return _result_from_outcome(
            command,
            outcome,
            plan_id=args.plan_id,
            plan=plan,
        )

    if command == "rollback":
        try:
            with OperationLock(args.state_dir):
                arbitration = OperationArbitrator(args.state_dir).inspect()
                if arbitration.state == "blocked":
                    return _arbitration_result(command, arbitration)

                if arbitration.reconciliation is not None:
                    if arbitration.operation_id != args.operation_id:
                        raise FileNotFoundError("operation_not_found")
                    if arbitration.recommended_action != "rollback":
                        return _arbitration_result(command, arbitration)
                    if services.transaction is None:
                        return blocked_not_implemented(command)

                    reconciliation = arbitration.reconciliation
                    checkpoint_path = Path(args.state_dir) / f"{args.operation_id}.json"
                    checkpoint, checkpoint_evidence = load_supported_v1_checkpoint(
                        checkpoint_path,
                        expected_operation_id=args.operation_id,
                    )
                    if checkpoint_evidence.sha256 != _v1_source_digest(
                        arbitration, ArtifactKind.CHECKPOINT
                    ):
                        raise CompatibilityDecodeError("v1_checkpoint_drift_detected")
                    plan_path = (
                        Path(args.state_dir)
                        / "plans"
                        / f"{reconciliation.plan_id}.json"
                    )
                    plan, _snapshot = load_supported_v1_saved_plan(
                        plan_path,
                        expected_plan_id=reconciliation.plan_id,
                    )
                    if hashlib.sha256(plan_path.read_bytes()).hexdigest() != _v1_source_digest(
                        arbitration, ArtifactKind.SAVED_PLAN
                    ):
                        raise CompatibilityDecodeError("v1_saved_plan_drift_detected")

                    effect_probe = getattr(
                        services.transaction,
                        "verify_supported_v1_staging_only_recovery",
                        None,
                    )
                    if not callable(effect_probe) or effect_probe(
                        plan,
                        operation_id=args.operation_id,
                        closed=False,
                    ) is not True:
                        return _v1_recovery_probe_failed(
                            command,
                            operation_id=args.operation_id,
                            plan_id=reconciliation.plan_id,
                        )

                    narrow_rollback = getattr(
                        services.transaction,
                        "rollback_supported_v1_staging_only",
                        None,
                    )
                    if not callable(narrow_rollback):
                        return _v1_recovery_probe_failed(
                            command,
                            operation_id=args.operation_id,
                            plan_id=reconciliation.plan_id,
                        )
                    outcome = narrow_rollback(
                        plan,
                        operation_id=args.operation_id,
                    )
                    if outcome.get("state") != "rolled_back":
                        return _v1_recovery_probe_failed(
                            command,
                            operation_id=args.operation_id,
                            plan_id=reconciliation.plan_id,
                            code=str(outcome.get("code") or "rollback_closure_unverified"),
                        )
                    if effect_probe(
                        plan,
                        operation_id=args.operation_id,
                        closed=True,
                    ) is not True:
                        return _v1_recovery_probe_failed(
                            command,
                            operation_id=args.operation_id,
                            plan_id=reconciliation.plan_id,
                            code="rollback_closure_unverified",
                        )
                    mark_supported_v1_checkpoint_rolled_back(
                        checkpoint_path,
                        expected_operation_id=args.operation_id,
                        expected_checkpoint_sha256=checkpoint_evidence.sha256,
                    )
                    closed = OperationArbitrator(args.state_dir).inspect()
                    if not (
                        closed.state == "clear"
                        and args.operation_id in closed.terminal_operation_ids
                    ):
                        return LifecycleResult(
                            command=command,
                            state="recovery_required",
                            code="rollback_closure_unverified",
                            message=(
                                "The local rollback ran, but the original operation "
                                "could not be verified terminal."
                            ),
                            plan_id=reconciliation.plan_id,
                            operation_id=args.operation_id,
                            journey=Journey.LEGACY_UPGRADE,
                            phase=LifecyclePhase.ROLLBACK,
                            irreversible_boundary_crossed=False,
                            ambiguity_state=AmbiguityState.NOT_APPLICABLE,
                            recovery_policy=RecoveryPolicy.MANUAL_RECOVERY_REQUIRED,
                            effect_summary=EffectSummary(
                                local_effect=EffectDisposition.RESTORED,
                                remote_effect=EffectDisposition.NOT_APPLICABLE,
                                credential_effect=CredentialEffect.NOT_APPLICABLE,
                                mutation_performed=bool(
                                    outcome.get("mutation_performed")
                                ),
                                owned_resource_count=0,
                                effect_codes=("rollback_closure_unverified",),
                            ),
                            next_actions=(_manual_recovery_action(),),
                            cancellation_available=False,
                            pairing_identity_policy=PairingIdentityPolicy.NOT_APPLICABLE,
                            data={"mutation_performed": bool(outcome.get("mutation_performed"))},
                        )
                    terminal_v1, _terminal_evidence = load_supported_v1_checkpoint(
                        checkpoint_path,
                        expected_operation_id=args.operation_id,
                    )
                    return _v1_terminal_result(
                        command,
                        terminal_v1,
                        code="rollback_completed",
                        mutation_performed=bool(outcome.get("mutation_performed")),
                        known_staging_closure=True,
                    )

                if args.operation_id in arbitration.terminal_operation_ids:
                    try:
                        legacy_checkpoint, _evidence = load_supported_v1_checkpoint(
                            Path(args.state_dir) / f"{args.operation_id}.json",
                            expected_operation_id=args.operation_id,
                        )
                    except CompatibilityDecodeError:
                        pass
                    else:
                        if legacy_checkpoint["state"] == "rolled_back":
                            return _v1_terminal_result(
                                command,
                                legacy_checkpoint,
                                code="rollback_already_completed",
                            )
                        return LifecycleResult(
                            command=command,
                            state="blocked",
                            code="rollback_not_available",
                            message="The supported Beta 4 operation is terminal and cannot be rolled back.",
                            operation_id=args.operation_id,
                            plan_id=str(legacy_checkpoint["plan_id"]),
                            journey=Journey.LEGACY_UPGRADE,
                            phase=LifecyclePhase.COMPLETE,
                            irreversible_boundary_crossed=False,
                            ambiguity_state=AmbiguityState.NOT_APPLICABLE,
                            recovery_policy=RecoveryPolicy.NOT_APPLICABLE,
                            effect_summary=EffectSummary(
                                local_effect=EffectDisposition.UNKNOWN,
                                remote_effect=EffectDisposition.UNKNOWN,
                                credential_effect=CredentialEffect.UNKNOWN,
                                mutation_performed=False,
                                owned_resource_count=0,
                                effect_codes=("legacy_terminal_effect_not_reprobed",),
                            ),
                            next_actions=(),
                            cancellation_available=False,
                            pairing_identity_policy=PairingIdentityPolicy.NOT_APPLICABLE,
                            data={"mutation_performed": False},
                        )
                    try:
                        terminal_checkpoint = checkpoints.read(args.operation_id)
                    except (FileNotFoundError, ValueError):
                        raise FileNotFoundError("operation_not_found")
                    if terminal_checkpoint["state"] == "rolled_back":
                        return LifecycleResult(
                            command=command,
                            state="rolled_back",
                            code="rollback_already_completed",
                            message="This lifecycle operation was already rolled back.",
                            operation_id=args.operation_id,
                            plan_id=str(terminal_checkpoint["plan_id"]),
                            **_checkpoint_controls(terminal_checkpoint),
                            data={"mutation_performed": False},
                        )
                    return LifecycleResult(
                        command=command,
                        state="blocked",
                        code="rollback_not_available",
                        message=(
                            "This lifecycle operation is already complete and "
                            "cannot be rolled back through its closed operation."
                        ),
                        operation_id=args.operation_id,
                        plan_id=str(terminal_checkpoint["plan_id"]),
                        **_checkpoint_controls(terminal_checkpoint),
                        data={"mutation_performed": False},
                    )

                if arbitration.state == "reconciliation_required":
                    if arbitration.operation_id != args.operation_id:
                        raise FileNotFoundError("operation_not_found")
                    if arbitration.recommended_action != "rollback":
                        return _arbitration_result(command, arbitration)

                checkpoint = checkpoints.read(args.operation_id)
                plan, _snapshot = plans.read(str(checkpoint["plan_id"]))
                outcome = (
                    services.transaction.rollback(
                        plan, operation_id=args.operation_id
                    )
                    if services.transaction
                    else {
                        "state": "blocked",
                        "code": "operation_not_implemented",
                        "mutation_performed": False,
                    }
                )
                updated_checkpoint = checkpoints.update(
                    args.operation_id,
                    **_checkpoint_transition(checkpoint, outcome, services),
                )
                return _result_from_outcome(
                    command,
                    outcome,
                    plan_id=str(checkpoint["plan_id"]),
                    operation_id=args.operation_id,
                    checkpoint=updated_checkpoint,
                )
        except OperationBusy:
            return _static_result(
                command=command,
                state="blocked",
                code="lifecycle_operation_busy",
                message="Another lifecycle mutation currently holds the installation lock.",
                operation_id=args.operation_id,
                phase=LifecyclePhase.ROLLBACK,
                data={"mutation_performed": False},
            )
        except (CompatibilityDecodeError, FileNotFoundError, ValueError):
            return _static_result(
                command=command,
                state="blocked",
                code="operation_not_found",
                message="No rollback checkpoint matches that operation reference.",
                operation_id=args.operation_id,
                phase=LifecyclePhase.ROLLBACK,
                data={"mutation_performed": False},
            )

    plan_id = getattr(args, "plan_id", None)
    return blocked_not_implemented(command, plan_id=plan_id)


def _result_from_outcome(
    command: str,
    outcome: Mapping[str, Any],
    *,
    plan_id: str | None = None,
    operation_id: str | None = None,
    checkpoint: Mapping[str, Any] | None = None,
    plan: Mapping[str, Any] | None = None,
    support_context: bool = False,
) -> LifecycleResult:
    authorities = int(checkpoint is not None) + int(plan is not None) + int(
        support_context
    )
    if authorities != 1:
        raise ValueError("result_control_authority_required")
    state = str(outcome.get("state") or "blocked")
    candidate = str(outcome.get("code") or "operation_failed")
    code = candidate if re.fullmatch(r"[a-z][a-z0-9_]{2,63}", candidate) else "operation_failed"
    safe_data = {
        key: value
        for key, value in outcome.items()
        if key not in {"state", "code", "gate"}
    }
    mutation = bool(outcome.get("mutation_performed"))
    if checkpoint is not None:
        controls = _checkpoint_controls(checkpoint)
    else:
        journey = (
            Journey(str(plan["journey"]))
            if plan is not None
            else Journey.NOT_APPLICABLE
        )
        ambiguity = (
            AmbiguityState.NOT_DISPATCHED
            if journey is Journey.LEGACY_UPGRADE
            else AmbiguityState.NOT_APPLICABLE
        )
        credential_effect = (
            CredentialEffect.NOT_DISPATCHED
            if ambiguity is AmbiguityState.NOT_DISPATCHED
            else (
                CredentialEffect.RETIRED
                if command == "revoke-device" and mutation
                else CredentialEffect.NOT_APPLICABLE
            )
        )
        controls = {
            "journey": journey,
            "phase": _phase_for_outcome(command, outcome),
            "irreversible_boundary_crossed": False,
            "ambiguity_state": ambiguity,
            "recovery_policy": RecoveryPolicy.NOT_APPLICABLE,
            "effect_summary": EffectSummary(
                local_effect=(
                    EffectDisposition.CHANGED
                    if mutation and command != "revoke-device"
                    else EffectDisposition.UNCHANGED
                ),
                remote_effect=(
                    EffectDisposition.CHANGED
                    if mutation and command == "revoke-device"
                    else EffectDisposition.NOT_APPLICABLE
                ),
                credential_effect=credential_effect,
                mutation_performed=mutation,
                owned_resource_count=1 if mutation else 0,
                effect_codes=(code,),
            ),
            "next_actions": (),
            "cancellation_available": False,
            "pairing_identity_policy": (
                PairingIdentityPolicy(str(plan["pairing_identity_policy"]))
                if plan is not None
                else PairingIdentityPolicy.NOT_APPLICABLE
            ),
        }
    return LifecycleResult(
        command=command,
        state=state,
        code=code,
        message={
            "ready": "The local Claudian Remote installation passed verification.",
            "blocked": "The lifecycle stopped at a verifiable blocking condition.",
            "rolled_back": "The local transaction restored its previous coherent state.",
            "prepared": "The lifecycle operation is prepared to continue.",
            "recovery_required": "The lifecycle requires an explicit recovery action.",
        }.get(state, "Lifecycle operation status updated."),
        plan_id=plan_id,
        operation_id=operation_id,
        gate=outcome.get("gate"),
        **controls,
        data=safe_data,
    )


def _run_mutation(
    *,
    command: str,
    operation_id: str,
    plan_id: str,
    args: argparse.Namespace,
    inspector: Inspector,
    plans: PlanStore,
    checkpoints: CheckpointStore,
    services: LifecycleServices,
    lock_held: bool = False,
) -> LifecycleResult:
    try:
        lock = nullcontext() if lock_held else OperationLock(args.state_dir)
        with lock:
            checkpoint = checkpoints.read(operation_id)
            original_command = str(checkpoint.get("command") or command)
            if original_command in {"install", "update"}:
                plan, planned_snapshot = plans.read(plan_id)
                if not services.transaction:
                    return blocked_not_implemented(command, plan_id=plan_id)
                recovery_action = _checkpoint_recovery_action(
                    checkpoint, services
                )
                if (
                    command == "resume"
                    and recovery_action == "reconcile_retirement_outcome"
                ):
                    reconcile = getattr(
                        services.transaction,
                        "reconcile_legacy_retirement",
                        None,
                    )
                    if not callable(reconcile):
                        raise RuntimeError(
                            "legacy_retirement_reconciliation_unsupported"
                        )
                    outcome = reconcile(plan, operation_id=operation_id)
                else:
                    validate_mutation_environment(
                        plan,
                        planned_snapshot,
                        inspector.snapshot(),
                        allow_plan_target=command == "resume",
                    )
                    outcome = services.transaction.install(
                        plan, operation_id=operation_id
                    )
            elif original_command == "purge":
                if services.uninstaller is None:
                    return blocked_not_implemented(command, plan_id=plan_id)
                plans.read(plan_id)
                outcome = services.uninstaller.purge(confirmation_verified=True)
            elif original_command == "uninstall":
                if services.uninstaller is None:
                    return blocked_not_implemented(command, plan_id=plan_id)
                plans.read(plan_id)
                outcome = services.uninstaller.uninstall()
            elif original_command == "export-diagnostics":
                if services.diagnostics is None:
                    return blocked_not_implemented(command)
                secure_path = Path(args.state_dir) / f"{operation_id}.diagnostic-destination.json"
                try:
                    secure_value = SecureInputFile(secure_path).consume()
                    destination = Path(str(secure_value.get("destination") or ""))
                except Exception:
                    outcome = {
                        "state": "blocked",
                        "code": "diagnostic_export_destination_unavailable",
                        "mutation_performed": False,
                    }
                else:
                    outcome = services.diagnostics.export(
                        _diagnostic_observation(inspector.snapshot(), services, checkpoints),
                        destination,
                        confirmation_verified=True,
                    )
            else:
                return blocked_not_implemented(command, plan_id=plan_id)
            raw_gate = outcome.get("gate")
            if isinstance(raw_gate, Mapping):
                blocking_code = str(outcome.get("code") or "human_action_required")
                gate = HumanGateController(checkpoints, services.gate_probes).require(
                    operation_id,
                    gate_type=str(raw_gate.get("gate_type") or blocking_code),
                    explanation=str(raw_gate.get("explanation") or "A verified external action is required."),
                    exact_action=str(
                        raw_gate.get("exact_action")
                        or raw_gate.get("human_action")
                        or "Complete the requested action, then resume this operation."
                    ),
                    verification_probe=str(raw_gate.get("verification_probe") or ""),
                    operator_options=tuple(
                        item for item in raw_gate.get("operator_options", ())
                        if isinstance(item, Mapping)
                    ),
                )
                outcome = {
                    **dict(outcome),
                    "state": "blocked",
                    "code": "human_action_required",
                    "blocking_code": blocking_code,
                    "gate": gate.to_dict(),
                }
            # Authority proof consumption may atomically advance an install or
            # update checkpoint while the transaction runs.  Derive those
            # transitions from the latest durable value so a successful proof
            # cannot be overwritten.  Support commands keep their pre-call
            # snapshot: purge is allowed to remove the whole state directory.
            if original_command in {"install", "update"}:
                checkpoint = checkpoints.read(operation_id)
            changes = {
                **_checkpoint_transition(checkpoint, outcome, services),
                "completed_phases": _completed_phases(services, operation_id),
            }
            if (
                original_command == "purge"
                and outcome.get("code") == "purge_completed"
                and not Path(args.state_dir).exists()
            ):
                # A successful purge intentionally removes the checkpoint
                # directory itself.  Never recreate lifecycle state merely to
                # record that the lifecycle state was deleted.
                return _result_from_outcome(
                    command,
                    outcome,
                    plan_id=plan_id,
                    operation_id=operation_id,
                    checkpoint={**dict(checkpoint), **changes},
                )
            updated_checkpoint = checkpoints.update(operation_id, **changes)
            return _result_from_outcome(
                command,
                outcome,
                plan_id=plan_id,
                operation_id=operation_id,
                checkpoint=updated_checkpoint,
            )
    except LifecycleInterrupted as exc:
        checkpoint = checkpoints.read(operation_id)
        interrupted_outcome = {
            "state": "prepared",
            "code": "operation_interrupted",
            "mutation_performed": True,
        }
        updated_checkpoint = checkpoints.update(
            operation_id,
            **_checkpoint_transition(
                checkpoint, interrupted_outcome, services
            ),
            completed_phases=_completed_phases(services, operation_id),
        )
        return LifecycleResult(
            command=command,
            state="prepared",
            code="operation_interrupted",
            message="The operation checkpoint is safe and can be resumed.",
            plan_id=plan_id,
            operation_id=operation_id,
            **_checkpoint_controls(updated_checkpoint),
            data={"phase": str(exc), "mutation_performed": True},
        )
    except OperationBusy:
        return _static_result(
            command=command,
            state="blocked",
            code="lifecycle_operation_busy",
            message="Another lifecycle mutation currently holds the installation lock.",
            plan_id=plan_id,
            operation_id=operation_id,
            phase=LifecyclePhase.RECONCILIATION,
            data={"mutation_performed": False},
        )
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        code = _stable_mutation_error(exc)
        checkpoint = checkpoints.read(operation_id)
        failed_outcome = {
            "state": "blocked",
            "code": code,
            "mutation_performed": False,
        }
        updated_checkpoint = checkpoints.update(
            operation_id,
            **_checkpoint_transition(checkpoint, failed_outcome, services),
        )
        return LifecycleResult(
            command=command,
            state="blocked",
            code=code,
            message="The operation failed closed at a verified lifecycle boundary.",
            plan_id=plan_id,
            operation_id=operation_id,
            **_checkpoint_controls(updated_checkpoint),
            data={"mutation_performed": False},
        )


def main(
    argv: Sequence[str] | None = None,
    *,
    stdout: TextIO | None = None,
    services: LifecycleServices | None = None,
) -> int:
    output = stdout or sys.stdout
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
        result = dispatch(
            args,
            services=services or LifecycleServices.local(
                state_dir=args.state_dir,
                release_dir=args.release_dir,
            ),
        )
    except Exception:
        command = "inspect"
        if argv:
            command = next((item for item in argv if item in COMMANDS), command)
        result = _static_result(
            command=command,
            state="blocked",
            code="invalid_lifecycle_input",
            message="Lifecycle input was rejected; no system state was changed.",
            phase=LifecyclePhase.PREPARATION,
            data={"mutation_performed": False},
        )
    try:
        payload = normalize_strict_result(result)
    except Exception:
        payload = normalize_strict_result(
            _static_result(
                command=result.command,
                state="blocked",
                code="internal_result_contract_violation",
                message=(
                    "The lifecycle stopped because an internal result did not "
                    "satisfy the public schema contract; no further action ran."
                ),
                phase=LifecyclePhase.RECONCILIATION,
                data={"mutation_performed": False},
            )
        )
    output.write(
        json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    output.write("\n")
    return 0 if payload["state"] in {"ready", "prepared", "rolled_back"} else 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
