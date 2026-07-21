"""Structured command-line entry point for the Claudian Remote lifecycle."""

from __future__ import annotations

import argparse
from contextlib import nullcontext
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
from .credentials import CredentialRevocationService
from .diagnostics import DiagnosticService
from .human_gates import HumanGateController
from .inspect import Inspector, InspectionProbe, LocalInspectionProbe
from .model import COMMANDS, LifecycleResult, blocked_not_implemented
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

        def paired() -> bool:
            try:
                devices = relay_request("/api/v2/pairing/devices").get("devices", [])
                return any(
                    item.get("status") == "active" and item.get("revoked") is not True
                    for item in devices
                    if isinstance(item, dict)
                )
            except Exception:
                return False

        def desktop_plugin_authenticated() -> bool:
            return verify_bridge_bootstrap_ack(layout)

        def revoke_device(device_id: str) -> dict[str, Any]:
            target = str(device_id or "")
            if not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", target):
                return {"state": "blocked", "code": "device_id_invalid", "mutation_performed": False}
            try:
                relay_request(
                    f"/api/v2/pairing/devices/{urllib.parse.quote(target, safe='')}/revoke",
                    method="POST",
                    body={"reason": "revoked"},
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
        transaction = LocalTailscaleTransaction(TransactionDependencies(
            layout=layout,
            release_source=release_source,
            launchd=launchd,
            tailscale=tailscale,
            keychain=keychain,
            vault_path=probe.resolve_vault,
            health_probe=health,
            pairing_probe=paired,
            bridge_ready_probe=desktop_plugin_authenticated,
            # A legacy shared credential can only be retired by its
            # authoritative Relay. Until a verified revocation adapter is
            # available, fail closed instead of falsely marking it migrated.
            legacy_credential_revoker=lambda _credential: {"verified": False},
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


def _diagnostic_observation(snapshot: Mapping[str, Any], services: LifecycleServices) -> dict[str, Any]:
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
    reasons = support.get("reason_codes") if isinstance(support.get("reason_codes"), list) else []
    return {
        "components": {
            "plugin": versions[0] if versions else "unknown",
            "claudian": str(claudian.get("version") or "unknown"),
        },
        "lifecycle": {
            "state": "ready" if not reasons else "blocked",
            "phase": "inspection",
            "ownership_receipt_present": bool(layout and layout.ownership_receipt.is_file()),
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
            "failed_checks": len(reasons),
            "pending_operations": 0,
        },
    }


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
        snapshot = inspector.snapshot()
        reasons = snapshot["support"]["reason_codes"]
        blocking_reasons = [reason for reason in reasons if reason != "secure_provisioning_missing"]
        return LifecycleResult(
            command=command,
            state="ready" if not blocking_reasons else "blocked",
            code="inspection_ready" if not blocking_reasons else blocking_reasons[0],
            message="Read-only inspection completed; no system state was changed.",
            data={"snapshot": snapshot, "mutation_performed": False},
        )

    if command == "plan":
        snapshot = _load_snapshot(args.snapshot, inspector)
        plan = PlanBuilder().build(
            snapshot,
            mode=args.mode,
            vault_id=args.vault_id,
            endpoint_audience=args.endpoint_audience,
        )
        plans.write(plan, snapshot)
        state = "blocked" if plan["blockers"] else "prepared"
        code = plan["blockers"][0] if plan["blockers"] else "plan_prepared"
        return LifecycleResult(
            command=command,
            state=state,
            code=code,
            message="Deterministic plan created without changing system state.",
            plan_id=plan["plan_id"],
            data={"plan": plan, "mutation_performed": False},
        )

    if command == "status":
        try:
            checkpoint = checkpoints.read(args.operation_id)
        except (FileNotFoundError, ValueError):
            return LifecycleResult(
                command=command,
                state="blocked",
                code="operation_not_found",
                message="No lifecycle checkpoint matches that operation reference.",
                operation_id=args.operation_id,
                data={"mutation_performed": False},
            )
        return LifecycleResult(
            command=command,
            state=checkpoint["state"],
            code="operation_status",
            message="Lifecycle checkpoint loaded.",
            operation_id=args.operation_id,
            plan_id=checkpoint["plan_id"],
            gate=checkpoint.get("active_gate"),
            data={"phase": checkpoint["phase"], "completed_phases": checkpoint["completed_phases"]},
        )

    if command == "resume":
        try:
            checkpoint = checkpoints.read(args.operation_id)
        except (FileNotFoundError, ValueError):
            return LifecycleResult(
                command=command,
                state="blocked",
                code="operation_not_found",
                message="No resumable lifecycle checkpoint matches that operation reference.",
                operation_id=args.operation_id,
                data={"mutation_performed": False},
            )
        original_command = str(checkpoint.get("command") or "")
        terminal_states = {"ready", "rolled_back"}
        if checkpoint.get("state") == "recovery_required" and original_command != "uninstall":
            terminal_states.add("recovery_required")
        if checkpoint.get("state") in terminal_states:
            return LifecycleResult(
                command=command,
                state=str(checkpoint["state"]),
                code="operation_status",
                message="This lifecycle operation is already in a terminal state.",
                operation_id=args.operation_id,
                plan_id=str(checkpoint.get("plan_id") or "") or None,
                data={
                    "phase": checkpoint.get("phase"),
                    "completed_phases": checkpoint.get("completed_phases", []),
                    "mutation_performed": False,
                },
            )
        if checkpoint.get("active_gate"):
            controller = HumanGateController(checkpoints, services.gate_probes)
            outcome = controller.verify_and_resume(args.operation_id)
            if not outcome["verified"]:
                return LifecycleResult(
                    command=command,
                    state="blocked",
                    code="human_action_required",
                    message="The required external action has not passed its verification probe.",
                    operation_id=args.operation_id,
                    gate=outcome["gate"],
                    data={"mutation_performed": False},
                )
            checkpoint = outcome["checkpoint"]
        return _run_mutation(
            command="resume",
            operation_id=args.operation_id,
            plan_id=str(checkpoint["plan_id"]),
            args=args,
            inspector=inspector,
            plans=plans,
            checkpoints=checkpoints,
            services=services,
        )

    if command in {"install", "update"}:
        try:
            with OperationLock(args.state_dir):
                plan, planned_snapshot = plans.read(args.plan_id)
                validate_mutation_environment(plan, planned_snapshot, inspector.snapshot())
                if services.transaction is None:
                    return blocked_not_implemented(command, plan_id=args.plan_id)
                checkpoint = checkpoints.create(command=command, plan_id=args.plan_id, phase=f"{command}_prepared")
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
            return LifecycleResult(
                command=command,
                state="blocked",
                code="lifecycle_operation_busy",
                message="Another lifecycle mutation currently holds the installation lock.",
                plan_id=args.plan_id,
                data={"mutation_performed": False},
            )
        except (FileNotFoundError, ValueError, PlanError) as exc:
            code = str(exc) if str(exc) in {
                "environment_drift", "verified_release_unavailable", "manifest_signature_unverified",
                "release_asset_missing", "release_asset_digest_mismatch",
            } else "plan_not_found"
            return LifecycleResult(
                command=command,
                state="blocked",
                code=code,
                message="The saved plan or verified release could not be used; no product state was changed.",
                plan_id=args.plan_id,
                data={"mutation_performed": False},
            )

    if command == "diagnose":
        if services.diagnostics is None:
            return blocked_not_implemented(command)
        summary = services.diagnostics.agent_safe_summary(
            _diagnostic_observation(inspector.snapshot(), services)
        )
        return LifecycleResult(
            command=command,
            state="ready",
            code="diagnostic_summary_ready",
            message="A local allowlisted diagnostic summary was generated; nothing was uploaded.",
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
            )
        try:
            with OperationLock(args.state_dir):
                checkpoint = checkpoints.create(
                    command=command,
                    plan_id="diagnostic-export",
                    phase="awaiting_diagnostic_export_confirmation",
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
            return LifecycleResult(
                command=command,
                state="blocked",
                code="lifecycle_operation_busy",
                message="Another lifecycle mutation currently holds the installation lock.",
                data={"mutation_performed": False},
            )

    if command == "revoke-device":
        if services.revoke_device is None:
            return blocked_not_implemented(command)
        try:
            with OperationLock(args.state_dir):
                outcome = services.revoke_device(args.device_id)
        except OperationBusy:
            outcome = {"state": "blocked", "code": "lifecycle_operation_busy", "mutation_performed": False}
        except Exception:
            outcome = {"state": "blocked", "code": "device_revocation_failed", "mutation_performed": False}
        return _result_from_outcome(command, outcome)

    if command == "uninstall":
        if services.uninstaller is None:
            return blocked_not_implemented(command, plan_id=args.plan_id)
        try:
            with OperationLock(args.state_dir):
                plans.read(args.plan_id)
                checkpoint = checkpoints.create(
                    command=command,
                    plan_id=args.plan_id,
                    phase="uninstall_prepared",
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
            return LifecycleResult(
                command=command,
                state="blocked",
                code="lifecycle_operation_busy",
                message="Another lifecycle mutation currently holds the installation lock.",
                plan_id=args.plan_id,
                data={"mutation_performed": False},
            )
        except (FileNotFoundError, ValueError):
            return LifecycleResult(
                command=command,
                state="blocked",
                code="plan_not_found",
                message="The saved plan could not be found; no product state was changed.",
                plan_id=args.plan_id,
                data={"mutation_performed": False},
            )

    if command == "purge":
        if services.uninstaller is None:
            return blocked_not_implemented(command, plan_id=args.plan_id)
        try:
            with OperationLock(args.state_dir):
                plans.read(args.plan_id)
                checkpoint = checkpoints.create(
                    command=command,
                    plan_id=args.plan_id,
                    phase="awaiting_purge_confirmation",
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
            return LifecycleResult(
                command=command,
                state="blocked",
                code="lifecycle_operation_busy",
                message="Another lifecycle mutation currently holds the installation lock.",
                plan_id=args.plan_id,
                data={"mutation_performed": False},
            )
        except (FileNotFoundError, ValueError):
            return LifecycleResult(
                command=command,
                state="blocked",
                code="plan_not_found",
                message="The saved plan could not be found; no product state was changed.",
                plan_id=args.plan_id,
                data={"mutation_performed": False},
            )

    if command == "verify":
        if not args.plan_id:
            return LifecycleResult(
                command=command,
                state="blocked",
                code="plan_required",
                message="Verification requires the immutable plan reference used for installation.",
                data={"mutation_performed": False},
            )
        try:
            plan, _snapshot = plans.read(args.plan_id)
            outcome = services.transaction.verify(plan) if services.transaction else {"state": "blocked", "code": "operation_not_implemented"}
        except (FileNotFoundError, ValueError):
            outcome = {"state": "blocked", "code": "plan_not_found", "mutation_performed": False}
        return _result_from_outcome(command, outcome, plan_id=args.plan_id)

    if command == "rollback":
        try:
            checkpoint = checkpoints.read(args.operation_id)
            plan, _snapshot = plans.read(str(checkpoint["plan_id"]))
            with OperationLock(args.state_dir):
                outcome = services.transaction.rollback(plan, operation_id=args.operation_id) if services.transaction else {
                    "state": "blocked", "code": "operation_not_implemented", "mutation_performed": False
                }
            checkpoints.update(args.operation_id, state=outcome["state"], phase=outcome["code"])
            return _result_from_outcome(command, outcome, plan_id=str(checkpoint["plan_id"]), operation_id=args.operation_id)
        except OperationBusy:
            return LifecycleResult(
                command=command,
                state="blocked",
                code="lifecycle_operation_busy",
                message="Another lifecycle mutation currently holds the installation lock.",
                operation_id=args.operation_id,
                data={"mutation_performed": False},
            )
        except (FileNotFoundError, ValueError):
            return LifecycleResult(
                command=command,
                state="blocked",
                code="operation_not_found",
                message="No rollback checkpoint matches that operation reference.",
                operation_id=args.operation_id,
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
) -> LifecycleResult:
    state = str(outcome.get("state") or "blocked")
    candidate = str(outcome.get("code") or "operation_failed")
    code = candidate if re.fullmatch(r"[a-z][a-z0-9_]{2,63}", candidate) else "operation_failed"
    safe_data = {
        key: value
        for key, value in outcome.items()
        if key not in {"state", "code", "gate"}
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
                validate_mutation_environment(
                    plan,
                    planned_snapshot,
                    inspector.snapshot(),
                    allow_plan_target=command == "resume",
                )
                if not services.transaction:
                    return blocked_not_implemented(command, plan_id=plan_id)
                outcome = services.transaction.install(plan, operation_id=operation_id)
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
                        _diagnostic_observation(inspector.snapshot(), services),
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
                )
                outcome = {
                    **dict(outcome),
                    "state": "blocked",
                    "code": "human_action_required",
                    "blocking_code": blocking_code,
                    "gate": gate.to_dict(),
                }
            if original_command == "purge" and outcome.get("code") == "purge_completed":
                # A successful purge intentionally removes the checkpoint
                # directory itself.  Never recreate lifecycle state merely to
                # record that the lifecycle state was deleted.
                return _result_from_outcome(
                    command,
                    outcome,
                    plan_id=plan_id,
                    operation_id=operation_id,
                )
            changes = {
                "state": outcome["state"],
                "phase": outcome.get("blocking_code", outcome["code"]),
                "completed_phases": _completed_phases(services, operation_id),
                "active_gate": outcome.get("gate"),
            }
            checkpoints.update(operation_id, **changes)
            return _result_from_outcome(
                command,
                outcome,
                plan_id=plan_id,
                operation_id=operation_id,
            )
    except LifecycleInterrupted as exc:
        checkpoints.update(
            operation_id,
            state="prepared",
            phase=str(exc),
            completed_phases=_completed_phases(services, operation_id),
        )
        return LifecycleResult(
            command=command,
            state="prepared",
            code="operation_interrupted",
            message="The operation checkpoint is safe and can be resumed.",
            plan_id=plan_id,
            operation_id=operation_id,
            data={"phase": str(exc), "mutation_performed": True},
        )
    except OperationBusy:
        return LifecycleResult(
            command=command,
            state="blocked",
            code="lifecycle_operation_busy",
            message="Another lifecycle mutation currently holds the installation lock.",
            plan_id=plan_id,
            operation_id=operation_id,
            data={"mutation_performed": False},
        )
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        code = _stable_mutation_error(exc)
        checkpoints.update(operation_id, state="blocked", phase=code)
        return LifecycleResult(
            command=command,
            state="blocked",
            code=code,
            message="The operation failed closed at a verified lifecycle boundary.",
            plan_id=plan_id,
            operation_id=operation_id,
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
        result = LifecycleResult(
            command=command,
            state="blocked",
            code="invalid_lifecycle_input",
            message="Lifecycle input was rejected; no system state was changed.",
            data={"mutation_performed": False},
        )
    output.write(json.dumps(result.to_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    output.write("\n")
    return 0 if result.state in {"ready", "prepared", "rolled_back"} else 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
