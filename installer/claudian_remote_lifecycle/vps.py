"""Exact-artifact VPS deployment plans with compensating rollback steps."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol

from .private_io import write_private_json


HOST_RE = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


@contextmanager
def trusted_regular_file(path: Path, root: Path):
    """Open a regular file beneath root without traversing symlink parents."""

    path = Path(path)
    root = Path(root).resolve()
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("retirement_helper_path_invalid")
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise ValueError("retirement_helper_path_invalid") from exc
    if not relative.parts:
        raise ValueError("retirement_helper_path_invalid")
    directory_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    directory_flags |= getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_NOFOLLOW", 0)
    file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    file_flags |= getattr(os, "O_NOFOLLOW", 0)
    directory_fd = None
    descriptor = None
    try:
        directory_fd = os.open(root, directory_flags)
        for component in relative.parts[:-1]:
            next_fd = os.open(component, directory_flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        descriptor = os.open(
            relative.parts[-1],
            file_flags,
            dir_fd=directory_fd,
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise ValueError("retirement_helper_unsafe")
        yield descriptor, metadata
    except ValueError:
        raise
    except OSError as exc:
        raise ValueError("retirement_helper_unsafe") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if directory_fd is not None:
            os.close(directory_fd)


@dataclass(frozen=True)
class RelayArtifact:
    version: str
    digest: str
    bytes: bytes


@dataclass(frozen=True)
class VpsHost:
    hostname: str
    os_id: str
    os_version: str
    architecture: str
    available_bytes: int
    host_key_fingerprint: str


class VpsDeploymentPlanner:
    SUPPORTED = {("ubuntu", "24.04", "x86_64"), ("debian", "12", "x86_64"), ("debian", "12", "aarch64")}
    MINIMUM_AVAILABLE_BYTES = 2 * 1024**3

    @staticmethod
    def _gate(gate_type: str, action: str) -> dict:
        return {
            "state": "blocked",
            "ready": False,
            "gate": {
                "gate_type": gate_type,
                "explanation": action,
                "human_action": action,
                "verification_probe": "vps_host_probe",
                "resume_reference": "network_mode:remote_vps",
            },
        }

    def plan(self, host: VpsHost, artifact: RelayArtifact, *, host_key_confirmed: bool, tls_ready: bool) -> dict:
        if not HOST_RE.fullmatch(host.hostname):
            raise ValueError("invalid_vps_hostname")
        if not host_key_confirmed:
            return self._gate("vps_host_key_confirmation_required", "Confirm the displayed VPS host-key fingerprint.")
        if (host.os_id, host.os_version, host.architecture) not in self.SUPPORTED:
            return self._gate("unsupported_vps_profile", "Use a supported Linux OS and architecture.")
        if host.available_bytes < self.MINIMUM_AVAILABLE_BYTES:
            return self._gate("insufficient_vps_storage", "Provide at least 2 GiB available managed storage.")
        if not tls_ready:
            return self._gate("vps_tls_required", "Configure a trusted HTTPS certificate for the selected hostname.")
        expected = "sha256:" + hashlib.sha256(artifact.bytes).hexdigest()
        if artifact.digest != expected:
            raise ValueError("relay_artifact_digest_mismatch")
        stage = f"/opt/claudian-remote/releases/{artifact.version}-{artifact.digest[7:19]}"
        rollback = ["stop_staged_service", "remove_owned_staged_release", "restore_previous_service"]
        deployment = {
            "deployment_plan_schema": "claudian-remote.vps-deployment/v1",
            "state": "prepared",
            "ready": False,
            "mode": "remote_vps",
            "host": host.hostname,
            "host_key_fingerprint": host.host_key_fingerprint,
            "service_user": "claudian-remote",
            "owned_directory": "/var/lib/claudian-remote",
            "staged_release": stage,
            "artifact": {"version": artifact.version, "digest": artifact.digest, "size": len(artifact.bytes)},
            "remote_input": "validated_json_stdin",
            "public_routes": ["HTTPS /api/v2/*", "WSS /api/v2/ws/*"],
            "private_routes": ["health", "management", "database"],
            "service_restrictions": ["dedicated_user", "read_only_release", "owned_data_directory"],
            "rollback": rollback,
            "trust_disclosure": "The user-owned VPS terminates TLS and can read conversation and attachment content; end-to-end encryption is not claimed.",
        }
        encoded = json.dumps(deployment, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        deployment["plan_id"] = "plan-" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()
        return deployment

    def verify_or_rollback(self, plan: dict, checks: dict[str, bool]) -> dict:
        """Assess probes without pretending that compensation was executed.

        Mutation and compensation belong to :class:`VpsSagaExecutor`.  The
        former implementation returned every planned rollback label as
        completed even though no remote operation had run.
        """
        required = ("tls", "wss", "storage", "protocol")
        failed = [name for name in required if checks.get(name) is not True]
        if failed:
            return {
                "state": "blocked",
                "code": "vps_verification_failed",
                "ready": False,
                "paired": False,
                "failed_checks": failed,
                "completed_compensations": [],
            }
        return {"state": "ready", "ready": True, "paired": False, "endpoint": f"https://{plan['host']}"}


class VpsSagaAdapter(Protocol):
    """Narrow mutation boundary for an exact, already-authorized VPS host."""

    def perform(self, step: str, plan: Mapping[str, Any]) -> None: ...

    def compensate(self, action: str, plan: Mapping[str, Any]) -> None: ...

    def verify(self, plan: Mapping[str, Any]) -> Mapping[str, bool]: ...


class VpsSagaInterrupted(RuntimeError):
    pass


class PinnedSshResponseLost(RuntimeError):
    """The remote action may have completed after its request was written."""


class PinnedSshChannel(Protocol):
    """OS-owned SSH channel; credentials never enter lifecycle payloads."""

    hostname: str
    host_key_fingerprint: str

    def upload_from_fd(self, source_fd: int, destination: str) -> None: ...

    def run_json(
        self,
        action: str,
        payload: Mapping[str, Any],
    ) -> Mapping[str, Any]: ...

    def remove(self, destination: str) -> None: ...


class PinnedSshRetirementPrimitives:
    """Pinned-host, immutable-upload primitives shared by retirement only."""

    ACTIONS = frozenset(
        {
            "verify_inert_asset",
            "retirement_preflight",
            "retirement_commit",
            "retirement_reconcile",
        }
    )

    def __init__(
        self,
        channel: PinnedSshChannel,
        *,
        expected_hostname: str,
        expected_host_key_fingerprint: str,
        trusted_source_root: Path,
    ) -> None:
        if not isinstance(expected_hostname, str) or not HOST_RE.fullmatch(
            expected_hostname
        ):
            raise ValueError("invalid_vps_hostname")
        if (
            not isinstance(expected_host_key_fingerprint, str)
            or not expected_host_key_fingerprint.startswith("SHA256:")
        ):
            raise ValueError("vps_host_key_fingerprint_invalid")
        if channel.hostname != expected_hostname:
            raise ValueError("vps_host_mismatch")
        if channel.host_key_fingerprint != expected_host_key_fingerprint:
            raise ValueError("vps_host_key_mismatch")
        self.channel = channel
        self.expected_hostname = expected_hostname
        self.expected_host_key_fingerprint = expected_host_key_fingerprint
        self.trusted_source_root = Path(trusted_source_root).resolve()

    def _assert_pinned(self) -> None:
        if self.channel.hostname != self.expected_hostname:
            raise ValueError("vps_host_changed")
        if self.channel.host_key_fingerprint != self.expected_host_key_fingerprint:
            raise ValueError("vps_host_key_changed")

    def upload_immutable(
        self,
        source: Path,
        destination: str,
        *,
        expected_digest: str,
    ) -> None:
        self._assert_pinned()
        source = Path(source)
        with trusted_regular_file(
            source,
            self.trusted_source_root,
        ) as (descriptor, opened):
            digest = hashlib.sha256()
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
            if digest.hexdigest() != expected_digest:
                raise ValueError("retirement_helper_digest_mismatch")
            after = os.fstat(descriptor)
            if (
                after.st_size != opened.st_size
                or after.st_mtime_ns != opened.st_mtime_ns
            ):
                raise ValueError("retirement_helper_changed")
            os.lseek(descriptor, 0, os.SEEK_SET)
            self.channel.upload_from_fd(descriptor, destination)
        result = dict(
            self.run(
                "verify_inert_asset",
                {
                    "path": destination,
                    "sha256": expected_digest,
                    "required_mode": "0444",
                },
            )
        )
        if result != {
            "ok": True,
            "digest": expected_digest,
            "immutable": True,
            "inert": True,
        }:
            raise ValueError("retirement_remote_stage_unverified")

    def run(
        self,
        action: str,
        payload: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        self._assert_pinned()
        if action not in self.ACTIONS:
            raise ValueError("vps_action_not_allowed")
        return self.channel.run_json(action, dict(payload))

    def remove_owned(self, destination: str) -> None:
        self._assert_pinned()
        self.channel.remove(destination)


class VpsSagaExecutor:
    """Resume and compensate the remote compatibility-window transaction.

    The executor persists only operation identity and fixed step names. Host
    authorization and credentials stay in the injected, OS-owned adapter.
    """

    REQUIRED_CHECKS = ("tls", "wss", "storage", "protocol")
    FORWARD_STEPS = (
        "deploy_compatible_relay",
        "activate_staged_relay",
        "switch_mac_profile",
        "retire_previous_release",
    )
    COMPENSATIONS = {
        "switch_mac_profile": ("restore_mac_profile",),
        "activate_staged_relay": ("stop_staged_service", "restore_previous_service"),
        "deploy_compatible_relay": ("remove_owned_staged_release",),
    }

    def __init__(
        self,
        state_dir: Path,
        adapter: VpsSagaAdapter,
        *,
        interruption_probe: Callable[[str], bool] = lambda _phase: False,
    ) -> None:
        self.state_dir = Path(state_dir)
        self.adapter = adapter
        self.interruption_probe = interruption_probe

    def _path(self, operation_id: str) -> Path:
        if not re.fullmatch(r"op-[0-9a-f]{32}", operation_id):
            raise ValueError("invalid_operation_id")
        return self.state_dir / f"{operation_id}.vps-saga.json"

    def _load(self, operation_id: str, plan_id: str) -> dict[str, Any]:
        path = self._path(operation_id)
        if not path.is_file():
            return {
                "saga_schema": "claudian-remote.vps-saga/v1",
                "operation_id": operation_id,
                "plan_id": plan_id,
                "phase": "prepared",
                "completed_steps": [],
                "completed_compensations": [],
            }
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError("vps_saga_journal_invalid") from exc
        if (
            not isinstance(value, Mapping)
            or value.get("saga_schema") != "claudian-remote.vps-saga/v1"
            or value.get("operation_id") != operation_id
            or value.get("plan_id") != plan_id
        ):
            raise ValueError("vps_saga_journal_invalid")
        journal = dict(value)
        completed_steps = journal.get("completed_steps")
        completed_compensations = journal.get("completed_compensations")
        allowed_phases = {
            "prepared",
            "awaiting_mobile_convergence",
            "ready",
            "rolled_back",
            "recovery_required",
            *("before_" + step for step in self.FORWARD_STEPS),
            *("after_" + step for step in self.FORWARD_STEPS),
        }
        allowed_compensations = {
            action for actions in self.COMPENSATIONS.values() for action in actions
        }
        if (
            journal.get("phase") not in allowed_phases
            or not isinstance(completed_steps, list)
            or not all(isinstance(step, str) for step in completed_steps)
            or len(completed_steps) != len(set(completed_steps))
            or completed_steps != list(self.FORWARD_STEPS[:len(completed_steps)])
            or not isinstance(completed_compensations, list)
            or not all(
                isinstance(action, str) and action in allowed_compensations
                for action in completed_compensations
            )
            or len(completed_compensations) != len(set(completed_compensations))
        ):
            raise ValueError("vps_saga_journal_invalid")
        return journal

    def _save(self, journal: Mapping[str, Any]) -> None:
        write_private_json(self._path(str(journal["operation_id"])), journal)

    def _checkpoint(self, journal: dict[str, Any], phase: str) -> None:
        journal["phase"] = phase
        self._save(journal)
        if self.interruption_probe(phase):
            raise VpsSagaInterrupted(phase)

    def _compensate(
        self,
        plan: Mapping[str, Any],
        journal: dict[str, Any],
        *,
        failed_checks: list[str] | None = None,
        attempted_step: str | None = None,
    ) -> dict[str, Any]:
        completed_actions = list(journal.get("completed_compensations") or [])
        failed_actions: list[str] = []
        applied_steps = list(journal.get("completed_steps") or [])
        if attempted_step and attempted_step not in applied_steps:
            # A remote command can fail after making a partial change. Its
            # compensation must therefore run even though the forward step
            # never reached the completed checkpoint.
            applied_steps.append(attempted_step)
        for step in reversed(applied_steps):
            for action in self.COMPENSATIONS.get(str(step), ()):
                if action in completed_actions:
                    continue
                try:
                    self.adapter.compensate(action, plan)
                except Exception:
                    failed_actions.append(action)
                else:
                    completed_actions.append(action)
                    journal["completed_compensations"] = completed_actions
                    self._save(journal)
        journal["phase"] = "recovery_required" if failed_actions else "rolled_back"
        journal["completed_compensations"] = completed_actions
        self._save(journal)
        if failed_actions:
            return {
                "state": "recovery_required",
                "code": "vps_compensation_incomplete",
                "mutation_performed": True,
                "failed_checks": list(failed_checks or []),
                "completed_compensations": completed_actions,
                "failed_compensations": failed_actions,
            }
        return {
            "state": "rolled_back",
            "code": "vps_saga_rolled_back",
            "mutation_performed": True,
            "failed_checks": list(failed_checks or []),
            "completed_compensations": completed_actions,
        }

    def execute(
        self,
        plan: Mapping[str, Any],
        *,
        operation_id: str,
    ) -> dict[str, Any]:
        if (
            plan.get("deployment_plan_schema") != "claudian-remote.vps-deployment/v1"
            or plan.get("mode") != "remote_vps"
            or plan.get("state") != "prepared"
        ):
            raise ValueError("invalid_vps_deployment_plan")
        plan_id = str(plan.get("plan_id") or "")
        if not plan_id:
            raise ValueError("invalid_vps_deployment_plan")
        journal = self._load(operation_id, plan_id)
        phase = str(journal.get("phase") or "")
        if phase == "ready":
            return {"state": "ready", "code": "vps_saga_ready", "mutation_performed": False}
        if phase == "rolled_back":
            return {
                "state": "rolled_back",
                "code": "vps_saga_rolled_back",
                "mutation_performed": False,
                "completed_compensations": list(journal.get("completed_compensations") or []),
            }
        if phase == "recovery_required":
            return {
                "state": "recovery_required",
                "code": "vps_compensation_incomplete",
                "mutation_performed": False,
                "completed_compensations": list(journal.get("completed_compensations") or []),
            }

        completed_steps = list(journal.get("completed_steps") or [])
        attempted_step: str | None = None
        try:
            for step in self.FORWARD_STEPS[:-1]:
                if step in completed_steps:
                    continue
                self._checkpoint(journal, "before_" + step)
                attempted_step = step
                self.adapter.perform(step, plan)
                completed_steps.append(step)
                journal["completed_steps"] = completed_steps
                attempted_step = None
                self._checkpoint(journal, "after_" + step)
        except VpsSagaInterrupted:
            raise
        except Exception:
            return self._compensate(plan, journal, attempted_step=attempted_step)

        checks = dict(self.adapter.verify(plan))
        failed_checks = [name for name in self.REQUIRED_CHECKS if checks.get(name) is not True]
        if failed_checks:
            return self._compensate(plan, journal, failed_checks=failed_checks)

        if checks.get("mobile_converged") is not True:
            self._checkpoint(journal, "awaiting_mobile_convergence")
            return {
                "state": "blocked",
                "code": "mobile_protocol_convergence_required",
                "mutation_performed": True,
                "compatibility_window_active": True,
            }

        retirement = self.FORWARD_STEPS[-1]
        if retirement not in completed_steps:
            try:
                self._checkpoint(journal, "before_" + retirement)
                self.adapter.perform(retirement, plan)
            except Exception:
                journal["phase"] = "recovery_required"
                self._save(journal)
                return {
                    "state": "recovery_required",
                    "code": "vps_retirement_incomplete",
                    "mutation_performed": True,
                    "compatibility_window_active": True,
                }
            completed_steps.append(retirement)
            journal["completed_steps"] = completed_steps
            self._checkpoint(journal, "after_" + retirement)
        journal["phase"] = "ready"
        self._save(journal)
        return {
            "state": "ready",
            "code": "vps_saga_ready",
            "mutation_performed": True,
            "compatibility_window_active": False,
        }
