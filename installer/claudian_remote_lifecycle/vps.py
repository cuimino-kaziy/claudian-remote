"""Exact-artifact VPS deployment plans with compensating rollback steps."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass


HOST_RE = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


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
        return {
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

    def verify_or_rollback(self, plan: dict, checks: dict[str, bool]) -> dict:
        required = ("tls", "wss", "storage", "protocol")
        failed = [name for name in required if checks.get(name) is not True]
        if failed:
            return {
                "state": "rolled_back",
                "ready": False,
                "paired": False,
                "failed_checks": failed,
                "completed_compensations": list(plan.get("rollback", [])),
            }
        return {"state": "ready", "ready": True, "paired": False, "endpoint": f"https://{plan['host']}"}
