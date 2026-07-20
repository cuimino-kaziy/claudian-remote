"""Mutation-free Tailscale inspection and Serve planning."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Callable, Sequence


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


def _version(value: str) -> tuple[int, ...]:
    try:
        return tuple(int(part) for part in value.split(".")[:3])
    except ValueError:
        return (0,)


class TailscalePlanner:
    MINIMUM_VERSION = (1, 52, 0)

    def __init__(self, runner: Callable[[Sequence[str]], CommandResult]) -> None:
        self.runner = runner

    @staticmethod
    def _gate(gate_type: str, action: str) -> dict:
        return {
            "state": "blocked",
            "ready": False,
            "commands": [],
            "gate": {
                "gate_type": gate_type,
                "explanation": action,
                "human_action": action,
                "verification_probe": "tailscale_status",
                "resume_reference": "network_mode:local_tailscale",
            },
        }

    def plan(self, *, loopback_port: int, test_credential_ref: str) -> dict:
        if not 1 <= int(loopback_port) <= 65535 or not test_credential_ref:
            raise ValueError("invalid_tailscale_plan_input")
        result = self.runner(("tailscale", "status", "--json"))
        try:
            status = json.loads(result.stdout) if result.returncode == 0 else {"installed": False}
        except json.JSONDecodeError:
            status = {"installed": False}
        if not status.get("installed"):
            return self._gate("tailscale_install_required", "Install the supported Tailscale app.")
        if _version(str(status.get("version") or "0")) < self.MINIMUM_VERSION:
            return self._gate("tailscale_update_required", "Update Tailscale to the supported version.")
        if not status.get("logged_in"):
            return self._gate("tailscale_login_required", "Sign in to Tailscale on this Mac.")
        if not status.get("https_consent"):
            return self._gate("tailscale_https_consent_required", "Approve Tailscale Serve HTTPS.")
        dns_name = str(status.get("dns_name") or "").strip().rstrip(".")
        if not dns_name or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-" for char in dns_name):
            return self._gate("tailscale_dns_required", "Enable a valid Tailnet DNS name.")
        return {
            "state": "prepared",
            "ready": False,
            "mode": "local_tailscale",
            "local_relay": {"bind": "127.0.0.1", "port": int(loopback_port)},
            "endpoint": f"https://{dns_name}",
            "commands": [["tailscale", "serve", "--bg", f"http://127.0.0.1:{int(loopback_port)}"]],
            "probe": {
                "https": f"https://{dns_name}/health",
                "wss": f"wss://{dns_name}/api/v2/ws/mobile",
                "credential_ref": "<secure-reference>",
                "application_auth_required": True,
            },
        }
