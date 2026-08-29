"""Mutation-free Tailscale inspection and Serve planning."""

from __future__ import annotations

import json
import re
import subprocess
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


def _version(value: str) -> tuple[int, ...]:
    match = re.fullmatch(
        r"\s*(\d+)\.(\d+)\.(\d+)(?:[-+][0-9A-Za-z.-]+)?\s*",
        value,
    )
    return tuple(int(part) for part in match.groups()) if match else (0,)


TAILSCALE_APP_EXECUTABLES = (
    Path("/Applications/Tailscale.app/Contents/MacOS/Tailscale"),
    Path.home() / "Applications/Tailscale.app/Contents/MacOS/Tailscale",
)


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
            return self._gate(
                "tailscale_install_required",
                "Install and open the official Tailscale app, approve its macOS VPN/network extension, and sign in. CLI integration is optional.",
            )
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
            "commands": [[
                "tailscale", "serve", "--bg", "--https=443", "--set-path=/",
                f"http://127.0.0.1:{int(loopback_port)}",
            ]],
            "probe": {
                "https": f"https://{dns_name}/health",
                "wss": f"wss://{dns_name}/api/v2/ws/mobile",
                "credential_ref": "<secure-reference>",
                "application_auth_required": True,
            },
        }


class TailscaleController:
    """Production adapter for a private Tailscale Serve exposure.

    Installation and login remain human-owned.  This adapter only inspects,
    configures Serve after the local Relay is ready, verifies it, and removes
    the lifecycle-owned Serve rule.  It never enables Funnel.
    """

    def __init__(self, *, runner=None) -> None:
        self.runner = runner or self._run

    @staticmethod
    def _run(arguments: Sequence[str]) -> CommandResult:
        candidates = [list(arguments)]
        if arguments and arguments[0] == "tailscale":
            candidates.extend([
                [str(executable), *arguments[1:]]
                for executable in TAILSCALE_APP_EXECUTABLES
            ])
        last_result = CommandResult(127, "", "tailscale unavailable")
        for candidate in candidates:
            try:
                result = subprocess.run(
                    candidate,
                    text=True,
                    capture_output=True,
                    check=False,
                    timeout=15,
                )
            except OSError:
                continue
            except subprocess.TimeoutExpired:
                last_result = CommandResult(124, "", "tailscale timed out")
                continue
            last_result = CommandResult(result.returncode, result.stdout, result.stderr)
            if result.returncode == 0:
                return last_result
        return last_result

    @staticmethod
    def _blocked(code: str, action: str, probe: str) -> dict:
        operator_options: list[dict[str, Any]] = []
        if code == "tailscale_install_required":
            operator_options = [
                {
                    "id": "agent_continue",
                    "label": "由 Agent 继续操作",
                    "recommended": True,
                    "requires_capability": "browser_control",
                    "url": "https://tailscale.com/download/mac",
                    "instructions": (
                        "Open the official Tailscale for macOS download page and guide installation. "
                        "Pause for the user to approve the installer, VPN/network extension, login, "
                        "2FA, or any macOS password prompt. CLI integration is optional."
                    ),
                },
                {
                    "id": "manual",
                    "label": "我自己操作",
                    "recommended": False,
                    "url": "https://tailscale.com/download/mac",
                    "instructions": (
                        "Download and install the official Tailscale app, approve its VPN/network "
                        "extension, open it, and sign in. CLI integration is optional."
                    ),
                },
            ]
        elif code == "tailscale_update_required":
            operator_options = [
                {
                    "id": "agent_continue",
                    "label": "由 Agent 继续操作",
                    "recommended": True,
                    "requires_capability": "browser_control",
                    "url": "https://tailscale.com/download/mac",
                    "instructions": (
                        "Open the official Tailscale for macOS download page and guide the update. "
                        "Pause for installer approval, a macOS password, or VPN/network extension "
                        "permission, then resume and probe the installed version automatically."
                    ),
                },
                {
                    "id": "manual",
                    "label": "我自己操作",
                    "recommended": False,
                    "url": "https://tailscale.com/download/mac",
                    "instructions": (
                        "Update Tailscale from the official macOS download page, reopen it, and "
                        "return here when the app reports that it is connected."
                    ),
                },
            ]
        elif code == "tailscale_login_required":
            operator_options = [
                {
                    "id": "agent_continue",
                    "label": "由 Agent 继续操作",
                    "recommended": True,
                    "requires_capability": "computer_control",
                    "instructions": (
                        "Open the installed Tailscale app and guide sign-in. Pause for account "
                        "selection, password, passkey, 2FA, or macOS permission prompts."
                    ),
                },
                {
                    "id": "manual",
                    "label": "我自己操作",
                    "recommended": False,
                    "instructions": "Open the Tailscale app on this Mac and finish sign-in.",
                },
            ]
        elif code == "tailscale_https_consent_required":
            operator_options = [
                {
                    "id": "agent_continue",
                    "label": "由 Agent 继续操作",
                    "recommended": True,
                    "requires_capability": "browser_control",
                    "url": "https://login.tailscale.com/admin/dns",
                    "instructions": (
                        "Open the official Tailscale DNS page, enable MagicDNS if needed, "
                        "then enable HTTPS Certificates. Pause only for login, 2FA, or the "
                        "certificate-transparency acknowledgement. Resume and probe automatically."
                    ),
                },
                {
                    "id": "manual",
                    "label": "我自己操作",
                    "recommended": False,
                    "url": "https://login.tailscale.com/admin/dns",
                    "instructions": (
                        "Open DNS, enable MagicDNS if needed, then select Enable HTTPS under "
                        "HTTPS Certificates. Return here when the console reports it enabled."
                    ),
                },
            ]
        elif code == "tailscale_dns_required":
            operator_options = [
                {
                    "id": "agent_continue",
                    "label": "由 Agent 继续操作",
                    "recommended": True,
                    "requires_capability": "browser_control",
                    "url": "https://login.tailscale.com/admin/dns",
                    "instructions": (
                        "Open the official Tailscale DNS page and enable MagicDNS. Pause for login "
                        "or 2FA, then resume and verify that this Mac has a Tailnet DNS name."
                    ),
                },
                {
                    "id": "manual",
                    "label": "我自己操作",
                    "recommended": False,
                    "url": "https://login.tailscale.com/admin/dns",
                    "instructions": (
                        "Open the Tailscale DNS page, enable MagicDNS, and return here after the "
                        "device list shows a DNS name for this Mac."
                    ),
                },
            ]
        return {
            "state": "blocked",
            "code": code,
            "gate": {
                "gate_type": code,
                "explanation": action,
                "exact_action": action,
                "verification_probe": probe,
                "resume_reference": "network_mode:local_tailscale",
                "operator_options": operator_options,
            },
        }

    def _status(self) -> Mapping[str, Any] | None:
        result = self.runner(("tailscale", "status", "--json"))
        if result.returncode != 0:
            return None
        try:
            value = json.loads(result.stdout)
        except json.JSONDecodeError:
            return None
        return value if isinstance(value, Mapping) else None

    def installed(self) -> bool:
        return self._status() is not None

    def logged_in(self) -> bool:
        status = self._status()
        return bool(status) and (
            str(status.get("BackendState") or "") == "Running"
            or status.get("logged_in") is True
        )

    @staticmethod
    def _dns_name(status: Mapping[str, Any]) -> str:
        self_value = status.get("Self") if isinstance(status.get("Self"), Mapping) else {}
        return str(self_value.get("DNSName") or status.get("dns_name") or "").strip().rstrip(".")

    @classmethod
    def _https_consent(cls, status: Mapping[str, Any], dns_name: str) -> bool:
        if status.get("https_consent") is True:
            return True
        domains = status.get("CertDomains")
        return isinstance(domains, list) and dns_name in {
            str(value).strip().rstrip(".") for value in domains
        }

    def https_ready(self) -> bool:
        status = self._status()
        if not status:
            return False
        dns_name = self._dns_name(status)
        return bool(dns_name) and self._https_consent(status, dns_name)

    def preflight(self) -> dict:
        # The runner is the authority. Tests inject it, while production's
        # default runner reports a stable unavailable result when the binary
        # cannot be executed.
        status = self._status()
        if status is None:
            return self._blocked(
                "tailscale_install_required",
                "Install and open the official Tailscale app on this Mac, approve its VPN/network extension, and sign in. CLI integration is optional.",
                "tailscale_installed",
            )
        version = str(status.get("Version") or status.get("version") or "0")
        if _version(version) < TailscalePlanner.MINIMUM_VERSION:
            return self._blocked(
                "tailscale_update_required",
                "Update Tailscale to a supported version.",
                "tailscale_installed",
            )
        backend = str(status.get("BackendState") or "")
        logged_in = backend == "Running" or status.get("logged_in") is True
        if not logged_in:
            return self._blocked(
                "tailscale_login_required",
                "Open Tailscale and finish sign-in.",
                "tailscale_logged_in",
            )
        dns = self._dns_name(status)
        if not dns or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-" for char in dns):
            return self._blocked(
                "tailscale_dns_required",
                "Enable a valid Tailnet DNS name.",
                "tailscale_logged_in",
            )
        if not self._https_consent(status, dns):
            return self._blocked(
                "tailscale_https_consent_required",
                "Enable HTTPS certificates for this Tailnet in the Tailscale admin console, then return here.",
                "tailscale_https_ready",
            )
        return {"state": "ready", "endpoint": f"https://{dns}"}

    def activate_serve(self, loopback_port: int) -> None:
        if not 1 <= int(loopback_port) <= 65535:
            raise ValueError("invalid_tailscale_serve_port")
        target = f"http://127.0.0.1:{int(loopback_port)}"
        result = self.runner((
            "tailscale",
            "serve",
            "--bg",
            "--https=443",
            "--set-path=/",
            target,
        ))
        if result.returncode != 0:
            raise RuntimeError("tailscale_serve_activation_failed")

    def verify(self, endpoint: str, loopback_port: int = 8787) -> bool:
        parsed = urllib.parse.urlsplit(str(endpoint))
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or parsed.path not in ("", "/")
            or not 1 <= int(loopback_port) <= 65535
        ):
            return False
        result = self.runner(("tailscale", "serve", "status", "--json"))
        if result.returncode != 0:
            return False
        try:
            status = json.loads(result.stdout or "{}")
        except json.JSONDecodeError:
            return False
        if not isinstance(status, dict):
            return False
        authority = f"{parsed.hostname.rstrip('.')}:{parsed.port or 443}"
        tcp = status.get("TCP") if isinstance(status.get("TCP"), dict) else {}
        port_config = tcp.get(str(parsed.port or 443))
        if not isinstance(port_config, dict) or port_config.get("HTTPS") is not True:
            return False
        web = status.get("Web") if isinstance(status.get("Web"), dict) else {}
        endpoint_config = web.get(authority)
        if not isinstance(endpoint_config, dict):
            return False
        handlers = endpoint_config.get("Handlers")
        root = handlers.get("/") if isinstance(handlers, dict) else None
        if not isinstance(root, dict) or root.get("Proxy") != f"http://127.0.0.1:{int(loopback_port)}":
            return False
        allow_funnel = status.get("AllowFunnel")
        if isinstance(allow_funnel, dict) and allow_funnel.get(authority) is True:
            return False
        return True

    def owned_serve_absent(self, loopback_port: int = 8787) -> bool:
        """Prove that no Serve handler targets Claudian Remote's loopback.

        A failed or malformed status probe is not evidence of absence.  This
        deliberately ignores unrelated user-owned Serve routes while failing
        closed if the lifecycle's exact loopback target is still exposed.
        """

        if not 1 <= int(loopback_port) <= 65535:
            return False
        result = self.runner(("tailscale", "serve", "status", "--json"))
        if result.returncode != 0:
            return False
        try:
            status = json.loads(result.stdout or "{}")
        except json.JSONDecodeError:
            return False
        if not isinstance(status, Mapping):
            return False
        target = f"http://127.0.0.1:{int(loopback_port)}"

        def contains_target(value: Any) -> bool:
            if isinstance(value, Mapping):
                return any(contains_target(item) for item in value.values())
            if isinstance(value, list):
                return any(contains_target(item) for item in value)
            return value == target

        return not contains_target(status)

    def remove_serve(self, loopback_port: int = 8787) -> None:
        if not 1 <= int(loopback_port) <= 65535:
            raise ValueError("invalid_tailscale_serve_port")
        target = f"http://127.0.0.1:{int(loopback_port)}"
        status_result = self.runner(("tailscale", "serve", "status", "--json"))
        if status_result.returncode != 0:
            raise RuntimeError("tailscale_serve_remove_unverified")
        try:
            status = json.loads(status_result.stdout or "{}")
        except json.JSONDecodeError as exc:
            raise RuntimeError("tailscale_serve_remove_unverified") from exc
        encoded_status = json.dumps(status, separators=(",", ":"))
        if f'"Proxy":"{target}"' not in encoded_status:
            return
        # Re-run the exact HTTPS/path selector with `off`; unlike `serve
        # reset`, this preserves unrelated user-owned Serve configuration.
        result = self.runner((
            "tailscale", "serve", "--https=443", "--set-path=/", target, "off",
        ))
        if result.returncode != 0:
            raise RuntimeError("tailscale_serve_remove_failed")
        status_result = self.runner(("tailscale", "serve", "status", "--json"))
        if status_result.returncode != 0:
            raise RuntimeError("tailscale_serve_remove_unverified")
        try:
            status = json.loads(status_result.stdout or "{}")
        except json.JSONDecodeError as exc:
            raise RuntimeError("tailscale_serve_remove_unverified") from exc
        if f'"Proxy":"{target}"' in json.dumps(status, separators=(",", ":")):
            raise RuntimeError("tailscale_serve_remove_unverified")
