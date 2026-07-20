"""Security-gated encrypted LAN exposure plan."""

from __future__ import annotations

import ipaddress


class LanGatewayPlanner:
    @staticmethod
    def _gate(gate_type: str, action: str) -> dict:
        return {
            "state": "blocked",
            "ready": False,
            "gate": {
                "gate_type": gate_type,
                "explanation": action,
                "human_action": action,
                "verification_probe": "lan_gateway_preconditions",
                "resume_reference": "network_mode:local_lan",
            },
        }

    def plan(
        self,
        *,
        approved_interface: str,
        approved_address: str,
        network_fingerprint: str,
        consent: bool,
        certificate_ref: str,
        test_credential_ref: str,
    ) -> dict:
        if not consent:
            return self._gate("trusted_lan_consent_required", "Approve this specific private network.")
        try:
            address = ipaddress.ip_address(approved_address)
        except ValueError as exc:
            raise ValueError("invalid_lan_address") from exc
        if not address.is_private or address.is_loopback or not approved_interface or not network_fingerprint:
            raise ValueError("unapproved_lan_binding")
        if not certificate_ref:
            return self._gate("lan_certificate_required", "Install or select a trusted TLS certificate.")
        if not test_credential_ref:
            raise ValueError("lan_application_auth_required")
        return {
            "state": "prepared",
            "ready": False,
            "mode": "local_lan",
            "listener": f"{approved_address}:9443",
            "approved_interface": approved_interface,
            "network_fingerprint": network_fingerprint,
            "upstream": "http://127.0.0.1:8787",
            "transport": "tls",
            "certificate_ref": "<secure-reference>",
            "application_auth_required": True,
            "credential_ref": "<secure-reference>",
            "network_change_policy": "close_and_require_new_consent",
        }


class LanNetworkGuard:
    def __init__(self, approved_interface: str, approved_fingerprint: str) -> None:
        self.approved_interface = approved_interface
        self.approved_fingerprint = approved_fingerprint
        self.closed = False

    def observe(self, interface: str, fingerprint: str) -> dict:
        if self.closed or interface != self.approved_interface or fingerprint != self.approved_fingerprint:
            self.closed = True
            return {"state": "blocked", "code": "network_identity_changed", "close_listener": True}
        return {"state": "ready", "close_listener": False}
