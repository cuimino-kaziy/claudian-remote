"""Pairing Admin operations proxied by the authenticated Companion Bridge."""

from __future__ import annotations

import asyncio
import inspect
import re
import aiohttp
from typing import Any, Awaitable, Callable, Mapping
from urllib.parse import quote


class PairingAdminProxyError(RuntimeError):
    pass


Request = Callable[[str, str, Mapping[str, Any] | None, str], Awaitable[Mapping[str, Any]]]


class PairingAdminProxy:
    IDENTIFIER = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
    REVOKE_REASONS = {
        "revoked",
        "lost_device",
        "suspected_disclosure",
        "profile_changed",
        "legacy_migration",
    }
    ROUTES = {
        "pairing.claim.create": ("POST", "/api/v2/pairing/claims"),
        "pairing.claims": ("GET", "/api/v2/pairing/claims"),
        "pairing.devices": ("GET", "/api/v2/pairing/devices"),
    }

    def __init__(
        self,
        *,
        relay_base_url: str,
        credential_provider: Callable[[], str],
        request: Request | None = None,
    ) -> None:
        self.relay_base_url = relay_base_url.rstrip("/")
        self.credential_provider = credential_provider
        self.request = request or self._request

    async def _request(
        self,
        method: str,
        path: str,
        body: Mapping[str, Any] | None,
        authorization: str,
    ) -> Mapping[str, Any]:
        async with aiohttp.ClientSession() as session:
            async with session.request(
                method,
                self.relay_base_url + path,
                json=body,
                headers={"Authorization": authorization, "Accept": "application/json"},
                timeout=aiohttp.ClientTimeout(total=15),
            ) as response:
                value = await response.json()
                if response.status < 200 or response.status >= 300:
                    raise PairingAdminProxyError("management_request_rejected")
                if not isinstance(value, Mapping):
                    raise PairingAdminProxyError("management_response_invalid")
                return dict(value)

    @classmethod
    def _identifier(cls, value: Any) -> str:
        identifier = str(value or "")
        if not cls.IDENTIFIER.fullmatch(identifier):
            raise PairingAdminProxyError("management_identifier_invalid")
        return identifier

    @staticmethod
    def _dynamic(operation: str, payload: Mapping[str, Any]) -> tuple[str, str, Mapping[str, Any] | None]:
        if operation == "pairing.claim.approve":
            claim_id = PairingAdminProxy._identifier(payload.get("claim_id"))
            device_id = PairingAdminProxy._identifier(payload.get("device_id"))
            return "POST", f"/api/v2/pairing/claims/{quote(claim_id, safe='')}/approve", {"device_id": device_id}
        if operation == "pairing.claim.reject":
            claim_id = PairingAdminProxy._identifier(payload.get("claim_id"))
            return "POST", f"/api/v2/pairing/claims/{quote(claim_id, safe='')}/reject", {}
        if operation == "pairing.device.revoke":
            device_id = PairingAdminProxy._identifier(payload.get("device_id"))
            reason = str(payload.get("reason") or "revoked")
            if reason not in PairingAdminProxy.REVOKE_REASONS:
                raise PairingAdminProxyError("management_revoke_reason_invalid")
            return "POST", f"/api/v2/pairing/devices/{quote(device_id, safe='')}/revoke", {"reason": reason}
        raise PairingAdminProxyError("management_operation_forbidden")

    async def handle(self, operation: str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        if operation in self.ROUTES:
            method, path = self.ROUTES[operation]
            body = {} if method == "POST" else None
        else:
            method, path, body = self._dynamic(operation, payload)
        try:
            secret = self.credential_provider()
        except Exception as exc:
            raise PairingAdminProxyError("pairing_admin_unavailable") from exc
        if not secret:
            raise PairingAdminProxyError("pairing_admin_unavailable")
        try:
            result = self.request(method, path, body, f"Bearer {secret}")
            if inspect.isawaitable(result):
                result = await result
        except PairingAdminProxyError:
            raise
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError, ValueError, TypeError) as exc:
            raise PairingAdminProxyError("management_transport_failed") from exc
        except Exception as exc:
            raise PairingAdminProxyError("management_transport_failed") from exc
        if not isinstance(result, Mapping):
            raise PairingAdminProxyError("management_response_invalid")
        return dict(result)
