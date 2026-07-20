"""Role credentials and short-lived, single-use mobile WSS tickets."""

from __future__ import annotations

import asyncio
import hashlib
import secrets
import time
from dataclasses import dataclass
from typing import Dict, Iterable, Optional, Protocol


class Principal(Protocol):
    name: str
    role: str
    pairing_id: str
    token: str
    installation_id: str
    vault_id: str
    device_id: str
    endpoint_audience: str
    revoked: bool
    generation: int


class AuthError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class TokenAuthenticator:
    def __init__(self, tokens: Iterable[Principal]) -> None:
        self._tokens = tuple(tokens)

    def authenticate(
        self,
        authorization: str,
        required_role: Optional[str] = None,
        *,
        installation_id: Optional[str] = None,
        vault_id: Optional[str] = None,
        device_id: Optional[str] = None,
        endpoint_audience: Optional[str] = None,
        generation: Optional[int] = None,
    ) -> Principal:
        if not authorization.startswith("Bearer "):
            raise AuthError("unauthorized")
        presented = authorization[7:].strip()
        for token in self._tokens:
            if secrets.compare_digest(token.token, presented):
                if getattr(token, "revoked", False):
                    raise AuthError("revoked")
                if required_role and token.role != required_role:
                    raise AuthError("wrong_role")
                for expected, actual, code in (
                    (installation_id, getattr(token, "installation_id", ""), "wrong_installation"),
                    (vault_id, getattr(token, "vault_id", ""), "wrong_vault"),
                    (device_id, getattr(token, "device_id", ""), "wrong_device"),
                    (endpoint_audience, getattr(token, "endpoint_audience", ""), "wrong_audience"),
                ):
                    if expected is not None and not secrets.compare_digest(str(actual), str(expected)):
                        raise AuthError(code)
                if generation is not None and int(getattr(token, "generation", 0)) != int(generation):
                    raise AuthError("stale_credential_generation")
                return token
        raise AuthError("unauthorized")


@dataclass(frozen=True)
class TicketGrant:
    role: str
    pairing_id: str
    device_id: str
    client_instance_id: str
    installation_id: str
    vault_id: str
    endpoint_audience: str
    expires_at: float


class TicketStore:
    def __init__(self, ttl_seconds: float = 30.0, clock=time.time) -> None:
        self.ttl_seconds = ttl_seconds
        self.clock = clock
        self._tickets: Dict[str, TicketGrant] = {}
        self._lock = asyncio.Lock()

    @staticmethod
    def _digest(ticket: str) -> str:
        return hashlib.sha256(ticket.encode("utf-8")).hexdigest()

    async def issue(self, principal: Principal, device_id: str, client_instance_id: str) -> tuple[str, TicketGrant]:
        if principal.role != "mobile":
            raise AuthError("wrong_role")
        if not device_id or not client_instance_id:
            raise AuthError("missing_ticket_binding")
        if not secrets.compare_digest(str(principal.device_id), str(device_id)):
            raise AuthError("wrong_device")
        ticket = secrets.token_urlsafe(32)
        grant = TicketGrant(
            role="mobile",
            pairing_id=principal.pairing_id,
            device_id=str(device_id)[:128],
            client_instance_id=str(client_instance_id)[:128],
            installation_id=principal.installation_id,
            vault_id=principal.vault_id,
            endpoint_audience=principal.endpoint_audience,
            expires_at=self.clock() + self.ttl_seconds,
        )
        async with self._lock:
            self._purge_locked()
            self._tickets[self._digest(ticket)] = grant
        return ticket, grant

    async def consume(
        self,
        ticket: str,
        *,
        role: str,
        device_id: str,
        client_instance_id: str,
    ) -> TicketGrant:
        digest = self._digest(str(ticket))
        async with self._lock:
            grant = self._tickets.pop(digest, None)
            self._purge_locked()
        if grant is None:
            raise AuthError("ticket_invalid_or_used")
        if grant.expires_at <= self.clock():
            raise AuthError("ticket_expired")
        if role != grant.role:
            raise AuthError("wrong_role")
        if not secrets.compare_digest(grant.device_id, str(device_id)):
            raise AuthError("ticket_binding_mismatch")
        if not secrets.compare_digest(grant.client_instance_id, str(client_instance_id)):
            raise AuthError("ticket_binding_mismatch")
        return grant

    async def count(self) -> int:
        async with self._lock:
            self._purge_locked()
            return len(self._tickets)

    def _purge_locked(self) -> None:
        now = self.clock()
        self._tickets = {digest: grant for digest, grant in self._tickets.items() if grant.expires_at > now}


def origin_allowed(origin: Optional[str], allowed_origins: Iterable[str]) -> bool:
    allowed = set(allowed_origins)
    if not origin:
        return True  # Native/desktop clients commonly omit Origin.
    return origin in allowed
