"""Role credentials and short-lived, single-use mobile WSS tickets."""

from __future__ import annotations

import asyncio
import hashlib
import secrets
import threading
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
    credential_id: str


class AuthError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass
class CredentialRecord:
    credential_id: str
    name: str
    role: str
    pairing_id: str
    verifier_digest: str
    installation_id: str
    vault_id: str
    device_id: str
    endpoint_audience: str
    revoked: bool = False
    generation: int = 1


class TokenAuthenticator:
    def __init__(self, tokens: Iterable[Principal]) -> None:
        self._records: Dict[str, CredentialRecord] = {}
        self._lock = threading.RLock()
        for item in tokens:
            token = str(getattr(item, "token", ""))
            if not token:
                continue
            self.register_digest(
                CredentialRecord(
                    credential_id=str(
                        getattr(item, "credential_id", "")
                        or f"bootstrap:{item.role}:{item.name}:{item.device_id}"
                    ),
                    name=item.name,
                    role=item.role,
                    pairing_id=item.pairing_id,
                    verifier_digest=self.digest(token),
                    installation_id=item.installation_id,
                    vault_id=item.vault_id,
                    device_id=item.device_id,
                    endpoint_audience=item.endpoint_audience,
                    revoked=bool(getattr(item, "revoked", False)),
                    generation=int(getattr(item, "generation", 1)),
                )
            )

    @staticmethod
    def digest(token: str) -> str:
        return hashlib.sha256(str(token).encode("utf-8")).hexdigest()

    def register_digest(self, record: CredentialRecord) -> None:
        if not record.credential_id or len(record.verifier_digest) != 64:
            raise AuthError("invalid_credential_record")
        with self._lock:
            if record.verifier_digest in self._records:
                raise AuthError("credential_digest_collision")
            self._records[record.verifier_digest] = record

    def revoke_credential(self, credential_id: str) -> bool:
        changed = False
        with self._lock:
            for record in self._records.values():
                if secrets.compare_digest(record.credential_id, str(credential_id)):
                    record.revoked = True
                    record.generation += 1
                    changed = True
        return changed

    def credential_count(self, *, role: Optional[str] = None, active_only: bool = False) -> int:
        with self._lock:
            return sum(
                1
                for item in self._records.values()
                if (role is None or item.role == role) and (not active_only or not item.revoked)
            )

    def assert_active(
        self,
        credential_id: str,
        *,
        generation: int,
        role: str,
        installation_id: str,
        vault_id: str,
        device_id: str,
        endpoint_audience: str,
    ) -> CredentialRecord:
        with self._lock:
            for item in self._records.values():
                if not secrets.compare_digest(item.credential_id, str(credential_id)):
                    continue
                if item.revoked:
                    raise AuthError("revoked")
                for actual, expected, code in (
                    (item.role, role, "wrong_role"),
                    (item.installation_id, installation_id, "wrong_installation"),
                    (item.vault_id, vault_id, "wrong_vault"),
                    (item.device_id, device_id, "wrong_device"),
                    (item.endpoint_audience, endpoint_audience, "wrong_audience"),
                ):
                    if not secrets.compare_digest(str(actual), str(expected)):
                        raise AuthError(code)
                if item.generation != int(generation):
                    raise AuthError("stale_credential_generation")
                return item
        raise AuthError("unauthorized")

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
        digest = self.digest(presented)
        with self._lock:
            token = self._records.get(digest)
            if token is not None:
                if token.revoked:
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
    credential_id: str
    generation: int
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
        credential_id = str(
            getattr(principal, "credential_id", "")
            or f"bootstrap:{principal.role}:{principal.name}:{principal.device_id}"
        )
        grant = TicketGrant(
            credential_id=credential_id,
            generation=principal.generation,
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
