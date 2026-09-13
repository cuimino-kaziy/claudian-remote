"""Single-use device enrollment and digest-only persistent credentials."""

from __future__ import annotations

import asyncio
import hashlib
import secrets
import sqlite3
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from gateway.relay.auth import CredentialRecord, TokenAuthenticator


SHORT_CODE_ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
TERMINAL_STATUSES = {"issued", "rejected", "expired", "attempts_exhausted", "credential_delivery_expired"}


class PairingError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class CreatedClaim:
    claim_id: str
    expires_at: float
    claim_token: str = field(repr=False)
    short_code: str = field(repr=False)


@dataclass(frozen=True)
class PendingClaim:
    claim_id: str
    status: str
    expires_at: float
    redemption_handle: str = field(repr=False)


@dataclass(frozen=True)
class ApprovedClaim:
    claim_id: str
    status: str
    credential_id: str
    device_id: str


@dataclass(frozen=True)
class IssuedCredential:
    credential_id: str
    device_id: str
    generation: int
    credential: str = field(repr=False)


@dataclass(frozen=True)
class ClaimInspection:
    claim_id: str
    status: str
    expires_at: float
    installation_id: str
    vault_id: str
    endpoint_audience: str
    device_id: str
    device_name: str
    credential_id: str


@dataclass(frozen=True)
class DeviceInspection:
    credential_id: str
    device_id: str
    device_name: str
    status: str
    generation: int


def _digest(value: str) -> str:
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


def _safe_text(value: Any, *, maximum: int = 128) -> str:
    text = str(value or "").strip()
    if not text or len(text) > maximum or any(ord(char) < 32 for char in text):
        raise PairingError("invalid_device_context")
    return text


class PairingStore:
    """Owns pairing state; raw claims and durable credentials never reach SQLite."""

    def __init__(
        self,
        path: Path | str,
        *,
        authenticator: TokenAuthenticator,
        ttl_seconds: float = 300,
        terminal_retention_seconds: float = 3600,
        max_attempts: int = 5,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.path = Path(path)
        self.authenticator = authenticator
        self.ttl_seconds = float(ttl_seconds)
        self.terminal_retention_seconds = float(terminal_retention_seconds)
        self.max_attempts = int(max_attempts)
        self.clock = clock
        self._connection: Optional[sqlite3.Connection] = None
        self._lock = asyncio.Lock()
        self._issuance: Dict[str, IssuedCredential] = {}
        self._request_attempts: Dict[str, tuple[int, float]] = {}

    async def start(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path.parent.chmod(0o700)
        connection = sqlite3.connect(self.path, isolation_level=None, check_same_thread=False)
        self.path.chmod(0o600)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS pairing_claims (
              claim_id TEXT PRIMARY KEY,
              claim_digest TEXT,
              short_digest TEXT,
              redemption_digest TEXT,
              status TEXT NOT NULL,
              pairing_id TEXT NOT NULL,
              installation_id TEXT NOT NULL,
              vault_id TEXT NOT NULL,
              endpoint_audience TEXT NOT NULL,
              device_id TEXT NOT NULL DEFAULT '',
              device_name TEXT NOT NULL DEFAULT '',
              credential_id TEXT NOT NULL DEFAULT '',
              attempts INTEGER NOT NULL DEFAULT 0,
              created_at REAL NOT NULL,
              expires_at REAL NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS pairing_claim_digest_idx
              ON pairing_claims(claim_digest) WHERE claim_digest IS NOT NULL;
            CREATE UNIQUE INDEX IF NOT EXISTS pairing_short_digest_idx
              ON pairing_claims(short_digest) WHERE short_digest IS NOT NULL;
            CREATE TABLE IF NOT EXISTS device_credentials (
              credential_id TEXT PRIMARY KEY,
              verifier_digest TEXT NOT NULL UNIQUE,
              name TEXT NOT NULL,
              role TEXT NOT NULL,
              pairing_id TEXT NOT NULL,
              installation_id TEXT NOT NULL,
              vault_id TEXT NOT NULL,
              device_id TEXT NOT NULL,
              endpoint_audience TEXT NOT NULL,
              generation INTEGER NOT NULL,
              created_at REAL NOT NULL,
              revoked_at REAL,
              revoke_reason TEXT NOT NULL DEFAULT ''
            );
            """
        )
        self._connection = connection
        for row in connection.execute("SELECT * FROM device_credentials"):
            self.authenticator.register_digest(self._record(row))
        # An approved claim's raw credential exists only in the process-local
        # one-time delivery slot.  After a restart that slot is gone, so any
        # corresponding verifier must fail closed instead of becoming an
        # active orphan the mobile can never receive.
        approved = connection.execute(
            "SELECT * FROM pairing_claims WHERE status='approved'"
        ).fetchall()
        for row in approved:
            self._revoke_claim_credential_locked(row, "credential_delivery_lost")
            connection.execute(
                """UPDATE pairing_claims SET status='credential_delivery_expired',
                   claim_digest=NULL, short_digest=NULL, redemption_digest=NULL
                   WHERE claim_id=?""",
                (row["claim_id"],),
            )
        await self.expire_claims()

    async def close(self) -> None:
        async with self._lock:
            self._issuance.clear()
            if self._connection is not None:
                self._connection.close()
                self._connection = None

    @property
    def connection(self) -> sqlite3.Connection:
        if self._connection is None:
            raise RuntimeError("pairing_store_not_started")
        return self._connection

    @staticmethod
    def _record(row: sqlite3.Row) -> CredentialRecord:
        return CredentialRecord(
            credential_id=row["credential_id"],
            name=row["name"],
            role=row["role"],
            pairing_id=row["pairing_id"],
            verifier_digest=row["verifier_digest"],
            installation_id=row["installation_id"],
            vault_id=row["vault_id"],
            device_id=row["device_id"],
            endpoint_audience=row["endpoint_audience"],
            revoked=row["revoked_at"] is not None,
            generation=int(row["generation"]),
        )

    async def create_claim(
        self,
        *,
        installation_id: str,
        vault_id: str,
        endpoint_audience: str,
        pairing_id: str,
    ) -> CreatedClaim:
        claim_id = "claim-" + uuid.uuid4().hex
        claim_token = secrets.token_urlsafe(32)
        short_code = "".join(secrets.choice(SHORT_CODE_ALPHABET) for _ in range(8))
        created_at = self.clock()
        expires_at = created_at + self.ttl_seconds
        async with self._lock:
            self.connection.execute(
                """INSERT INTO pairing_claims
                   (claim_id, claim_digest, short_digest, redemption_digest, status,
                    pairing_id, installation_id, vault_id, endpoint_audience,
                    created_at, expires_at)
                   VALUES (?, ?, ?, NULL, 'created', ?, ?, ?, ?, ?, ?)""",
                (
                    claim_id,
                    _digest(claim_token),
                    _digest(short_code),
                    pairing_id,
                    installation_id,
                    vault_id,
                    endpoint_audience,
                    created_at,
                    expires_at,
                ),
            )
        return CreatedClaim(claim_id, expires_at, claim_token, short_code)

    def _check_profile(
        self,
        row: sqlite3.Row,
        installation_id: str,
        vault_id: str,
        endpoint_audience: str,
    ) -> None:
        # The synced non-secret Vault identity is always required, so opening a
        # claim in another Vault fails before authority can be minted.  A fresh
        # phone may not yet have installation/audience device-local state; for
        # that first redemption those values are derived from the claim.  When
        # supplied (deep-link path), they still must match exactly.
        if not vault_id or not secrets.compare_digest(str(vault_id), str(row["vault_id"])):
            raise PairingError("wrong_vault")
        if installation_id and not secrets.compare_digest(
            str(installation_id), str(row["installation_id"])
        ):
            raise PairingError("wrong_installation")
        if endpoint_audience and not secrets.compare_digest(
            str(endpoint_audience), str(row["endpoint_audience"])
        ):
            raise PairingError("wrong_audience")

    def _invalid_attempt(self, requester: str) -> None:
        key = _digest(str(requester or "unknown"))
        count, reset_at = self._request_attempts.get(key, (0, self.clock() + self.ttl_seconds))
        if self.clock() >= reset_at:
            count, reset_at = 0, self.clock() + self.ttl_seconds
        count += 1
        self._request_attempts[key] = (count, reset_at)
        if count >= self.max_attempts:
            raise PairingError("attempt_limit_exceeded")
        raise PairingError("claim_invalid")

    def _requester_blocked(self, requester: str) -> bool:
        key = _digest(str(requester or "unknown"))
        count, reset_at = self._request_attempts.get(key, (0, 0.0))
        if self.clock() >= reset_at:
            self._request_attempts.pop(key, None)
            return False
        return count >= self.max_attempts

    def _invalid_claim_attempt(self, row: sqlite3.Row, requester: str) -> None:
        attempts = int(row["attempts"]) + 1
        if attempts >= self.max_attempts:
            self.connection.execute(
                """UPDATE pairing_claims SET attempts=?, status='attempts_exhausted',
                   claim_digest=NULL, short_digest=NULL, redemption_digest=NULL WHERE claim_id=?""",
                (attempts, row["claim_id"]),
            )
            key = _digest(str(requester or "unknown"))
            self._request_attempts[key] = (self.max_attempts, self.clock() + self.ttl_seconds)
            raise PairingError("attempt_limit_exceeded")
        self.connection.execute(
            "UPDATE pairing_claims SET attempts=? WHERE claim_id=?", (attempts, row["claim_id"])
        )
        self._invalid_attempt(requester)

    async def redeem(
        self,
        *,
        claim_id: Optional[str],
        claim_token: Optional[str],
        short_code: Optional[str],
        device_id: str,
        device_name: str,
        requester: str,
        installation_id: str,
        vault_id: str,
        endpoint_audience: str,
    ) -> PendingClaim:
        device_id = _safe_text(device_id)
        device_name = _safe_text(device_name)
        async with self._lock:
            if self._requester_blocked(requester):
                raise PairingError("attempt_limit_exceeded")
            if claim_id and claim_token:
                row = self.connection.execute(
                    "SELECT * FROM pairing_claims WHERE claim_id = ?", (str(claim_id),)
                ).fetchone()
                valid = bool(
                    row
                    and row["claim_digest"]
                    and secrets.compare_digest(row["claim_digest"], _digest(str(claim_token)))
                )
            elif short_code:
                normalized = str(short_code).replace("-", "").replace(" ", "").upper()
                row = self.connection.execute(
                    "SELECT * FROM pairing_claims WHERE short_digest = ?", (_digest(normalized),)
                ).fetchone()
                valid = row is not None
            else:
                row, valid = None, False
            if row is not None and not valid:
                self._invalid_claim_attempt(row, requester)
            if not valid or row is None:
                self._invalid_attempt(requester)
            if row["status"] == "attempts_exhausted":
                raise PairingError("attempt_limit_exceeded")
            if row["status"] != "created":
                raise PairingError("claim_replayed")
            if float(row["expires_at"]) <= self.clock():
                self.connection.execute(
                    "UPDATE pairing_claims SET status='expired', claim_digest=NULL, short_digest=NULL WHERE claim_id=?",
                    (row["claim_id"],),
                )
                raise PairingError("claim_expired")
            self._check_profile(row, installation_id, vault_id, endpoint_audience)
            redemption_handle = secrets.token_urlsafe(32)
            self.connection.execute("BEGIN IMMEDIATE")
            try:
                updated = self.connection.execute(
                    """UPDATE pairing_claims
                       SET status='pending_approval', short_digest=NULL,
                           redemption_digest=?, device_id=?, device_name=?
                       WHERE claim_id=? AND status='created'""",
                    (_digest(redemption_handle), device_id, device_name, row["claim_id"]),
                )
                if updated.rowcount != 1:
                    raise PairingError("claim_replayed")
                self.connection.execute("COMMIT")
            except Exception:
                self.connection.execute("ROLLBACK")
                raise
            self._request_attempts.pop(_digest(str(requester or "unknown")), None)
            return PendingClaim(row["claim_id"], "pending_approval", float(row["expires_at"]), redemption_handle)

    async def approve(
        self,
        claim_id: str,
        *,
        expected_device_id: str,
        installation_id: str,
        vault_id: str,
        endpoint_audience: str,
    ) -> ApprovedClaim:
        async with self._lock:
            row = self.connection.execute(
                "SELECT * FROM pairing_claims WHERE claim_id=?", (str(claim_id),)
            ).fetchone()
            if row is None:
                raise PairingError("claim_not_found")
            if row["status"] != "pending_approval":
                raise PairingError("claim_replayed")
            if float(row["expires_at"]) <= self.clock():
                self.connection.execute(
                    "UPDATE pairing_claims SET status='expired', redemption_digest=NULL WHERE claim_id=?",
                    (row["claim_id"],),
                )
                raise PairingError("claim_expired")
            self._check_profile(row, installation_id, vault_id, endpoint_audience)
            if not secrets.compare_digest(row["device_id"], str(expected_device_id)):
                raise PairingError("wrong_device")
            credential = secrets.token_urlsafe(32)
            credential_id = "device-credential-" + uuid.uuid4().hex
            generation_row = self.connection.execute(
                "SELECT COALESCE(MAX(generation), 0) AS value FROM device_credentials WHERE device_id=?",
                (row["device_id"],),
            ).fetchone()
            generation = int(generation_row["value"]) + 1
            now = self.clock()
            self.connection.execute("BEGIN IMMEDIATE")
            try:
                self.connection.execute(
                    """INSERT INTO device_credentials
                       (credential_id, verifier_digest, name, role, pairing_id,
                        installation_id, vault_id, device_id, endpoint_audience,
                        generation, created_at, revoked_at, revoke_reason)
                       VALUES (?, ?, ?, 'mobile', ?, ?, ?, ?, ?, ?, ?, NULL, '')""",
                    (
                        credential_id,
                        _digest(credential),
                        row["device_name"],
                        row["pairing_id"],
                        row["installation_id"],
                        row["vault_id"],
                        row["device_id"],
                        row["endpoint_audience"],
                        generation,
                        now,
                    ),
                )
                updated = self.connection.execute(
                    "UPDATE pairing_claims SET status='approved', credential_id=? WHERE claim_id=? AND status='pending_approval'",
                    (credential_id, row["claim_id"]),
                )
                if updated.rowcount != 1:
                    raise PairingError("claim_replayed")
                self.connection.execute("COMMIT")
            except Exception:
                self.connection.execute("ROLLBACK")
                raise
            record_row = self.connection.execute(
                "SELECT * FROM device_credentials WHERE credential_id=?", (credential_id,)
            ).fetchone()
            self.authenticator.register_digest(self._record(record_row))
            self._issuance[row["claim_id"]] = IssuedCredential(
                credential_id, row["device_id"], generation, credential
            )
            return ApprovedClaim(row["claim_id"], "approved", credential_id, row["device_id"])

    async def complete(self, claim_id: str, redemption_handle: str, *, device_id: str) -> IssuedCredential:
        async with self._lock:
            row = self.connection.execute(
                "SELECT * FROM pairing_claims WHERE claim_id=?", (str(claim_id),)
            ).fetchone()
            if row is not None and row["status"] == "credential_delivery_expired":
                raise PairingError("credential_delivery_expired")
            if row is not None and row["status"] == "pending_approval":
                raise PairingError("claim_pending_approval")
            if row is None or row["status"] != "approved":
                raise PairingError("claim_replayed")
            if float(row["expires_at"]) <= self.clock():
                self._issuance.pop(row["claim_id"], None)
                self._revoke_claim_credential_locked(row, "claim_expired_before_delivery")
                self.connection.execute(
                    "UPDATE pairing_claims SET status='credential_delivery_expired', claim_digest=NULL, redemption_digest=NULL WHERE claim_id=?",
                    (row["claim_id"],),
                )
                raise PairingError("claim_expired")
            if not row["redemption_digest"] or not secrets.compare_digest(
                row["redemption_digest"], _digest(str(redemption_handle))
            ):
                raise PairingError("claim_invalid")
            if not secrets.compare_digest(row["device_id"], str(device_id)):
                raise PairingError("wrong_device")
            issued = self._issuance.pop(row["claim_id"], None)
            if issued is None:
                self._revoke_claim_credential_locked(row, "credential_delivery_lost")
                self.connection.execute(
                    "UPDATE pairing_claims SET status='credential_delivery_expired', claim_digest=NULL, redemption_digest=NULL WHERE claim_id=?",
                    (row["claim_id"],),
                )
                raise PairingError("credential_delivery_expired")
            self.connection.execute(
                "UPDATE pairing_claims SET status='issued', claim_digest=NULL, redemption_digest=NULL WHERE claim_id=?",
                (row["claim_id"],),
            )
            return issued

    def _revoke_claim_credential_locked(self, row: sqlite3.Row, reason: str) -> None:
        credential_id = str(row["credential_id"] or "")
        if not credential_id:
            return
        self.connection.execute(
            """UPDATE device_credentials SET revoked_at=COALESCE(revoked_at, ?),
               revoke_reason=CASE WHEN revoked_at IS NULL THEN ? ELSE revoke_reason END,
               generation=CASE WHEN revoked_at IS NULL THEN generation+1 ELSE generation END
               WHERE credential_id=?""",
            (self.clock(), str(reason)[:64], credential_id),
        )
        self.authenticator.revoke_credential(credential_id)

    async def reject(
        self,
        claim_id: str,
        *,
        installation_id: str,
        vault_id: str,
        endpoint_audience: str,
    ) -> ClaimInspection:
        async with self._lock:
            row = self.connection.execute(
                "SELECT * FROM pairing_claims WHERE claim_id=?", (str(claim_id),)
            ).fetchone()
            if row is None:
                raise PairingError("claim_not_found")
            self._check_profile(row, installation_id, vault_id, endpoint_audience)
            if row["status"] != "pending_approval":
                raise PairingError("claim_replayed")
            self._issuance.pop(row["claim_id"], None)
            self.connection.execute(
                """UPDATE pairing_claims SET status='rejected', claim_digest=NULL,
                   short_digest=NULL, redemption_digest=NULL WHERE claim_id=?""",
                (row["claim_id"],),
            )
        return await self.inspect_claim(claim_id)

    async def expire_claims(self) -> int:
        async with self._lock:
            now = self.clock()
            rows = self.connection.execute(
                "SELECT * FROM pairing_claims WHERE expires_at <= ? AND status IN ('created','pending_approval','approved')",
                (now,),
            ).fetchall()
            for row in rows:
                self._issuance.pop(row["claim_id"], None)
                self._revoke_claim_credential_locked(row, "claim_expired_before_delivery")
                status = "credential_delivery_expired" if row["status"] == "approved" else "expired"
                self.connection.execute(
                    """UPDATE pairing_claims SET status=?, claim_digest=NULL,
                       short_digest=NULL, redemption_digest=NULL WHERE claim_id=?""",
                    (status, row["claim_id"]),
                )
            return len(rows)

    async def prune_claims(self) -> Dict[str, int]:
        """Expire active claims and bound terminal claim metadata retention."""
        expired = await self.expire_claims()
        async with self._lock:
            expired_requesters = [
                key for key, (_count, reset_at) in self._request_attempts.items()
                if reset_at <= self.clock()
            ]
            for key in expired_requesters:
                self._request_attempts.pop(key, None)
            cutoff = self.clock() - self.terminal_retention_seconds
            placeholders = ",".join("?" for _ in TERMINAL_STATUSES)
            deleted = self.connection.execute(
                f"DELETE FROM pairing_claims WHERE status IN ({placeholders}) AND expires_at <= ?",
                (*sorted(TERMINAL_STATUSES), cutoff),
            ).rowcount
            return {
                "expired": expired,
                "deleted_terminal": int(deleted),
                "deleted_attempt_windows": len(expired_requesters),
            }

    async def inspect_claim(self, claim_id: str) -> ClaimInspection:
        async with self._lock:
            row = self.connection.execute(
                "SELECT * FROM pairing_claims WHERE claim_id=?", (str(claim_id),)
            ).fetchone()
            if row is None:
                raise PairingError("claim_not_found")
            return ClaimInspection(
                row["claim_id"],
                row["status"],
                float(row["expires_at"]),
                row["installation_id"],
                row["vault_id"],
                row["endpoint_audience"],
                row["device_id"],
                row["device_name"],
                row["credential_id"],
            )

    async def pending_claims(
        self,
        *,
        installation_id: str,
        vault_id: str,
        endpoint_audience: str,
    ) -> list[ClaimInspection]:
        async with self._lock:
            rows = self.connection.execute(
                """SELECT claim_id FROM pairing_claims
                   WHERE status='pending_approval' AND installation_id=? AND vault_id=?
                     AND endpoint_audience=? ORDER BY created_at""",
                (installation_id, vault_id, endpoint_audience),
            ).fetchall()
        return [await self.inspect_claim(row["claim_id"]) for row in rows]

    async def devices(
        self,
        *,
        installation_id: str,
        vault_id: str,
        endpoint_audience: str,
    ) -> list[DeviceInspection]:
        async with self._lock:
            rows = self.connection.execute(
                """SELECT credential_id, device_id, name, generation, revoked_at
                   FROM device_credentials
                   WHERE installation_id=? AND vault_id=? AND endpoint_audience=?
                   ORDER BY created_at DESC, credential_id DESC""",
                (installation_id, vault_id, endpoint_audience),
            ).fetchall()
            return [
                DeviceInspection(
                    credential_id=row["credential_id"],
                    device_id=row["device_id"],
                    device_name=row["name"],
                    status="revoked" if row["revoked_at"] is not None else "active",
                    generation=int(row["generation"]),
                )
                for row in rows
            ]

    async def revoke_device(
        self,
        *,
        device_id: str,
        installation_id: str,
        vault_id: str,
        endpoint_audience: str,
        reason: str,
    ) -> list[str]:
        async with self.authenticator.command_boundary():
            async with self._lock:
                rows = self.connection.execute(
                    """SELECT credential_id FROM device_credentials
                       WHERE device_id=? AND installation_id=? AND vault_id=?
                         AND endpoint_audience=? AND revoked_at IS NULL""",
                    (device_id, installation_id, vault_id, endpoint_audience),
                ).fetchall()
                ids = [row["credential_id"] for row in rows]
                now = self.clock()
                for credential_id in ids:
                    self.connection.execute(
                        """UPDATE device_credentials SET revoked_at=?, revoke_reason=?, generation=generation+1
                           WHERE credential_id=? AND revoked_at IS NULL""",
                        (now, str(reason or "revoked")[:64], credential_id),
                    )
                    self.authenticator.revoke_credential(credential_id)
                return ids

    async def diagnostic_summary(self) -> Dict[str, Any]:
        async with self._lock:
            claims = {
                row["status"]: int(row["count"])
                for row in self.connection.execute(
                    "SELECT status, COUNT(*) AS count FROM pairing_claims GROUP BY status"
                )
            }
            credentials = self.connection.execute(
                "SELECT COUNT(*) AS count, SUM(CASE WHEN revoked_at IS NULL THEN 1 ELSE 0 END) AS active FROM device_credentials"
            ).fetchone()
            return {
                "claim_counts": claims,
                "credential_count": int(credentials["count"] or 0),
                "active_credential_count": int(credentials["active"] or 0),
            }
