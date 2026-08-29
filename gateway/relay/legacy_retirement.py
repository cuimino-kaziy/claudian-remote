"""Persistent, narrowly scoped authority for legacy credential retirement."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import sqlite3
import stat
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping


_SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,191}")
_PROTOCOL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,95}")
_OPERATION_ID = re.compile(r"op-[0-9a-f]{32}")
_PLAN_ID = re.compile(r"plan-[A-Za-z0-9._:-]{1,194}")
_DIGEST = re.compile(r"[0-9a-f]{64}")
_REQUEST_FIELDS = frozenset(
    {
        "operation_id",
        "plan_id",
        "authority_origin",
        "owner_id",
        "installation_id",
        "mac_id",
        "vault_id",
        "role",
        "slot_id",
        "old_generation",
        "target_generation",
        "release_digest",
        "helper_digest",
        "nonce",
        "idempotency_key",
    }
)
_MAX_RUNTIME_KEY_BYTES = 4 * 1024


def read_private_runtime_key(path: Path) -> bytes:
    """Read one stable, owner-only runtime key without following symlinks."""

    path = Path(path)
    if not path.is_absolute():
        raise ValueError("legacy_retirement_runtime_key_unsafe")
    try:
        before = path.lstat()
        if (
            stat.S_ISLNK(before.st_mode)
            or not stat.S_ISREG(before.st_mode)
            or before.st_mode & (stat.S_IRWXG | stat.S_IRWXO)
            or before.st_size > _MAX_RUNTIME_KEY_BYTES
        ):
            raise ValueError("legacy_retirement_runtime_key_unsafe")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
    except ValueError:
        raise
    except OSError as exc:
        raise ValueError("legacy_retirement_runtime_key_unavailable") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or before.st_dev != opened.st_dev
            or before.st_ino != opened.st_ino
            or opened.st_mode & (stat.S_IRWXG | stat.S_IRWXO)
            or opened.st_size > _MAX_RUNTIME_KEY_BYTES
        ):
            raise ValueError("legacy_retirement_runtime_key_unsafe")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(
                descriptor,
                min(4096, _MAX_RUNTIME_KEY_BYTES + 1 - total),
            )
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > _MAX_RUNTIME_KEY_BYTES:
                raise ValueError("legacy_retirement_runtime_key_unsafe")
        after = path.lstat()
        if (
            after.st_dev != opened.st_dev
            or after.st_ino != opened.st_ino
            or after.st_size != opened.st_size
            or after.st_mtime_ns != opened.st_mtime_ns
        ):
            raise ValueError("legacy_retirement_runtime_key_unsafe")
        value = b"".join(chunks)
        if len(value) < 16:
            raise ValueError("runtime_key_invalid")
        return value
    except OSError as exc:
        raise ValueError("legacy_retirement_runtime_key_unsafe") from exc
    finally:
        os.close(descriptor)


def _safe_id(value: Any, code: str) -> str:
    if not isinstance(value, str) or not _SAFE_ID.fullmatch(value):
        raise ValueError(code)
    return value


def _integer(value: Any, code: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(code)
    return value


@dataclass(frozen=True)
class LegacyRetirementRequest:
    operation_id: str
    plan_id: str
    authority_origin: str
    owner_id: str
    installation_id: str
    mac_id: str
    vault_id: str
    role: str
    slot_id: str
    old_generation: int
    target_generation: int
    release_digest: str
    helper_digest: str
    nonce: str
    idempotency_key: str

    @classmethod
    def from_mapping(cls, value: Any) -> "LegacyRetirementRequest":
        if not isinstance(value, Mapping) or set(value) != _REQUEST_FIELDS:
            raise ValueError("legacy_retirement_request_invalid")
        raw = dict(value)
        operation_id = str(raw["operation_id"])
        plan_id = str(raw["plan_id"])
        release_digest = str(raw["release_digest"])
        helper_digest = str(raw["helper_digest"])
        if not _OPERATION_ID.fullmatch(operation_id):
            raise ValueError("legacy_retirement_operation_invalid")
        if not _PLAN_ID.fullmatch(plan_id):
            raise ValueError("legacy_retirement_plan_invalid")
        if not _DIGEST.fullmatch(release_digest) or not _DIGEST.fullmatch(
            helper_digest
        ):
            raise ValueError("legacy_retirement_digest_invalid")
        authority_origin = str(raw["authority_origin"])
        if (
            not authority_origin.startswith("https://")
            or authority_origin.endswith("/")
            or any(item in authority_origin for item in ("@", "?", "#"))
        ):
            raise ValueError("legacy_authority_origin_invalid")
        old_generation = _integer(
            raw["old_generation"], "retirement_generation_invalid"
        )
        target_generation = _integer(
            raw["target_generation"], "retirement_generation_invalid", minimum=1
        )
        if target_generation != old_generation + 1:
            raise ValueError("retirement_generation_invalid")
        return cls(
            operation_id=operation_id,
            plan_id=plan_id,
            authority_origin=authority_origin,
            owner_id=_safe_id(raw["owner_id"], "retirement_scope_invalid"),
            installation_id=_safe_id(
                raw["installation_id"], "retirement_scope_invalid"
            ),
            mac_id=_safe_id(raw["mac_id"], "retirement_scope_invalid"),
            vault_id=_safe_id(raw["vault_id"], "retirement_scope_invalid"),
            role=_safe_id(raw["role"], "retirement_scope_invalid"),
            slot_id=_safe_id(raw["slot_id"], "retirement_slot_invalid"),
            old_generation=old_generation,
            target_generation=target_generation,
            release_digest=release_digest,
            helper_digest=helper_digest,
            nonce=_safe_id(raw["nonce"], "retirement_nonce_invalid"),
            idempotency_key=_safe_id(
                raw["idempotency_key"], "retirement_idempotency_invalid"
            ),
        )

    def to_mapping(self) -> dict[str, Any]:
        return {
            field: getattr(self, field)
            for field in sorted(_REQUEST_FIELDS)
        }


class LegacyRetirementStore:
    """Authority-owned SQLite state with durable generation and tombstones."""

    def __init__(
        self,
        path: Path,
        *,
        authority_instance_id: str,
        protocol_version: str,
        runtime_key_id: str,
        runtime_key: bytes,
        restart_epoch: int,
        clock: Callable[[], int],
    ) -> None:
        self.path = Path(path)
        self.authority_instance_id = _safe_id(
            authority_instance_id, "legacy_authority_instance_invalid"
        )
        if (
            not isinstance(protocol_version, str)
            or not _PROTOCOL_ID.fullmatch(protocol_version)
        ):
            raise ValueError("legacy_authority_protocol_invalid")
        self.protocol_version = protocol_version
        self.runtime_key_id = _safe_id(
            runtime_key_id, "runtime_key_id_invalid"
        )
        if not isinstance(runtime_key, bytes) or len(runtime_key) < 16:
            raise ValueError("runtime_key_invalid")
        self._runtime_key = bytes(runtime_key)
        self.restart_epoch = _integer(
            restart_epoch, "restart_epoch_invalid", minimum=1
        )
        self.clock = clock
        self._lock = threading.RLock()
        self._database_initialized = False

    @staticmethod
    def _credential_digest(credential: bytes) -> str:
        return hashlib.sha256(credential).hexdigest()

    @staticmethod
    def _request_digest(request: LegacyRetirementRequest) -> str:
        encoded = json.dumps(
            request.to_mapping(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    @staticmethod
    def canonical_proof_payload(proof: Mapping[str, Any]) -> bytes:
        return json.dumps(
            {key: value for key, value in proof.items() if key != "evidence"},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")

    def _connect(self) -> sqlite3.Connection:
        if not self._database_initialized:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            os.chmod(self.path.parent, 0o700)
        connection = sqlite3.connect(str(self.path), timeout=10, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA synchronous=FULL")
        if not self._database_initialized:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS credentials (
                    slot_id TEXT PRIMARY KEY,
                    verifier_digest TEXT NOT NULL,
                    owner_id TEXT NOT NULL,
                    installation_id TEXT NOT NULL,
                    mac_id TEXT NOT NULL,
                    vault_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    consumers_json TEXT NOT NULL,
                    generation INTEGER NOT NULL,
                    retired INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS tombstones (
                    idempotency_key TEXT PRIMARY KEY,
                    request_digest TEXT NOT NULL,
                    proof_json TEXT NOT NULL
                );
                """
            )
            os.chmod(self.path, 0o600)
            self._database_initialized = True
        return connection

    def register_credential(
        self,
        *,
        slot_id: str,
        credential: bytes,
        owner_id: str,
        installation_id: str,
        mac_id: str,
        vault_id: str,
        role: str,
        consumer_installation_ids: tuple[str, ...],
        generation: int,
    ) -> None:
        installation_id = _safe_id(
            installation_id, "legacy_credential_scope_invalid"
        )
        if consumer_installation_ids != (installation_id,):
            raise ValueError("shared_credential_scope_unsupported")
        if not isinstance(credential, bytes) or not credential:
            raise ValueError("credential_invalid")
        values = (
            _safe_id(slot_id, "opaque_slot_id_invalid"),
            self._credential_digest(credential),
            _safe_id(owner_id, "legacy_credential_scope_invalid"),
            installation_id,
            _safe_id(mac_id, "legacy_credential_scope_invalid"),
            _safe_id(vault_id, "legacy_credential_scope_invalid"),
            _safe_id(role, "legacy_credential_scope_invalid"),
            json.dumps(list(consumer_installation_ids), separators=(",", ":")),
            _integer(generation, "retirement_generation_invalid"),
        )
        with self._lock, self._connect() as connection:
            existing = connection.execute(
                "SELECT * FROM credentials WHERE slot_id = ?", (values[0],)
            ).fetchone()
            if existing is None:
                connection.execute(
                    """
                    INSERT INTO credentials (
                        slot_id, verifier_digest, owner_id, installation_id,
                        mac_id, vault_id, role, consumers_json, generation
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    values,
                )
                return
            expected = tuple(existing[key] for key in (
                "slot_id",
                "verifier_digest",
                "owner_id",
                "installation_id",
                "mac_id",
                "vault_id",
                "role",
                "consumers_json",
            ))
            if expected != values[:8]:
                raise ValueError("legacy_credential_registration_conflict")

    def credential_active(self, slot_id: str, credential: bytes) -> bool:
        if not isinstance(credential, bytes) or not credential:
            return False
        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT verifier_digest, retired FROM credentials WHERE slot_id = ?",
                (slot_id,),
            ).fetchone()
        return bool(
            row is not None
            and int(row["retired"]) == 0
            and hmac.compare_digest(
                str(row["verifier_digest"]), self._credential_digest(credential)
            )
        )

    def descriptor(self, slot_id: str, *, authority_origin: str) -> dict[str, Any]:
        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM credentials WHERE slot_id = ?",
                (slot_id,),
            ).fetchone()
        if row is None:
            raise ValueError("retirement_slot_unknown")
        consumers = json.loads(str(row["consumers_json"]))
        return {
            "authority": {
                "authority_schema": "claudian-remote.legacy-authority/v1",
                "profile_id": "dogfood-local-v1",
                "protocol_version": self.protocol_version,
                "authority_instance_id": self.authority_instance_id,
                "authority_origin": authority_origin,
                "runtime_key_id": self.runtime_key_id,
                "owner_id": str(row["owner_id"]),
                "installation_id": str(row["installation_id"]),
                "mac_id": str(row["mac_id"]),
                "vault_id": str(row["vault_id"]),
                "role": str(row["role"]),
            },
            "slot": {
                "slot_schema": "claudian-remote.legacy-credential-slot/v1",
                "slot_id": str(row["slot_id"]),
                "owner_id": str(row["owner_id"]),
                "installation_id": str(row["installation_id"]),
                "vault_id": str(row["vault_id"]),
                "role": str(row["role"]),
                "consumer_installation_ids": consumers,
                "old_generation": int(row["generation"]),
                "target_generation": int(row["generation"]) + 1,
            },
            "restart_epoch": self.restart_epoch,
        }

    def _proof(
        self,
        request: LegacyRetirementRequest,
        *,
        outcome: str,
        issued_at: int,
    ) -> dict[str, Any]:
        proof = {
            "proof_schema": "claudian-remote.legacy-retirement-proof/v1",
            "outcome": outcome,
            "authority_instance_id": self.authority_instance_id,
            "authority_origin": request.authority_origin,
            "runtime_key_id": self.runtime_key_id,
            "owner_id": request.owner_id,
            "installation_id": request.installation_id,
            "mac_id": request.mac_id,
            "vault_id": request.vault_id,
            "role": request.role,
            "slot_id": request.slot_id,
            "old_generation": request.old_generation,
            "target_generation": request.target_generation,
            "operation_id": request.operation_id,
            "plan_id": request.plan_id,
            "release_digest": request.release_digest,
            "helper_digest": request.helper_digest,
            "nonce": request.nonce,
            "idempotency_key": request.idempotency_key,
            "issued_at_epoch": issued_at,
            "expires_at_epoch": issued_at + 300,
        }
        proof["evidence"] = base64.b64encode(
            hmac.new(
                self._runtime_key,
                self.canonical_proof_payload(proof),
                hashlib.sha256,
            ).digest()
        ).decode("ascii")
        return proof

    def verify_retirement(
        self,
        request: LegacyRetirementRequest,
        credential: bytes,
    ) -> dict[str, Any]:
        request = LegacyRetirementRequest.from_mapping(request.to_mapping())
        if not isinstance(credential, bytes) or not credential:
            raise ValueError("credential_invalid")
        request_digest = self._request_digest(request)
        now = _integer(self.clock(), "retirement_time_invalid")
        with self._lock, self._connect() as connection:
            tombstone = connection.execute(
                "SELECT request_digest FROM tombstones WHERE idempotency_key = ?",
                (request.idempotency_key,),
            ).fetchone()
            row = connection.execute(
                """
                SELECT verifier_digest, generation, retired
                FROM credentials WHERE slot_id = ?
                """,
                (request.slot_id,),
            ).fetchone()
        if (
            tombstone is None
            or row is None
            or not hmac.compare_digest(
                str(tombstone["request_digest"]), request_digest
            )
            or not hmac.compare_digest(
                str(row["verifier_digest"]),
                self._credential_digest(credential),
            )
        ):
            raise ValueError("retirement_verification_binding_invalid")
        if (
            int(row["retired"]) != 1
            or int(row["generation"]) != request.target_generation
        ):
            raise ValueError("retirement_verification_state_invalid")
        verification = {
            "verification_schema": "claudian-remote.legacy-retirement-health/v1",
            "authority_instance_id": self.authority_instance_id,
            "protocol_version": self.protocol_version,
            "restart_epoch": self.restart_epoch,
            "runtime_key_id": self.runtime_key_id,
            "slot_id": request.slot_id,
            "target_generation": request.target_generation,
            "idempotency_key": request.idempotency_key,
            "old_credential_rejected": True,
            "issued_at_epoch": now,
        }
        verification["evidence"] = base64.b64encode(
            hmac.new(
                self._runtime_key,
                self.canonical_proof_payload(verification),
                hashlib.sha256,
            ).digest()
        ).decode("ascii")
        return verification

    def reconcile(
        self,
        request: LegacyRetirementRequest,
        credential: bytes,
    ) -> dict[str, Any]:
        """Read one durable retirement outcome without changing authority state."""

        request = LegacyRetirementRequest.from_mapping(request.to_mapping())
        if not isinstance(credential, bytes) or not credential:
            raise ValueError("credential_invalid")
        request_digest = self._request_digest(request)
        now = _integer(self.clock(), "retirement_time_invalid")
        with self._lock, self._connect() as connection:
            tombstone = connection.execute(
                "SELECT * FROM tombstones WHERE idempotency_key = ?",
                (request.idempotency_key,),
            ).fetchone()
            row = connection.execute(
                "SELECT * FROM credentials WHERE slot_id = ?",
                (request.slot_id,),
            ).fetchone()
        if row is None:
            raise ValueError("retirement_slot_unknown")
        if not hmac.compare_digest(
            str(row["verifier_digest"]), self._credential_digest(credential)
        ):
            raise ValueError("retirement_credential_invalid")
        scope = tuple(
            str(row[key])
            for key in ("owner_id", "installation_id", "mac_id", "vault_id", "role")
        )
        if scope != (
            request.owner_id,
            request.installation_id,
            request.mac_id,
            request.vault_id,
            request.role,
        ):
            raise ValueError("retirement_scope_mismatch")
        if tombstone is not None:
            if not hmac.compare_digest(
                str(tombstone["request_digest"]), request_digest
            ):
                raise ValueError("retirement_idempotency_conflict")
            if (
                int(row["retired"]) != 1
                or int(row["generation"]) != request.target_generation
            ):
                raise ValueError("retirement_verification_state_invalid")
            return {
                "outcome": "retired",
                "proof": self._proof(request, outcome="already_retired", issued_at=now),
                "verification": self.verify_retirement(request, credential),
                "restart_epoch": self.restart_epoch,
            }
        if (
            int(row["retired"]) != 0
            or int(row["generation"]) != request.old_generation
        ):
            raise ValueError("retirement_generation_mismatch")
        receipt = {
            "reconciliation_schema": "claudian-remote.legacy-retirement-reconciliation/v1",
            "outcome": "not_applied",
            "authority_instance_id": self.authority_instance_id,
            "authority_origin": request.authority_origin,
            "runtime_key_id": self.runtime_key_id,
            "owner_id": request.owner_id,
            "installation_id": request.installation_id,
            "mac_id": request.mac_id,
            "vault_id": request.vault_id,
            "role": request.role,
            "slot_id": request.slot_id,
            "old_generation": request.old_generation,
            "target_generation": request.target_generation,
            "current_generation": int(row["generation"]),
            "operation_id": request.operation_id,
            "plan_id": request.plan_id,
            "release_digest": request.release_digest,
            "helper_digest": request.helper_digest,
            "nonce": request.nonce,
            "idempotency_key": request.idempotency_key,
            "issued_at_epoch": now,
            "expires_at_epoch": now + 300,
        }
        receipt["evidence"] = base64.b64encode(
            hmac.new(
                self._runtime_key,
                self.canonical_proof_payload(receipt),
                hashlib.sha256,
            ).digest()
        ).decode("ascii")
        return {"outcome": "not_applied", "receipt": receipt}

    def retire(
        self,
        request: LegacyRetirementRequest,
        credential: bytes,
    ) -> dict[str, Any]:
        request = LegacyRetirementRequest.from_mapping(request.to_mapping())
        if not isinstance(credential, bytes) or not credential:
            raise ValueError("credential_invalid")
        request_digest = self._request_digest(request)
        now = _integer(self.clock(), "retirement_time_invalid")
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                tombstone = connection.execute(
                    "SELECT * FROM tombstones WHERE idempotency_key = ?",
                    (request.idempotency_key,),
                ).fetchone()
                if tombstone is not None:
                    if not hmac.compare_digest(
                        str(tombstone["request_digest"]), request_digest
                    ):
                        raise ValueError("retirement_idempotency_conflict")
                    row = connection.execute(
                        "SELECT verifier_digest FROM credentials WHERE slot_id = ?",
                        (request.slot_id,),
                    ).fetchone()
                    if row is None:
                        raise ValueError("retirement_slot_unknown")
                    if not hmac.compare_digest(
                        str(row["verifier_digest"]),
                        self._credential_digest(credential),
                    ):
                        raise ValueError("retirement_credential_invalid")
                    persisted = json.loads(str(tombstone["proof_json"]))
                    proof = self._proof(
                        request,
                        outcome="already_retired",
                        issued_at=now,
                    )
                    if (
                        persisted.get("authority_instance_id")
                        != proof["authority_instance_id"]
                        or persisted.get("target_generation")
                        != proof["target_generation"]
                    ):
                        raise ValueError("retirement_tombstone_invalid")
                    connection.execute("COMMIT")
                    return proof
                row = connection.execute(
                    "SELECT * FROM credentials WHERE slot_id = ?",
                    (request.slot_id,),
                ).fetchone()
                if row is None:
                    raise ValueError("retirement_slot_unknown")
                scope = tuple(
                    str(row[key])
                    for key in (
                        "owner_id",
                        "installation_id",
                        "mac_id",
                        "vault_id",
                        "role",
                    )
                )
                if scope != (
                    request.owner_id,
                    request.installation_id,
                    request.mac_id,
                    request.vault_id,
                    request.role,
                ):
                    raise ValueError("retirement_scope_mismatch")
                consumers = json.loads(str(row["consumers_json"]))
                if consumers != [request.installation_id]:
                    raise ValueError("shared_credential_scope_unsupported")
                if int(row["generation"]) != request.old_generation:
                    raise ValueError("retirement_generation_mismatch")
                if int(row["retired"]) != 0:
                    raise ValueError("retirement_generation_mismatch")
                if not hmac.compare_digest(
                    str(row["verifier_digest"]),
                    self._credential_digest(credential),
                ):
                    raise ValueError("retirement_credential_invalid")
                proof = self._proof(request, outcome="retired", issued_at=now)
                connection.execute(
                    """
                    UPDATE credentials
                    SET retired = 1, generation = ?
                    WHERE slot_id = ? AND generation = ? AND retired = 0
                    """,
                    (
                        request.target_generation,
                        request.slot_id,
                        request.old_generation,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO tombstones (
                        idempotency_key, request_digest, proof_json
                    ) VALUES (?, ?, ?)
                    """,
                    (
                        request.idempotency_key,
                        request_digest,
                        json.dumps(
                            proof,
                            sort_keys=True,
                            separators=(",", ":"),
                            ensure_ascii=True,
                        ),
                    ),
                )
                connection.execute("COMMIT")
                return proof
            except Exception:
                connection.execute("ROLLBACK")
                raise
