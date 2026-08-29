"""Strict, secret-isolated contracts for legacy credential retirement.

This module deliberately contains no network or Relay implementation.  U3
defines the authority/proof boundary; supported local and VPS adapters are
added later and must produce these exact contracts.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import ssl
import stat
import time
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from contextlib import nullcontext
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit

from .checkpoint import CheckpointStore, OperationLock
from .model import (
    ActionOwner,
    AmbiguityState,
    CredentialEffect,
    EffectDisposition,
    EffectSummary,
    NextAction,
    NextActionType,
    RecoveryPolicy,
)


AUTHORITY_SCHEMA = "claudian-remote.legacy-authority/v1"
SLOT_SCHEMA = "claudian-remote.legacy-credential-slot/v1"
PROOF_SCHEMA = "claudian-remote.legacy-retirement-proof/v1"
COMMIT_SCHEMA = "claudian-remote.retirement-commit/v1"
PROFILE_SCHEMA = "claudian-remote.legacy-authority-profile/v1"
INTENT_SCHEMA = "claudian-remote.legacy-retirement-intent/v1"
RECONCILIATION_SCHEMA = "claudian-remote.legacy-retirement-reconciliation/v1"

_SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,191}")
_PROTOCOL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,95}")
_OPERATION_ID = re.compile(r"op-[0-9a-f]{32}")
_PLAN_ID = re.compile(r"plan-[A-Za-z0-9._:-]{1,194}")
_DIGEST = re.compile(r"[0-9a-f]{64}")
_PROOF_FIELDS = frozenset(
    {
        "proof_schema",
        "outcome",
        "authority_instance_id",
        "authority_origin",
        "runtime_key_id",
        "owner_id",
        "installation_id",
        "mac_id",
        "vault_id",
        "role",
        "slot_id",
        "old_generation",
        "target_generation",
        "operation_id",
        "plan_id",
        "release_digest",
        "helper_digest",
        "nonce",
        "idempotency_key",
        "issued_at_epoch",
        "expires_at_epoch",
        "evidence",
    }
)
_AUTHORITY_FIELDS = frozenset(
    {
        "authority_schema",
        "profile_id",
        "protocol_version",
        "authority_instance_id",
        "authority_origin",
        "runtime_key_id",
        "owner_id",
        "installation_id",
        "mac_id",
        "vault_id",
        "role",
    }
)
_SLOT_FIELDS = frozenset(
    {
        "slot_schema",
        "slot_id",
        "owner_id",
        "installation_id",
        "vault_id",
        "role",
        "consumer_installation_ids",
        "old_generation",
        "target_generation",
    }
)
_COMMIT_FIELDS = frozenset(
    {
        "commit_schema",
        "authority_instance_id",
        "authority_origin_digest",
        "runtime_key_id",
        "owner_id",
        "installation_id",
        "mac_id",
        "vault_id",
        "role",
        "slot_id",
        "old_generation",
        "target_generation",
        "operation_id",
        "plan_id",
        "release_digest",
        "helper_digest",
        "nonce_digest",
        "idempotency_digest",
        "proof_digest",
        "consumed_at_epoch",
    }
)
_PROFILE_FIELDS = frozenset(
    {
        "profile_schema",
        "profile_id",
        "protocol_version",
        "authority_origin",
        "authority_instance_id",
        "runtime_key_id",
        "runtime_key_path",
        "release_digest",
        "helper_digest",
        "owner_id",
        "mac_id",
    }
)
_HEALTH_FIELDS = frozenset(
    {
        "verification_schema",
        "authority_instance_id",
        "protocol_version",
        "restart_epoch",
        "runtime_key_id",
        "slot_id",
        "target_generation",
        "idempotency_key",
        "old_credential_rejected",
        "issued_at_epoch",
        "evidence",
    }
)
_INTENT_FIELDS = frozenset(
    {
        "intent_schema",
        "profile_id",
        "protocol_version",
        "authority_instance_id",
        "authority_origin_digest",
        "runtime_key_id",
        "owner_id",
        "installation_id",
        "mac_id",
        "vault_id",
        "role",
        "slot_id",
        "old_generation",
        "target_generation",
        "operation_id",
        "plan_id",
        "release_digest",
        "helper_digest",
        "nonce_digest",
        "idempotency_digest",
    }
)
_RECONCILIATION_FIELDS = frozenset(
    {
        "reconciliation_schema",
        "outcome",
        "authority_instance_id",
        "authority_origin",
        "runtime_key_id",
        "owner_id",
        "installation_id",
        "mac_id",
        "vault_id",
        "role",
        "slot_id",
        "old_generation",
        "target_generation",
        "current_generation",
        "operation_id",
        "plan_id",
        "release_digest",
        "helper_digest",
        "nonce",
        "idempotency_key",
        "issued_at_epoch",
        "expires_at_epoch",
        "evidence",
    }
)
_MAX_PROFILE_BYTES = 64 * 1024
_MAX_RUNTIME_KEY_BYTES = 4 * 1024
_MAX_AUTHORITY_RESPONSE_BYTES = 64 * 1024
_AUTHORITY_REJECTION_CODES = frozenset(
    {
        "missing_bearer",
        "invalid_token",
        "revoked",
        "wrong_role",
        "retirement_scope_mismatch",
        "retirement_slot_unknown",
        "retirement_generation_mismatch",
        "retirement_idempotency_conflict",
        "retirement_credential_invalid",
        "retirement_verification_binding_invalid",
        "retirement_verification_state_invalid",
    }
)


def _exact_mapping(value: Any, fields: frozenset[str], code: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ValueError(code)
    return dict(value)


def _safe_id(value: Any, code: str) -> str:
    if not isinstance(value, str) or not _SAFE_ID.fullmatch(value):
        raise ValueError(code)
    return value


def _protocol_id(value: Any, code: str) -> str:
    if not isinstance(value, str) or not _PROTOCOL_ID.fullmatch(value):
        raise ValueError(code)
    return value


def _read_stable_private_file(
    path: Path,
    *,
    max_bytes: int,
    unavailable_code: str,
    unsafe_code: str,
) -> bytes:
    path = Path(path)
    if not path.is_absolute():
        raise ValueError(unsafe_code)
    try:
        before = path.lstat()
        if (
            stat.S_ISLNK(before.st_mode)
            or not stat.S_ISREG(before.st_mode)
            or before.st_mode & (stat.S_IRWXG | stat.S_IRWXO)
            or before.st_size > max_bytes
        ):
            raise ValueError(unsafe_code)
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
    except ValueError:
        raise
    except OSError as exc:
        raise ValueError(unavailable_code) from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or before.st_dev != opened.st_dev
            or before.st_ino != opened.st_ino
            or opened.st_mode & (stat.S_IRWXG | stat.S_IRWXO)
            or opened.st_size > max_bytes
        ):
            raise ValueError(unsafe_code)
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, max_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                raise ValueError(unsafe_code)
        after = path.lstat()
        if (
            after.st_dev != opened.st_dev
            or after.st_ino != opened.st_ino
            or after.st_size != opened.st_size
            or after.st_mtime_ns != opened.st_mtime_ns
        ):
            raise ValueError(unsafe_code)
        return b"".join(chunks)
    except OSError as exc:
        raise ValueError(unsafe_code) from exc
    finally:
        os.close(descriptor)


def _integer(value: Any, code: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(code)
    return value


def _digest(value: Any, code: str) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise ValueError(code)
    return value


def _operation_id(value: Any, code: str) -> str:
    if not isinstance(value, str) or not _OPERATION_ID.fullmatch(value):
        raise ValueError(code)
    return value


def _plan_id(value: Any, code: str) -> str:
    if not isinstance(value, str) or not _PLAN_ID.fullmatch(value):
        raise ValueError(code)
    return value


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _canonical_origin(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value) > 2048:
        raise ValueError("legacy_authority_origin_invalid")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("legacy_authority_origin_invalid") from exc
    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in ("", "/")
    ):
        raise ValueError("legacy_authority_origin_invalid")
    host = parsed.hostname
    if "%" in host:
        raise ValueError("legacy_authority_origin_invalid")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        try:
            host = host.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ValueError("legacy_authority_origin_invalid") from exc
        if not host or len(host) > 253 or any(not label for label in host.split(".")):
            raise ValueError("legacy_authority_origin_invalid")
        authority = host
    else:
        authority = f"[{address.compressed}]" if address.version == 6 else address.compressed
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("legacy_authority_origin_invalid")
    if port not in (None, 443):
        authority = f"{authority}:{port}"
    return f"https://{authority}"


@dataclass(frozen=True, repr=False)
class AuthorityDescriptor:
    profile_id: str
    protocol_version: str
    authority_instance_id: str
    authority_origin: str
    runtime_key_id: str
    owner_id: str
    installation_id: str
    mac_id: str
    vault_id: str
    role: str
    authority_schema: str = AUTHORITY_SCHEMA

    @classmethod
    def from_mapping(cls, value: Any) -> "AuthorityDescriptor":
        raw = _exact_mapping(value, _AUTHORITY_FIELDS, "legacy_authority_fields_invalid")
        if raw["authority_schema"] != AUTHORITY_SCHEMA:
            raise ValueError("legacy_authority_schema_invalid")
        return cls(
            profile_id=_safe_id(raw["profile_id"], "legacy_authority_profile_invalid"),
            protocol_version=_protocol_id(
                raw["protocol_version"], "legacy_authority_protocol_invalid"
            ),
            authority_instance_id=_safe_id(
                raw["authority_instance_id"], "legacy_authority_instance_invalid"
            ),
            authority_origin=_canonical_origin(raw["authority_origin"]),
            runtime_key_id=_safe_id(raw["runtime_key_id"], "runtime_key_id_invalid"),
            owner_id=_safe_id(raw["owner_id"], "legacy_authority_scope_invalid"),
            installation_id=_safe_id(
                raw["installation_id"], "legacy_authority_scope_invalid"
            ),
            mac_id=_safe_id(raw["mac_id"], "legacy_authority_scope_invalid"),
            vault_id=_safe_id(raw["vault_id"], "legacy_authority_scope_invalid"),
            role=_safe_id(raw["role"], "legacy_authority_scope_invalid"),
        )

    def __repr__(self) -> str:
        return (
            "AuthorityDescriptor("
            f"profile_id={self.profile_id!r}, authority_instance_id={self.authority_instance_id!r}, "
            "authority_origin='<redacted>', "
            f"installation_id={self.installation_id!r}, vault_id={self.vault_id!r})"
        )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "authority_schema": self.authority_schema,
            "profile_id": self.profile_id,
            "protocol_version": self.protocol_version,
            "authority_instance_id": self.authority_instance_id,
            "authority_origin": self.authority_origin,
            "runtime_key_id": self.runtime_key_id,
            "owner_id": self.owner_id,
            "installation_id": self.installation_id,
            "mac_id": self.mac_id,
            "vault_id": self.vault_id,
            "role": self.role,
        }


@dataclass(frozen=True)
class OpaqueCredentialSlot:
    slot_id: str
    owner_id: str
    installation_id: str
    vault_id: str
    role: str
    consumer_installation_ids: tuple[str, ...]
    old_generation: int
    target_generation: int
    slot_schema: str = SLOT_SCHEMA

    @classmethod
    def from_mapping(cls, value: Any) -> "OpaqueCredentialSlot":
        raw = _exact_mapping(value, _SLOT_FIELDS, "legacy_credential_slot_fields_invalid")
        if raw["slot_schema"] != SLOT_SCHEMA:
            raise ValueError("legacy_credential_slot_schema_invalid")
        slot_id = _safe_id(raw["slot_id"], "opaque_slot_id_invalid")
        if slot_id.startswith(("sha256:", "sha1:", "md5:")) or _DIGEST.fullmatch(slot_id):
            raise ValueError("opaque_slot_id_invalid")
        consumers = raw["consumer_installation_ids"]
        if not isinstance(consumers, list):
            raise ValueError("shared_credential_scope_unsupported")
        normalized_consumers = tuple(
            _safe_id(item, "shared_credential_scope_unsupported") for item in consumers
        )
        installation_id = _safe_id(
            raw["installation_id"], "legacy_credential_scope_invalid"
        )
        if normalized_consumers != (installation_id,):
            raise ValueError("shared_credential_scope_unsupported")
        old_generation = _integer(raw["old_generation"], "retirement_generation_invalid")
        target_generation = _integer(
            raw["target_generation"], "retirement_generation_invalid", minimum=1
        )
        if target_generation != old_generation + 1:
            raise ValueError("retirement_generation_invalid")
        return cls(
            slot_id=slot_id,
            owner_id=_safe_id(raw["owner_id"], "legacy_credential_scope_invalid"),
            installation_id=installation_id,
            vault_id=_safe_id(raw["vault_id"], "legacy_credential_scope_invalid"),
            role=_safe_id(raw["role"], "legacy_credential_scope_invalid"),
            consumer_installation_ids=normalized_consumers,
            old_generation=old_generation,
            target_generation=target_generation,
        )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "slot_schema": self.slot_schema,
            "slot_id": self.slot_id,
            "owner_id": self.owner_id,
            "installation_id": self.installation_id,
            "vault_id": self.vault_id,
            "role": self.role,
            "consumer_installation_ids": list(self.consumer_installation_ids),
            "old_generation": self.old_generation,
            "target_generation": self.target_generation,
        }


class CredentialHandle:
    """One-read in-memory handle whose representation never reveals material."""

    def __init__(self, material: bytes) -> None:
        if not material:
            raise ValueError("credential_handle_empty")
        self._material = bytearray(material)
        self._consumed = False
        self._destroyed = False

    @classmethod
    def from_memory(cls, value: str | bytes) -> "CredentialHandle":
        if isinstance(value, str):
            value = value.encode("utf-8")
        if not isinstance(value, bytes):
            raise TypeError("credential_handle_material_invalid")
        return cls(value)

    def read_once(self) -> bytes:
        if self._destroyed:
            raise ValueError("credential_handle_destroyed")
        if self._consumed:
            raise ValueError("credential_handle_consumed")
        value = bytes(self._material)
        self._consumed = True
        for index in range(len(self._material)):
            self._material[index] = 0
        return value

    def destroy(self) -> None:
        for index in range(len(self._material)):
            self._material[index] = 0
        self._destroyed = True

    def __repr__(self) -> str:
        return "CredentialHandle(<redacted>)"

    __str__ = __repr__


@dataclass(frozen=True)
class RetirementExpectation:
    authority: AuthorityDescriptor
    slot: OpaqueCredentialSlot
    operation_id: str
    plan_id: str
    release_digest: str
    helper_digest: str
    nonce: str
    idempotency_key: str
    not_before_epoch: int

    def __post_init__(self) -> None:
        if not isinstance(self.authority, AuthorityDescriptor) or not isinstance(
            self.slot, OpaqueCredentialSlot
        ):
            raise TypeError("retirement_expectation_contract_invalid")
        _operation_id(self.operation_id, "retirement_operation_invalid")
        _plan_id(self.plan_id, "retirement_plan_invalid")
        _digest(self.release_digest, "retirement_release_digest_invalid")
        _digest(self.helper_digest, "retirement_helper_digest_invalid")
        _safe_id(self.nonce, "retirement_nonce_invalid")
        _safe_id(self.idempotency_key, "retirement_idempotency_invalid")
        _integer(self.not_before_epoch, "retirement_time_invalid")
        scope = (
            self.authority.owner_id,
            self.authority.installation_id,
            self.authority.vault_id,
            self.authority.role,
        )
        slot_scope = (
            self.slot.owner_id,
            self.slot.installation_id,
            self.slot.vault_id,
            self.slot.role,
        )
        if scope != slot_scope:
            raise ValueError("retirement_scope_mismatch")


@dataclass(frozen=True)
class RetirementIntent:
    """Secret-free, durable binding used to reconcile one dispatched request."""

    profile_id: str
    protocol_version: str
    authority_instance_id: str
    authority_origin_digest: str
    runtime_key_id: str
    owner_id: str
    installation_id: str
    mac_id: str
    vault_id: str
    role: str
    slot_id: str
    old_generation: int
    target_generation: int
    operation_id: str
    plan_id: str
    release_digest: str
    helper_digest: str
    nonce_digest: str
    idempotency_digest: str
    intent_schema: str = INTENT_SCHEMA

    @classmethod
    def from_mapping(cls, value: Any) -> "RetirementIntent":
        raw = _exact_mapping(value, _INTENT_FIELDS, "retirement_intent_invalid")
        if raw["intent_schema"] != INTENT_SCHEMA:
            raise ValueError("retirement_intent_invalid")
        old_generation = _integer(
            raw["old_generation"], "retirement_intent_invalid"
        )
        target_generation = _integer(
            raw["target_generation"], "retirement_intent_invalid", minimum=1
        )
        if target_generation != old_generation + 1:
            raise ValueError("retirement_intent_invalid")
        return cls(
            profile_id=_safe_id(raw["profile_id"], "retirement_intent_invalid"),
            protocol_version=_protocol_id(
                raw["protocol_version"], "retirement_intent_invalid"
            ),
            authority_instance_id=_safe_id(
                raw["authority_instance_id"], "retirement_intent_invalid"
            ),
            authority_origin_digest=_digest(
                raw["authority_origin_digest"], "retirement_intent_invalid"
            ),
            runtime_key_id=_safe_id(
                raw["runtime_key_id"], "retirement_intent_invalid"
            ),
            owner_id=_safe_id(raw["owner_id"], "retirement_intent_invalid"),
            installation_id=_safe_id(
                raw["installation_id"], "retirement_intent_invalid"
            ),
            mac_id=_safe_id(raw["mac_id"], "retirement_intent_invalid"),
            vault_id=_safe_id(raw["vault_id"], "retirement_intent_invalid"),
            role=_safe_id(raw["role"], "retirement_intent_invalid"),
            slot_id=_safe_id(raw["slot_id"], "retirement_intent_invalid"),
            old_generation=old_generation,
            target_generation=target_generation,
            operation_id=_operation_id(
                raw["operation_id"], "retirement_intent_invalid"
            ),
            plan_id=_plan_id(raw["plan_id"], "retirement_intent_invalid"),
            release_digest=_digest(
                raw["release_digest"], "retirement_intent_invalid"
            ),
            helper_digest=_digest(
                raw["helper_digest"], "retirement_intent_invalid"
            ),
            nonce_digest=_digest(
                raw["nonce_digest"], "retirement_intent_invalid"
            ),
            idempotency_digest=_digest(
                raw["idempotency_digest"], "retirement_intent_invalid"
            ),
        )

    @classmethod
    def from_expectation(cls, expected: RetirementExpectation) -> "RetirementIntent":
        return cls(
            profile_id=expected.authority.profile_id,
            protocol_version=expected.authority.protocol_version,
            authority_instance_id=expected.authority.authority_instance_id,
            authority_origin_digest=_sha256_text(expected.authority.authority_origin),
            runtime_key_id=expected.authority.runtime_key_id,
            owner_id=expected.authority.owner_id,
            installation_id=expected.authority.installation_id,
            mac_id=expected.authority.mac_id,
            vault_id=expected.authority.vault_id,
            role=expected.authority.role,
            slot_id=expected.slot.slot_id,
            old_generation=expected.slot.old_generation,
            target_generation=expected.slot.target_generation,
            operation_id=expected.operation_id,
            plan_id=expected.plan_id,
            release_digest=expected.release_digest,
            helper_digest=expected.helper_digest,
            nonce_digest=_sha256_text(expected.nonce),
            idempotency_digest=_sha256_text(expected.idempotency_key),
        )

    def to_mapping(self) -> dict[str, Any]:
        return {field: getattr(self, field) for field in sorted(_INTENT_FIELDS)}


@dataclass(frozen=True)
class RetirementReconciliationResult:
    outcome: str
    commit: "RetirementCommit | None" = None

    def __post_init__(self) -> None:
        if self.outcome not in {"not_applied", "retired", "inconclusive"}:
            raise ValueError("retirement_reconciliation_outcome_invalid")
        if (self.outcome == "retired") != isinstance(self.commit, RetirementCommit):
            raise ValueError("retirement_reconciliation_commit_invalid")


def canonical_retirement_payload(value: Mapping[str, Any]) -> bytes:
    if not isinstance(value, Mapping):
        raise TypeError("retirement_proof_shape_invalid")
    raw = {str(key): item for key, item in value.items() if key != "evidence"}
    expected = _PROOF_FIELDS - {"evidence"}
    if set(raw) != expected:
        raise ValueError("retirement_proof_fields_invalid")
    return json.dumps(
        raw,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


@dataclass(frozen=True, repr=False)
class RetirementProofCandidate:
    outcome: str
    authority_instance_id: str
    authority_origin: str
    runtime_key_id: str
    owner_id: str
    installation_id: str
    mac_id: str
    vault_id: str
    role: str
    slot_id: str
    old_generation: int
    target_generation: int
    operation_id: str
    plan_id: str
    release_digest: str
    helper_digest: str
    nonce: str
    idempotency_key: str
    issued_at_epoch: int
    expires_at_epoch: int
    evidence: str
    proof_schema: str = PROOF_SCHEMA

    @classmethod
    def from_mapping(cls, value: Any) -> "RetirementProofCandidate":
        raw = _exact_mapping(value, _PROOF_FIELDS, "retirement_proof_fields_invalid")
        if raw["proof_schema"] != PROOF_SCHEMA:
            raise ValueError("retirement_proof_schema_invalid")
        if raw["outcome"] not in {"retired", "already_retired"}:
            raise ValueError("retirement_proof_outcome_invalid")
        evidence = raw["evidence"]
        if not isinstance(evidence, str) or len(evidence) > 8192:
            raise ValueError("retirement_evidence_invalid")
        try:
            decoded = base64.b64decode(evidence, validate=True)
        except (ValueError, TypeError) as exc:
            raise ValueError("retirement_evidence_invalid") from exc
        if not decoded:
            raise ValueError("retirement_evidence_invalid")
        return cls(
            outcome=raw["outcome"],
            authority_instance_id=_safe_id(
                raw["authority_instance_id"], "retirement_authority_invalid"
            ),
            authority_origin=_canonical_origin(raw["authority_origin"]),
            runtime_key_id=_safe_id(raw["runtime_key_id"], "runtime_key_id_invalid"),
            owner_id=_safe_id(raw["owner_id"], "retirement_scope_invalid"),
            installation_id=_safe_id(
                raw["installation_id"], "retirement_scope_invalid"
            ),
            mac_id=_safe_id(raw["mac_id"], "retirement_scope_invalid"),
            vault_id=_safe_id(raw["vault_id"], "retirement_scope_invalid"),
            role=_safe_id(raw["role"], "retirement_scope_invalid"),
            slot_id=_safe_id(raw["slot_id"], "retirement_slot_invalid"),
            old_generation=_integer(
                raw["old_generation"], "retirement_generation_invalid"
            ),
            target_generation=_integer(
                raw["target_generation"], "retirement_generation_invalid", minimum=1
            ),
            operation_id=_operation_id(
                raw["operation_id"], "retirement_operation_invalid"
            ),
            plan_id=_plan_id(raw["plan_id"], "retirement_plan_invalid"),
            release_digest=_digest(
                raw["release_digest"], "retirement_release_digest_invalid"
            ),
            helper_digest=_digest(
                raw["helper_digest"], "retirement_helper_digest_invalid"
            ),
            nonce=_safe_id(raw["nonce"], "retirement_nonce_invalid"),
            idempotency_key=_safe_id(
                raw["idempotency_key"], "retirement_idempotency_invalid"
            ),
            issued_at_epoch=_integer(raw["issued_at_epoch"], "retirement_time_invalid"),
            expires_at_epoch=_integer(
                raw["expires_at_epoch"], "retirement_time_invalid", minimum=1
            ),
            evidence=evidence,
        )

    def signing_payload(self) -> bytes:
        return canonical_retirement_payload(self.to_mapping())

    def to_mapping(self) -> dict[str, Any]:
        return {
            "proof_schema": self.proof_schema,
            "outcome": self.outcome,
            "authority_instance_id": self.authority_instance_id,
            "authority_origin": self.authority_origin,
            "runtime_key_id": self.runtime_key_id,
            "owner_id": self.owner_id,
            "installation_id": self.installation_id,
            "mac_id": self.mac_id,
            "vault_id": self.vault_id,
            "role": self.role,
            "slot_id": self.slot_id,
            "old_generation": self.old_generation,
            "target_generation": self.target_generation,
            "operation_id": self.operation_id,
            "plan_id": self.plan_id,
            "release_digest": self.release_digest,
            "helper_digest": self.helper_digest,
            "nonce": self.nonce,
            "idempotency_key": self.idempotency_key,
            "issued_at_epoch": self.issued_at_epoch,
            "expires_at_epoch": self.expires_at_epoch,
            "evidence": self.evidence,
        }

    def __repr__(self) -> str:
        return (
            "RetirementProofCandidate("
            f"outcome={self.outcome!r}, authority_instance_id={self.authority_instance_id!r}, "
            f"operation_id={self.operation_id!r}, evidence='<redacted>')"
        )


class RuntimeEvidenceVerifier(ABC):
    """Independent runtime trust verifier; adapters cannot self-approve proof."""

    @abstractmethod
    def verify(self, *, payload: bytes, evidence: str, runtime_key_id: str) -> None:
        """Raise on invalid evidence; return only after authentic validation."""


class HmacRuntimeEvidenceVerifier(RuntimeEvidenceVerifier):
    """Verify an operation-pinned authority challenge held outside the Kit."""

    def __init__(self, runtime_key_id: str, key: bytes) -> None:
        self.runtime_key_id = _safe_id(runtime_key_id, "runtime_key_id_invalid")
        if not isinstance(key, bytes) or len(key) < 16:
            raise ValueError("runtime_evidence_key_invalid")
        self._key = bytes(key)

    def verify(self, *, payload: bytes, evidence: str, runtime_key_id: str) -> None:
        if runtime_key_id != self.runtime_key_id:
            raise ValueError("retirement_runtime_key_mismatch")
        try:
            actual = base64.b64decode(evidence, validate=True)
        except (TypeError, ValueError) as exc:
            raise ValueError("retirement_evidence_invalid") from exc
        expected = hmac.new(self._key, payload, hashlib.sha256).digest()
        if not hmac.compare_digest(actual, expected):
            raise ValueError("retirement_evidence_invalid")


@dataclass(frozen=True)
class RetirementCommit:
    authority_instance_id: str
    authority_origin_digest: str
    runtime_key_id: str
    owner_id: str
    installation_id: str
    mac_id: str
    vault_id: str
    role: str
    slot_id: str
    old_generation: int
    target_generation: int
    operation_id: str
    plan_id: str
    release_digest: str
    helper_digest: str
    nonce_digest: str
    idempotency_digest: str
    proof_digest: str
    consumed_at_epoch: int
    commit_schema: str = COMMIT_SCHEMA

    def __post_init__(self) -> None:
        if self.commit_schema != COMMIT_SCHEMA:
            raise ValueError("retirement_commit_schema_invalid")
        for value in (
            self.authority_instance_id,
            self.runtime_key_id,
            self.owner_id,
            self.installation_id,
            self.mac_id,
            self.vault_id,
            self.role,
            self.slot_id,
        ):
            _safe_id(value, "retirement_commit_invalid")
        for value in (
            self.authority_origin_digest,
            self.release_digest,
            self.helper_digest,
            self.nonce_digest,
            self.idempotency_digest,
            self.proof_digest,
        ):
            _digest(value, "retirement_commit_invalid")
        _operation_id(self.operation_id, "retirement_commit_invalid")
        _plan_id(self.plan_id, "retirement_commit_invalid")
        _integer(self.old_generation, "retirement_commit_invalid")
        _integer(self.target_generation, "retirement_commit_invalid", minimum=1)
        if self.target_generation != self.old_generation + 1:
            raise ValueError("retirement_commit_invalid")
        _integer(self.consumed_at_epoch, "retirement_commit_invalid")

    def to_mapping(self) -> dict[str, Any]:
        return {
            "commit_schema": self.commit_schema,
            "authority_instance_id": self.authority_instance_id,
            "authority_origin_digest": self.authority_origin_digest,
            "runtime_key_id": self.runtime_key_id,
            "owner_id": self.owner_id,
            "installation_id": self.installation_id,
            "mac_id": self.mac_id,
            "vault_id": self.vault_id,
            "role": self.role,
            "slot_id": self.slot_id,
            "old_generation": self.old_generation,
            "target_generation": self.target_generation,
            "operation_id": self.operation_id,
            "plan_id": self.plan_id,
            "release_digest": self.release_digest,
            "helper_digest": self.helper_digest,
            "nonce_digest": self.nonce_digest,
            "idempotency_digest": self.idempotency_digest,
            "proof_digest": self.proof_digest,
            "consumed_at_epoch": self.consumed_at_epoch,
        }

    @classmethod
    def from_mapping(cls, value: Any) -> "RetirementCommit":
        raw = _exact_mapping(value, _COMMIT_FIELDS, "retirement_commit_fields_invalid")
        if raw["commit_schema"] != COMMIT_SCHEMA:
            raise ValueError("retirement_commit_schema_invalid")
        return cls(
            authority_instance_id=_safe_id(
                raw["authority_instance_id"], "retirement_commit_invalid"
            ),
            authority_origin_digest=_digest(
                raw["authority_origin_digest"], "retirement_commit_invalid"
            ),
            runtime_key_id=_safe_id(raw["runtime_key_id"], "retirement_commit_invalid"),
            owner_id=_safe_id(raw["owner_id"], "retirement_commit_invalid"),
            installation_id=_safe_id(
                raw["installation_id"], "retirement_commit_invalid"
            ),
            mac_id=_safe_id(raw["mac_id"], "retirement_commit_invalid"),
            vault_id=_safe_id(raw["vault_id"], "retirement_commit_invalid"),
            role=_safe_id(raw["role"], "retirement_commit_invalid"),
            slot_id=_safe_id(raw["slot_id"], "retirement_commit_invalid"),
            old_generation=_integer(
                raw["old_generation"], "retirement_commit_invalid"
            ),
            target_generation=_integer(
                raw["target_generation"], "retirement_commit_invalid", minimum=1
            ),
            operation_id=_operation_id(raw["operation_id"], "retirement_commit_invalid"),
            plan_id=_plan_id(raw["plan_id"], "retirement_commit_invalid"),
            release_digest=_digest(raw["release_digest"], "retirement_commit_invalid"),
            helper_digest=_digest(raw["helper_digest"], "retirement_commit_invalid"),
            nonce_digest=_digest(raw["nonce_digest"], "retirement_commit_invalid"),
            idempotency_digest=_digest(
                raw["idempotency_digest"], "retirement_commit_invalid"
            ),
            proof_digest=_digest(raw["proof_digest"], "retirement_commit_invalid"),
            consumed_at_epoch=_integer(
                raw["consumed_at_epoch"], "retirement_commit_invalid"
            ),
        )


class LegacyCredentialRetirementService(ABC):
    """Capability boundary implemented by supported authority adapters in U4.

    U3 intentionally defines only this typed seam.  Implementations must
    independently validate an authority-issued proof and return the resulting
    secret-free commit; a boolean or arbitrary mapping is never sufficient.
    """

    @abstractmethod
    def retire(
        self,
        *,
        credential: CredentialHandle,
        operation_id: str,
        plan_id: str,
        installation_id: str,
        vault_id: str,
        role: str,
        lock_held: bool = False,
    ) -> RetirementCommit:
        """Retire one credential and return its already-consumed commit."""

    def reconcile(
        self,
        *,
        credential: CredentialHandle,
        operation_id: str,
        plan_id: str,
        installation_id: str,
        vault_id: str,
        role: str,
        lock_held: bool = False,
    ) -> RetirementReconciliationResult:
        """Reconcile one already-dispatched request without dispatching again."""

        raise LegacyRetirementOutcomeUnknown(
            "legacy_credential_retirement_reconciliation_unsupported"
        )

    def authorized(self, *, operation_id: str, plan_id: str) -> bool:
        """Return whether the caller persisted human approval for this operation."""

        # Capability availability is not human authorization.  Concrete
        # adapters must prove an operation-bound authorization marker.
        return False


class LegacyRetirementOutcomeUnknown(RuntimeError):
    """The authority request may have committed and must be reconciled."""


@dataclass(frozen=True)
class LegacyAuthorityProfile:
    profile_id: str
    protocol_version: str
    authority_origin: str
    authority_instance_id: str
    runtime_key_id: str
    runtime_key_path: str
    release_digest: str
    helper_digest: str
    owner_id: str
    mac_id: str
    profile_schema: str = PROFILE_SCHEMA

    @classmethod
    def from_mapping(cls, value: Any) -> "LegacyAuthorityProfile":
        raw = _exact_mapping(value, _PROFILE_FIELDS, "legacy_authority_profile_invalid")
        if raw["profile_schema"] != PROFILE_SCHEMA:
            raise ValueError("legacy_authority_profile_invalid")
        runtime_key_path = raw["runtime_key_path"]
        if not isinstance(runtime_key_path, str) or not os.path.isabs(runtime_key_path):
            raise ValueError("legacy_authority_profile_invalid")
        return cls(
            profile_id=_safe_id(raw["profile_id"], "legacy_authority_profile_invalid"),
            protocol_version=_protocol_id(
                raw["protocol_version"], "legacy_authority_profile_invalid"
            ),
            authority_origin=_canonical_origin(raw["authority_origin"]),
            authority_instance_id=_safe_id(
                raw["authority_instance_id"], "legacy_authority_profile_invalid"
            ),
            runtime_key_id=_safe_id(
                raw["runtime_key_id"], "legacy_authority_profile_invalid"
            ),
            runtime_key_path=runtime_key_path,
            release_digest=_digest(
                raw["release_digest"], "legacy_authority_profile_invalid"
            ),
            helper_digest=_digest(
                raw["helper_digest"], "legacy_authority_profile_invalid"
            ),
            owner_id=_safe_id(raw["owner_id"], "legacy_authority_profile_invalid"),
            mac_id=_safe_id(raw["mac_id"], "legacy_authority_profile_invalid"),
        )


def load_legacy_authority_profile(path: Path) -> LegacyAuthorityProfile:
    try:
        value = json.loads(
            _read_stable_private_file(
                Path(path),
                max_bytes=_MAX_PROFILE_BYTES,
                unavailable_code="legacy_authority_unsupported",
                unsafe_code="legacy_authority_profile_unsafe",
            ).decode("utf-8")
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("legacy_authority_profile_invalid") from exc
    profile = LegacyAuthorityProfile.from_mapping(value)
    if profile.profile_id not in {"dogfood-local-v1", "dogfood-vps-v1"}:
        raise ValueError("legacy_authority_unsupported")
    return profile


def legacy_authority_profile_status(path: Path) -> dict[str, str]:
    try:
        profile = load_legacy_authority_profile(path)
    except ValueError:
        return {"adapter": "unclassified", "capability": "unavailable"}
    return {
        "adapter": (
            "local_managed_relay"
            if profile.profile_id == "dogfood-local-v1"
            else "legacy_vps_relay"
        ),
        "capability": "available",
    }


class LegacyAuthorityTransport(ABC):
    @abstractmethod
    def descriptor(self, credential: bytearray) -> Mapping[str, Any]:
        """Return the authenticated authority and opaque credential slot."""

    @abstractmethod
    def commit(
        self,
        credential: bytearray,
        request: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        """Dispatch exactly one idempotent retirement request."""

    @abstractmethod
    def verify(
        self,
        credential: bytearray,
        request: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        """Authenticate the retired generation on the same authority."""

    def reconcile(
        self,
        credential: bytearray,
        request: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        """Read the exact authority outcome for a previously dispatched request."""

        raise ValueError("legacy_authority_reconciliation_unsupported")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        raise urllib.error.HTTPError(
            "", 409, "legacy_authority_redirect_forbidden", {}, None
        )


class UrllibLegacyAuthorityTransport(LegacyAuthorityTransport):
    """Exact-origin HTTPS transport with redirects and proxy inheritance disabled."""

    def __init__(self, origin: str, *, timeout_seconds: float = 10.0) -> None:
        self.origin = _canonical_origin(origin)
        self.timeout_seconds = max(1.0, min(float(timeout_seconds), 30.0))
        context = ssl.create_default_context()
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=context),
            _NoRedirect(),
        )

    @staticmethod
    def _authorization(credential: bytearray) -> str:
        try:
            value = bytes(credential).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("legacy_credential_encoding_invalid") from exc
        if not value or any(character in value for character in ("\x00", "\r", "\n")):
            raise ValueError("legacy_credential_encoding_invalid")
        return "Bearer " + value

    @staticmethod
    def _read_json_response(response: Any) -> Any:
        content_length = response.headers.get("Content-Length")
        if content_length is not None:
            try:
                declared_length = int(content_length)
            except ValueError as exc:
                raise ValueError("legacy_authority_response_invalid") from exc
            if declared_length < 0 or declared_length > _MAX_AUTHORITY_RESPONSE_BYTES:
                raise ValueError("legacy_authority_response_invalid")
        payload = response.read(_MAX_AUTHORITY_RESPONSE_BYTES + 1)
        if len(payload) > _MAX_AUTHORITY_RESPONSE_BYTES:
            raise ValueError("legacy_authority_response_invalid")
        try:
            return json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("legacy_authority_response_invalid") from exc

    def _request(
        self,
        path: str,
        credential: bytearray,
        *,
        body: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        if path not in {
            "/api/v2/legacy-retirement/descriptor",
            "/api/v2/legacy-retirement/commit",
            "/api/v2/legacy-retirement/verify",
            "/api/v2/legacy-retirement/reconcile",
        }:
            raise ValueError("legacy_authority_path_invalid")
        encoded = (
            None
            if body is None
            else json.dumps(
                dict(body),
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        )
        request = urllib.request.Request(
            self.origin + path,
            data=encoded,
            method="GET" if encoded is None else "POST",
            headers={
                "Authorization": self._authorization(credential),
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
        )
        try:
            with self._opener.open(request, timeout=self.timeout_seconds) as response:
                if _canonical_origin(response.geturl().rsplit(path, 1)[0]) != self.origin:
                    raise ValueError("legacy_authority_origin_changed")
                value = self._read_json_response(response)
        except urllib.error.HTTPError as exc:
            if exc.fp is None:
                raise ValueError("legacy_authority_response_invalid") from None
            rejection = self._read_json_response(exc)
            if (
                isinstance(rejection, Mapping)
                and set(rejection) == {"ok", "error"}
                and rejection.get("ok") is False
                and rejection.get("error") in _AUTHORITY_REJECTION_CODES
            ):
                raise ValueError(
                    f"legacy_authority_rejected:{rejection['error']}"
                ) from None
            raise ValueError("legacy_authority_response_invalid") from None
        except (urllib.error.URLError, OSError):
            raise ValueError("legacy_authority_unavailable") from None
        if not isinstance(value, Mapping) or value.get("ok") is not True:
            raise ValueError("legacy_authority_response_invalid")
        return dict(value)

    def descriptor(self, credential: bytearray) -> Mapping[str, Any]:
        value = self._request(
            "/api/v2/legacy-retirement/descriptor",
            credential,
        )
        if set(value) != {"ok", "authority", "slot", "restart_epoch"}:
            raise ValueError("legacy_authority_response_invalid")
        return {
            "authority": value["authority"],
            "slot": value["slot"],
            "restart_epoch": value["restart_epoch"],
        }

    def commit(
        self,
        credential: bytearray,
        request: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        value = self._request(
            "/api/v2/legacy-retirement/commit",
            credential,
            body=request,
        )
        if set(value) != {"ok", "proof"} or not isinstance(
            value["proof"], Mapping
        ):
            raise ValueError("legacy_authority_response_invalid")
        return dict(value["proof"])

    def verify(
        self,
        credential: bytearray,
        request: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        value = self._request(
            "/api/v2/legacy-retirement/verify",
            credential,
            body=request,
        )
        if set(value) != {"ok", "verification"} or not isinstance(
            value["verification"], Mapping
        ):
            raise ValueError("legacy_authority_response_invalid")
        return dict(value["verification"])

    def reconcile(
        self,
        credential: bytearray,
        request: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        value = self._request(
            "/api/v2/legacy-retirement/reconcile",
            credential,
            body=request,
        )
        if set(value) != {"ok", "reconciliation"} or not isinstance(
            value["reconciliation"], Mapping
        ):
            raise ValueError("legacy_authority_response_invalid")
        return dict(value["reconciliation"])


class CapabilityAwareLegacyRetirementService(LegacyCredentialRetirementService):
    """Load one recognized authority profile and consume its strict proof."""

    def __init__(
        self,
        profile_path: Path,
        checkpoint_store: CheckpointStore,
        *,
        clock: Callable[[], int] = lambda: int(time.time()),
        transport_factory: Callable[[str], LegacyAuthorityTransport] = (
            lambda origin: UrllibLegacyAuthorityTransport(origin)
        ),
        lock_held_by_caller: bool = False,
    ) -> None:
        self.profile_path = Path(profile_path)
        self.checkpoint_store = checkpoint_store
        self.clock = clock
        self.transport_factory = transport_factory
        self.lock_held_by_caller = bool(lock_held_by_caller)

    def _profile(self) -> LegacyAuthorityProfile:
        return load_legacy_authority_profile(self.profile_path)

    @staticmethod
    def _runtime_key(profile: LegacyAuthorityProfile) -> bytes:
        key = _read_stable_private_file(
            Path(profile.runtime_key_path),
            max_bytes=_MAX_RUNTIME_KEY_BYTES,
            unavailable_code="runtime_evidence_key_unavailable",
            unsafe_code="runtime_evidence_key_unsafe",
        )
        if len(key) < 16:
            raise ValueError("runtime_evidence_key_invalid")
        return key

    def available(self) -> bool:
        try:
            profile = self._profile()
            self._runtime_key(profile)
        except ValueError:
            return False
        return True

    def authorized(self, *, operation_id: str, plan_id: str) -> bool:
        try:
            checkpoint = self.checkpoint_store.read(operation_id)
        except (FileNotFoundError, ValueError):
            return False
        marker = checkpoint["recorded_answers"].get(
            "legacy_authority_authorization"
        )
        return marker == {
            "operation_id": operation_id,
            "plan_id": plan_id,
            "authorized": True,
        }

    def _mark_dispatch_unknown(
        self,
        operation_id: str,
        plan_id: str,
        intent: RetirementIntent,
    ) -> None:
        """Persist the conservative dispatch boundary before request bytes leave.

        This write intentionally precedes ``transport.commit``.  If the
        process or network fails after this point, a caller may only reconcile
        this same operation; it may not infer that the old credential remains
        active from the absence of a response.
        """

        checkpoint = self.checkpoint_store.read(operation_id)
        if (
            checkpoint["plan_id"] != plan_id
            or checkpoint["journey"] != "legacy_upgrade"
            or checkpoint["prior_operation_terminal"] is not True
            or checkpoint["irreversible_boundary_crossed"] is not False
        ):
            raise ValueError("retirement_checkpoint_invalid")
        ambiguity = checkpoint["ambiguity_state"]
        if ambiguity == AmbiguityState.RETIREMENT_OUTCOME_UNKNOWN.value:
            existing = checkpoint["recorded_answers"].get("retirement_intent")
            if RetirementIntent.from_mapping(existing) != intent:
                raise ValueError("retirement_intent_binding_mismatch")
            return
        if ambiguity != AmbiguityState.NOT_DISPATCHED.value:
            raise ValueError("retirement_checkpoint_invalid")
        effect = checkpoint["effect_summary"]
        codes = tuple(
            dict.fromkeys((*effect["effect_codes"], "retirement_dispatched"))
        )
        reconcile = NextAction(
            action_id="reconcile-original-operation",
            action_type=NextActionType.LIFECYCLE_COMMAND,
            owner=ActionOwner.AGENT,
            recommended=True,
            executable=True,
            command="resume",
            parameters={"operation_id_ref": "result.operation_id"},
        )
        recorded = dict(checkpoint["recorded_answers"])
        recorded["retirement_intent"] = intent.to_mapping()
        self.checkpoint_store.update(
            operation_id,
            state="recovery_required",
            phase="retirement_reconciliation",
            active_gate=None,
            irreversible_boundary_crossed=False,
            ambiguity_state=AmbiguityState.RETIREMENT_OUTCOME_UNKNOWN,
            recovery_policy=RecoveryPolicy.RECONCILE_SAME_OPERATION,
            recorded_answers=recorded,
            effect_summary=EffectSummary(
                local_effect=EffectDisposition(effect["local_effect"]),
                remote_effect=EffectDisposition.CHANGED,
                credential_effect=CredentialEffect.OUTCOME_UNKNOWN,
                mutation_performed=True,
                owned_resource_count=effect["owned_resource_count"],
                effect_codes=codes,
            ),
            next_actions=(reconcile,),
            cancellation_available=False,
        )

    @staticmethod
    def _request_from_intent(
        profile: LegacyAuthorityProfile,
        intent: RetirementIntent,
    ) -> tuple[RetirementExpectation, dict[str, Any]]:
        if (
            intent.profile_id != profile.profile_id
            or intent.protocol_version != profile.protocol_version
            or intent.authority_instance_id != profile.authority_instance_id
            or intent.authority_origin_digest != _sha256_text(profile.authority_origin)
            or intent.runtime_key_id != profile.runtime_key_id
            or intent.owner_id != profile.owner_id
            or intent.mac_id != profile.mac_id
            or intent.release_digest != profile.release_digest
            or intent.helper_digest != profile.helper_digest
        ):
            raise ValueError("retirement_intent_binding_mismatch")
        authority = AuthorityDescriptor(
            profile_id=intent.profile_id,
            protocol_version=intent.protocol_version,
            authority_instance_id=intent.authority_instance_id,
            authority_origin=profile.authority_origin,
            runtime_key_id=intent.runtime_key_id,
            owner_id=intent.owner_id,
            installation_id=intent.installation_id,
            mac_id=intent.mac_id,
            vault_id=intent.vault_id,
            role=intent.role,
        )
        slot = OpaqueCredentialSlot(
            slot_id=intent.slot_id,
            owner_id=intent.owner_id,
            installation_id=intent.installation_id,
            vault_id=intent.vault_id,
            role=intent.role,
            consumer_installation_ids=(intent.installation_id,),
            old_generation=intent.old_generation,
            target_generation=intent.target_generation,
        )
        binding = (
            f"{intent.operation_id}:{intent.plan_id}:{intent.slot_id}:"
            f"{intent.old_generation}:{intent.target_generation}"
        )
        nonce = "nonce-" + hashlib.sha256(
            (binding + ":nonce").encode("utf-8")
        ).hexdigest()[:32]
        idempotency_key = "retire-" + hashlib.sha256(
            (binding + ":idempotency").encode("utf-8")
        ).hexdigest()[:32]
        if (
            _sha256_text(nonce) != intent.nonce_digest
            or _sha256_text(idempotency_key) != intent.idempotency_digest
        ):
            raise ValueError("retirement_intent_binding_mismatch")
        expected = RetirementExpectation(
            authority=authority,
            slot=slot,
            operation_id=intent.operation_id,
            plan_id=intent.plan_id,
            release_digest=intent.release_digest,
            helper_digest=intent.helper_digest,
            nonce=nonce,
            idempotency_key=idempotency_key,
            not_before_epoch=0,
        )
        request = {
            "operation_id": intent.operation_id,
            "plan_id": intent.plan_id,
            "authority_origin": profile.authority_origin,
            "owner_id": intent.owner_id,
            "installation_id": intent.installation_id,
            "mac_id": intent.mac_id,
            "vault_id": intent.vault_id,
            "role": intent.role,
            "slot_id": intent.slot_id,
            "old_generation": intent.old_generation,
            "target_generation": intent.target_generation,
            "release_digest": intent.release_digest,
            "helper_digest": intent.helper_digest,
            "nonce": nonce,
            "idempotency_key": idempotency_key,
        }
        return expected, request

    @staticmethod
    def _validate_not_applied(
        value: Any,
        *,
        expected: RetirementExpectation,
        verifier: RuntimeEvidenceVerifier,
        now_epoch: int,
    ) -> None:
        raw = _exact_mapping(
            value, _RECONCILIATION_FIELDS, "retirement_reconciliation_invalid"
        )
        if (
            raw["reconciliation_schema"] != RECONCILIATION_SCHEMA
            or raw["outcome"] != "not_applied"
            or _canonical_origin(raw["authority_origin"])
            != expected.authority.authority_origin
            or _safe_id(raw["authority_instance_id"], "retirement_reconciliation_invalid")
            != expected.authority.authority_instance_id
            or _safe_id(raw["runtime_key_id"], "retirement_reconciliation_invalid")
            != expected.authority.runtime_key_id
            or tuple(raw[field] for field in ("owner_id", "installation_id", "mac_id", "vault_id", "role"))
            != (
                expected.authority.owner_id,
                expected.authority.installation_id,
                expected.authority.mac_id,
                expected.authority.vault_id,
                expected.authority.role,
            )
            or _safe_id(raw["slot_id"], "retirement_reconciliation_invalid")
            != expected.slot.slot_id
            or raw["operation_id"] != expected.operation_id
            or raw["plan_id"] != expected.plan_id
            or raw["release_digest"] != expected.release_digest
            or raw["helper_digest"] != expected.helper_digest
            or raw["nonce"] != expected.nonce
            or raw["idempotency_key"] != expected.idempotency_key
            or _integer(raw["old_generation"], "retirement_reconciliation_invalid")
            != expected.slot.old_generation
            or _integer(raw["target_generation"], "retirement_reconciliation_invalid", minimum=1)
            != expected.slot.target_generation
            or _integer(raw["current_generation"], "retirement_reconciliation_invalid")
            != expected.slot.old_generation
        ):
            raise ValueError("retirement_reconciliation_invalid")
        issued_at = _integer(raw["issued_at_epoch"], "retirement_reconciliation_invalid")
        expires_at = _integer(raw["expires_at_epoch"], "retirement_reconciliation_invalid", minimum=1)
        if issued_at > now_epoch + 120 or expires_at <= now_epoch or expires_at - issued_at > 600:
            raise ValueError("retirement_reconciliation_invalid")
        payload = json.dumps(
            {key: item for key, item in raw.items() if key != "evidence"},
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        verifier.verify(
            payload=payload,
            evidence=raw["evidence"],
            runtime_key_id=expected.authority.runtime_key_id,
        )

    def _record_reconciliation_state(
        self,
        operation_id: str,
        *,
        ambiguity: AmbiguityState,
        recovery: RecoveryPolicy,
        credential_effect: CredentialEffect,
        code: str,
        action: NextAction,
    ) -> None:
        checkpoint = self.checkpoint_store.read(operation_id)
        effect = checkpoint["effect_summary"]
        codes = tuple(dict.fromkeys((*effect["effect_codes"], code)))
        self.checkpoint_store.update(
            operation_id,
            state="recovery_required",
            phase="retirement_reconciliation",
            active_gate=None,
            irreversible_boundary_crossed=False,
            ambiguity_state=ambiguity,
            recovery_policy=recovery,
            effect_summary=EffectSummary(
                local_effect=EffectDisposition(effect["local_effect"]),
                remote_effect=EffectDisposition(effect["remote_effect"]),
                credential_effect=credential_effect,
                mutation_performed=True,
                owned_resource_count=effect["owned_resource_count"],
                effect_codes=codes,
            ),
            next_actions=(action,),
            cancellation_available=False,
        )

    @staticmethod
    def _validate_health(
        value: Any,
        *,
        profile: LegacyAuthorityProfile,
        slot: OpaqueCredentialSlot,
        idempotency_key: str,
        minimum_restart_epoch: int,
        runtime_key: bytes,
        now_epoch: int,
    ) -> None:
        health = _exact_mapping(
            value,
            _HEALTH_FIELDS,
            "legacy_retirement_health_invalid",
        )
        if (
            health["verification_schema"]
            != "claudian-remote.legacy-retirement-health/v1"
            or _safe_id(
                health["authority_instance_id"],
                "legacy_retirement_health_invalid",
            )
            != profile.authority_instance_id
            or _protocol_id(
                health["protocol_version"],
                "legacy_retirement_health_invalid",
            )
            != profile.protocol_version
            or _safe_id(
                health["runtime_key_id"],
                "legacy_retirement_health_invalid",
            )
            != profile.runtime_key_id
            or _safe_id(
                health["slot_id"],
                "legacy_retirement_health_invalid",
            )
            != slot.slot_id
            or _integer(
                health["target_generation"],
                "legacy_retirement_health_invalid",
                minimum=1,
            )
            != slot.target_generation
            or _safe_id(
                health["idempotency_key"],
                "legacy_retirement_health_invalid",
            )
            != idempotency_key
            or health["old_credential_rejected"] is not True
        ):
            raise ValueError("legacy_retirement_health_invalid")
        restart_epoch = _integer(
            health["restart_epoch"],
            "legacy_retirement_health_invalid",
            minimum=1,
        )
        issued_at = _integer(
            health["issued_at_epoch"],
            "legacy_retirement_health_invalid",
        )
        if restart_epoch < minimum_restart_epoch or abs(now_epoch - issued_at) > 120:
            raise ValueError("legacy_retirement_health_invalid")
        try:
            evidence = base64.b64decode(health["evidence"], validate=True)
        except (TypeError, ValueError):
            raise ValueError("legacy_retirement_health_invalid") from None
        payload = json.dumps(
            {key: item for key, item in health.items() if key != "evidence"},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        expected = hmac.new(runtime_key, payload, hashlib.sha256).digest()
        if not hmac.compare_digest(evidence, expected):
            raise ValueError("legacy_retirement_health_invalid")

    def retire(
        self,
        *,
        credential: CredentialHandle,
        operation_id: str,
        plan_id: str,
        installation_id: str,
        vault_id: str,
        role: str,
        lock_held: bool = False,
    ) -> RetirementCommit:
        profile = self._profile()
        runtime_key = self._runtime_key(profile)
        material = bytearray(credential.read_once())
        try:
            transport = self.transport_factory(profile.authority_origin)
            descriptor = dict(transport.descriptor(material))
            if set(descriptor) != {"authority", "slot", "restart_epoch"}:
                raise ValueError("legacy_authority_response_invalid")
            authority = AuthorityDescriptor.from_mapping(descriptor["authority"])
            slot = OpaqueCredentialSlot.from_mapping(descriptor["slot"])
            restart_epoch = _integer(
                descriptor["restart_epoch"],
                "legacy_authority_response_invalid",
                minimum=1,
            )
            if (
                authority.profile_id != profile.profile_id
                or authority.protocol_version != profile.protocol_version
                or authority.authority_origin != profile.authority_origin
                or authority.authority_instance_id
                != profile.authority_instance_id
                or authority.runtime_key_id != profile.runtime_key_id
                or authority.owner_id != profile.owner_id
                or authority.mac_id != profile.mac_id
                or authority.installation_id != installation_id
                or authority.vault_id != vault_id
                or authority.role != role
            ):
                raise ValueError("legacy_authority_binding_mismatch")
            now = _integer(self.clock(), "retirement_time_invalid")
            binding = (
                f"{operation_id}:{plan_id}:{slot.slot_id}:"
                f"{slot.old_generation}:{slot.target_generation}"
            )
            nonce = "nonce-" + hashlib.sha256(
                (binding + ":nonce").encode("utf-8")
            ).hexdigest()[:32]
            idempotency_key = "retire-" + hashlib.sha256(
                (binding + ":idempotency").encode("utf-8")
            ).hexdigest()[:32]
            expected = RetirementExpectation(
                authority=authority,
                slot=slot,
                operation_id=operation_id,
                plan_id=plan_id,
                release_digest=profile.release_digest,
                helper_digest=profile.helper_digest,
                nonce=nonce,
                idempotency_key=idempotency_key,
                not_before_epoch=now,
            )
            request = {
                "operation_id": operation_id,
                "plan_id": plan_id,
                "authority_origin": authority.authority_origin,
                "owner_id": authority.owner_id,
                "installation_id": installation_id,
                "mac_id": authority.mac_id,
                "vault_id": vault_id,
                "role": role,
                "slot_id": slot.slot_id,
                "old_generation": slot.old_generation,
                "target_generation": slot.target_generation,
                "release_digest": profile.release_digest,
                "helper_digest": profile.helper_digest,
                "nonce": nonce,
                "idempotency_key": idempotency_key,
            }
            intent = RetirementIntent.from_expectation(expected)
            self._mark_dispatch_unknown(operation_id, plan_id, intent)
            try:
                candidate = RetirementProofCandidate.from_mapping(
                    transport.commit(material, request)
                )
                self._validate_health(
                    transport.verify(material, request),
                    profile=profile,
                    slot=slot,
                    idempotency_key=idempotency_key,
                    minimum_restart_epoch=restart_epoch,
                    runtime_key=runtime_key,
                    now_epoch=_integer(self.clock(), "retirement_time_invalid"),
                )
                consumer = RetirementProofConsumer(
                    self.checkpoint_store,
                    HmacRuntimeEvidenceVerifier(profile.runtime_key_id, runtime_key),
                    clock=self.clock,
                )
                return consumer.consume(
                    candidate,
                    expected,
                    lock_held=lock_held or self.lock_held_by_caller,
                )
            except Exception as exc:
                if isinstance(exc, LegacyRetirementOutcomeUnknown):
                    raise
                raise LegacyRetirementOutcomeUnknown(
                    "legacy_credential_retirement_outcome_unknown"
                ) from None
        finally:
            for index in range(len(material)):
                material[index] = 0

    def reconcile(
        self,
        *,
        credential: CredentialHandle,
        operation_id: str,
        plan_id: str,
        installation_id: str,
        vault_id: str,
        role: str,
        lock_held: bool = False,
    ) -> RetirementReconciliationResult:
        profile = self._profile()
        runtime_key = self._runtime_key(profile)
        checkpoint = self.checkpoint_store.read(operation_id)
        if checkpoint["plan_id"] != plan_id or checkpoint["journey"] != "legacy_upgrade":
            raise ValueError("retirement_checkpoint_invalid")
        intent = RetirementIntent.from_mapping(
            checkpoint["recorded_answers"].get("retirement_intent")
        )
        if (
            intent.operation_id != operation_id
            or intent.plan_id != plan_id
            or intent.installation_id != installation_id
            or intent.vault_id != vault_id
            or intent.role != role
        ):
            raise ValueError("retirement_intent_binding_mismatch")
        expected, request = self._request_from_intent(profile, intent)
        material = bytearray(credential.read_once())
        try:
            transport = self.transport_factory(profile.authority_origin)
            try:
                response = dict(transport.reconcile(material, request))
                outcome = response.get("outcome")
                if outcome == "retired":
                    if set(response) != {"outcome", "proof", "verification", "restart_epoch"}:
                        raise ValueError("retirement_reconciliation_invalid")
                    candidate = RetirementProofCandidate.from_mapping(response["proof"])
                    self._validate_health(
                        response["verification"],
                        profile=profile,
                        slot=expected.slot,
                        idempotency_key=expected.idempotency_key,
                        minimum_restart_epoch=_integer(
                            response["restart_epoch"],
                            "retirement_reconciliation_invalid",
                            minimum=1,
                        ),
                        runtime_key=runtime_key,
                        now_epoch=_integer(self.clock(), "retirement_time_invalid"),
                    )
                    consumer = RetirementProofConsumer(
                        self.checkpoint_store,
                        HmacRuntimeEvidenceVerifier(profile.runtime_key_id, runtime_key),
                        clock=self.clock,
                    )
                    commit = consumer.consume(
                        candidate,
                        expected,
                        lock_held=lock_held or self.lock_held_by_caller,
                    )
                    return RetirementReconciliationResult("retired", commit)
                if outcome == "not_applied":
                    if set(response) != {"outcome", "receipt"}:
                        raise ValueError("retirement_reconciliation_invalid")
                    self._validate_not_applied(
                        response["receipt"],
                        expected=expected,
                        verifier=HmacRuntimeEvidenceVerifier(
                            profile.runtime_key_id, runtime_key
                        ),
                        now_epoch=_integer(self.clock(), "retirement_time_invalid"),
                    )
                    rollback = NextAction(
                        action_id="rollback-original-operation",
                        action_type=NextActionType.LIFECYCLE_COMMAND,
                        owner=ActionOwner.AGENT,
                        recommended=True,
                        executable=True,
                        command="rollback",
                        parameters={"operation_id_ref": "result.operation_id"},
                    )
                    self._record_reconciliation_state(
                        operation_id,
                        ambiguity=AmbiguityState.NOT_APPLIED,
                        recovery=RecoveryPolicy.ROLLBACK_PRE_BOUNDARY,
                        credential_effect=CredentialEffect.NOT_APPLIED,
                        code="retirement_not_applied_proven",
                        action=rollback,
                    )
                    return RetirementReconciliationResult("not_applied")
                raise ValueError("retirement_reconciliation_invalid")
            except Exception:
                manual = NextAction(
                    action_id="manual-retirement-reconciliation",
                    action_type=NextActionType.MANUAL_INSTRUCTION,
                    owner=ActionOwner.MAINTAINER,
                    recommended=True,
                    executable=True,
                    parameters={"operation_id_ref": "result.operation_id"},
                )
                self._record_reconciliation_state(
                    operation_id,
                    ambiguity=AmbiguityState.INCONCLUSIVE,
                    recovery=RecoveryPolicy.MANUAL_RECOVERY_REQUIRED,
                    credential_effect=CredentialEffect.INCONCLUSIVE,
                    code="retirement_reconciliation_inconclusive",
                    action=manual,
                )
                return RetirementReconciliationResult("inconclusive")
        finally:
            for index in range(len(material)):
                material[index] = 0


class RetirementProofConsumer:
    MAX_PROOF_TTL_SECONDS = 600
    MAX_CLOCK_SKEW_SECONDS = 120

    def __init__(
        self,
        checkpoint_store: CheckpointStore,
        evidence_verifier: RuntimeEvidenceVerifier,
        *,
        clock: Callable[[], int],
    ) -> None:
        if not isinstance(checkpoint_store, CheckpointStore):
            raise TypeError("retirement_checkpoint_store_invalid")
        if not isinstance(evidence_verifier, RuntimeEvidenceVerifier):
            raise TypeError("runtime_evidence_verifier_invalid")
        self.store = checkpoint_store
        self.verifier = evidence_verifier
        self.clock = clock

    @classmethod
    def validate_only(
        cls,
        candidate: RetirementProofCandidate,
        expected: RetirementExpectation,
        verifier: RuntimeEvidenceVerifier,
        *,
        now_epoch: int,
    ) -> RetirementProofCandidate:
        if not isinstance(candidate, RetirementProofCandidate) or not isinstance(
            expected, RetirementExpectation
        ):
            raise TypeError("retirement_proof_contract_invalid")
        if not isinstance(verifier, RuntimeEvidenceVerifier):
            raise TypeError("runtime_evidence_verifier_invalid")
        # Public frozen dataclasses remain convenient typed values, but are not
        # themselves a parsing boundary.  Reparse every value before trust so
        # direct construction/dataclasses.replace cannot bypass strict schemas.
        candidate = RetirementProofCandidate.from_mapping(candidate.to_mapping())
        normalized_authority = AuthorityDescriptor.from_mapping(
            expected.authority.to_mapping()
        )
        normalized_slot = OpaqueCredentialSlot.from_mapping(expected.slot.to_mapping())
        if (
            normalized_authority != expected.authority
            or normalized_slot != expected.slot
        ):
            raise ValueError("retirement_expectation_contract_invalid")
        if candidate.authority_instance_id != expected.authority.authority_instance_id:
            raise ValueError("retirement_authority_mismatch")
        if candidate.authority_origin != expected.authority.authority_origin:
            raise ValueError("retirement_authority_mismatch")
        if candidate.runtime_key_id != expected.authority.runtime_key_id:
            raise ValueError("retirement_runtime_key_mismatch")
        candidate_scope = (
            candidate.owner_id,
            candidate.installation_id,
            candidate.mac_id,
            candidate.vault_id,
            candidate.role,
        )
        expected_scope = (
            expected.authority.owner_id,
            expected.authority.installation_id,
            expected.authority.mac_id,
            expected.authority.vault_id,
            expected.authority.role,
        )
        if candidate_scope != expected_scope:
            raise ValueError("retirement_scope_mismatch")
        if candidate.slot_id != expected.slot.slot_id:
            raise ValueError("retirement_slot_mismatch")
        if candidate.operation_id != expected.operation_id:
            raise ValueError("retirement_operation_mismatch")
        if candidate.plan_id != expected.plan_id:
            raise ValueError("retirement_plan_mismatch")
        if candidate.release_digest != expected.release_digest:
            raise ValueError("retirement_release_mismatch")
        if candidate.helper_digest != expected.helper_digest:
            raise ValueError("retirement_helper_mismatch")
        if candidate.nonce != expected.nonce:
            raise ValueError("retirement_nonce_mismatch")
        if candidate.idempotency_key != expected.idempotency_key:
            raise ValueError("retirement_idempotency_mismatch")
        if (
            candidate.old_generation != expected.slot.old_generation
            or candidate.target_generation != expected.slot.target_generation
        ):
            raise ValueError("retirement_generation_mismatch")
        if candidate.issued_at_epoch < (
            expected.not_before_epoch - cls.MAX_CLOCK_SKEW_SECONDS
        ) or candidate.issued_at_epoch > now_epoch + cls.MAX_CLOCK_SKEW_SECONDS:
            raise ValueError("retirement_clock_skew_invalid")
        if candidate.expires_at_epoch <= candidate.issued_at_epoch or (
            candidate.expires_at_epoch - candidate.issued_at_epoch
            > cls.MAX_PROOF_TTL_SECONDS
        ):
            raise ValueError("retirement_proof_ttl_invalid")
        if candidate.expires_at_epoch <= now_epoch:
            raise ValueError("retirement_proof_expired")
        verifier.verify(
            payload=candidate.signing_payload(),
            evidence=candidate.evidence,
            runtime_key_id=candidate.runtime_key_id,
        )
        return candidate

    def consume(
        self,
        candidate: RetirementProofCandidate,
        expected: RetirementExpectation,
        *,
        lock_held: bool = False,
    ) -> RetirementCommit:
        now_epoch = _integer(self.clock(), "retirement_time_invalid")
        context = nullcontext() if lock_held else OperationLock(self.store.directory.path)
        with context:
            checkpoint = self.store.read(expected.operation_id)
            if (
                checkpoint["operation_id"] != expected.operation_id
                or checkpoint["plan_id"] != expected.plan_id
                or checkpoint["journey"] != "legacy_upgrade"
                or (
                    checkpoint["irreversible_boundary_crossed"] is not False
                    and "retirement_commit"
                    not in checkpoint["recorded_answers"]
                )
                or checkpoint["ambiguity_state"]
                not in {"retirement_outcome_unknown", "retired"}
            ):
                raise ValueError("retirement_checkpoint_invalid")
            existing_raw = checkpoint["recorded_answers"].get("retirement_commit")
            existing = (
                RetirementCommit.from_mapping(existing_raw)
                if existing_raw is not None
                else None
            )
            if existing is not None and (
                now_epoch + self.MAX_CLOCK_SKEW_SECONDS < existing.consumed_at_epoch
            ):
                raise ValueError("retirement_clock_rollback")

            candidate = self.validate_only(
                candidate,
                expected,
                self.verifier,
                now_epoch=now_epoch,
            )
            if existing is not None:
                if candidate.outcome != "already_retired":
                    raise ValueError("retirement_proof_replay")
                if not self._same_binding(existing, candidate, expected):
                    raise ValueError("retirement_proof_replay")
                return existing

            checkpoints, invalid_count = self.store.inventory()
            if invalid_count:
                # A corrupt checkpoint may contain the only durable generation
                # commit.  Continuing would turn unreadable history into a
                # replay window, so proof consumption must fail closed.
                raise ValueError("retirement_generation_history_invalid")
            self._require_next_generation(
                checkpoints,
                candidate,
                current_operation_id=expected.operation_id,
            )

            proof_digest = hashlib.sha256(
                json.dumps(
                    candidate.to_mapping(),
                    ensure_ascii=True,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest()
            commit = RetirementCommit(
                authority_instance_id=candidate.authority_instance_id,
                authority_origin_digest=_sha256_text(candidate.authority_origin),
                runtime_key_id=candidate.runtime_key_id,
                owner_id=candidate.owner_id,
                installation_id=candidate.installation_id,
                mac_id=candidate.mac_id,
                vault_id=candidate.vault_id,
                role=candidate.role,
                slot_id=candidate.slot_id,
                old_generation=candidate.old_generation,
                target_generation=candidate.target_generation,
                operation_id=candidate.operation_id,
                plan_id=candidate.plan_id,
                release_digest=candidate.release_digest,
                helper_digest=candidate.helper_digest,
                nonce_digest=_sha256_text(candidate.nonce),
                idempotency_digest=_sha256_text(candidate.idempotency_key),
                proof_digest=proof_digest,
                consumed_at_epoch=now_epoch,
            )
            recorded = dict(checkpoint["recorded_answers"])
            recorded["retirement_commit"] = commit.to_mapping()
            effect = checkpoint["effect_summary"]
            codes = tuple(dict.fromkeys((*effect["effect_codes"], "retirement_proof_consumed")))
            finish_forward = NextAction(
                action_id="finish-forward-original-operation",
                action_type=NextActionType.LIFECYCLE_COMMAND,
                owner=ActionOwner.AGENT,
                recommended=True,
                executable=True,
                command="resume",
                parameters={"operation_id_ref": "result.operation_id"},
            )
            self.store.update(
                expected.operation_id,
                state="recovery_required",
                phase="retirement_reconciliation",
                recorded_answers=recorded,
                active_gate=None,
                irreversible_boundary_crossed=True,
                ambiguity_state=AmbiguityState.RETIRED,
                recovery_policy=RecoveryPolicy.FINISH_FORWARD,
                effect_summary=EffectSummary(
                    local_effect=EffectDisposition(effect["local_effect"]),
                    remote_effect=EffectDisposition(effect["remote_effect"]),
                    credential_effect=CredentialEffect.RETIRED,
                    mutation_performed=True,
                    owned_resource_count=effect["owned_resource_count"],
                    effect_codes=codes,
                ),
                next_actions=(finish_forward,),
                cancellation_available=False,
            )
            return commit

    @staticmethod
    def _require_next_generation(
        checkpoints: list[Mapping[str, Any]],
        candidate: RetirementProofCandidate,
        *,
        current_operation_id: str,
    ) -> None:
        high_water: int | None = None
        origin_digest = _sha256_text(candidate.authority_origin)
        for checkpoint in checkpoints:
            if checkpoint.get("operation_id") == current_operation_id:
                continue
            raw = checkpoint.get("recorded_answers", {}).get("retirement_commit")
            if raw is None:
                continue
            commit = RetirementCommit.from_mapping(raw)
            same_slot = (
                commit.authority_instance_id == candidate.authority_instance_id
                and commit.authority_origin_digest == origin_digest
                and commit.owner_id == candidate.owner_id
                and commit.installation_id == candidate.installation_id
                and commit.vault_id == candidate.vault_id
                and commit.role == candidate.role
                and commit.slot_id == candidate.slot_id
            )
            if same_slot:
                high_water = max(high_water or 0, commit.target_generation)
        if high_water is None:
            return
        if (
            candidate.old_generation < high_water
            or candidate.target_generation <= high_water
        ):
            raise ValueError("retirement_generation_replay")
        if candidate.old_generation != high_water:
            raise ValueError("retirement_generation_mismatch")

    @staticmethod
    def _same_binding(
        commit: RetirementCommit,
        candidate: RetirementProofCandidate,
        expected: RetirementExpectation,
    ) -> bool:
        return (
            commit.authority_instance_id == candidate.authority_instance_id
            and commit.authority_origin_digest == _sha256_text(candidate.authority_origin)
            and commit.runtime_key_id == candidate.runtime_key_id
            and commit.owner_id == candidate.owner_id
            and commit.installation_id == candidate.installation_id
            and commit.mac_id == candidate.mac_id
            and commit.vault_id == candidate.vault_id
            and commit.role == candidate.role
            and commit.slot_id == candidate.slot_id
            and commit.old_generation == candidate.old_generation
            and commit.target_generation == candidate.target_generation
            and commit.operation_id == candidate.operation_id
            and commit.plan_id == candidate.plan_id
            and commit.release_digest == candidate.release_digest
            and commit.helper_digest == candidate.helper_digest
            and commit.nonce_digest == _sha256_text(expected.nonce)
            and commit.idempotency_digest == _sha256_text(expected.idempotency_key)
        )
