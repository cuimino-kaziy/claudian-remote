"""Agent-safe pairing orchestration.

The Relay owns claims and credentials.  This module only coordinates the
human-facing Mac UI and emits non-secret lifecycle gates/results.  Raw claim
material is passed directly to the injected presenter and is never retained in
the operation journal or returned to an Agent.
"""

from __future__ import annotations

import json
import re
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol

from .private_io import write_private_json


SUPPORTED_MODES = frozenset({"local_tailscale", "local_lan", "remote_vps"})
REPAIR_REASONS = frozenset(
    {
        "legacy_token_migration",
        "lost_device",
        "profile_changed",
        "suspected_disclosure",
        "endpoint_changed",
    }
)
PAIRING_IDENTITY_SCHEMA = "claudian-remote.pairing-identity/v1"
DEVICE_ID_PATTERN = re.compile(r"[A-Za-z0-9._:-]{1,128}")


class PairingManagement(Protocol):
    def create_claim(self, profile: Mapping[str, str]) -> Mapping[str, Any]: ...

    def inspect_claim(self, claim_id: str) -> Mapping[str, Any]: ...

    def approve_claim(self, claim_id: str, device_id: str) -> Mapping[str, Any]: ...

    def revoke_device(self, device_id: str) -> Mapping[str, Any]: ...


@dataclass(frozen=True)
class _PendingPairing:
    claim_id: str
    profile: dict[str, str]


def _validate_profile(profile: Mapping[str, Any]) -> dict[str, str]:
    normalized = {
        "mode": str(profile.get("mode") or ""),
        "installation_id": str(profile.get("installation_id") or ""),
        "vault_id": str(profile.get("vault_id") or ""),
        "endpoint_audience": str(profile.get("endpoint_audience") or ""),
    }
    if normalized["mode"] not in SUPPORTED_MODES:
        raise ValueError("unsupported_connection_mode")
    if not normalized["installation_id"] or not normalized["vault_id"]:
        raise ValueError("incomplete_pairing_profile")
    expected = f"claudian-remote:{normalized['mode']}:{normalized['installation_id']}"
    if normalized["endpoint_audience"] != expected:
        raise ValueError("pairing_profile_audience_mismatch")
    return normalized


def _gate(
    *,
    gate_type: str,
    explanation: str,
    human_action: str,
    verification_probe: str,
    resume_reference: str,
    code: str | None = None,
) -> dict[str, Any]:
    return {
        "state": "blocked",
        "ready": False,
        "code": code or gate_type,
        "gate": {
            "gate_type": gate_type,
            "explanation": explanation,
            "human_action": human_action,
            "verification_probe": verification_probe,
            "resume_reference": resume_reference,
        },
    }


class PairingAdminBootstrap:
    """Require a locally verified secure reference before claim management."""

    def inspect(
        self,
        *,
        credential_ref: str | None,
        verify_ref: Callable[[str], bool],
    ) -> dict[str, Any]:
        reference = str(credential_ref or "")
        if not reference or not verify_ref(reference):
            return _gate(
                gate_type="pairing_admin_bootstrap_required",
                explanation="The Mac needs a device-local Pairing Admin identity before it can enroll a phone.",
                human_action="Open Claudian Remote settings on the Mac and create or restore the Pairing Admin identity.",
                verification_probe="pairing_admin_secure_reference",
                resume_reference="pairing-admin:bootstrap",
            )
        return {
            "state": "ready",
            "ready": True,
            "pairing_admin": {"credential_ref": "<secure-reference>"},
        }


class PairingLifecycle:
    def __init__(
        self,
        management: PairingManagement,
        present_to_human: Callable[[Mapping[str, Any]], None],
    ) -> None:
        self._management = management
        self._present_to_human = present_to_human
        self._pending: dict[str, _PendingPairing] = {}

    def begin(self, profile: Mapping[str, Any]) -> dict[str, Any]:
        normalized = _validate_profile(profile)
        created = dict(self._management.create_claim(normalized))
        claim_id = str(created.get("claim_id") or "")
        if not claim_id:
            raise RuntimeError("pairing_claim_identifier_missing")

        # This callback is the only intended consumer of raw claim material.
        # Do not save ``created`` or include it in Agent-visible output.
        self._present_to_human(created)
        resume_reference = f"pairing:{secrets.token_urlsafe(18)}"
        self._pending[resume_reference] = _PendingPairing(claim_id, normalized)
        return _gate(
            gate_type="pairing_approval_required",
            explanation="A person must redeem the code on the phone and approve that device on the Mac.",
            human_action="Use the code shown in the Mac pairing window, then review and approve the displayed phone.",
            verification_probe="pairing_claim_state",
            resume_reference=resume_reference,
        )

    def resume(self, resume_reference: str) -> dict[str, Any]:
        operation = self._operation(resume_reference)
        inspected = dict(self._management.inspect_claim(operation.claim_id))
        state = str(inspected.get("state") or "")
        if state == "pending_redemption":
            return _gate(
                gate_type="pairing_redemption_required",
                explanation="The phone has not redeemed the one-time claim yet.",
                human_action="Enter the displayed short code on the phone or open the QR deep link.",
                verification_probe="pairing_claim_state",
                resume_reference=resume_reference,
            )
        if state == "pending_approval":
            device_id = str(inspected.get("device_id") or "")
            result = _gate(
                gate_type="pairing_device_confirmation_required",
                explanation="The Mac must confirm the phone shown in the pairing window.",
                human_action="Verify the displayed phone and approve it in Claudian Remote settings.",
                verification_probe="pairing_claim_state",
                resume_reference=resume_reference,
            )
            result["device"] = {"device_id": device_id}
            return result
        if state in {"paired", "completed", "issued"}:
            self._pending.pop(resume_reference, None)
            return self._paired(operation, str(inspected.get("device_id") or ""))
        if state == "credential_ready":
            return _gate(
                gate_type="pairing_mobile_completion_required",
                explanation="The Mac approved the phone; the phone still needs to receive its one-time credential.",
                human_action="Return to Claudian Remote on the phone and finish pairing.",
                verification_probe="paired_device_active",
                resume_reference=resume_reference,
            )
        self._pending.pop(resume_reference, None)
        return {
            "state": "blocked",
            "ready": False,
            "code": state or "pairing_claim_unavailable",
            "re_pair_required": True,
            "restore_cache": False,
            "reuse_credential": False,
        }

    def approve(self, resume_reference: str, *, confirmed_device_id: str) -> dict[str, Any]:
        operation = self._operation(resume_reference)
        inspected = dict(self._management.inspect_claim(operation.claim_id))
        if inspected.get("state") != "pending_approval":
            return self.resume(resume_reference)
        actual_device_id = str(inspected.get("device_id") or "")
        if not actual_device_id or not secrets.compare_digest(actual_device_id, str(confirmed_device_id)):
            return {
                "state": "blocked",
                "ready": False,
                "code": "pairing_device_confirmation_mismatch",
                "re_pair_required": False,
            }
        approved = dict(self._management.approve_claim(operation.claim_id, actual_device_id))
        # Ignore any accidental credential field returned by an adapter.
        approved_state = str(approved.get("state") or "")
        if approved_state in {"paired", "completed", "issued"}:
            self._pending.pop(resume_reference, None)
            return self._paired(operation, actual_device_id)
        if approved_state in {"approved", "credential_ready"}:
            return _gate(
                gate_type="pairing_mobile_completion_required",
                explanation="The Mac approved the phone; the phone still needs to receive its one-time credential.",
                human_action="Return to Claudian Remote on the phone and finish pairing.",
                verification_probe="paired_device_active",
                resume_reference=resume_reference,
            )
        return self.resume(resume_reference)

    def revoke(self, device_id: str, *, reason: str) -> dict[str, Any]:
        if reason not in REPAIR_REASONS:
            raise ValueError("unsupported_pairing_repair_reason")
        target = str(device_id or "")
        if not target:
            raise ValueError("device_id_required")
        self._management.revoke_device(target)
        return {
            "state": "revoked",
            "ready": False,
            "device": {"device_id": target},
            "reason": reason,
            "re_pair_required": True,
            "restore_cache": False,
            "reuse_credential": False,
        }

    def repair_required(self, reason: str) -> dict[str, Any]:
        if reason not in REPAIR_REASONS:
            raise ValueError("unsupported_pairing_repair_reason")
        result = _gate(
            gate_type="pairing_repair_required",
            code="new_pairing_required",
            explanation="This profile requires a new device credential; the prior credential cannot be reused.",
            human_action="Revoke the old phone if present, then start a new pairing from the Mac.",
            verification_probe="paired_device_active",
            resume_reference=f"pairing-repair:{reason}",
        )
        result.update(
            {
                "reason": reason,
                "re_pair_required": True,
                "restore_cache": False,
                "reuse_credential": False,
            }
        )
        return result

    def _operation(self, resume_reference: str) -> _PendingPairing:
        try:
            return self._pending[str(resume_reference)]
        except KeyError as exc:
            raise ValueError("unknown_pairing_resume_reference") from exc

    def _paired(self, operation: _PendingPairing, device_id: str) -> dict[str, Any]:
        return {
            "state": "paired",
            "ready": True,
            "device": {"device_id": device_id},
            "profile": dict(operation.profile),
            "repair_required": False,
        }


class PairingIdentityTransition:
    """Persist and enforce the signed pairing policy for one update operation.

    Device identifiers are private lifecycle state. They never appear in the
    Agent-facing result. Rotation is deliberately delayed until the new
    release and desktop bridge have both passed verification.
    """

    def __init__(
        self,
        state_directory: Path,
        *,
        active_device_ids: Callable[[], object],
        revoke_device: Callable[[str, str], Mapping[str, Any]] | None = None,
        interruption_probe: Callable[[str], None] = lambda _phase: None,
    ) -> None:
        self._state_directory = Path(state_directory)
        self._active_device_ids = active_device_ids
        self._revoke_device = revoke_device
        self._interrupt = interruption_probe

    def _path(self, operation_id: str) -> Path:
        return self._state_directory / f"{operation_id}.pairing-identity.json"

    @staticmethod
    def _normalize_device_ids(value: object) -> list[str]:
        if isinstance(value, (str, bytes, Mapping)) or not isinstance(
            value, (list, tuple, set, frozenset)
        ):
            raise ValueError("pairing_device_inventory_invalid")
        normalized: set[str] = set()
        for item in value:
            device_id = str(item or "")
            if not DEVICE_ID_PATTERN.fullmatch(device_id):
                raise ValueError("pairing_device_inventory_invalid")
            normalized.add(device_id)
        return sorted(normalized)

    def _read(
        self,
        *,
        operation_id: str,
        plan_id: str,
        policy: str,
    ) -> dict[str, Any] | None:
        try:
            value = json.loads(self._path(operation_id).read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError("pairing_identity_journal_invalid") from exc
        expected = {
            "pairing_identity_schema",
            "operation_id",
            "plan_id",
            "policy",
            "phase",
            "original_device_ids",
            "revoked_device_ids",
        }
        if (
            not isinstance(value, dict)
            or set(value) != expected
            or value.get("pairing_identity_schema") != PAIRING_IDENTITY_SCHEMA
            or value.get("operation_id") != operation_id
            or value.get("plan_id") != plan_id
            or value.get("policy") != policy
            or value.get("phase")
            not in {"captured", "rotation_committed", "ready", "rolled_back"}
        ):
            raise ValueError("pairing_identity_journal_invalid")
        original = self._normalize_device_ids(value.get("original_device_ids"))
        revoked = self._normalize_device_ids(value.get("revoked_device_ids"))
        if not set(revoked).issubset(original):
            raise ValueError("pairing_identity_journal_invalid")
        return {**value, "original_device_ids": original, "revoked_device_ids": revoked}

    def _write(self, operation_id: str, value: Mapping[str, Any]) -> None:
        write_private_json(self._path(operation_id), dict(value))

    def capture(
        self,
        *,
        operation_id: str,
        plan_id: str,
        policy: str,
    ) -> None:
        if policy not in {"preserve", "rotate"}:
            raise ValueError("current_update_pairing_identity_policy_invalid")
        if self._read(operation_id=operation_id, plan_id=plan_id, policy=policy) is not None:
            return
        self._write(
            operation_id,
            {
                "pairing_identity_schema": PAIRING_IDENTITY_SCHEMA,
                "operation_id": operation_id,
                "plan_id": plan_id,
                "policy": policy,
                "phase": "captured",
                "original_device_ids": self._normalize_device_ids(
                    self._active_device_ids()
                ),
                "revoked_device_ids": [],
            },
        )

    def rotation_committed(
        self, *, operation_id: str, plan_id: str, policy: str
    ) -> bool:
        value = self._read(operation_id=operation_id, plan_id=plan_id, policy=policy)
        return bool(value and value["phase"] in {"rotation_committed", "ready"})

    def operation_rotation_committed(
        self, *, operation_id: str, plan_id: str
    ) -> bool:
        """Return whether this operation crossed the irreversible rotate boundary.

        Recovery does not yet have the signed plan payload, so it must inspect
        the journal's own policy before selecting the matching strict reader.
        A valid preserve journal is not a rotate recovery and must return False.
        """

        path = self._path(operation_id)
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return False
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError("pairing_identity_journal_invalid") from exc
        if not isinstance(raw, dict) or raw.get("policy") not in {
            "preserve",
            "rotate",
        }:
            raise ValueError("pairing_identity_journal_invalid")
        policy = str(raw["policy"])
        value = self._read(
            operation_id=operation_id,
            plan_id=plan_id,
            policy=policy,
        )
        return bool(
            policy == "rotate"
            and value
            and value["phase"] in {"rotation_committed", "ready"}
        )

    def ready(self, *, operation_id: str, plan_id: str, policy: str) -> bool:
        value = self._read(operation_id=operation_id, plan_id=plan_id, policy=policy)
        return bool(value and value["phase"] == "ready")

    def rollback(self, *, operation_id: str, plan_id: str, policy: str) -> bool:
        value = self._read(operation_id=operation_id, plan_id=plan_id, policy=policy)
        if value is None:
            return True
        if policy == "rotate" and value["phase"] in {
            "rotation_committed",
            "ready",
        }:
            return False
        self._write(operation_id, {**value, "phase": "rolled_back"})
        return True

    def finalize(
        self, *, operation_id: str, plan_id: str, policy: str
    ) -> dict[str, Any]:
        value = self._read(operation_id=operation_id, plan_id=plan_id, policy=policy)
        if value is None or value["phase"] == "rolled_back":
            raise ValueError("pairing_identity_capture_missing")
        active = set(self._normalize_device_ids(self._active_device_ids()))
        original = set(value["original_device_ids"])

        if policy == "preserve":
            if original and not original.issubset(active):
                return {
                    "state": "blocked",
                    "code": "pairing_identity_preservation_failed",
                    "re_pair_required": True,
                }
            if not active:
                return {
                    "state": "blocked",
                    "code": "pairing_approval_required",
                    "re_pair_required": True,
                }
            self._write(operation_id, {**value, "phase": "ready"})
            return {
                "state": "ready",
                "code": "pairing_identity_preserved",
                "re_pair_required": False,
            }

        if value["phase"] == "captured":
            if self._revoke_device is None:
                return {
                    "state": "blocked",
                    "code": "pairing_identity_authority_unavailable",
                    "re_pair_required": False,
                }
            revoked = set(value["revoked_device_ids"])
            for device_id in sorted(original - revoked):
                result = dict(self._revoke_device(device_id, "profile_changed"))
                if result.get("state") not in {"ready", "revoked"}:
                    return {
                        "state": "blocked",
                        "code": "pairing_identity_rotation_failed",
                        "re_pair_required": False,
                    }
                revoked.add(device_id)
                value = {**value, "revoked_device_ids": sorted(revoked)}
                self._write(operation_id, value)
            value = {**value, "phase": "rotation_committed"}
            self._write(operation_id, value)
            self._interrupt("after_pairing_identity_rotation")

        active = set(self._normalize_device_ids(self._active_device_ids()))
        if original.intersection(active):
            return {
                "state": "blocked",
                "code": "pairing_identity_rotation_unverified",
                "re_pair_required": False,
            }
        if not (active - original):
            return {
                "state": "blocked",
                "code": "pairing_approval_required",
                "re_pair_required": True,
            }
        self._write(operation_id, {**value, "phase": "ready"})
        return {
            "state": "ready",
            "code": "pairing_identity_rotated",
            "re_pair_required": False,
        }
