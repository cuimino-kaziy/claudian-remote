"""Strict, read-only decoding of the exact supported Beta 4 lifecycle set.

The v1 files pre-date the Beta 5 authority proof contract.  This module only
normalizes facts that v1 can prove from its own bytes.  In particular, a
legacy migration marker is never promoted into proof that a credential was
retired: any operation which carried a legacy credential remains
``inconclusive`` until the original operation is reconciled by its v1 path.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any, Mapping, Sequence


CHECKPOINT_V1 = "claudian-remote.checkpoint/v1"
PLAN_V1 = "claudian-remote.plan/v1"
SNAPSHOT_V1 = "claudian-remote.inspection/v1"
LOCAL_TRANSACTION_V1 = "claudian-remote.local-transaction/v1"
LEGACY_MIGRATION_V1 = "claudian-remote.legacy-plugin/v1"

_OPERATION_ID = re.compile(r"op-[0-9a-f]{32}")
_CONTENT_ID = re.compile(r"(?:plan|inspection)-[0-9a-f]{64}")
_INSTALLATION_ID = re.compile(r"installation-[0-9a-f]{24}")
_PROFILE_GENERATION_ID = re.compile(r"profile-generation-[0-9a-f]{64}")
_COMPATIBILITY_SET_ID = re.compile(r"claudian-remote-[0-9A-Za-z][0-9A-Za-z.+-]{0,127}")
_SAFE_PHASE = re.compile(r"[a-z][a-z0-9_]{0,127}")
_VAULT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}")

_CHECKPOINT_STATES = frozenset(
    {"ready", "prepared", "blocked", "rolled_back", "recovery_required"}
)
_COMMANDS = frozenset({"install", "update"})
_CONNECTION_MODES = frozenset({"local_tailscale", "remote_vps", "local_lan"})
_TRANSACTION_PHASES = frozenset(
    {
        "before_staging",
        "before_legacy_migration",
        "before_activation",
        "activation_started",
        "plugin_activated",
        "after_activation",
        "await_plugin_bootstrap",
        "await_pairing",
        "ready",
        "rolled_back",
        "recovery_required",
    }
)
_MIGRATION_PHASES = frozenset(
    {
        "pending_revocation",
        "credential_revoked",
        "sanitized",
        "isolated",
        "prepared",
        "activated",
        "committed",
        "rolled_back",
    }
)
_LOCAL_PHASE_ORDER = (
    "staging",
    "legacy_plugin_migration",
    "secure_provisioning",
    "plugin_activation",
    "launchd",
    "tailscale_serve",
    "verified",
    "paired",
)
_TOPOLOGY_COMBINATIONS = frozenset(
    {
        ("local_tailscale", "mac_loopback", "tailscale_serve"),
        ("remote_vps", "vps", "user_owned_https_wss"),
        ("local_lan", "mac_loopback", "approved_tls_lan_gateway"),
    }
)
_GATE_COMBINATIONS = frozenset(
    {
        ("pairing_admin_bootstrap_required", "companion_secure_provisioning_available"),
        ("tailscale_install_required", "tailscale_installed"),
        ("tailscale_login_required", "tailscale_logged_in"),
        ("vps_host_authorization_required", "vps_host_key_confirmed"),
        ("trusted_lan_consent_required", "trusted_lan_consent_recorded"),
        ("pairing_approval_required", "pairing_credential_active"),
    }
)
_AFFECTED_RESOURCES = (
    "device_local_state",
    "mac_companion",
    "obsidian_plugin:claudian-remote",
    "pairing_identity",
    "relay_runtime",
)


class CompatibilityDecodeError(ValueError):
    """Stable fail-closed error without including source data or paths."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class ArtifactKind(str, Enum):
    CHECKPOINT = "checkpoint"
    SAVED_PLAN = "saved_plan"
    LOCAL_TRANSACTION = "local_transaction"
    LEGACY_MIGRATION = "legacy_migration"


class LegacyCredentialEffect(str, Enum):
    NOT_APPLIED = "not_applied"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True)
class SourceEvidence:
    artifact: ArtifactKind
    source_name: str
    schema: str
    byte_length: int
    sha256: str


@dataclass(frozen=True)
class V1Reconciliation:
    """Secret-free facts suitable for later schema-v2 operation arbitration."""

    operation_id: str
    plan_id: str
    command: str
    checkpoint_state: str
    checkpoint_phase: str
    completed_phases: tuple[str, ...]
    active_gate_present: bool
    compatibility_set_id: str
    vault_id: str
    topology_mode: str
    transaction_phase: str | None
    migration_phase: str | None
    legacy_credential_effect: LegacyCredentialEffect
    mutation_may_have_started: bool
    sources: tuple[SourceEvidence, ...]


@dataclass(frozen=True)
class _DecodedSource:
    value: Mapping[str, Any]
    evidence: SourceEvidence


def load_supported_v1_checkpoint(
    checkpoint_path: Path,
    *,
    expected_operation_id: str,
) -> tuple[dict[str, Any], SourceEvidence]:
    """Read one strict v1 checkpoint bound to an expected operation id."""

    _require_match(
        expected_operation_id,
        _OPERATION_ID,
        "v1_checkpoint_expected_identity_invalid",
    )
    source_path = Path(checkpoint_path)
    if source_path.parent.is_symlink():
        raise CompatibilityDecodeError("v1_artifact_parent_invalid")
    source = _read_source(source_path, ArtifactKind.CHECKPOINT)
    checkpoint = _validate_checkpoint(source.value)
    _require_filename(source_path, f"{expected_operation_id}.json")
    if checkpoint["operation_id"] != expected_operation_id:
        raise CompatibilityDecodeError("v1_checkpoint_identity_mismatch")
    return _detached_mapping(checkpoint), source.evidence


def load_supported_v1_saved_plan(
    saved_plan_path: Path,
    *,
    expected_plan_id: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Load one immutable v1 plan/snapshot bound to an expected plan id.

    This is intentionally narrower than a generic JSON loader.  Recovery may
    use only the exact Beta 4 plan schema whose content hash, snapshot hash,
    filename, and caller-supplied identity all agree.  Detached copies are
    returned so callers cannot mutate the decoder's validated source value.
    """

    _require_match(
        expected_plan_id,
        re.compile(r"plan-[0-9a-f]{64}"),
        "v1_saved_plan_expected_identity_invalid",
    )
    source_path = Path(saved_plan_path)
    if source_path.parent.is_symlink():
        raise CompatibilityDecodeError("v1_artifact_parent_invalid")
    source = _read_source(source_path, ArtifactKind.SAVED_PLAN)
    plan, snapshot = _validate_saved_plan(source.value)
    _require_filename(source_path, f"{expected_plan_id}.json")
    if plan["plan_id"] != expected_plan_id:
        raise CompatibilityDecodeError("v1_companion_identity_mismatch")
    return _detached_mapping(plan), _detached_mapping(snapshot)


def mark_supported_v1_checkpoint_rolled_back(
    checkpoint_path: Path,
    *,
    expected_operation_id: str,
    expected_checkpoint_sha256: str,
) -> SourceEvidence:
    """Atomically close one exact v1 recovery checkpoint after rollback.

    ``expected_checkpoint_sha256`` is the digest observed during the prior
    read-only arbitration.  The checkpoint is validated and compared again
    immediately before ``os.replace`` so stale or concurrently changed input
    fails closed instead of closing a different operation.  The checkpoint is
    retained as terminal evidence; no operation artifact is deleted.
    """

    _require_match(
        expected_operation_id,
        _OPERATION_ID,
        "v1_checkpoint_expected_identity_invalid",
    )
    _require_match(
        expected_checkpoint_sha256,
        re.compile(r"[0-9a-f]{64}"),
        "v1_checkpoint_expected_digest_invalid",
    )
    target = Path(checkpoint_path)
    if target.parent.is_symlink():
        raise CompatibilityDecodeError("v1_artifact_parent_invalid")

    source = _read_source(target, ArtifactKind.CHECKPOINT)
    checkpoint = _validate_checkpoint(source.value)
    _require_checkpoint_update_binding(
        target,
        checkpoint,
        source.evidence,
        expected_operation_id=expected_operation_id,
        expected_checkpoint_sha256=expected_checkpoint_sha256,
    )

    if checkpoint["state"] == "rolled_back":
        if checkpoint["phase"] != "rollback_completed":
            raise CompatibilityDecodeError("v1_checkpoint_terminal_state_invalid")
        return source.evidence
    if checkpoint["state"] != "recovery_required":
        raise CompatibilityDecodeError("v1_checkpoint_not_recoverable")

    updated = {
        **checkpoint,
        "phase": "rollback_completed",
        "state": "rolled_back",
        "active_gate": None,
    }
    _validate_checkpoint(updated)
    _atomic_replace_checkpoint_if_unchanged(
        target,
        updated,
        expected_operation_id=expected_operation_id,
        expected_checkpoint_sha256=expected_checkpoint_sha256,
    )

    persisted = _read_source(target, ArtifactKind.CHECKPOINT)
    persisted_checkpoint = _validate_checkpoint(persisted.value)
    if persisted_checkpoint != updated:
        raise CompatibilityDecodeError("v1_checkpoint_write_verification_failed")
    return persisted.evidence


def decode_v1_compatibility_set(
    *,
    checkpoint_path: Path,
    saved_plan_path: Path,
    local_transaction_path: Path | None = None,
    legacy_migration_path: Path | None = None,
) -> V1Reconciliation:
    """Decode one operation-bound v1 set without modifying any source file.

    A checkpoint and its immutable saved plan/snapshot are always required.
    Transaction and migration journals are accepted only as companions bound
    to the same operation.  A recovery/terminal checkpoint with recorded local
    phases must have its local transaction companion.
    """

    checkpoint_source = _read_source(checkpoint_path, ArtifactKind.CHECKPOINT)
    checkpoint = _validate_checkpoint(checkpoint_source.value)
    operation_id = checkpoint["operation_id"]
    plan_id = checkpoint["plan_id"]
    _require_filename(checkpoint_path, f"{operation_id}.json")

    plan_source = _read_source(saved_plan_path, ArtifactKind.SAVED_PLAN)
    plan, _snapshot = _validate_saved_plan(plan_source.value)
    _require_filename(saved_plan_path, f"{plan_id}.json")
    if plan["plan_id"] != plan_id:
        raise CompatibilityDecodeError("v1_companion_identity_mismatch")

    transaction_source: _DecodedSource | None = None
    transaction: Mapping[str, Any] | None = None
    if local_transaction_path is not None:
        transaction_source = _read_source(
            local_transaction_path, ArtifactKind.LOCAL_TRANSACTION
        )
        transaction = _validate_local_transaction(transaction_source.value)
        _require_filename(
            local_transaction_path, f"{operation_id}.transaction.json"
        )
        if (
            transaction["operation_id"] != operation_id
            or transaction["plan_id"] != plan_id
        ):
            raise CompatibilityDecodeError("v1_companion_identity_mismatch")

    if _transaction_companion_required(checkpoint) and transaction is None:
        raise CompatibilityDecodeError("v1_companion_missing")
    if transaction is not None and tuple(transaction["completed_phases"]) != tuple(
        checkpoint["completed_phases"]
    ):
        raise CompatibilityDecodeError("v1_companion_phase_mismatch")

    migration_source: _DecodedSource | None = None
    migration: Mapping[str, Any] | None = None
    if legacy_migration_path is not None:
        if transaction is None:
            raise CompatibilityDecodeError("v1_companion_missing")
        migration_source = _read_source(
            legacy_migration_path, ArtifactKind.LEGACY_MIGRATION
        )
        migration = _validate_legacy_migration(migration_source.value)
        # v1 migration journals intentionally had no operation_id.  Their
        # only admissible binding is the exact validated operation filename.
        _require_filename(
            legacy_migration_path, f"{operation_id}.legacy-plugin.json"
        )
        synchronized = migration["synchronized"]
        if (
            synchronized["vault_id"] != plan["vault_id"]
            or synchronized["connection_mode"] != plan["topology"]["mode"]
        ):
            raise CompatibilityDecodeError("v1_companion_identity_mismatch")

    if migration is not None and migration["re_pair_required"] is True:
        legacy_effect = LegacyCredentialEffect.INCONCLUSIVE
    else:
        legacy_effect = LegacyCredentialEffect.NOT_APPLIED

    sources = [checkpoint_source.evidence, plan_source.evidence]
    if transaction_source is not None:
        sources.append(transaction_source.evidence)
    if migration_source is not None:
        sources.append(migration_source.evidence)
    return V1Reconciliation(
        operation_id=operation_id,
        plan_id=plan_id,
        command=checkpoint["command"],
        checkpoint_state=checkpoint["state"],
        checkpoint_phase=checkpoint["phase"],
        completed_phases=tuple(checkpoint["completed_phases"]),
        active_gate_present=checkpoint["active_gate"] is not None,
        compatibility_set_id=plan["compatibility_set_id"],
        vault_id=plan["vault_id"],
        topology_mode=plan["topology"]["mode"],
        transaction_phase=(str(transaction["phase"]) if transaction else None),
        migration_phase=(str(migration["phase"]) if migration else None),
        legacy_credential_effect=legacy_effect,
        mutation_may_have_started=bool(
            checkpoint["completed_phases"]
            or (transaction and transaction["activation_started"])
            or migration is not None
        ),
        sources=tuple(sources),
    )


def _read_source(path: Path, artifact: ArtifactKind) -> _DecodedSource:
    source = Path(path)
    try:
        if source.is_symlink() or not source.is_file():
            raise CompatibilityDecodeError("v1_artifact_not_regular_file")
        raw = source.read_bytes()
    except CompatibilityDecodeError:
        raise
    except OSError as exc:
        raise CompatibilityDecodeError("v1_artifact_unreadable") from exc
    if not raw or len(raw) > 2 * 1024 * 1024:
        raise CompatibilityDecodeError("v1_artifact_size_invalid")
    try:
        decoded = raw.decode("utf-8")
        value = json.loads(
            decoded,
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CompatibilityDecodeError("v1_artifact_json_invalid") from exc
    if not isinstance(value, Mapping):
        raise CompatibilityDecodeError("v1_artifact_root_invalid")
    schema = _artifact_schema(artifact, value)
    return _DecodedSource(
        value=value,
        evidence=SourceEvidence(
            artifact=artifact,
            source_name=source.name,
            schema=schema,
            byte_length=len(raw),
            sha256=hashlib.sha256(raw).hexdigest(),
        ),
    )


def _atomic_replace_checkpoint_if_unchanged(
    target: Path,
    value: Mapping[str, Any],
    *,
    expected_operation_id: str,
    expected_checkpoint_sha256: str,
) -> None:
    parent = target.parent
    if parent.is_symlink() or not parent.is_dir():
        raise CompatibilityDecodeError("v1_artifact_parent_invalid")
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{target.name}.", dir=parent
        )
    except OSError as exc:
        raise CompatibilityDecodeError("v1_checkpoint_write_failed") from exc
    temporary = Path(temporary_name)
    try:
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(
                    value,
                    handle,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                )
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
        except (OSError, TypeError, ValueError) as exc:
            raise CompatibilityDecodeError("v1_checkpoint_write_failed") from exc

        # Re-read after staging the replacement.  A digest observed before
        # rollback is not authority to overwrite bytes that changed while the
        # recovery action was running.
        current = _read_source(target, ArtifactKind.CHECKPOINT)
        checkpoint = _validate_checkpoint(current.value)
        _require_checkpoint_update_binding(
            target,
            checkpoint,
            current.evidence,
            expected_operation_id=expected_operation_id,
            expected_checkpoint_sha256=expected_checkpoint_sha256,
        )
        if checkpoint["state"] != "recovery_required":
            raise CompatibilityDecodeError("v1_checkpoint_not_recoverable")

        try:
            os.replace(temporary, target)
            directory = os.open(parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except OSError as exc:
            raise CompatibilityDecodeError("v1_checkpoint_write_failed") from exc
    finally:
        temporary.unlink(missing_ok=True)


def _require_checkpoint_update_binding(
    path: Path,
    checkpoint: Mapping[str, Any],
    evidence: SourceEvidence,
    *,
    expected_operation_id: str,
    expected_checkpoint_sha256: str,
) -> None:
    _require_filename(path, f"{expected_operation_id}.json")
    if checkpoint["operation_id"] != expected_operation_id:
        raise CompatibilityDecodeError("v1_checkpoint_identity_mismatch")
    if evidence.sha256 != expected_checkpoint_sha256:
        raise CompatibilityDecodeError("v1_checkpoint_drift_detected")


def _detached_mapping(value: Mapping[str, Any]) -> dict[str, Any]:
    # Validated v1 documents contain only JSON values, so a JSON round-trip is
    # a compact deep copy that cannot retain mutable aliases.  Do not use the
    # content-id normalizer here: callers receive the source list ordering.
    detached = json.loads(
        json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    )
    if not isinstance(detached, dict):  # Defensive; validation already proves it.
        raise CompatibilityDecodeError("v1_artifact_root_invalid")
    return detached


def _object_without_duplicates(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise CompatibilityDecodeError("v1_artifact_duplicate_field")
        value[key] = item
    return value


def _reject_json_constant(_value: str) -> None:
    raise CompatibilityDecodeError("v1_artifact_json_invalid")


def _artifact_schema(artifact: ArtifactKind, value: Mapping[str, Any]) -> str:
    if artifact is ArtifactKind.CHECKPOINT:
        schema = value.get("checkpoint_schema")
        expected = CHECKPOINT_V1
    elif artifact is ArtifactKind.SAVED_PLAN:
        plan = value.get("plan")
        snapshot = value.get("snapshot")
        if not isinstance(plan, Mapping) or not isinstance(snapshot, Mapping):
            raise CompatibilityDecodeError("v1_saved_plan_shape_invalid")
        plan_schema = plan.get("plan_schema")
        snapshot_schema = snapshot.get("snapshot_schema")
        if plan_schema != PLAN_V1 or snapshot_schema != SNAPSHOT_V1:
            raise CompatibilityDecodeError("unsupported_or_mixed_schema_set")
        return f"{PLAN_V1}+{SNAPSHOT_V1}"
    elif artifact is ArtifactKind.LOCAL_TRANSACTION:
        schema = value.get("transaction_schema")
        expected = LOCAL_TRANSACTION_V1
    else:
        schema = value.get("migration_schema")
        expected = LEGACY_MIGRATION_V1
    if schema != expected:
        raise CompatibilityDecodeError("unsupported_or_mixed_schema_set")
    return expected


def _validate_checkpoint(value: Mapping[str, Any]) -> Mapping[str, Any]:
    _exact_keys(
        value,
        {
            "checkpoint_schema",
            "operation_id",
            "command",
            "plan_id",
            "phase",
            "state",
            "completed_phases",
            "recorded_answers",
            "active_gate",
        },
    )
    _require_match(value["operation_id"], _OPERATION_ID, "v1_checkpoint_identity_invalid")
    _require_match(value["plan_id"], re.compile(r"plan-[0-9a-f]{64}"), "v1_checkpoint_identity_invalid")
    if value["command"] not in _COMMANDS:
        raise CompatibilityDecodeError("v1_checkpoint_command_unsupported")
    if value["state"] not in _CHECKPOINT_STATES:
        raise CompatibilityDecodeError("v1_checkpoint_state_invalid")
    _require_match(value["phase"], _SAFE_PHASE, "v1_checkpoint_phase_invalid")
    completed = _validate_completed_phases(value["completed_phases"])
    answers = _mapping(value["recorded_answers"], "v1_checkpoint_answers_invalid")
    _exact_keys(answers, set(), optional={"connection_mode"})
    if "connection_mode" in answers and answers["connection_mode"] not in _CONNECTION_MODES:
        raise CompatibilityDecodeError("v1_checkpoint_answers_invalid")
    gate = value["active_gate"]
    if gate is not None:
        _validate_human_gate(gate, value["operation_id"])
        if value["state"] != "blocked":
            raise CompatibilityDecodeError("v1_checkpoint_gate_state_invalid")
    if value["state"] == "ready" and gate is not None:
        raise CompatibilityDecodeError("v1_checkpoint_gate_state_invalid")
    return {**value, "completed_phases": completed}


def _validate_human_gate(value: Any, operation_id: str) -> None:
    gate = _mapping(value, "v1_checkpoint_gate_invalid")
    _exact_keys(
        gate,
        {
            "gate_id",
            "gate_type",
            "explanation",
            "exact_action",
            "verification_probe",
            "resume_reference",
            "operator_options",
            "status",
        },
    )
    _require_match(gate["gate_id"], re.compile(r"gate-[0-9a-f]{24}"), "v1_checkpoint_gate_invalid")
    for field in ("gate_type", "verification_probe"):
        _require_match(gate[field], _SAFE_PHASE, "v1_checkpoint_gate_invalid")
    for field in ("explanation", "exact_action"):
        if not _is_nonempty_string(gate[field], 2000):
            raise CompatibilityDecodeError("v1_checkpoint_gate_invalid")
    if gate["resume_reference"] != operation_id or gate["status"] != "waiting":
        raise CompatibilityDecodeError("v1_checkpoint_gate_invalid")
    options = gate["operator_options"]
    if not isinstance(options, list) or len(options) > 8:
        raise CompatibilityDecodeError("v1_checkpoint_gate_invalid")
    for option in options:
        item = _mapping(option, "v1_checkpoint_gate_invalid")
        _exact_keys(
            item,
            {"id", "label", "instructions", "recommended"},
            optional={"url", "requires_capability"},
        )
        _require_match(item["id"], re.compile(r"[a-z][a-z0-9_]{1,31}"), "v1_checkpoint_gate_invalid")
        if not _is_nonempty_string(item["label"], 80) or not _is_nonempty_string(
            item["instructions"], 1000
        ):
            raise CompatibilityDecodeError("v1_checkpoint_gate_invalid")
        _require_bool(item["recommended"], "v1_checkpoint_gate_invalid")
        for optional in ("url", "requires_capability"):
            if optional in item and not _is_nonempty_string(item[optional], 2048):
                raise CompatibilityDecodeError("v1_checkpoint_gate_invalid")


def _validate_saved_plan(value: Mapping[str, Any]) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    _exact_keys(value, {"plan", "snapshot"})
    plan = _mapping(value["plan"], "v1_saved_plan_shape_invalid")
    snapshot = _mapping(value["snapshot"], "v1_saved_plan_shape_invalid")
    _validate_snapshot(snapshot)
    _validate_plan(plan, snapshot)
    return plan, snapshot


def _validate_snapshot(value: Mapping[str, Any]) -> None:
    _exact_keys(
        value,
        {
            "snapshot_schema",
            "macos",
            "obsidian",
            "claudian",
            "vaults",
            "installation",
            "network",
            "read_only",
            "support",
            "snapshot_id",
        },
    )
    if value["snapshot_schema"] != SNAPSHOT_V1 or value["read_only"] is not True:
        raise CompatibilityDecodeError("v1_snapshot_invalid")
    _require_content_id(value["snapshot_id"], "inspection", value, "snapshot_id")

    macos = _mapping(value["macos"], "v1_snapshot_invalid")
    _exact_keys(macos, {"platform", "version", "architecture"})
    if macos["platform"] != "Darwin" or not all(
        isinstance(macos[field], str) for field in ("version", "architecture")
    ):
        raise CompatibilityDecodeError("v1_snapshot_invalid")
    obsidian = _mapping(value["obsidian"], "v1_snapshot_invalid")
    _exact_keys(obsidian, {"installed", "version", "running"})
    _require_bool(obsidian["installed"], "v1_snapshot_invalid")
    _require_bool(obsidian["running"], "v1_snapshot_invalid")
    _require_nullable_string(obsidian["version"], "v1_snapshot_invalid")

    claudian = _mapping(value["claudian"], "v1_snapshot_invalid")
    _exact_keys(
        claudian,
        {"installed", "enabled", "version"},
        optional={"detected_versions"},
    )
    _require_bool(claudian["installed"], "v1_snapshot_invalid")
    _require_bool(claudian["enabled"], "v1_snapshot_invalid")
    _require_nullable_string(claudian["version"], "v1_snapshot_invalid")
    if "detected_versions" in claudian:
        _string_list(claudian["detected_versions"], "v1_snapshot_invalid", unique=True)

    vaults = value["vaults"]
    if not isinstance(vaults, list) or not vaults:
        raise CompatibilityDecodeError("v1_snapshot_invalid")
    seen_vaults: set[str] = set()
    for raw_vault in vaults:
        vault = _mapping(raw_vault, "v1_snapshot_invalid")
        _exact_keys(
            vault,
            {"vault_id"},
            optional={
                "display_name",
                "open",
                "claudian_version",
                "claudian_enabled",
            },
        )
        _require_match(vault["vault_id"], _VAULT_ID, "v1_snapshot_invalid")
        if vault["vault_id"] in seen_vaults:
            raise CompatibilityDecodeError("v1_snapshot_invalid")
        seen_vaults.add(vault["vault_id"])
        if "display_name" in vault and not _is_nonempty_string(vault["display_name"], 512):
            raise CompatibilityDecodeError("v1_snapshot_invalid")
        if "open" in vault:
            _require_bool(vault["open"], "v1_snapshot_invalid")
        if "claudian_version" in vault:
            _require_nullable_string(vault["claudian_version"], "v1_snapshot_invalid")
        if "claudian_enabled" in vault:
            _require_bool(vault["claudian_enabled"], "v1_snapshot_invalid")

    installation = _mapping(value["installation"], "v1_snapshot_invalid")
    _exact_keys(
        installation,
        {
            "installed",
            "compatibility_set_id",
            "operation_id",
            "secure_provisioning_available",
            "secure_provisioning_probe",
        },
        optional={"plugin_versions", "profile_mode", "profile_generation_id"},
    )
    _require_bool(installation["installed"], "v1_snapshot_invalid")
    if "plugin_versions" in installation:
        _string_list(installation["plugin_versions"], "v1_snapshot_invalid", unique=True)
    if installation["compatibility_set_id"] is not None:
        _require_match(
            installation["compatibility_set_id"],
            _COMPATIBILITY_SET_ID,
            "v1_snapshot_invalid",
        )
    if installation["operation_id"] is not None:
        _require_match(installation["operation_id"], _OPERATION_ID, "v1_snapshot_invalid")
    if "profile_mode" in installation and installation["profile_mode"] is not None:
        if installation["profile_mode"] not in _CONNECTION_MODES:
            raise CompatibilityDecodeError("v1_snapshot_invalid")
    if "profile_generation_id" in installation and installation["profile_generation_id"] is not None:
        _require_match(
            installation["profile_generation_id"],
            _PROFILE_GENERATION_ID,
            "v1_snapshot_invalid",
        )
    _require_bool(installation["secure_provisioning_available"], "v1_snapshot_invalid")
    if not _is_nonempty_string(installation["secure_provisioning_probe"], 256):
        raise CompatibilityDecodeError("v1_snapshot_invalid")

    network = _mapping(value["network"], "v1_snapshot_invalid")
    _exact_keys(network, {"tailscale_installed", "tailscale_logged_in"})
    _require_bool(network["tailscale_installed"], "v1_snapshot_invalid")
    _require_bool(network["tailscale_logged_in"], "v1_snapshot_invalid")

    support = _mapping(value["support"], "v1_snapshot_invalid")
    _exact_keys(support, {"supported", "required_claudian_version", "reason_codes"})
    _require_bool(support["supported"], "v1_snapshot_invalid")
    if not _is_nonempty_string(support["required_claudian_version"], 64):
        raise CompatibilityDecodeError("v1_snapshot_invalid")
    _string_list(support["reason_codes"], "v1_snapshot_invalid", unique=True)


def _validate_plan(value: Mapping[str, Any], snapshot: Mapping[str, Any]) -> None:
    _exact_keys(
        value,
        {
            "plan_schema",
            "inspection_snapshot_id",
            "environment_fingerprint",
            "compatibility_set_id",
            "vault_id",
            "installation_id",
            "endpoint_audience",
            "topology",
            "gates",
            "blockers",
            "affected_resources",
            "rollback_boundary",
            "mutation_performed",
            "plan_id",
        },
    )
    if value["plan_schema"] != PLAN_V1:
        raise CompatibilityDecodeError("unsupported_or_mixed_schema_set")
    _require_content_id(value["plan_id"], "plan", value, "plan_id")
    if (
        value["inspection_snapshot_id"] != snapshot["snapshot_id"]
        or value["environment_fingerprint"] != snapshot["snapshot_id"]
    ):
        raise CompatibilityDecodeError("v1_plan_snapshot_binding_invalid")
    _require_match(value["compatibility_set_id"], _COMPATIBILITY_SET_ID, "v1_plan_invalid")
    _require_match(value["vault_id"], _VAULT_ID, "v1_plan_invalid")
    if value["vault_id"] not in {item["vault_id"] for item in snapshot["vaults"]}:
        raise CompatibilityDecodeError("v1_plan_snapshot_binding_invalid")
    _require_match(value["installation_id"], _INSTALLATION_ID, "v1_plan_invalid")
    _require_nullable_string(value["endpoint_audience"], "v1_plan_invalid")

    topology = _mapping(value["topology"], "v1_plan_invalid")
    _exact_keys(topology, {"mode", "relay_location", "exposure", "silent_fallback"})
    _require_bool(topology["silent_fallback"], "v1_plan_invalid")
    if topology["silent_fallback"] is not False or (
        topology["mode"], topology["relay_location"], topology["exposure"]
    ) not in _TOPOLOGY_COMBINATIONS:
        raise CompatibilityDecodeError("v1_plan_topology_invalid")

    gates = value["gates"]
    if not isinstance(gates, list):
        raise CompatibilityDecodeError("v1_plan_invalid")
    gate_pairs: list[tuple[str, str]] = []
    for raw_gate in gates:
        gate = _mapping(raw_gate, "v1_plan_invalid")
        _exact_keys(gate, {"gate_type", "probe"})
        pair = (gate["gate_type"], gate["probe"])
        if pair not in _GATE_COMBINATIONS or pair in gate_pairs:
            raise CompatibilityDecodeError("v1_plan_invalid")
        gate_pairs.append(pair)
    _string_list(value["blockers"], "v1_plan_invalid", unique=True)
    if tuple(value["affected_resources"]) != _AFFECTED_RESOURCES:
        raise CompatibilityDecodeError("v1_plan_invalid")
    if value["rollback_boundary"] != "previous_locally_coherent_compatibility_set":
        raise CompatibilityDecodeError("v1_plan_invalid")
    if value["mutation_performed"] is not False:
        raise CompatibilityDecodeError("v1_plan_invalid")


def _validate_local_transaction(value: Mapping[str, Any]) -> Mapping[str, Any]:
    _exact_keys(
        value,
        {
            "transaction_schema",
            "operation_id",
            "plan_id",
            "phase",
            "completed_phases",
            "prior_availability_vault",
            "prior_release_id",
            "activation_started",
            "plugin_activated",
        },
    )
    _require_match(value["operation_id"], _OPERATION_ID, "v1_transaction_invalid")
    _require_match(value["plan_id"], re.compile(r"plan-[0-9a-f]{64}"), "v1_transaction_invalid")
    if value["phase"] not in _TRANSACTION_PHASES:
        raise CompatibilityDecodeError("v1_transaction_invalid")
    completed = _validate_completed_phases(value["completed_phases"])
    _require_nullable_string(value["prior_availability_vault"], "v1_transaction_invalid")
    if value["prior_release_id"] is not None:
        _require_match(value["prior_release_id"], _COMPATIBILITY_SET_ID, "v1_transaction_invalid")
    _require_bool(value["activation_started"], "v1_transaction_invalid")
    _require_bool(value["plugin_activated"], "v1_transaction_invalid")
    if value["plugin_activated"] and not value["activation_started"]:
        raise CompatibilityDecodeError("v1_transaction_invalid")
    if value["plugin_activated"] and "secure_provisioning" not in completed:
        raise CompatibilityDecodeError("v1_transaction_invalid")
    if "plugin_activation" in completed and not value["plugin_activated"]:
        raise CompatibilityDecodeError("v1_transaction_invalid")
    if value["phase"] == "ready" and completed != list(_LOCAL_PHASE_ORDER):
        raise CompatibilityDecodeError("v1_transaction_invalid")
    if value["phase"] == "await_pairing" and completed != list(_LOCAL_PHASE_ORDER[:-1]):
        raise CompatibilityDecodeError("v1_transaction_invalid")
    if value["phase"] in {"after_activation", "await_plugin_bootstrap"} and completed != list(
        _LOCAL_PHASE_ORDER[:6]
    ):
        raise CompatibilityDecodeError("v1_transaction_invalid")
    if value["phase"] == "plugin_activated" and completed != list(_LOCAL_PHASE_ORDER[:3]):
        raise CompatibilityDecodeError("v1_transaction_invalid")
    if value["phase"] == "activation_started" and completed != list(_LOCAL_PHASE_ORDER[:2]):
        raise CompatibilityDecodeError("v1_transaction_invalid")
    if value["phase"] == "before_activation" and completed != list(_LOCAL_PHASE_ORDER[:2]):
        raise CompatibilityDecodeError("v1_transaction_invalid")
    if value["phase"] == "before_legacy_migration" and completed != ["staging"]:
        raise CompatibilityDecodeError("v1_transaction_invalid")
    if value["phase"] == "before_staging" and completed:
        raise CompatibilityDecodeError("v1_transaction_invalid")
    return {**value, "completed_phases": completed}


def _validate_legacy_migration(value: Mapping[str, Any]) -> Mapping[str, Any]:
    _exact_keys(
        value,
        {
            "migration_schema",
            "phase",
            "legacy_present",
            "legacy_was_enabled",
            "current_was_enabled",
            "re_pair_required",
            "synchronized",
        },
    )
    if value["phase"] not in _MIGRATION_PHASES or value["legacy_present"] is not True:
        raise CompatibilityDecodeError("v1_migration_invalid")
    for field in ("legacy_was_enabled", "current_was_enabled", "re_pair_required"):
        _require_bool(value[field], "v1_migration_invalid")
    if value["legacy_was_enabled"] and value["current_was_enabled"]:
        raise CompatibilityDecodeError("v1_migration_invalid")
    synchronized = _mapping(value["synchronized"], "v1_migration_invalid")
    _exact_keys(
        synchronized,
        {
            "schema_version",
            "vault_id",
            "connection_mode",
            "notifications_enabled",
            "haptics_enabled",
        },
    )
    if type(synchronized["schema_version"]) is not int or synchronized["schema_version"] != 2:
        raise CompatibilityDecodeError("v1_migration_invalid")
    _require_match(synchronized["vault_id"], _VAULT_ID, "v1_migration_invalid")
    if synchronized["connection_mode"] not in _CONNECTION_MODES:
        raise CompatibilityDecodeError("v1_migration_invalid")
    _require_bool(synchronized["notifications_enabled"], "v1_migration_invalid")
    _require_bool(synchronized["haptics_enabled"], "v1_migration_invalid")
    return value


def _transaction_companion_required(checkpoint: Mapping[str, Any]) -> bool:
    return bool(checkpoint["completed_phases"]) or checkpoint["state"] in {
        "ready",
        "rolled_back",
        "recovery_required",
    }


def _validate_completed_phases(value: Any) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise CompatibilityDecodeError("v1_completed_phases_invalid")
    if value != list(_LOCAL_PHASE_ORDER[: len(value)]):
        raise CompatibilityDecodeError("v1_completed_phases_invalid")
    return list(value)


def _require_filename(path: Path, expected: str) -> None:
    if Path(path).name != expected:
        raise CompatibilityDecodeError("v1_filename_binding_invalid")


def _exact_keys(
    value: Mapping[str, Any], required: set[str], *, optional: set[str] | None = None
) -> None:
    allowed = required | (optional or set())
    keys = set(value)
    if not required.issubset(keys) or not keys.issubset(allowed):
        raise CompatibilityDecodeError("v1_artifact_fields_invalid")


def _mapping(value: Any, code: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise CompatibilityDecodeError(code)
    return value


def _require_match(value: Any, pattern: re.Pattern[str], code: str) -> None:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise CompatibilityDecodeError(code)


def _require_bool(value: Any, code: str) -> None:
    if type(value) is not bool:
        raise CompatibilityDecodeError(code)


def _require_nullable_string(value: Any, code: str) -> None:
    if value is not None and not isinstance(value, str):
        raise CompatibilityDecodeError(code)


def _is_nonempty_string(value: Any, limit: int) -> bool:
    return isinstance(value, str) and 0 < len(value) <= limit and "\x00" not in value


def _string_list(value: Any, code: str, *, unique: bool) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise CompatibilityDecodeError(code)
    if unique and len(value) != len(set(value)):
        raise CompatibilityDecodeError(code)
    return list(value)


def _require_content_id(
    value: Any, prefix: str, document: Mapping[str, Any], identity_field: str
) -> None:
    _require_match(value, _CONTENT_ID, f"v1_{prefix}_identity_invalid")
    body = {key: item for key, item in document.items() if key != identity_field}
    digest = hashlib.sha256(_canonical_json(body).encode("utf-8")).hexdigest()
    if value != f"{prefix}-{digest}":
        raise CompatibilityDecodeError(f"v1_{prefix}_integrity_failed")


def _canonical_json(value: Any) -> str:
    return json.dumps(
        _normalize(value), ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )


def _normalize(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _normalize(value[key]) for key in sorted(value)}
    if isinstance(value, (list, tuple)):
        normalized = [_normalize(item) for item in value]
        if all(isinstance(item, Mapping) and "vault_id" in item for item in normalized):
            normalized.sort(key=lambda item: str(item["vault_id"]))
        return normalized
    return value
