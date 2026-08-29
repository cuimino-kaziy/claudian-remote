"""Versioned VPS saga dedicated to retiring one supported legacy credential."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Protocol

from .private_io import write_private_json
from .vps import (
    HOST_RE,
    PinnedSshResponseLost,
    PinnedSshRetirementPrimitives,
    trusted_regular_file,
)


_OPERATION_ID = re.compile(r"op-[0-9a-f]{32}")
_PLAN_ID = re.compile(r"plan-[A-Za-z0-9._:-]{1,194}")
_DIGEST = re.compile(r"[0-9a-f]{64}")
_PLAN_FIELDS = frozenset(
    {
        "retirement_plan_schema",
        "mode",
        "plan_id",
        "host",
        "host_key_fingerprint",
        "host_key_confirmed",
        "helper_path",
        "helper_digest",
        "remote_stage_path",
        "runtime_path",
        "import_paths",
    }
)


class RetirementDispatchUncertain(RuntimeError):
    """The authority may have committed but no authenticated result arrived."""


class LegacyRetirementAdapter(Protocol):
    def validate(self, plan: Mapping[str, Any]) -> None: ...

    def stage(self, plan: Mapping[str, Any]) -> None: ...

    def preflight(self, plan: Mapping[str, Any]) -> None: ...

    def dispatch(self, plan: Mapping[str, Any]) -> Mapping[str, Any]: ...

    def reconcile(self, plan: Mapping[str, Any]) -> Mapping[str, Any]: ...

    def compensate_stage(self, plan: Mapping[str, Any]) -> None: ...


class PinnedSshLegacyRetirementAdapter:
    """Concrete retirement adapter over an already-authorized SSH channel."""

    def __init__(self, primitives: PinnedSshRetirementPrimitives) -> None:
        self.primitives = primitives

    @staticmethod
    def _helper_destination(plan: Mapping[str, Any]) -> str:
        return str(PurePosixPath(str(plan["remote_stage_path"])) / "retire.py")

    @staticmethod
    def _remote_payload(plan: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "retirement_plan_schema": plan["retirement_plan_schema"],
            "plan_id": plan["plan_id"],
            "runtime_path": plan["runtime_path"],
            "import_paths": list(plan["import_paths"]),
            "helper_path": PinnedSshLegacyRetirementAdapter._helper_destination(plan),
            "helper_digest": plan["helper_digest"],
        }

    def _assert_plan_identity(self, plan: Mapping[str, Any]) -> None:
        if (
            not hmac.compare_digest(
                str(plan["host"]),
                self.primitives.expected_hostname,
            )
            or not hmac.compare_digest(
                str(plan["host_key_fingerprint"]),
                self.primitives.expected_host_key_fingerprint,
            )
        ):
            raise ValueError("vps_plan_identity_mismatch")

    def validate(self, plan: Mapping[str, Any]) -> None:
        self._assert_plan_identity(plan)

    def stage(self, plan: Mapping[str, Any]) -> None:
        self._assert_plan_identity(plan)
        self.primitives.upload_immutable(
            Path(str(plan["helper_path"])),
            self._helper_destination(plan),
            expected_digest=str(plan["helper_digest"]),
        )

    def preflight(self, plan: Mapping[str, Any]) -> None:
        self._assert_plan_identity(plan)
        result = dict(
            self.primitives.run(
                "retirement_preflight",
                self._remote_payload(plan),
            )
        )
        if result != {"ok": True, "mutation_performed": False}:
            raise ValueError("legacy_retirement_remote_preflight_failed")

    def dispatch(self, plan: Mapping[str, Any]) -> Mapping[str, Any]:
        self._assert_plan_identity(plan)
        try:
            result = self.primitives.run(
                "retirement_commit",
                self._remote_payload(plan),
            )
        except PinnedSshResponseLost as exc:
            raise RetirementDispatchUncertain("response_lost") from exc
        return dict(result)

    def reconcile(self, plan: Mapping[str, Any]) -> Mapping[str, Any]:
        self._assert_plan_identity(plan)
        return dict(
            self.primitives.run(
                "retirement_reconcile",
                self._remote_payload(plan),
            )
        )

    def compensate_stage(self, plan: Mapping[str, Any]) -> None:
        self._assert_plan_identity(plan)
        self.primitives.remove_owned(str(plan["remote_stage_path"]))


class LegacyRetirementSaga:
    """Keep inert staging retryable and dispatch ambiguity read-only."""

    def __init__(
        self,
        state_dir: Path,
        adapter: LegacyRetirementAdapter,
        *,
        trusted_helper_root: Path,
    ) -> None:
        self.state_dir = Path(state_dir)
        self.adapter = adapter
        self.trusted_helper_root = Path(trusted_helper_root).resolve()

    def _path(self, operation_id: str) -> Path:
        if not _OPERATION_ID.fullmatch(operation_id):
            raise ValueError("invalid_operation_id")
        return self.state_dir / f"{operation_id}.legacy-retirement-saga.json"

    @staticmethod
    def _absolute_posix(value: Any, code: str) -> str:
        if not isinstance(value, str):
            raise ValueError(code)
        path = PurePosixPath(value)
        if not path.is_absolute() or ".." in path.parts:
            raise ValueError(code)
        return str(path)

    @staticmethod
    def _under(path: str, root: str) -> bool:
        value = PurePosixPath(path)
        parent = PurePosixPath(root)
        return value == parent or parent in value.parents

    def _verified_helper_digest(self, helper: Path) -> str:
        with trusted_regular_file(
            helper,
            self.trusted_helper_root,
        ) as (descriptor, opened):
            digest = hashlib.sha256()
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
            after = os.fstat(descriptor)
            if (
                after.st_size != opened.st_size
                or after.st_mtime_ns != opened.st_mtime_ns
            ):
                raise ValueError("retirement_helper_changed")
            return digest.hexdigest()

    def _validate_structure(
        self,
        plan: Mapping[str, Any],
        *,
        operation_id: str,
    ) -> dict[str, Any]:
        if not isinstance(plan, Mapping) or set(plan) != _PLAN_FIELDS:
            raise ValueError("invalid_legacy_retirement_plan")
        value = dict(plan)
        if (
            value["retirement_plan_schema"]
            != "claudian-remote.legacy-retirement-saga/v1"
            or value["mode"] != "legacy_retirement"
            or not _PLAN_ID.fullmatch(str(value["plan_id"]))
        ):
            raise ValueError("invalid_legacy_retirement_plan")
        if value["host_key_confirmed"] is not True:
            raise ValueError("vps_host_key_confirmation_required")
        if not isinstance(value["host"], str) or not HOST_RE.fullmatch(
            value["host"]
        ):
            raise ValueError("invalid_vps_hostname")
        if not isinstance(value["host_key_fingerprint"], str) or not str(
            value["host_key_fingerprint"]
        ).startswith("SHA256:"):
            raise ValueError("vps_host_key_fingerprint_invalid")
        runtime_path = self._absolute_posix(
            value["runtime_path"], "retirement_runtime_path_invalid"
        )
        if runtime_path not in {"/usr/bin/python3", "/usr/local/bin/python3"} and not self._under(
            runtime_path, "/opt/claudian-remote/runtime"
        ):
            raise ValueError("retirement_runtime_path_invalid")
        stage_path = self._absolute_posix(
            value["remote_stage_path"], "retirement_stage_path_invalid"
        )
        expected_stage = f"/var/lib/claudian-remote/operations/{operation_id}"
        if stage_path != expected_stage:
            raise ValueError("retirement_stage_path_invalid")
        imports = value["import_paths"]
        if not isinstance(imports, list) or not imports:
            raise ValueError("retirement_import_path_invalid")
        import_paths = [
            self._absolute_posix(item, "retirement_import_path_invalid")
            for item in imports
        ]
        if any(
            not self._under(item, "/opt/claudian-remote")
            and not self._under(item, stage_path)
            for item in import_paths
        ):
            raise ValueError("retirement_import_path_invalid")
        helper = Path(str(value["helper_path"]))
        if not helper.is_absolute() or ".." in helper.parts:
            raise ValueError("retirement_helper_path_invalid")
        try:
            helper.relative_to(self.trusted_helper_root)
        except ValueError as exc:
            raise ValueError("retirement_helper_path_invalid") from exc
        digest = str(value["helper_digest"])
        if not _DIGEST.fullmatch(digest):
            raise ValueError("retirement_helper_digest_invalid")
        value["helper_path"] = str(helper)
        value["runtime_path"] = runtime_path
        value["remote_stage_path"] = stage_path
        value["import_paths"] = import_paths
        return value

    def _validate_helper(self, plan: Mapping[str, Any]) -> None:
        helper = Path(str(plan["helper_path"]))
        digest = str(plan["helper_digest"])
        actual = self._verified_helper_digest(helper)
        if not hmac.compare_digest(digest, actual):
            raise ValueError("retirement_helper_digest_mismatch")

    def _load(self, operation_id: str, plan_id: str) -> dict[str, Any]:
        path = self._path(operation_id)
        if not path.is_file():
            return {
                "saga_schema": "claudian-remote.legacy-retirement-saga-state/v1",
                "operation_id": operation_id,
                "plan_id": plan_id,
                "phase": "prepared",
            }
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError("legacy_retirement_saga_journal_invalid") from exc
        if (
            not isinstance(value, Mapping)
            or set(value) != {
                "saga_schema",
                "operation_id",
                "plan_id",
                "phase",
            }
            or value.get("saga_schema")
            != "claudian-remote.legacy-retirement-saga-state/v1"
            or value.get("operation_id") != operation_id
            or value.get("plan_id") != plan_id
            or value.get("phase")
            not in {
                "prepared",
                "staged",
                "dispatching",
                "retirement_outcome_unknown",
                "proof_ready",
                "compensated",
                "recovery_required",
            }
        ):
            raise ValueError("legacy_retirement_saga_journal_invalid")
        return dict(value)

    def _save(self, journal: Mapping[str, Any]) -> None:
        write_private_json(
            self._path(str(journal["operation_id"])),
            journal,
        )

    def execute(
        self,
        plan: Mapping[str, Any],
        *,
        operation_id: str,
    ) -> dict[str, Any]:
        plan = self._validate_structure(plan, operation_id=operation_id)
        journal = self._load(operation_id, str(plan["plan_id"]))
        phase = str(journal["phase"])
        if phase == "compensated":
            return {"state": "compensated", "mutation_performed": False}
        if phase == "proof_ready":
            return {"state": "proof_ready", "mutation_performed": False}
        if phase == "recovery_required":
            return {"state": "recovery_required", "mutation_performed": False}
        if phase == "dispatching":
            journal["phase"] = "retirement_outcome_unknown"
            self._save(journal)
            phase = "retirement_outcome_unknown"
        if phase == "prepared":
            self._validate_helper(plan)
        self.adapter.validate(plan)
        if phase == "retirement_outcome_unknown":
            outcome = dict(self.adapter.reconcile(plan))
            state = str(outcome.get("state") or "inconclusive")
            if state == "retired":
                proof = outcome.get("proof")
                if (
                    not isinstance(proof, Mapping)
                    or proof.get("proof_schema")
                    != "claudian-remote.legacy-retirement-proof/v1"
                ):
                    return {
                        "state": "inconclusive",
                        "code": "legacy_retirement_proof_invalid",
                        "mutation_performed": False,
                    }
                return {
                    "state": "proof_ready",
                    "proof": dict(proof),
                    "mutation_performed": False,
                }
            return {
                **outcome,
                "state": state,
                "mutation_performed": False,
            }
        try:
            if phase == "prepared":
                self.adapter.stage(plan)
                journal["phase"] = "staged"
                self._save(journal)
            self.adapter.preflight(plan)
        except Exception:
            try:
                self.adapter.compensate_stage(plan)
            except Exception:
                journal["phase"] = "recovery_required"
                self._save(journal)
                return {
                    "state": "recovery_required",
                    "code": "legacy_retirement_stage_compensation_failed",
                    "mutation_performed": True,
                }
            journal["phase"] = "compensated"
            self._save(journal)
            return {
                "state": "compensated",
                "code": "legacy_retirement_preflight_failed",
                "mutation_performed": True,
            }
        journal["phase"] = "dispatching"
        self._save(journal)
        try:
            proof = dict(self.adapter.dispatch(plan))
        except RetirementDispatchUncertain:
            journal["phase"] = "retirement_outcome_unknown"
            self._save(journal)
            return {
                "state": "retirement_outcome_unknown",
                "code": "legacy_retirement_response_lost",
                "mutation_performed": True,
            }
        except Exception:
            journal["phase"] = "retirement_outcome_unknown"
            self._save(journal)
            return {
                "state": "retirement_outcome_unknown",
                "code": "legacy_retirement_dispatch_failed",
                "mutation_performed": True,
            }
        if proof.get("proof_schema") != "claudian-remote.legacy-retirement-proof/v1":
            journal["phase"] = "retirement_outcome_unknown"
            self._save(journal)
            return {
                "state": "retirement_outcome_unknown",
                "code": "legacy_retirement_proof_invalid",
                "mutation_performed": True,
            }
        journal["phase"] = "retirement_outcome_unknown"
        self._save(journal)
        return {
            "state": "proof_ready",
            "proof": proof,
            "mutation_performed": True,
        }
