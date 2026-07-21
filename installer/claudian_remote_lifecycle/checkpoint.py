"""Private atomic checkpoints and one-process lifecycle operation lock."""

from __future__ import annotations

import fcntl
import json
import os
import re
import secrets
import tempfile
from pathlib import Path
from typing import Any, Mapping

from .model import CHECKPOINT_SCHEMA, COMMANDS


class OperationBusy(RuntimeError):
    pass


def _assert_secret_free(value: Any, path: str = "root") -> None:
    forbidden_keys = ("password", "secret", "token", "credential", "claim")
    if isinstance(value, Mapping):
        for key, item in value.items():
            lowered = str(key).lower()
            if any(part in lowered for part in forbidden_keys) and not lowered.endswith("_ref"):
                raise ValueError(f"checkpoint_forbidden_field:{path}.{key}")
            _assert_secret_free(item, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _assert_secret_free(item, f"{path}[{index}]")


class PrivateStateDirectory:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    def ensure(self) -> Path:
        self.path.mkdir(parents=True, exist_ok=True)
        os.chmod(self.path, 0o700)
        return self.path

    def atomic_write_json(self, path: Path, value: Mapping[str, Any]) -> None:
        self.ensure()
        _assert_secret_free(value)
        descriptor, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=self.path)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(value, handle, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, path)
            directory = os.open(self.path, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            Path(temporary).unlink(missing_ok=True)


class OperationLock:
    def __init__(self, state_dir: Path) -> None:
        self.directory = PrivateStateDirectory(state_dir)
        self.path = Path(state_dir) / "operation.lock"
        self._handle: Any = None

    def acquire(self) -> "OperationLock":
        self.directory.ensure()
        handle = self.path.open("a+", encoding="utf-8")
        os.chmod(self.path, 0o600)
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            handle.close()
            raise OperationBusy("lifecycle_operation_busy") from exc
        self._handle = handle
        return self

    def release(self) -> None:
        if self._handle is not None:
            fcntl.flock(self._handle.fileno(), fcntl.LOCK_UN)
            self._handle.close()
            self._handle = None

    def __enter__(self) -> "OperationLock":
        return self.acquire()

    def __exit__(self, *_args: Any) -> None:
        self.release()


class CheckpointStore:
    def __init__(self, state_dir: Path) -> None:
        self.directory = PrivateStateDirectory(state_dir)

    def create(self, *, command: str, plan_id: str, phase: str = "created") -> dict[str, Any]:
        if command not in COMMANDS:
            raise ValueError("unknown_lifecycle_command")
        checkpoint = {
            "checkpoint_schema": CHECKPOINT_SCHEMA,
            "operation_id": "op-" + secrets.token_hex(16),
            "command": command,
            "plan_id": plan_id,
            "phase": phase,
            "state": "prepared",
            "completed_phases": [],
            "recorded_answers": {},
            "active_gate": None,
        }
        self.write(checkpoint)
        return checkpoint

    def path_for(self, operation_id: str) -> Path:
        if not re.fullmatch(r"op-[0-9a-f]{32}", operation_id):
            raise ValueError("invalid_operation_id")
        return self.directory.path / f"{operation_id}.json"

    def write(self, checkpoint: Mapping[str, Any]) -> None:
        if checkpoint.get("checkpoint_schema") != CHECKPOINT_SCHEMA:
            raise ValueError("invalid_checkpoint_schema")
        self.directory.atomic_write_json(self.path_for(str(checkpoint["operation_id"])), dict(checkpoint))

    def read(self, operation_id: str) -> dict[str, Any]:
        value = json.loads(self.path_for(operation_id).read_text(encoding="utf-8"))
        if not isinstance(value, Mapping) or value.get("checkpoint_schema") != CHECKPOINT_SCHEMA:
            raise ValueError("invalid_checkpoint_schema")
        if value.get("operation_id") != operation_id or value.get("command") not in COMMANDS:
            raise ValueError("invalid_checkpoint_identity")
        _assert_secret_free(value)
        return dict(value)

    def update(self, operation_id: str, **changes: Any) -> dict[str, Any]:
        checkpoint = self.read(operation_id)
        checkpoint.update(changes)
        self.write(checkpoint)
        return checkpoint
