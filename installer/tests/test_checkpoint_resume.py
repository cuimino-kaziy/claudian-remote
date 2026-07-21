import json
import os

import pytest

from installer.claudian_remote_lifecycle.checkpoint import CheckpointStore, OperationBusy, OperationLock


def test_checkpoint_is_atomic_private_secret_free_and_resumable(tmp_path):
    store = CheckpointStore(tmp_path / "state")
    checkpoint = store.create(command="install", plan_id="plan-a", phase="before_download")
    updated = store.update(
        checkpoint["operation_id"],
        phase="staging",
        completed_phases=["before_download"],
        recorded_answers={"connection_mode": "local_tailscale"},
    )

    restored = CheckpointStore(tmp_path / "state").read(checkpoint["operation_id"])
    assert restored == updated
    assert (tmp_path / "state").stat().st_mode & 0o777 == 0o700
    assert store.path_for(checkpoint["operation_id"]).stat().st_mode & 0o777 == 0o600
    assert not list((tmp_path / "state").glob("*.tmp"))

    with pytest.raises(ValueError, match="checkpoint_forbidden_field"):
        store.update(checkpoint["operation_id"], mobile_token="do-not-persist")
    assert "do-not-persist" not in store.path_for(checkpoint["operation_id"]).read_text()


def test_operation_lock_is_exclusive_and_returns_busy_without_mutation(tmp_path):
    first = OperationLock(tmp_path / "state").acquire()
    try:
        with pytest.raises(OperationBusy, match="lifecycle_operation_busy"):
            OperationLock(tmp_path / "state").acquire()
    finally:
        first.release()

    with OperationLock(tmp_path / "state"):
        assert (tmp_path / "state" / "operation.lock").stat().st_mode & 0o777 == 0o600
