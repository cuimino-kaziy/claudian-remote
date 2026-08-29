from __future__ import annotations

import hashlib
import json
import os

import pytest

from installer.claudian_remote_lifecycle.legacy_retirement_saga import (
    LegacyRetirementSaga,
    PinnedSshLegacyRetirementAdapter,
    RetirementDispatchUncertain,
)
from installer.claudian_remote_lifecycle.vps import (
    PinnedSshRetirementPrimitives,
    VpsSagaExecutor,
)


OPERATION_ID = "op-" + "a" * 32
PLAN_ID = "plan-" + "b" * 64


class Adapter:
    def __init__(
        self,
        *,
        fail_preflight=False,
        uncertain=False,
        reconcile_outcome=None,
    ):
        self.fail_preflight = fail_preflight
        self.uncertain = uncertain
        self.reconcile_outcome = reconcile_outcome or {"state": "inconclusive"}
        self.calls = []

    def validate(self, plan):
        return None

    def stage(self, plan):
        self.calls.append("stage")

    def preflight(self, plan):
        self.calls.append("preflight")
        if self.fail_preflight:
            raise ValueError("runtime_preflight_failed")

    def dispatch(self, plan):
        self.calls.append("dispatch")
        if self.uncertain:
            raise RetirementDispatchUncertain("response_lost")
        return {"proof_schema": "claudian-remote.legacy-retirement-proof/v1"}

    def reconcile(self, plan):
        self.calls.append("reconcile")
        return dict(self.reconcile_outcome)

    def compensate_stage(self, plan):
        self.calls.append("compensate_stage")


class SshChannel:
    def __init__(self):
        self.hostname = "relay.example"
        self.host_key_fingerprint = "SHA256:known-host-key"
        self.calls = []

    def upload_from_fd(self, source_fd, destination):
        self.calls.append(("upload", os.read(source_fd, 1024).hex(), destination))

    def run_json(self, action, payload):
        self.calls.append((action, dict(payload)))
        if action == "verify_inert_asset":
            return {
                "ok": True,
                "digest": payload["sha256"],
                "immutable": True,
                "inert": True,
            }
        if action == "retirement_preflight":
            return {"ok": True, "mutation_performed": False}
        if action == "retirement_commit":
            return {
                "proof_schema": "claudian-remote.legacy-retirement-proof/v1"
            }
        return {"state": "retired"}

    def remove(self, destination):
        self.calls.append(("remove", destination))


def make_plan_with_digest(helper, digest, **changes):
    value = {
        "retirement_plan_schema": "claudian-remote.legacy-retirement-saga/v1",
        "mode": "legacy_retirement",
        "plan_id": PLAN_ID,
        "host": "relay.example",
        "host_key_fingerprint": "SHA256:known-host-key",
        "host_key_confirmed": True,
        "helper_path": str(helper),
        "helper_digest": digest,
        "remote_stage_path": f"/var/lib/claudian-remote/operations/{OPERATION_ID}",
        "runtime_path": "/usr/bin/python3",
        "import_paths": ["/opt/claudian-remote/lib"],
    }
    value.update(changes)
    return value


def make_plan(helper, **changes):
    return make_plan_with_digest(
        helper,
        hashlib.sha256(helper.read_bytes()).hexdigest(),
        **changes,
    )


def test_preflight_failure_compensates_only_inert_stage(tmp_path):
    helper = tmp_path / "retirement-helper.py"
    helper.write_bytes(b"helper-v1")
    adapter = Adapter(fail_preflight=True)

    outcome = LegacyRetirementSaga(
        tmp_path / "state",
        adapter,
        trusted_helper_root=tmp_path,
    ).execute(
        make_plan(helper),
        operation_id=OPERATION_ID,
    )

    assert outcome["state"] == "compensated"
    assert adapter.calls == ["stage", "preflight", "compensate_stage"]
    journal = json.loads(
        (tmp_path / "state" / f"{OPERATION_ID}.legacy-retirement-saga.json").read_text()
    )
    assert "relay.example" not in json.dumps(journal)
    assert journal["phase"] == "compensated"


def test_response_loss_enters_read_only_reconciliation_without_redispatch(tmp_path):
    helper = tmp_path / "retirement-helper.py"
    helper.write_bytes(b"helper-v1")
    adapter = Adapter(uncertain=True)
    saga = LegacyRetirementSaga(
        tmp_path / "state",
        adapter,
        trusted_helper_root=tmp_path,
    )

    first = saga.execute(make_plan(helper), operation_id=OPERATION_ID)
    assert first["state"] == "retirement_outcome_unknown"
    assert adapter.calls == ["stage", "preflight", "dispatch"]

    second = saga.execute(make_plan(helper), operation_id=OPERATION_ID)
    assert second["state"] == "inconclusive"
    assert adapter.calls == ["stage", "preflight", "dispatch", "reconcile"]


def test_reconciled_proof_remains_recoverable_until_consumer_commits(tmp_path):
    helper = tmp_path / "retirement-helper.py"
    helper.write_bytes(b"helper-v1")
    digest = hashlib.sha256(helper.read_bytes()).hexdigest()
    proof = {
        "proof_schema": "claudian-remote.legacy-retirement-proof/v1",
        "outcome": "retired",
    }
    adapter = Adapter(
        uncertain=True,
        reconcile_outcome={"state": "retired", "proof": proof},
    )
    saga = LegacyRetirementSaga(
        tmp_path / "state",
        adapter,
        trusted_helper_root=tmp_path,
    )
    plan = make_plan_with_digest(helper, digest)

    assert saga.execute(plan, operation_id=OPERATION_ID)["state"] == (
        "retirement_outcome_unknown"
    )
    helper.unlink()

    second = saga.execute(plan, operation_id=OPERATION_ID)
    third = saga.execute(plan, operation_id=OPERATION_ID)
    assert second["proof"] == proof
    assert third["proof"] == proof
    assert adapter.calls == [
        "stage",
        "preflight",
        "dispatch",
        "reconcile",
        "reconcile",
    ]
    journal = json.loads(
        (tmp_path / "state" / f"{OPERATION_ID}.legacy-retirement-saga.json").read_text()
    )
    assert journal["phase"] == "retirement_outcome_unknown"


def test_dispatching_restart_reconciles_without_redispatch(tmp_path):
    helper = tmp_path / "retirement-helper.py"
    helper.write_bytes(b"helper-v1")
    proof = {
        "proof_schema": "claudian-remote.legacy-retirement-proof/v1",
        "outcome": "retired",
    }
    adapter = Adapter(
        reconcile_outcome={"state": "retired", "proof": proof},
    )
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    journal_path = state_dir / f"{OPERATION_ID}.legacy-retirement-saga.json"
    journal_path.write_text(
        json.dumps(
            {
                "saga_schema": "claudian-remote.legacy-retirement-saga-state/v1",
                "operation_id": OPERATION_ID,
                "plan_id": PLAN_ID,
                "phase": "dispatching",
            }
        )
    )

    outcome = LegacyRetirementSaga(
        state_dir,
        adapter,
        trusted_helper_root=tmp_path,
    ).execute(make_plan(helper), operation_id=OPERATION_ID)

    assert outcome["state"] == "proof_ready"
    assert outcome["proof"] == proof
    assert adapter.calls == ["reconcile"]
    assert json.loads(journal_path.read_text())["phase"] == (
        "retirement_outcome_unknown"
    )


@pytest.mark.parametrize(
    ("change", "code"),
    [
        ({"host_key_confirmed": False}, "vps_host_key_confirmation_required"),
        ({"runtime_path": "python3"}, "retirement_runtime_path_invalid"),
        ({"runtime_path": "/tmp/python3"}, "retirement_runtime_path_invalid"),
        ({"remote_stage_path": "/tmp/stage"}, "retirement_stage_path_invalid"),
        ({"import_paths": ["relative"]}, "retirement_import_path_invalid"),
        ({"import_paths": ["/tmp/imports"]}, "retirement_import_path_invalid"),
        ({"helper_digest": "0" * 64}, "retirement_helper_digest_mismatch"),
    ],
)
def test_invalid_remote_trust_or_helper_fails_before_stage(tmp_path, change, code):
    helper = tmp_path / "retirement-helper.py"
    helper.write_bytes(b"helper-v1")
    adapter = Adapter()
    with pytest.raises(ValueError, match=code):
        LegacyRetirementSaga(
            tmp_path / "state",
            adapter,
            trusted_helper_root=tmp_path,
        ).execute(
            make_plan(helper, **change),
            operation_id=OPERATION_ID,
        )
    assert adapter.calls == []


def test_symlinked_helper_is_rejected_before_stage(tmp_path):
    target = tmp_path / "target-helper.py"
    target.write_bytes(b"helper-v1")
    helper = tmp_path / "retirement-helper.py"
    helper.symlink_to(target)
    adapter = Adapter()

    with pytest.raises(ValueError, match="retirement_helper"):
        LegacyRetirementSaga(
            tmp_path / "state",
            adapter,
            trusted_helper_root=tmp_path,
        ).execute(
            make_plan(helper),
            operation_id=OPERATION_ID,
        )
    assert adapter.calls == []


def test_helper_must_be_absolute_and_under_trusted_root(tmp_path):
    trusted = tmp_path / "trusted"
    trusted.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_bytes(b"helper-v1")
    adapter = Adapter()
    saga = LegacyRetirementSaga(
        tmp_path / "state",
        adapter,
        trusted_helper_root=trusted,
    )

    with pytest.raises(ValueError, match="retirement_helper_path_invalid"):
        saga.execute(make_plan(outside), operation_id=OPERATION_ID)
    with pytest.raises(ValueError, match="retirement_helper_path_invalid"):
        saga.execute(
            make_plan_with_digest(
                "retirement-helper.py",
                hashlib.sha256(b"helper-v1").hexdigest(),
            ),
            operation_id=OPERATION_ID,
        )
    assert adapter.calls == []


def test_helper_parent_symlink_cannot_escape_trusted_root(tmp_path):
    trusted = tmp_path / "trusted"
    outside = tmp_path / "outside"
    trusted.mkdir()
    outside.mkdir()
    outside_helper = outside / "retirement-helper.py"
    outside_helper.write_bytes(b"helper-v1")
    (trusted / "link").symlink_to(outside, target_is_directory=True)
    helper = trusted / "link" / "retirement-helper.py"
    adapter = Adapter()

    with pytest.raises(ValueError, match="retirement_helper_unsafe"):
        LegacyRetirementSaga(
            tmp_path / "state",
            adapter,
            trusted_helper_root=trusted,
        ).execute(make_plan(helper), operation_id=OPERATION_ID)
    assert adapter.calls == []


def test_pinned_ssh_adapter_uploads_only_inert_asset_and_allowlisted_actions(
    tmp_path,
):
    helper = tmp_path / "retirement-helper.py"
    helper.write_bytes(b"helper-v1")
    plan = make_plan(helper)
    channel = SshChannel()
    primitives = PinnedSshRetirementPrimitives(
        channel,
        expected_hostname=plan["host"],
        expected_host_key_fingerprint=plan["host_key_fingerprint"],
        trusted_source_root=tmp_path,
    )
    outcome = LegacyRetirementSaga(
        tmp_path / "state",
        PinnedSshLegacyRetirementAdapter(primitives),
        trusted_helper_root=tmp_path,
    ).execute(plan, operation_id=OPERATION_ID)

    assert outcome["state"] == "proof_ready"
    actions = [call[0] for call in channel.calls]
    assert actions == [
        "upload",
        "verify_inert_asset",
        "retirement_preflight",
        "retirement_commit",
    ]
    serialized = json.dumps(channel.calls)
    assert "synthetic-secret" not in serialized
    assert str(helper) not in json.dumps(channel.calls[1:])


def test_pinned_ssh_identity_mismatch_fails_before_any_remote_action(tmp_path):
    channel = SshChannel()
    with pytest.raises(ValueError, match="vps_host_key_mismatch"):
        PinnedSshRetirementPrimitives(
            channel,
            expected_hostname="relay.example",
            expected_host_key_fingerprint="SHA256:different-host-key",
            trusted_source_root=tmp_path,
        )
    assert channel.calls == []


def test_plan_identity_mismatch_fails_before_any_remote_action(tmp_path):
    helper = tmp_path / "retirement-helper.py"
    helper.write_bytes(b"helper-v1")
    channel = SshChannel()
    primitives = PinnedSshRetirementPrimitives(
        channel,
        expected_hostname="relay.example",
        expected_host_key_fingerprint="SHA256:known-host-key",
        trusted_source_root=tmp_path,
    )
    saga = LegacyRetirementSaga(
        tmp_path / "state",
        PinnedSshLegacyRetirementAdapter(primitives),
        trusted_helper_root=tmp_path,
    )

    with pytest.raises(ValueError, match="vps_plan_identity_mismatch"):
        saga.execute(
            make_plan(helper, host="other.example"),
            operation_id=OPERATION_ID,
        )
    assert channel.calls == []


def test_deployment_saga_rejects_retirement_plan(tmp_path):
    helper = tmp_path / "retirement-helper.py"
    helper.write_bytes(b"helper-v1")
    with pytest.raises(ValueError, match="invalid_vps_deployment_plan"):
        VpsSagaExecutor(tmp_path / "deploy", Adapter()).execute(
            make_plan(helper),
            operation_id=OPERATION_ID,
        )
