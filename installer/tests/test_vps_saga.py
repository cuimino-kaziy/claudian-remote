from __future__ import annotations

import json

from installer.claudian_remote_lifecycle.vps import VpsSagaExecutor, VpsSagaInterrupted


class FakeAdapter:
    def __init__(self, *, checks=None, fail_step="", fail_compensation=""):
        self.checks = checks or {
            "tls": True,
            "wss": True,
            "storage": True,
            "protocol": True,
            "mobile_converged": True,
        }
        self.fail_step = fail_step
        self.fail_compensation = fail_compensation
        self.performed = []
        self.compensated = []

    def perform(self, step, _plan):
        self.performed.append(step)
        if step == self.fail_step:
            raise RuntimeError("synthetic_forward_failure")

    def compensate(self, action, _plan):
        if action == self.fail_compensation:
            raise RuntimeError("synthetic_compensation_failure")
        self.compensated.append(action)

    def verify(self, _plan):
        return self.checks


def plan():
    return {
        "plan_id": "plan-" + "a" * 64,
        "deployment_plan_schema": "claudian-remote.vps-deployment/v1",
        "state": "prepared",
        "mode": "remote_vps",
        "host": "relay.user.example",
    }


def operation_id():
    return "op-" + "b" * 32


def test_failed_probe_executes_real_compensations_in_reverse_order(tmp_path):
    adapter = FakeAdapter(checks={"tls": False, "wss": True, "storage": True, "protocol": True})
    executor = VpsSagaExecutor(tmp_path, adapter)

    outcome = executor.execute(plan(), operation_id=operation_id())

    assert outcome["state"] == "rolled_back"
    assert outcome["failed_checks"] == ["tls"]
    assert adapter.compensated == [
        "restore_mac_profile",
        "stop_staged_service",
        "restore_previous_service",
        "remove_owned_staged_release",
    ]
    assert outcome["completed_compensations"] == adapter.compensated


def test_interrupted_saga_resumes_without_repeating_completed_remote_steps(tmp_path):
    interrupted = {"after_activate_staged_relay"}
    adapter = FakeAdapter()
    executor = VpsSagaExecutor(
        tmp_path,
        adapter,
        interruption_probe=lambda phase: phase in interrupted,
    )

    try:
        executor.execute(plan(), operation_id=operation_id())
    except VpsSagaInterrupted as exc:
        assert str(exc) == "after_activate_staged_relay"
    else:  # pragma: no cover - assertion guard
        raise AssertionError("saga should have been interrupted")

    interrupted.clear()
    resumed = executor.execute(plan(), operation_id=operation_id())
    assert resumed["state"] == "ready"
    assert adapter.performed == [
        "deploy_compatible_relay",
        "activate_staged_relay",
        "switch_mac_profile",
        "retire_previous_release",
    ]


def test_mobile_lag_keeps_compatibility_window_and_resume_retires_once(tmp_path):
    adapter = FakeAdapter()
    executor = VpsSagaExecutor(tmp_path, adapter)

    adapter.checks["mobile_converged"] = False
    waiting = executor.execute(plan(), operation_id=operation_id())
    assert waiting["code"] == "mobile_protocol_convergence_required"
    assert waiting["compatibility_window_active"] is True
    assert "retire_previous_release" not in adapter.performed

    adapter.checks["mobile_converged"] = True
    ready = executor.execute(plan(), operation_id=operation_id())
    assert ready["state"] == "ready"
    assert adapter.performed.count("retire_previous_release") == 1


def test_failed_compensation_is_recovery_required_and_journal_is_secret_free(tmp_path):
    adapter = FakeAdapter(fail_step="switch_mac_profile", fail_compensation="restore_previous_service")
    executor = VpsSagaExecutor(tmp_path, adapter)

    outcome = executor.execute(plan(), operation_id=operation_id())

    assert outcome["state"] == "recovery_required"
    assert outcome["failed_compensations"] == ["restore_previous_service"]
    journal = json.loads((tmp_path / f"{operation_id()}.vps-saga.json").read_text())
    encoded = json.dumps(journal)
    assert "relay.user.example" not in encoded
    assert "token" not in encoded.lower()


def test_tampered_journal_steps_fail_closed_before_remote_mutation(tmp_path):
    adapter = FakeAdapter()
    path = tmp_path / f"{operation_id()}.vps-saga.json"
    path.write_text(json.dumps({
        "saga_schema": "claudian-remote.vps-saga/v1",
        "operation_id": operation_id(),
        "plan_id": plan()["plan_id"],
        "phase": "before_switch_mac_profile",
        "completed_steps": ["switch_mac_profile"],
        "completed_compensations": [],
    }))

    try:
        VpsSagaExecutor(tmp_path, adapter).execute(plan(), operation_id=operation_id())
    except ValueError as exc:
        assert str(exc) == "vps_saga_journal_invalid"
    else:  # pragma: no cover - assertion guard
        raise AssertionError("tampered journal must fail closed")
    assert adapter.performed == []


def test_retirement_failure_preserves_working_release_and_requires_recovery(tmp_path):
    adapter = FakeAdapter(fail_step="retire_previous_release")
    outcome = VpsSagaExecutor(tmp_path, adapter).execute(plan(), operation_id=operation_id())

    assert outcome["state"] == "recovery_required"
    assert outcome["code"] == "vps_retirement_incomplete"
    assert outcome["compatibility_window_active"] is True
    assert adapter.compensated == []
