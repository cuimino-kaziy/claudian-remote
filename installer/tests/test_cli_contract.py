import io
import json
import shutil

import pytest

from installer.claudian_remote_lifecycle.cli import (
    LifecycleArgumentError,
    LifecycleServices,
    build_parser,
    main,
)
from installer.claudian_remote_lifecycle.diagnostics import DiagnosticService
from installer.claudian_remote_lifecycle.model import COMMANDS, RESULT_SCHEMA
from installer.tests.test_inspect import FakeProbe


def test_every_contract_command_is_parseable_and_unimplemented_mutations_fail_closed(tmp_path):
    parser = build_parser()
    invocations = {
        "inspect": ["inspect"],
        "plan": ["plan", "--mode", "local_tailscale"],
        "status": ["status", "--operation-id", "op-" + "a" * 32],
        "resume": ["resume", "--operation-id", "op-" + "a" * 32],
        "install": ["install", "--plan-id", "plan-a"],
        "verify": ["verify"],
        "update": ["update", "--plan-id", "plan-a"],
        "rollback": ["rollback", "--operation-id", "op-" + "a" * 32],
        "uninstall": ["uninstall", "--plan-id", "plan-a"],
        "purge": ["purge", "--plan-id", "plan-a"],
        "revoke-device": ["revoke-device", "--device-id", "device-a"],
        "diagnose": ["diagnose"],
        "export-diagnostics": ["export-diagnostics", "--destination", str((tmp_path / "diagnostics.json").resolve())],
    }
    assert set(invocations) == set(COMMANDS)
    for command, argv in invocations.items():
        assert parser.parse_args(["--state-dir", str(tmp_path), *argv]).command == command

    for command in ("uninstall", "purge"):
        output = io.StringIO()
        exit_code = main(
            ["--state-dir", str(tmp_path), command, "--plan-id", "plan-a"],
            stdout=output,
            services=LifecycleServices(FakeProbe(), {}),
        )
        result = json.loads(output.getvalue())
        assert exit_code == 2
        assert result["result_schema"] == RESULT_SCHEMA
        assert result["code"] == "operation_not_implemented"
        assert result["data"]["mutation_performed"] is False

    output = io.StringIO()
    exit_code = main(
        ["--state-dir", str(tmp_path), "update", "--plan-id", "plan-a"],
        stdout=output,
        services=LifecycleServices(FakeProbe(), {}),
    )
    assert exit_code == 2
    assert json.loads(output.getvalue())["code"] == "plan_not_found"

    output = io.StringIO()
    exit_code = main(
        ["--state-dir", str(tmp_path), "install", "--plan-id", "plan-a"],
        stdout=output,
        services=LifecycleServices(FakeProbe(), {}),
    )
    assert exit_code == 2
    assert json.loads(output.getvalue())["code"] == "plan_not_found"


class FakeUninstaller:
    def __init__(self):
        self.calls = []

    def uninstall(self):
        self.calls.append("uninstall")
        return {"state": "ready", "code": "uninstall_completed", "mutation_performed": True}

    def purge(self, *, confirmation_verified):
        assert confirmation_verified is True
        self.calls.append("purge")
        return {"state": "ready", "code": "purge_completed", "mutation_performed": True}


def _prepare_plan(tmp_path, services):
    output = io.StringIO()
    assert main(
        ["--state-dir", str(tmp_path), "plan", "--mode", "local_tailscale", "--vault-id", "vault-a"],
        stdout=output,
        services=services,
    ) == 0
    return json.loads(output.getvalue())["plan_id"]


def test_local_support_commands_are_wired_and_human_gates_resume(tmp_path):
    uninstaller = FakeUninstaller()
    revoked = []
    services = LifecycleServices(
        FakeProbe(),
        {
            "purge_confirmation_verified": lambda: True,
            "diagnostic_export_confirmation_verified": lambda: True,
        },
        diagnostics=DiagnosticService(),
        uninstaller=uninstaller,
        revoke_device=lambda device_id: (
            revoked.append(device_id)
            or {"state": "ready", "code": "device_revoked", "mutation_performed": True, "device_id": device_id}
        ),
    )
    plan_id = _prepare_plan(tmp_path, services)

    output = io.StringIO()
    assert main(
        ["--state-dir", str(tmp_path), "uninstall", "--plan-id", plan_id],
        stdout=output,
        services=services,
    ) == 0
    assert json.loads(output.getvalue())["code"] == "uninstall_completed"

    output = io.StringIO()
    assert main(
        ["--state-dir", str(tmp_path), "revoke-device", "--device-id", "iphone-a"],
        stdout=output,
        services=services,
    ) == 0
    assert revoked == ["iphone-a"]

    output = io.StringIO()
    assert main(["--state-dir", str(tmp_path), "diagnose"], stdout=output, services=services) == 0
    diagnosis = json.loads(output.getvalue())
    assert diagnosis["code"] == "diagnostic_summary_ready"
    assert diagnosis["data"]["uploaded"] is False

    output = io.StringIO()
    assert main(
        ["--state-dir", str(tmp_path), "purge", "--plan-id", plan_id],
        stdout=output,
        services=services,
    ) == 2
    purge_gate = json.loads(output.getvalue())
    assert purge_gate["code"] == "human_action_required"
    output = io.StringIO()
    assert main(
        ["--state-dir", str(tmp_path), "resume", "--operation-id", purge_gate["operation_id"]],
        stdout=output,
        services=services,
    ) == 0
    assert json.loads(output.getvalue())["code"] == "purge_completed"

    destination = (tmp_path / "export.json").resolve()
    output = io.StringIO()
    assert main(
        ["--state-dir", str(tmp_path), "export-diagnostics", "--destination", str(destination)],
        stdout=output,
        services=services,
    ) == 2
    export_gate = json.loads(output.getvalue())
    assert export_gate["data"]["preview"]["uploaded"] is False
    output = io.StringIO()
    assert main(
        ["--state-dir", str(tmp_path), "resume", "--operation-id", export_gate["operation_id"]],
        stdout=output,
        services=services,
    ) == 0
    assert json.loads(output.getvalue())["code"] == "diagnostic_export_ready"
    assert destination.stat().st_mode & 0o777 == 0o600


def test_partial_uninstall_returns_an_operation_that_resume_can_finish(tmp_path):
    class InterruptedUninstaller(FakeUninstaller):
        def uninstall(self):
            self.calls.append("uninstall")
            if len(self.calls) == 1:
                return {
                    "state": "recovery_required",
                    "code": "uninstall_precondition_incomplete",
                    "mutation_performed": True,
                }
            return {
                "state": "ready",
                "code": "uninstall_completed",
                "mutation_performed": True,
            }

    uninstaller = InterruptedUninstaller()
    services = LifecycleServices(FakeProbe(), {}, uninstaller=uninstaller)
    plan_id = _prepare_plan(tmp_path, services)

    output = io.StringIO()
    assert main(
        ["--state-dir", str(tmp_path), "uninstall", "--plan-id", plan_id],
        stdout=output,
        services=services,
    ) == 2
    interrupted = json.loads(output.getvalue())
    assert interrupted["code"] == "uninstall_precondition_incomplete"
    assert interrupted["state"] == "recovery_required"
    assert interrupted["operation_id"].startswith("op-")

    output = io.StringIO()
    assert main(
        ["--state-dir", str(tmp_path), "resume", "--operation-id", interrupted["operation_id"]],
        stdout=output,
        services=services,
    ) == 0
    completed = json.loads(output.getvalue())
    assert completed["code"] == "uninstall_completed"
    assert completed["operation_id"] == interrupted["operation_id"]
    assert uninstaller.calls == ["uninstall", "uninstall"]


def test_successful_purge_does_not_recreate_deleted_lifecycle_state(tmp_path):
    class StateDeletingUninstaller(FakeUninstaller):
        def purge(self, *, confirmation_verified):
            assert confirmation_verified is True
            shutil.rmtree(tmp_path)
            return {"state": "ready", "code": "purge_completed", "mutation_performed": True}

    services = LifecycleServices(
        FakeProbe(),
        {"purge_confirmation_verified": lambda: True},
        uninstaller=StateDeletingUninstaller(),
    )
    plan_id = _prepare_plan(tmp_path, services)
    output = io.StringIO()
    assert main(
        ["--state-dir", str(tmp_path), "purge", "--plan-id", plan_id],
        stdout=output,
        services=services,
    ) == 2
    operation_id = json.loads(output.getvalue())["operation_id"]

    output = io.StringIO()
    assert main(
        ["--state-dir", str(tmp_path), "resume", "--operation-id", operation_id],
        stdout=output,
        services=services,
    ) == 0
    assert json.loads(output.getvalue())["code"] == "purge_completed"
    assert not tmp_path.exists()


def test_stdout_is_exactly_one_json_result(tmp_path):
    output = io.StringIO()
    code = main(
        ["--state-dir", str(tmp_path), "inspect"],
        stdout=output,
        services=LifecycleServices(FakeProbe(), {}),
    )
    lines = output.getvalue().splitlines()
    assert code == 0
    assert len(lines) == 1
    assert json.loads(lines[0])["code"] == "inspection_ready"


def test_invalid_arguments_and_agent_unsafe_result_fields_fail_closed_to_json(tmp_path):
    output = io.StringIO()
    code = main(["--state-dir", str(tmp_path), "plan"], stdout=output)
    result = json.loads(output.getvalue())
    assert code == 2
    assert result["code"] == "invalid_lifecycle_input"

    from installer.claudian_remote_lifecycle.model import LifecycleResult

    unsafe = LifecycleResult(
        command="diagnose",
        state="blocked",
        code="test",
        message="safe",
        data={"access_token": "must-not-print"},
    )
    with pytest.raises(ValueError, match="agent_unsafe_result_field"):
        unsafe.to_dict()


def test_production_services_reject_an_arbitrary_state_directory_that_could_expand_purge_scope(tmp_path):
    with pytest.raises(LifecycleArgumentError, match="state_directory_not_supported"):
        LifecycleServices.local(state_dir=tmp_path / "state")


def test_unknown_runtime_exception_is_normalized_in_result_and_checkpoint(tmp_path):
    class FailingTransaction:
        def install(self, _plan, *, operation_id):
            raise RuntimeError("looks_stable_but_contains_private_context")

        def completed_phases(self, _operation_id):
            return []

    services = LifecycleServices(FakeProbe(), {}, transaction=FailingTransaction())
    plan_id = _prepare_plan(tmp_path, services)
    output = io.StringIO()
    assert main(
        ["--state-dir", str(tmp_path), "install", "--plan-id", plan_id],
        stdout=output,
        services=services,
    ) == 2
    result = json.loads(output.getvalue())
    assert result["code"] == "operation_failed"
    checkpoint = json.loads((tmp_path / f"{result['operation_id']}.json").read_text())
    assert checkpoint["phase"] == "operation_failed"
    assert "private_context" not in json.dumps(result)


@pytest.mark.parametrize(
    ("blocking_code", "probe_name"),
    [
        ("tailscale_https_consent_required", "tailscale_https_ready"),
        ("desktop_plugin_bootstrap_required", "desktop_plugin_authenticated"),
        ("pairing_approval_required", "pairing_credential_active"),
    ],
)
def test_transaction_gates_use_one_canonical_human_gate_and_resume_contract(
    tmp_path, blocking_code, probe_name,
):
    ready = False

    class GatedTransaction:
        def install(self, _plan, *, operation_id):
            if ready:
                return {"state": "ready", "code": "installation_ready", "mutation_performed": True}
            return {
                "state": "blocked",
                "code": blocking_code,
                "mutation_performed": blocking_code != "tailscale_https_consent_required",
                "gate": {
                    "gate_type": blocking_code,
                    "explanation": "A verified external action is required.",
                    "exact_action": "Complete the external action, then resume.",
                    "verification_probe": probe_name,
                },
            }

        def completed_phases(self, _operation_id):
            return []

    services = LifecycleServices(
        FakeProbe(),
        {probe_name: lambda: ready},
        transaction=GatedTransaction(),
    )
    plan_id = _prepare_plan(tmp_path, services)
    output = io.StringIO()
    assert main(
        ["--state-dir", str(tmp_path), "install", "--plan-id", plan_id],
        stdout=output,
        services=services,
    ) == 2
    waiting = json.loads(output.getvalue())
    assert waiting["code"] == "human_action_required"
    assert waiting["data"]["blocking_code"] == blocking_code
    assert waiting["gate"]["verification_probe"] == probe_name
    operation_id = waiting["operation_id"]

    output = io.StringIO()
    assert main(
        ["--state-dir", str(tmp_path), "resume", "--operation-id", operation_id],
        stdout=output,
        services=services,
    ) == 2
    assert json.loads(output.getvalue())["code"] == "human_action_required"

    ready = True
    output = io.StringIO()
    assert main(
        ["--state-dir", str(tmp_path), "resume", "--operation-id", operation_id],
        stdout=output,
        services=services,
    ) == 0
    assert json.loads(output.getvalue())["code"] == "installation_ready"
