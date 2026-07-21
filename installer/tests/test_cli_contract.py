import io
import json

import pytest

from installer.claudian_remote_lifecycle.cli import LifecycleServices, build_parser, main
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
        "export-diagnostics": ["export-diagnostics"],
    }
    assert set(invocations) == set(COMMANDS)
    for command, argv in invocations.items():
        assert parser.parse_args(["--state-dir", str(tmp_path), *argv]).command == command

    for command in ("install", "update", "uninstall", "purge"):
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
