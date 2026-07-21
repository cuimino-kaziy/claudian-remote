import io
import json

from installer.claudian_remote_lifecycle.cli import LifecycleServices, main
from installer.tests.test_inspect import FakeProbe


def run(argv, *, state_dir):
    output = io.StringIO()
    code = main(
        ["--state-dir", str(state_dir), *argv],
        stdout=output,
        services=LifecycleServices(FakeProbe(), {}),
    )
    return code, json.loads(output.getvalue())


def test_repeated_plan_and_fail_closed_mutation_are_idempotent(tmp_path):
    first_code, first = run(["plan", "--mode", "local_tailscale"], state_dir=tmp_path / "state")
    second_code, second = run(["plan", "--mode", "local_tailscale"], state_dir=tmp_path / "state")
    assert first_code == second_code == 0
    assert first["plan_id"] == second["plan_id"]
    assert first["data"]["plan"] == second["data"]["plan"]

    install_one = run(["install", "--plan-id", first["plan_id"]], state_dir=tmp_path / "state")
    install_two = run(["install", "--plan-id", first["plan_id"]], state_dir=tmp_path / "state")
    assert install_one == install_two
    assert install_one[1]["code"] == "operation_not_implemented"
    assert install_one[1]["data"]["mutation_performed"] is False
    assert not (tmp_path / "state").exists()


def test_selected_vault_must_itself_have_supported_enabled_claudian():
    probe = FakeProbe(
        vaults=[
            {"vault_id": "good", "claudian_version": "2.0.4", "claudian_enabled": True},
            {"vault_id": "bad", "claudian_version": "2.0.3", "claudian_enabled": False},
        ]
    )
    output = io.StringIO()
    code = main(
        ["plan", "--mode", "local_tailscale", "--vault-id", "bad"],
        stdout=output,
        services=LifecycleServices(probe, {}),
    )
    result = json.loads(output.getvalue())
    assert code == 2
    assert result["state"] == "blocked"
    assert result["code"] in {"unsupported_claudian_version", "claudian_not_enabled"}

    good_output = io.StringIO()
    good_code = main(
        ["plan", "--mode", "local_tailscale", "--vault-id", "good"],
        stdout=good_output,
        services=LifecycleServices(probe, {}),
    )
    good = json.loads(good_output.getvalue())
    assert good_code == 0
    assert good["state"] == "prepared"
    assert good["code"] == "plan_prepared"
