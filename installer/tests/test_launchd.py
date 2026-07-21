import plistlib
import subprocess
from pathlib import Path

import pytest

from installer.claudian_remote_lifecycle.launchd import (
    InMemoryLaunchctl,
    LaunchAgentManager,
    SystemLaunchctl,
)
from installer.claudian_remote_lifecycle.runtime import RuntimeLayout


def test_launch_agents_use_managed_dynamic_paths_and_are_idempotent(tmp_path):
    layout = RuntimeLayout(tmp_path / "Claudian Remote", tmp_path / "LaunchAgents")
    python = layout.runtime / "python" / "3.12.11" / "bin" / "python3"
    python.parent.mkdir(parents=True)
    python.write_text("python")
    runner = InMemoryLaunchctl()
    manager = LaunchAgentManager(layout, runner=runner)

    first = manager.install_local_agents(python)
    second = manager.install_local_agents(python)
    assert first["changed"] is True
    assert second["changed"] is False
    assert len(runner.loaded) == 2
    for path in (layout.relay_launch_agent, layout.companion_launch_agent):
        value = plistlib.loads(path.read_bytes())
        args = value["ProgramArguments"]
        assert args[0] == str(python)
        assert str(Path.home()) not in path.read_text()
        assert value["WorkingDirectory"] == str(layout.current / "installer")
        assert value["EnvironmentVariables"] == {
            "PYTHONPATH": ":".join((
                str(layout.current / "installer"),
                str(layout.current / "companion"),
                str(layout.current / "relay"),
            )),
            "PYTHONDONTWRITEBYTECODE": "1",
            "UV_NO_CONFIG": "1",
        }
        assert path.stat().st_mode & 0o777 == 0o600

    assert manager.status()["ready"] is True
    removed = manager.remove_local_agents()
    assert removed["changed"] is True
    assert not runner.loaded
    assert not layout.relay_launch_agent.exists()
    assert not layout.companion_launch_agent.exists()


def test_loaded_system_job_is_booted_out_before_new_definition_is_bootstrapped(tmp_path):
    calls = []

    def runner(arguments, **_kwargs):
        calls.append(arguments)
        return subprocess.CompletedProcess(arguments, 0, "", "")

    launchctl = SystemLaunchctl(runner=runner, uid=501)
    path = tmp_path / "com.claudian.remote.relay.plist"
    launchctl.bootstrap("com.claudian.remote.relay", path)

    assert calls == [
        ["/bin/launchctl", "print", "gui/501/com.claudian.remote.relay"],
        ["/bin/launchctl", "bootout", "gui/501", str(path)],
        ["/bin/launchctl", "bootstrap", "gui/501", str(path)],
    ]


def test_launchctl_timeout_is_bounded_and_fails_closed(tmp_path):
    def runner(arguments, **_kwargs):
        raise subprocess.TimeoutExpired(arguments, 15)

    launchctl = SystemLaunchctl(runner=runner, uid=501)
    assert launchctl.loaded_status("com.claudian.remote.relay") is False
    with pytest.raises(RuntimeError, match="launchctl_operation_failed"):
        launchctl.bootout("com.claudian.remote.relay", tmp_path / "relay.plist")
