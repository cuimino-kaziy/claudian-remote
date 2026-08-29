import json
import subprocess

import pytest

from installer.claudian_remote_lifecycle import availability
from installer.claudian_remote_lifecycle.availability import ObsidianLauncher
from installer.claudian_remote_lifecycle.runtime_entrypoints import main as runtime_main


def test_obsidian_launcher_uses_only_fixed_application_and_encoded_vault(tmp_path):
    application = tmp_path / "Obsidian.app"
    application.mkdir()
    calls = []

    def runner(arguments, **kwargs):
        calls.append((arguments, kwargs))
        return subprocess.CompletedProcess(arguments, 0, "", "")

    launcher = ObsidianLauncher(applications=(application,), runner=runner)

    assert launcher.launch("Whale & Notes") is True
    assert calls[0][0] == [
        "/usr/bin/open",
        "-a",
        str(application),
        "obsidian://open?vault=Whale%20%26%20Notes",
    ]
    assert calls[0][1]["env"] == {
        "PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"
    }


def test_obsidian_launcher_fails_closed_without_fixed_app_or_valid_vault(tmp_path):
    calls = []
    launcher = ObsidianLauncher(
        applications=(tmp_path / "Missing.app",),
        runner=lambda *args, **kwargs: calls.append((args, kwargs)),
    )

    assert launcher.launch("Whale") is False
    assert launcher.launch("bad\nname") is False
    assert calls == []


def test_availability_entrypoint_records_one_shot_launch_result(tmp_path, monkeypatch):
    config = tmp_path / "availability.json"
    status = tmp_path / "status.json"
    config.write_text(json.dumps({
        "schema": "claudian-remote.availability/v1",
        "vault_name": "Whale",
    }))

    monkeypatch.setattr(availability.ObsidianLauncher, "launch", lambda _self, _vault: True)
    runtime_main(["availability", "--config", str(config), "--status", str(status)])

    assert json.loads(status.read_text()) == {
        "schema": "claudian-remote.availability-status/v1",
        "state": "launch_succeeded",
        "vault_name": "Whale",
    }
    assert status.stat().st_mode & 0o777 == 0o600


def test_availability_entrypoint_records_failure_instead_of_waiting_forever(tmp_path, monkeypatch):
    config = tmp_path / "availability.json"
    status = tmp_path / "status.json"
    config.write_text(json.dumps({
        "schema": "claudian-remote.availability/v1",
        "vault_name": "Whale",
    }))
    monkeypatch.setattr(availability.ObsidianLauncher, "launch", lambda _self, _vault: False)

    with pytest.raises(RuntimeError, match="obsidian_launch_failed"):
        runtime_main(["availability", "--config", str(config), "--status", str(status)])

    assert json.loads(status.read_text())["state"] == "launch_failed"
