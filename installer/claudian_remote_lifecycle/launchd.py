"""Dynamic user LaunchAgent generation and lifecycle control."""

from __future__ import annotations

import os
import plistlib
import subprocess
import tempfile
from pathlib import Path
from typing import Protocol, Sequence

from .runtime import RuntimeLayout


class Launchctl(Protocol):
    def bootstrap(self, label: str, path: Path) -> None: ...

    def bootout(self, label: str, path: Path) -> None: ...

    def loaded_status(self, label: str) -> bool: ...


class SystemLaunchctl:
    def __init__(self, *, runner=subprocess.run, uid: int | None = None) -> None:
        self.runner = runner
        self.uid = int(uid if uid is not None else os.getuid())

    @property
    def domain(self) -> str:
        return f"gui/{self.uid}"

    def _run(self, arguments: Sequence[str], *, allowed=(0,)) -> subprocess.CompletedProcess:
        try:
            result = self.runner(
                ["/bin/launchctl", *arguments],
                text=True,
                capture_output=True,
                check=False,
                timeout=15,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RuntimeError("launchctl_operation_failed") from exc
        if result.returncode not in allowed:
            raise RuntimeError("launchctl_operation_failed")
        return result

    def bootstrap(self, label: str, path: Path) -> None:
        if self.loaded_status(label):
            # launchd keeps the loaded job definition in memory. Boot it out
            # before bootstrapping so an update actually consumes the newly
            # written ProgramArguments and environment.
            self.bootout(label, path)
        self._run(["bootstrap", self.domain, str(path)])

    def bootout(self, label: str, path: Path) -> None:
        self._run(["bootout", self.domain, str(path)], allowed=(0, 3, 113))

    def loaded_status(self, label: str) -> bool:
        try:
            result = self.runner(
                ["/bin/launchctl", "print", f"{self.domain}/{label}"],
                text=True,
                capture_output=True,
                check=False,
                timeout=15,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        return result.returncode == 0


class InMemoryLaunchctl:
    """Deterministic test adapter with launchctl semantics."""

    def __init__(self) -> None:
        self.loaded: dict[str, Path] = {}

    def bootstrap(self, label: str, path: Path) -> None:
        self.loaded[label] = Path(path)

    def bootout(self, label: str, _path: Path) -> None:
        self.loaded.pop(label, None)

    def loaded_status(self, label: str) -> bool:
        return label in self.loaded


def _write_private(path: Path, content: bytes) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.read_bytes() == content:
        os.chmod(path, 0o600)
        return False
    descriptor, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return True


class LaunchAgentManager:
    RELAY_LABEL = "com.claudian.remote.relay"
    COMPANION_LABEL = "com.claudian.remote.companion"

    def __init__(self, layout: RuntimeLayout, *, runner: Launchctl | None = None) -> None:
        self.layout = layout
        self.runner = runner or SystemLaunchctl()

    def _payload(self, label: str, python: Path, role: str, config: Path) -> bytes:
        python_path = ":".join((
            str(self.layout.current / "installer"),
            str(self.layout.current / "companion"),
            str(self.layout.current / "relay"),
        ))
        value = {
            "Label": label,
            "ProgramArguments": [
                str(python),
                "-m",
                "installer.claudian_remote_lifecycle.runtime_entrypoints",
                role,
                "--config",
                str(config),
            ],
            "WorkingDirectory": str(self.layout.current / "installer"),
            "EnvironmentVariables": {
                "PYTHONPATH": python_path,
                "PYTHONDONTWRITEBYTECODE": "1",
                "UV_NO_CONFIG": "1",
            },
            "RunAtLoad": True,
            "KeepAlive": {"SuccessfulExit": False},
            "ProcessType": "Background",
            "StandardOutPath": str(self.layout.logs / f"{role}.out.log"),
            "StandardErrorPath": str(self.layout.logs / f"{role}.err.log"),
            "Umask": 0o077,
        }
        return plistlib.dumps(value, fmt=plistlib.FMT_XML, sort_keys=True)

    def install_local_agents(self, python: Path) -> dict[str, object]:
        self.layout.ensure()
        self.layout.launch_agents.mkdir(parents=True, exist_ok=True)
        changed = False
        for label, path, role, config in (
            (self.RELAY_LABEL, self.layout.relay_launch_agent, "relay", self.layout.relay_config),
            (
                self.COMPANION_LABEL,
                self.layout.companion_launch_agent,
                "companion",
                self.layout.companion_config,
            ),
        ):
            content = self._payload(label, Path(python), role, config)
            changed = _write_private(path, content) or changed
            self.runner.bootstrap(label, path)
        return {"changed": changed, "ready": self.status()["ready"]}

    def status(self) -> dict[str, object]:
        relay = self.runner.loaded_status(self.RELAY_LABEL)
        companion = self.runner.loaded_status(self.COMPANION_LABEL)
        return {
            "ready": relay and companion,
            "relay": "running" if relay else "stopped",
            "companion": "running" if companion else "stopped",
        }

    def remove_local_agents(self) -> dict[str, object]:
        changed = False
        for label, path in (
            (self.COMPANION_LABEL, self.layout.companion_launch_agent),
            (self.RELAY_LABEL, self.layout.relay_launch_agent),
        ):
            if self.runner.loaded_status(label) or path.exists():
                self.runner.bootout(label, path)
                changed = True
            path.unlink(missing_ok=True)
        return {"changed": changed, "ready": False}
