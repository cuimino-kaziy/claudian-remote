"""Narrow macOS availability support for the bound Obsidian Vault."""

from __future__ import annotations

import subprocess
import urllib.parse
from pathlib import Path
from typing import Callable, Sequence


OBSIDIAN_APPLICATIONS = (
    Path("/Applications/Obsidian.app"),
    Path.home() / "Applications/Obsidian.app",
)


def validate_bound_vault_name(value: object) -> str:
    """Return a safe Vault display name or fail closed.

    A Vault binding is a display name used only inside an Obsidian URI. It is
    deliberately not a filesystem path, app name, or command fragment.
    """

    name = str(value or "")
    if not name or len(name) > 255 or any(
        character in name for character in ("\x00", "\r", "\n")
    ):
        raise ValueError("availability_vault_name_invalid")
    return name


class ObsidianLauncher:
    """Open only Obsidian and only a caller-provided Vault display name."""

    def __init__(
        self,
        *,
        applications: Sequence[Path] = OBSIDIAN_APPLICATIONS,
        runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
    ) -> None:
        self.applications = tuple(Path(path) for path in applications)
        self.runner = runner

    def launch(self, vault_name: str) -> bool:
        try:
            name = validate_bound_vault_name(vault_name)
        except ValueError:
            return False
        application = next((path for path in self.applications if path.is_dir()), None)
        if application is None:
            return False
        target = "obsidian://open?vault=" + urllib.parse.quote(name, safe="")
        try:
            result = self.runner(
                ["/usr/bin/open", "-a", str(application), target],
                text=True,
                capture_output=True,
                check=False,
                timeout=15,
                env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        return result.returncode == 0
