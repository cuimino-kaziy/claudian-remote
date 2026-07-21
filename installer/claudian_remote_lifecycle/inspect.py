"""Read-only, dependency-injected inspection for lifecycle planning."""

from __future__ import annotations

import hashlib
import json
import platform
import plistlib
import shutil
import socket
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence

from .keychain import MacOSKeychain
from .model import SNAPSHOT_SCHEMA
from .provisioning import verify_secure_provisioning
from .runtime import RuntimeLayout


SUPPORTED_CLAUDIAN_VERSION = "2.0.4"


class InspectionProbe(Protocol):
    def macos(self) -> Mapping[str, Any]: ...

    def obsidian(self) -> Mapping[str, Any]: ...

    def claudian(self) -> Mapping[str, Any]: ...

    def vaults(self) -> Sequence[Mapping[str, Any]]: ...

    def installation(self) -> Mapping[str, Any]: ...

    def network(self) -> Mapping[str, Any]: ...


class LocalInspectionProbe:
    """Conservative host probe.

    It reads only Obsidian's registered Vaults and their plugin manifests. It
    neither crawls unrelated user directories nor starts applications.
    """

    def __init__(self, *, home: Path | None = None) -> None:
        self.home = Path(home or Path.home())
        self._vault_cache: list[dict[str, Any]] | None = None

    def macos(self) -> Mapping[str, Any]:
        return {
            "platform": platform.system(),
            "version": platform.mac_ver()[0],
            "architecture": platform.machine(),
        }

    def obsidian(self) -> Mapping[str, Any]:
        applications = (Path("/Applications/Obsidian.app"), self.home / "Applications" / "Obsidian.app")
        app = next((candidate for candidate in applications if candidate.is_dir()), applications[0])
        version = None
        info = app / "Contents" / "Info.plist"
        if info.is_file():
            try:
                with info.open("rb") as handle:
                    metadata = plistlib.load(handle)
                version = metadata.get("CFBundleShortVersionString")
            except (OSError, plistlib.InvalidFileException):
                version = None
        try:
            running = subprocess.run(
                ["pgrep", "-x", "Obsidian"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=2,
            ).returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            running = False
        return {"installed": app.is_dir(), "version": version, "running": running}

    def claudian(self) -> Mapping[str, Any]:
        vaults = self._discover_vaults()
        versions = sorted({str(vault["claudian_version"]) for vault in vaults if vault.get("claudian_version")})
        enabled = any(bool(vault.get("claudian_enabled")) for vault in vaults)
        return {
            "installed": bool(versions),
            "enabled": enabled,
            "version": versions[0] if len(versions) == 1 else None,
            "detected_versions": versions,
        }

    def vaults(self) -> Sequence[Mapping[str, Any]]:
        return [
            {key: value for key, value in vault.items() if key != "_path"}
            for vault in self._discover_vaults()
        ]

    def installation(self) -> Mapping[str, Any]:
        manifests = []
        for vault in self._discover_vaults():
            path = vault["_path"] / ".obsidian" / "plugins" / "claudian-remote" / "manifest.json"
            value = self._read_json(path)
            if isinstance(value, Mapping):
                manifests.append(value)
        versions = sorted({str(value.get("version")) for value in manifests if value.get("version")})
        provisioning = self._secure_provisioning_status()
        managed = self._managed_installation_status()
        return {
            "installed": bool(manifests),
            "plugin_versions": versions,
            **managed,
            "operation_id": None,
            # A lifecycle process cannot safely provision an Obsidian WebView's
            # localStorage. This becomes true only when the signed Companion
            # secure-provisioning route and its OS-backed store are probed.
            **provisioning,
        }

    def _managed_installation_status(self) -> Mapping[str, Any]:
        root = self.home / "Library" / "Application Support" / "Claudian Remote"
        current = root / "current"
        compatibility_set_id = None
        if current.is_symlink():
            try:
                target = current.resolve(strict=True)
                releases = (root / "releases").resolve()
                if target.parent == releases and target.name.startswith("claudian-remote-"):
                    compatibility_set_id = target.name
            except OSError:
                compatibility_set_id = None

        profile_mode = None
        profile_generation_id = None
        profile = self._read_json(root / "config" / "connection-profile.json")
        if isinstance(profile, Mapping):
            mode = str(profile.get("mode") or "")
            if mode in {"local_tailscale", "remote_vps", "local_lan"}:
                profile_mode = mode
                generation = {
                    "mode": mode,
                    "installation_id": str(profile.get("installation_id") or ""),
                    "vault_id": str(profile.get("vault_id") or ""),
                    "endpoint": str(profile.get("endpoint") or ""),
                    "endpoint_audience": str(profile.get("endpoint_audience") or ""),
                    "epoch": str(profile.get("epoch") or ""),
                }
                profile_generation_id = content_id("profile-generation", generation)
        return {
            "compatibility_set_id": compatibility_set_id,
            "profile_mode": profile_mode,
            "profile_generation_id": profile_generation_id,
        }

    def _secure_provisioning_status(self) -> Mapping[str, Any]:
        root = self.home / "Library" / "Application Support" / "Claudian Remote"
        try:
            layout = RuntimeLayout(root, self.home / "Library" / "LaunchAgents")
            if not verify_secure_provisioning(layout, MacOSKeychain()):
                raise ValueError("secure_provisioning_missing")
            with socket.create_connection(("127.0.0.1", 27124), timeout=0.25):
                pass
            return {
                "secure_provisioning_available": True,
                "secure_provisioning_probe": "companion_route_and_keychain_verified",
            }
        except Exception:
            return {
                "secure_provisioning_available": False,
                "secure_provisioning_probe": "companion_route_unavailable",
            }

    def resolve_vault(self, vault_id: str) -> Path:
        for item in self._discover_vaults():
            if str(item.get("vault_id")) == str(vault_id):
                return Path(item["_path"])
        raise FileNotFoundError("vault_not_found")

    def network(self) -> Mapping[str, Any]:
        executable = shutil.which("tailscale")
        app_installed = Path("/Applications/Tailscale.app").is_dir()
        logged_in = False
        if executable:
            try:
                result = subprocess.run(
                    [executable, "status", "--json"],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=3,
                )
                if result.returncode == 0:
                    status = json.loads(result.stdout)
                    logged_in = status.get("BackendState") == "Running"
            except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
                logged_in = False
        return {"tailscale_installed": bool(executable or app_installed), "tailscale_logged_in": logged_in}

    @staticmethod
    def _read_json(path: Path) -> Any:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    def _discover_vaults(self) -> list[dict[str, Any]]:
        if self._vault_cache is not None:
            return self._vault_cache
        configuration = self._read_json(
            self.home / "Library" / "Application Support" / "obsidian" / "obsidian.json"
        )
        discovered: list[dict[str, Any]] = []
        values = configuration.get("vaults", {}) if isinstance(configuration, Mapping) else {}
        for vault_id, metadata in values.items():
            if not isinstance(metadata, Mapping) or not metadata.get("path"):
                continue
            path = Path(str(metadata["path"])).expanduser()
            if not path.is_dir():
                continue
            enabled_plugins = self._read_json(path / ".obsidian" / "community-plugins.json")
            enabled_ids = set(enabled_plugins) if isinstance(enabled_plugins, list) else set()
            claudian_id = None
            claudian_version = None
            plugins_dir = path / ".obsidian" / "plugins"
            try:
                candidates = tuple(plugins_dir.iterdir()) if plugins_dir.is_dir() else ()
            except OSError:
                candidates = ()
            for plugin_dir in candidates:
                manifest = self._read_json(plugin_dir / "manifest.json")
                if not isinstance(manifest, Mapping):
                    continue
                plugin_id = str(manifest.get("id") or plugin_dir.name)
                plugin_name = str(manifest.get("name") or "")
                if plugin_id.lower() == "claudian" or plugin_name.lower() == "claudian":
                    claudian_id = plugin_id
                    claudian_version = manifest.get("version")
                    break
            discovered.append(
                {
                    "vault_id": str(vault_id),
                    "display_name": path.name,
                    "open": bool(metadata.get("open")),
                    "claudian_version": claudian_version,
                    "claudian_enabled": bool(claudian_id and claudian_id in enabled_ids),
                    "_path": path,
                }
            )
        discovered.sort(key=lambda item: item["vault_id"])
        self._vault_cache = discovered
        return discovered


def _normalize(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _normalize(value[key]) for key in sorted(value)}
    if isinstance(value, (list, tuple)):
        normalized = [_normalize(item) for item in value]
        if all(isinstance(item, Mapping) and "vault_id" in item for item in normalized):
            normalized.sort(key=lambda item: str(item["vault_id"]))
        return normalized
    return value


def canonical_json(value: Any) -> str:
    return json.dumps(_normalize(value), ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def content_id(prefix: str, value: Any) -> str:
    digest = hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()
    return f"{prefix}-{digest}"


def validate_snapshot(snapshot: Mapping[str, Any]) -> None:
    if snapshot.get("snapshot_schema") != SNAPSHOT_SCHEMA or not snapshot.get("snapshot_id"):
        raise ValueError("invalid_inspection_snapshot")
    signed_body = {key: value for key, value in snapshot.items() if key != "snapshot_id"}
    if snapshot.get("snapshot_id") != content_id("inspection", signed_body):
        raise ValueError("inspection_integrity_failed")


@dataclass(frozen=True)
class Inspector:
    probe: InspectionProbe

    def snapshot(self) -> dict[str, Any]:
        body = {
            "snapshot_schema": SNAPSHOT_SCHEMA,
            "macos": dict(self.probe.macos()),
            "obsidian": dict(self.probe.obsidian()),
            "claudian": dict(self.probe.claudian()),
            "vaults": list(self.probe.vaults()),
            "installation": dict(self.probe.installation()),
            "network": dict(self.probe.network()),
        }
        body = _normalize(body)
        body["read_only"] = True
        body["support"] = self._support(body)
        body["snapshot_id"] = content_id("inspection", body)
        return body

    @staticmethod
    def _support(snapshot: Mapping[str, Any]) -> dict[str, Any]:
        reasons: list[str] = []
        if snapshot["macos"].get("platform") != "Darwin":
            reasons.append("unsupported_desktop_os")
        claudian = snapshot["claudian"]
        if claudian.get("version") != SUPPORTED_CLAUDIAN_VERSION:
            reasons.append("unsupported_claudian_version")
        if not claudian.get("enabled"):
            reasons.append("claudian_not_enabled")
        if not snapshot["installation"].get("secure_provisioning_available"):
            reasons.append("secure_provisioning_missing")
        vaults = snapshot["vaults"]
        if not vaults:
            reasons.append("vault_not_found")
        elif len(vaults) > 1:
            reasons.append("vault_selection_required")
        return {
            "supported": not reasons,
            "required_claudian_version": SUPPORTED_CLAUDIAN_VERSION,
            "reason_codes": reasons,
        }
