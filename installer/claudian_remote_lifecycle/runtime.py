"""Private runtime layout and verified release staging.

The lifecycle never executes from a mutable source checkout.  Production
staging consumes a release directory that a trusted bootstrap has already
verified and records the manifest digest in a receipt.  Unit tests inject a
release source and therefore do not download or execute third-party code.
"""

from __future__ import annotations

import hashlib
import base64
import json
import os
import platform
import re
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol
from urllib.parse import urlsplit


class ReleaseValidationError(ValueError):
    pass


def _canonical_json(value: Any) -> str:
    if isinstance(value, Mapping):
        return "{" + ",".join(
            json.dumps(str(key), ensure_ascii=False, separators=(",", ":"))
            + ":"
            + _canonical_json(value[key])
            for key in sorted(value)
        ) + "}"
    if isinstance(value, list):
        return "[" + ",".join(_canonical_json(item) for item in value) + "]"
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _default_key_fingerprint(public_key_pem: str) -> str:
    match = re.fullmatch(
        r"-----BEGIN PUBLIC KEY-----\s+([A-Za-z0-9+/=\s]+?)\s+-----END PUBLIC KEY-----\s*",
        str(public_key_pem or ""),
    )
    if not match:
        raise ReleaseValidationError("manifest_signing_key_invalid")
    try:
        encoded = base64.b64decode(re.sub(r"\s+", "", match.group(1)), validate=True)
    except (ValueError, TypeError) as exc:
        raise ReleaseValidationError("manifest_signing_key_invalid") from exc
    # Ed25519 SubjectPublicKeyInfo is 44 bytes in DER form.  Requiring the
    # exact algorithm prefix prevents a differently typed public key from
    # sharing this trust-root path.
    if len(encoded) != 44 or not encoded.startswith(bytes.fromhex("302a300506032b6570032100")):
        raise ReleaseValidationError("manifest_signing_key_invalid")
    return hashlib.sha256(encoded).hexdigest()


def _default_signature_verifier(public_key_pem: str, payload: bytes, signature: bytes) -> bool:
    node = shutil.which("node")
    if not node:
        raise ReleaseValidationError("release_signature_verifier_unavailable")
    verifier = """
const crypto = require('node:crypto');
let body = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', chunk => { body += chunk; });
process.stdin.on('end', () => {
  try {
    const value = JSON.parse(body);
    const ok = crypto.verify(
      null,
      Buffer.from(value.payload, 'base64'),
      crypto.createPublicKey(value.public_key_pem),
      Buffer.from(value.signature, 'base64')
    );
    process.stdout.write(ok ? 'verified' : 'rejected');
  } catch {
    process.exitCode = 2;
  }
});
"""
    request = json.dumps(
        {
            "public_key_pem": public_key_pem,
            "payload": base64.b64encode(payload).decode("ascii"),
            "signature": base64.b64encode(signature).decode("ascii"),
        },
        separators=(",", ":"),
    )
    try:
        result = subprocess.run(
            [node, "-e", verifier],
            input=request,
            text=True,
            capture_output=True,
            check=False,
            timeout=10,
            env={"PATH": str(Path(node).parent), "LANG": "C", "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ReleaseValidationError("release_signature_verifier_unavailable") from exc
    if result.returncode == 0:
        return result.stdout == "verified"
    if result.returncode == 2:
        raise ReleaseValidationError("manifest_signing_key_invalid")
    raise ReleaseValidationError("release_signature_verifier_unavailable")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _private_directory(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    return path


@dataclass(frozen=True)
class RuntimeLayout:
    base: Path
    launch_agents: Path

    def __post_init__(self) -> None:
        object.__setattr__(self, "base", Path(self.base))
        object.__setattr__(self, "launch_agents", Path(self.launch_agents))

    @property
    def releases(self) -> Path:
        return self.base / "releases"

    @property
    def staging(self) -> Path:
        return self.base / "staging"

    @property
    def runtime(self) -> Path:
        return self.base / "runtime"

    @property
    def config(self) -> Path:
        return self.base / "config"

    @property
    def state(self) -> Path:
        return self.base / "state"

    @property
    def logs(self) -> Path:
        return self.base / "logs"

    @property
    def backups(self) -> Path:
        return self.base / "backups"

    @property
    def current(self) -> Path:
        return self.base / "current"

    @property
    def previous(self) -> Path:
        return self.base / "previous"

    @property
    def ownership_receipt(self) -> Path:
        return self.state / "ownership.json"

    @property
    def relay_config(self) -> Path:
        return self.config / "relay.json"

    @property
    def companion_config(self) -> Path:
        return self.config / "companion.json"

    @property
    def bridge_bootstrap(self) -> Path:
        return self.state / "bridge-bootstrap.json"

    def bridge_bootstrap_for(self, vault_id: str) -> Path:
        digest = hashlib.sha256(str(vault_id).encode("utf-8")).hexdigest()[:24]
        return self.state / f"bridge-bootstrap.{digest}.json"

    @property
    def bridge_bootstrap_ack(self) -> Path:
        return self.state / "bridge-bootstrap-ack.json"

    @property
    def secure_provisioning(self) -> Path:
        return self.state / "secure-provisioning.json"

    @property
    def connection_profile(self) -> Path:
        return self.config / "connection-profile.json"

    @property
    def relay_launch_agent(self) -> Path:
        return self.launch_agents / "com.claudian.remote.relay.plist"

    @property
    def companion_launch_agent(self) -> Path:
        return self.launch_agents / "com.claudian.remote.companion.plist"

    def release_path(self, compatibility_set_id: str) -> Path:
        self._validate_component(compatibility_set_id)
        return self.releases / compatibility_set_id

    @staticmethod
    def _validate_component(value: str) -> None:
        if not value or "/" in value or ".." in value:
            raise ValueError("invalid_compatibility_set_id")

    def environment_path(self, compatibility_set_id: str) -> Path:
        self._validate_component(compatibility_set_id)
        return self.runtime / "environments" / compatibility_set_id

    def environment_python(self, compatibility_set_id: str) -> Path:
        return self.environment_path(compatibility_set_id) / "bin" / "python"

    def ensure(self) -> None:
        for path in (
            self.base,
            self.releases,
            self.staging,
            self.runtime,
            self.config,
            self.state,
            self.logs,
            self.backups,
        ):
            _private_directory(path)


@dataclass(frozen=True)
class StagedRelease:
    release_root: Path
    plugin_dir: Path
    python_executable: Path
    uv_executable: Path
    version: str


class ReleaseSource(Protocol):
    def verify(self, plan: Mapping[str, Any]) -> Mapping[str, Any]: ...

    def stage(
        self,
        plan: Mapping[str, Any],
        destination: Path,
        runtime_root: Path,
    ) -> StagedRelease: ...


def _safe_extract(archive: Path, destination: Path) -> None:
    destination = destination.resolve()
    with tarfile.open(archive, "r:*") as bundle:
        for member in bundle.getmembers():
            target = (destination / member.name).resolve()
            if destination != target and destination not in target.parents:
                raise ReleaseValidationError("release_archive_path_escape")
            if member.issym() or member.islnk() or member.isdev():
                raise ReleaseValidationError("release_archive_unsafe_member")
        bundle.extractall(destination, filter="data")


class BootstrapVerifiedReleaseSource:
    """Verify a signed manifest and consume only its exact release assets.

    The lifecycle verifies Ed25519 against its pinned trust root itself and
    then verifies every asset digest.  ``release-verification.json`` is not an
    authority boundary and a mutable source archive is never a fallback.
    """

    def __init__(
        self,
        directory: Path,
        *,
        downloader: Callable[[str, Path], None] | None = None,
        architecture: str | None = None,
        runner: Callable[..., subprocess.CompletedProcess[Any]] | None = None,
        trust_root: Path | Mapping[str, Any] | None = None,
        key_fingerprint: Callable[[str], str] | None = None,
        signature_verifier: Callable[[str, bytes, bytes], bool] | None = None,
    ) -> None:
        self.directory = Path(directory)
        self.downloader = downloader or self._download
        self.architecture = architecture or platform.machine()
        self.runner = runner or subprocess.run
        self.trust_root = trust_root or Path(__file__).resolve().parents[2] / "release" / "trust-root.json"
        self.key_fingerprint = key_fingerprint or _default_key_fingerprint
        self.signature_verifier = signature_verifier or _default_signature_verifier
        self._manifest: dict[str, Any] | None = None

    def _load_trust_root(self) -> Mapping[str, Any]:
        if isinstance(self.trust_root, Mapping):
            return self.trust_root
        try:
            value = json.loads(Path(self.trust_root).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ReleaseValidationError("release_trust_root_unavailable") from exc
        if not isinstance(value, Mapping):
            raise ReleaseValidationError("release_trust_root_unavailable")
        return value

    @staticmethod
    def _download(url: str, destination: Path) -> None:
        parsed = urlsplit(str(url))
        if parsed.scheme != "https" or parsed.username or parsed.password or parsed.fragment:
            raise ReleaseValidationError("runtime_asset_url_untrusted")
        with urllib.request.urlopen(url, timeout=60) as response, destination.open("wb") as output:
            final = urlsplit(str(response.geturl()))
            if final.scheme != "https" or final.username or final.password or final.fragment:
                raise ReleaseValidationError("runtime_asset_redirect_untrusted")
            shutil.copyfileobj(response, output, length=1024 * 1024)

    def verify(self, plan: Mapping[str, Any]) -> Mapping[str, Any]:
        manifest_path = self.directory / "release-manifest.json"
        try:
            manifest_bytes = manifest_path.read_bytes()
            manifest = json.loads(manifest_bytes)
        except (OSError, json.JSONDecodeError) as exc:
            raise ReleaseValidationError("verified_release_unavailable") from exc
        if not isinstance(manifest, Mapping):
            raise ReleaseValidationError("release_contract_mismatch")
        signature = manifest.get("signature")
        if not isinstance(signature, Mapping) or signature.get("algorithm") != "ed25519":
            raise ReleaseValidationError("manifest_signature_unverified")
        fingerprint = str(signature.get("key_fingerprint") or "")
        trust_root = self._load_trust_root()
        trusted = next(
            (
                item for item in trust_root.get("keys", [])
                if isinstance(item, Mapping) and item.get("fingerprint") == fingerprint
            ),
            None,
        )
        if trusted is None or trusted.get("status") != "trusted":
            raise ReleaseValidationError("manifest_signing_key_untrusted")
        public_key = str(trusted.get("public_key_pem") or "")
        if not public_key or self.key_fingerprint(public_key) != fingerprint:
            raise ReleaseValidationError("manifest_signing_key_invalid")
        try:
            encoded_signature = base64.b64decode(str(signature.get("value") or ""), validate=True)
        except (ValueError, TypeError) as exc:
            raise ReleaseValidationError("manifest_signature_unverified") from exc
        unsigned = {key: value for key, value in manifest.items() if key != "signature"}
        payload = _canonical_json(unsigned).encode("utf-8")
        if not encoded_signature or not self.signature_verifier(public_key, payload, encoded_signature):
            raise ReleaseValidationError("manifest_signature_unverified")
        if (
            manifest.get("distribution_channel") != "private_beta"
            or manifest.get("plugin_update_owner") != "lifecycle_manager"
            or manifest.get("compatibility_set", {}).get("plugin", {}).get("id") != "claudian-remote"
        ):
            raise ReleaseValidationError("release_contract_mismatch")
        expected = str(plan.get("compatibility_set_id") or "")
        actual_version = str(manifest.get("release_version") or "")
        if expected != f"claudian-remote-{actual_version}":
            raise ReleaseValidationError("release_plan_mismatch")
        assets = manifest.get("assets")
        if not isinstance(assets, list):
            raise ReleaseValidationError("release_contract_mismatch")
        for asset in assets:
            if not isinstance(asset, Mapping):
                raise ReleaseValidationError("release_asset_descriptor_invalid")
            name = str(asset.get("name") or "")
            component = str(asset.get("component") or "")
            if (
                not name
                or Path(name).is_absolute()
                or Path(name).name != name
                or name in {".", ".."}
                or component not in {"plugin", "companion", "relay", "installer"}
            ):
                raise ReleaseValidationError("release_asset_descriptor_invalid")
            path = self.directory / "assets" / name
            if not path.is_file() or path.stat().st_size != int(asset.get("size") or -1):
                raise ReleaseValidationError("release_asset_missing")
            if sha256_file(path) != str(asset.get("sha256") or ""):
                raise ReleaseValidationError("release_asset_digest_mismatch")
        self._manifest = manifest
        return {"verified": True, "release_version": actual_version}

    def _runtime_descriptor(self) -> Mapping[str, Any]:
        manifest = self._manifest or {}
        assets = manifest.get("compatibility_set", {}).get("runtime", {}).get("assets", [])
        for descriptor in assets:
            if descriptor.get("platform") == "darwin" and descriptor.get("arch") == self.architecture:
                return descriptor
        raise ReleaseValidationError("runtime_asset_target_missing")

    def _install_runtime_asset(self, descriptor: Mapping[str, Any], component: str, root: Path) -> Path:
        item = descriptor.get(component) or {}
        version = str(item.get("version") or "")
        url = str(item.get("url") or "")
        digest = str(item.get("sha256") or "")
        if not version or not url.startswith("https://") or len(digest) != 64:
            raise ReleaseValidationError("runtime_asset_descriptor_invalid")
        target = root / component / version
        executable = target / ("uv" if component == "uv" else "bin/python3")
        receipt = target / ".claudian-remote-runtime.json"
        if executable.is_file():
            try:
                value = json.loads(receipt.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise ReleaseValidationError("runtime_asset_mismatch") from exc
            if (
                value.get("runtime_asset_schema") != "claudian-remote.runtime-asset/v1"
                or value.get("component") != component
                or value.get("version") != version
                or value.get("archive_sha256") != digest
                or value.get("executable_sha256") != sha256_file(executable)
            ):
                raise ReleaseValidationError("runtime_asset_mismatch")
            return executable
        _private_directory(target.parent)
        temp_dir = Path(tempfile.mkdtemp(prefix=f"{component}.", dir=target.parent))
        archive = temp_dir / "asset"
        try:
            self.downloader(url, archive)
            if sha256_file(archive) != digest:
                raise ReleaseValidationError("runtime_asset_digest_mismatch")
            extracted = temp_dir / "extracted"
            extracted.mkdir()
            _safe_extract(archive, extracted)
            entries = list(extracted.iterdir())
            source = entries[0] if len(entries) == 1 and entries[0].is_dir() else extracted
            source_executable = source / ("uv" if component == "uv" else "bin/python3")
            if not source_executable.is_file():
                raise ReleaseValidationError("runtime_executable_missing")
            source_executable.chmod(0o700)
            runtime_receipt = source / ".claudian-remote-runtime.json"
            runtime_receipt.write_text(
                json.dumps(
                    {
                        "runtime_asset_schema": "claudian-remote.runtime-asset/v1",
                        "component": component,
                        "version": version,
                        "archive_sha256": digest,
                        "executable_sha256": sha256_file(source_executable),
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ) + "\n",
                encoding="utf-8",
            )
            os.chmod(runtime_receipt, 0o600)
            source.replace(target)
            return executable
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def _run_runtime_command(self, arguments: list[str], *, environment_root: Path) -> None:
        cache = _private_directory(environment_root / "cache")
        inherited = {
            key: os.environ[key]
            for key in ("HOME", "PATH", "TMPDIR", "LANG", "LC_ALL")
            if key in os.environ
        }
        try:
            result = self.runner(
                arguments,
                text=True,
                capture_output=True,
                check=False,
                timeout=300,
                env={
                    **inherited,
                    "UV_CACHE_DIR": str(cache),
                    "UV_NO_CONFIG": "1",
                    "UV_PYTHON_DOWNLOADS": "never",
                    "PYTHONDONTWRITEBYTECODE": "1",
                },
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ReleaseValidationError("runtime_environment_install_failed") from exc
        if result.returncode != 0:
            raise ReleaseValidationError("runtime_environment_install_failed")

    def _install_environment(
        self,
        *,
        compatibility_set_id: str,
        python: Path,
        uv: Path,
        components: Mapping[str, Path],
        runtime_root: Path,
    ) -> Path:
        companion = components.get("companion")
        requirements = companion / "requirements.lock" if companion else None
        if requirements is None or not requirements.is_file():
            raise ReleaseValidationError("runtime_dependency_lock_missing")
        lock_digest = sha256_file(requirements)
        python_digest = sha256_file(python)
        uv_digest = sha256_file(uv)
        layout = RuntimeLayout(runtime_root.parent, runtime_root.parent / "unused-launch-agents")
        target = layout.environment_path(compatibility_set_id)
        executable = target / "bin" / "python"
        receipt = target / ".claudian-remote-environment.json"
        if target.exists():
            try:
                value = json.loads(receipt.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise ReleaseValidationError("runtime_environment_mismatch") from exc
            if (
                not executable.is_file()
                or value.get("environment_schema") != "claudian-remote.runtime-environment/v1"
                or value.get("compatibility_set_id") != compatibility_set_id
                or value.get("requirements_sha256") != lock_digest
                or value.get("python_sha256") != python_digest
                or value.get("uv_sha256") != uv_digest
                or value.get("environment_python_sha256") != sha256_file(executable)
            ):
                raise ReleaseValidationError("runtime_environment_mismatch")
            return executable

        parent = _private_directory(target.parent)
        temporary = Path(tempfile.mkdtemp(prefix=f"{compatibility_set_id}.", dir=parent))
        try:
            self._run_runtime_command(
                [str(uv), "--no-config", "venv", "--python", str(python), str(temporary)],
                environment_root=runtime_root,
            )
            temporary_python = temporary / "bin" / "python"
            self._run_runtime_command(
                [
                    str(uv), "--no-config", "pip", "install",
                    "--python", str(temporary_python),
                    "--require-hashes", "-r", str(requirements),
                ],
                environment_root=runtime_root,
            )
            if not temporary_python.is_file():
                raise ReleaseValidationError("runtime_environment_python_missing")
            receipt_value = {
                "environment_schema": "claudian-remote.runtime-environment/v1",
                "compatibility_set_id": compatibility_set_id,
                "requirements_sha256": lock_digest,
                "python_sha256": python_digest,
                "uv_sha256": uv_digest,
                "environment_python_sha256": sha256_file(temporary_python),
            }
            receipt_path = temporary / ".claudian-remote-environment.json"
            receipt_path.write_text(
                json.dumps(receipt_value, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            os.chmod(receipt_path, 0o600)
            temporary.replace(target)
            return executable
        finally:
            shutil.rmtree(temporary, ignore_errors=True)

    def stage(self, plan: Mapping[str, Any], destination: Path, runtime_root: Path) -> StagedRelease:
        verified = self.verify(plan)
        destination.mkdir(parents=True, exist_ok=False)
        components: dict[str, Path] = {}
        for asset in self._manifest.get("assets", []):  # type: ignore[union-attr]
            component = str(asset["component"])
            if component not in {"plugin", "companion", "relay", "installer"}:
                raise ReleaseValidationError("release_asset_descriptor_invalid")
            target = destination / component
            target.mkdir()
            _safe_extract(self.directory / "assets" / str(asset["name"]), target)
            components[component] = target
        runtime = self._runtime_descriptor()
        python = self._install_runtime_asset(runtime, "python", runtime_root)
        uv = self._install_runtime_asset(runtime, "uv", runtime_root)
        plugin = components.get("plugin")
        if plugin is None:
            raise ReleaseValidationError("plugin_asset_missing")
        compatibility_set_id = str(plan.get("compatibility_set_id") or "")
        managed_python = self._install_environment(
            compatibility_set_id=compatibility_set_id,
            python=python,
            uv=uv,
            components=components,
            runtime_root=runtime_root,
        )
        return StagedRelease(destination, plugin, managed_python, uv, str(verified["release_version"]))


class UnavailableReleaseSource:
    def verify(self, _plan: Mapping[str, Any]) -> Mapping[str, Any]:
        raise ReleaseValidationError("verified_release_unavailable")

    def stage(self, *_args: Any, **_kwargs: Any) -> StagedRelease:
        raise ReleaseValidationError("verified_release_unavailable")
