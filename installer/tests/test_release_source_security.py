import base64
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tarfile

import pytest

from installer.claudian_remote_lifecycle.runtime import (
    BootstrapVerifiedReleaseSource,
    ReleaseValidationError,
    _default_key_fingerprint,
    _default_signature_verifier,
    _safe_extract,
)


def runtime_distribution(*, delivery="immutable_upstream_asset"):
    targets = []
    for arch in ("arm64", "x86_64"):
        targets.append({
            "platform": "darwin",
            "arch": arch,
            "python": {
                "version": "3.12.11",
                "url": f"https://downloads.example/python-{arch}.tar.gz",
                "sha256": "a" * 64,
            },
            "uv": {
                "version": "0.10.12",
                "url": f"https://downloads.example/uv-{arch}.tar.gz",
                "sha256": "b" * 64,
            },
        })
    return {
        "python": "3.12.11",
        "uv": "0.10.12",
        "delivery": delivery,
        "assets": targets,
    }


def write_release(tmp_path: Path, *, name="plugin.tar.gz", component="plugin", version="0.2.0-beta.1"):
    release = tmp_path / "release"
    assets = release / "assets"
    assets.mkdir(parents=True)
    payload = b"signed asset"
    if "/" not in name and name not in {".", ".."}:
        (assets / name).write_bytes(payload)
    fingerprint = "f" * 64
    manifest = {
        "schema_version": 1,
        "release_version": version,
        "distribution_channel": "private_beta",
        "plugin_update_owner": "lifecycle_manager",
        "compatibility_set": {
            "plugin": {"id": "claudian-remote"},
            "runtime": runtime_distribution(),
        },
        "assets": [{
            "name": name,
            "component": component,
            "size": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }],
        "signature": {
            "algorithm": "ed25519",
            "key_fingerprint": fingerprint,
            "value": base64.b64encode(b"signature").decode(),
        },
    }
    (release / "release-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    trust = {
        "schema_version": 1,
        "keys": [{
            "fingerprint": fingerprint,
            "status": "trusted",
            "public_key_pem": "fixture-public-key",
        }],
    }
    plan = {"compatibility_set_id": f"claudian-remote-{version}"}
    return release, trust, plan


def source(release, trust, *, signature_valid=True):
    return BootstrapVerifiedReleaseSource(
        release,
        trust_root=trust,
        key_fingerprint=lambda _public_key: "f" * 64,
        signature_verifier=lambda _public_key, _payload, _signature: signature_valid,
    )


def test_safe_extract_supports_the_macos_bootstrap_python(tmp_path):
    source_root = tmp_path / "source"
    source_root.mkdir()
    (source_root / "payload.txt").write_text("verified payload", encoding="utf-8")
    archive = tmp_path / "payload.tar.gz"
    with tarfile.open(archive, "w:gz") as bundle:
        bundle.add(source_root / "payload.txt", arcname="payload.txt")

    destination = tmp_path / "destination"
    destination.mkdir()
    _safe_extract(archive, destination)

    assert (destination / "payload.txt").read_text(encoding="utf-8") == "verified payload"


def test_manifest_signature_is_verified_by_lifecycle_not_a_forgeable_receipt(tmp_path):
    release, trust, plan = write_release(tmp_path)
    (release / "release-verification.json").write_text(json.dumps({
        "receipt_schema": "claudian-remote.release-verification/v1",
        "signature_verified": True,
        "trusted_key_fingerprint": "f" * 64,
        "manifest_sha256": "0" * 64,
    }))

    assert source(release, trust).verify(plan)["verified"] is True
    with pytest.raises(ReleaseValidationError, match="manifest_signature_unverified"):
        source(release, trust, signature_valid=False).verify(plan)


@pytest.mark.parametrize(
    ("name", "component"),
    [
        ("../../outside.tar.gz", "plugin"),
        ("/tmp/outside.tar.gz", "plugin"),
        ("plugin.tar.gz", "../../outside"),
        ("plugin.tar.gz", "/tmp/outside"),
    ],
)
def test_asset_name_and_component_cannot_escape_release_or_staging(tmp_path, name, component):
    release, trust, plan = write_release(tmp_path, name=name, component=component)
    with pytest.raises(ReleaseValidationError, match="release_asset_descriptor_invalid"):
        source(release, trust).verify(plan)
    assert not (tmp_path / "outside.tar.gz").exists()


def test_release_plan_binding_is_exact_not_a_version_substring(tmp_path):
    release, trust, _ = write_release(tmp_path, version="0.2.0-beta.1")
    with pytest.raises(ReleaseValidationError, match="release_plan_mismatch"):
        source(release, trust).verify({
            "compatibility_set_id": "claudian-remote-prefix-0.2.0-beta.1-suffix",
        })


def test_installer_rejects_legacy_runtime_delivery_even_when_manifest_signature_is_valid(tmp_path):
    release, trust, plan = write_release(tmp_path)
    manifest_path = release / "release-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["compatibility_set"]["runtime"] = runtime_distribution(delivery="private_release_asset")
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ReleaseValidationError, match="runtime_distribution_invalid"):
        source(release, trust).verify(plan)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda runtime: runtime["assets"].pop(),
        lambda runtime: runtime["assets"][0]["python"].update({"version": "3.13.0"}),
        lambda runtime: runtime["assets"][0]["uv"].update({"url": "https://downloads.example/uv.tar.gz?token=secret"}),
        lambda runtime: runtime["assets"][0]["uv"].update({"sha256": "A" * 64}),
    ],
)
def test_installer_rejects_incomplete_or_unsafe_runtime_contract(tmp_path, mutate):
    release, trust, plan = write_release(tmp_path)
    manifest_path = release / "release-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    mutate(manifest["compatibility_set"]["runtime"])
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ReleaseValidationError, match="runtime_distribution_invalid"):
        source(release, trust).verify(plan)


def test_unknown_or_revoked_trust_root_key_fails_closed(tmp_path):
    release, trust, plan = write_release(tmp_path)
    trust["keys"][0]["status"] = "revoked"
    with pytest.raises(ReleaseValidationError, match="manifest_signing_key_untrusted"):
        source(release, trust).verify(plan)

    trust["keys"] = []
    with pytest.raises(ReleaseValidationError, match="manifest_signing_key_untrusted"):
        source(release, trust).verify(plan)


@pytest.mark.skipif(shutil.which("node") is None, reason="supported Agent Node.js runtime unavailable")
def test_default_ed25519_verifier_needs_no_unlocked_python_package():
    result = subprocess.run(
        [
            shutil.which("node"),
            "-e",
            """
const crypto = require('node:crypto');
const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const payload = Buffer.from('manifest-payload');
process.stdout.write(JSON.stringify({
  public_key_pem: publicKey.export({ type: 'spki', format: 'pem' }),
  payload: payload.toString('base64'),
  signature: crypto.sign(null, payload, privateKey).toString('base64')
}));
""",
        ],
        text=True,
        capture_output=True,
        check=True,
    )
    fixture = json.loads(result.stdout)
    public_key = fixture["public_key_pem"]
    payload = base64.b64decode(fixture["payload"])
    signature = base64.b64decode(fixture["signature"])
    assert len(_default_key_fingerprint(public_key)) == 64
    assert _default_signature_verifier(public_key, payload, signature) is True
    assert _default_signature_verifier(public_key, payload + b"tampered", signature) is False


def test_reused_managed_runtime_is_bound_to_verified_asset_receipt(tmp_path):
    archive_root = tmp_path / "archive-root"
    archive_root.mkdir()
    executable = archive_root / "uv"
    executable.write_text("verified uv", encoding="utf-8")
    archive = tmp_path / "uv.tar.gz"
    with tarfile.open(archive, "w:gz") as bundle:
        bundle.add(archive_root, arcname="uv-runtime")
    descriptor = {
        "uv": {
            "version": "0.10.12",
            "url": "https://downloads.example/uv.tar.gz",
            "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
        }
    }
    release, trust, _plan = write_release(tmp_path / "release-source")
    release_source = BootstrapVerifiedReleaseSource(
        release,
        trust_root=trust,
        downloader=lambda _url, destination: shutil.copyfile(archive, destination),
        key_fingerprint=lambda _public_key: "f" * 64,
        signature_verifier=lambda *_args: True,
    )
    installed = release_source._install_runtime_asset(descriptor, "uv", tmp_path / "runtime")
    installed.write_text("tampered uv", encoding="utf-8")

    with pytest.raises(ReleaseValidationError, match="runtime_asset_mismatch"):
        release_source._install_runtime_asset(descriptor, "uv", tmp_path / "runtime")
