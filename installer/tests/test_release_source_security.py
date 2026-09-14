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


ROOT = Path(__file__).resolve().parents[2]
SUPPORT_MATRIX = json.loads(
    (ROOT / "release" / "support-matrix.json").read_text(encoding="utf-8")
)


def runtime_distribution(*, delivery="immutable_upstream_asset"):
    runtime = SUPPORT_MATRIX["runtime"]
    return {
        "python": runtime["python"],
        "uv": runtime["uv"],
        "delivery": delivery,
        "assets": json.loads(json.dumps(runtime["required_assets"])),
    }


def write_release(
    tmp_path: Path,
    *,
    name=None,
    component="plugin",
    version="0.2.0-beta.6.7",
):
    release = tmp_path / "release"
    assets = release / "assets"
    assets.mkdir(parents=True)
    rows = [
        ("plugin", f"claudian-remote-plugin-{version}.tar.gz", "package-lock.json"),
        ("companion", f"claudian-remote-companion-{version}.tar.gz", "gateway/requirements.lock"),
        ("relay", f"claudian-remote-relay-{version}.tar.gz", "gateway/requirements.lock"),
        ("installer", f"claudian-remote-lifecycle-{version}.tar.gz", "release/lifecycle-dependencies.lock.json"),
        (
            "legacy_retirement_helper",
            f"claudian-remote-legacy-retirement-helper-{version}.py",
            "gateway/requirements.lock",
        ),
    ]
    if name is not None:
        rows[0] = (component, name, rows[0][2])
    manifest_assets = []
    for row_component, row_name, lock_path in rows:
        payload = (
            (ROOT / "gateway" / "relay" / "legacy_retirement.py").read_bytes()
            if row_component == "legacy_retirement_helper"
            else f"signed {row_component} asset".encode()
        )
        if "/" not in row_name and row_name not in {".", ".."}:
            (assets / row_name).write_bytes(payload)
        manifest_assets.append(
            {
                "name": row_name,
                "component": row_component,
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "license": (
                    "AGPL-3.0-only"
                    if row_component
                    in {"relay", "legacy_retirement_helper"}
                    else "MIT"
                ),
                "dependency_locks": [
                    {
                        "path": lock_path,
                        "sha256": hashlib.sha256(
                            (ROOT / lock_path).read_bytes()
                        ).hexdigest(),
                    }
                ],
            }
        )
    fingerprint = "f" * 64
    manifest = {
        "schema_version": 1,
        "release_version": version,
        "release_tag": f"v{version}",
        "source_ref": f"refs/tags/v{version}",
        "distribution_channel": "private_beta",
        "plugin_update_owner": "lifecycle_manager",
        "compatibility_set": {
            "id": f"claudian-remote-{version}",
            "plugin": {
                "id": "claudian-remote",
                "version": version,
                "minimum_obsidian_version": "1.12.3",
            },
            "companion": {"version": version},
            "relay": {"version": version},
            "installer": {"version": version},
            "protocol": json.loads(json.dumps(SUPPORT_MATRIX["protocol"])),
            "configuration_schema": SUPPORT_MATRIX["components"][
                "configuration_schema"
            ],
            "claudian": {"exact_version": "2.2.6", "supported_versions": ["2.0.4", "2.2.6", "2.2.7"]},
            "runtime": runtime_distribution(),
            "upgrade_contract": json.loads(
                json.dumps(SUPPORT_MATRIX["upgrade_contract"])
            ),
        },
        "assets": manifest_assets,
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


def test_safe_extract_allows_internal_relative_runtime_symlink(tmp_path):
    source_root = tmp_path / "source"
    binary = source_root / "python" / "bin" / "python3.12"
    binary.parent.mkdir(parents=True)
    binary.write_text("pinned runtime", encoding="utf-8")
    archive = tmp_path / "python-runtime.tar.gz"
    with tarfile.open(archive, "w:gz") as bundle:
        bundle.add(source_root / "python", arcname="python")
        link = tarfile.TarInfo("python/bin/python3")
        link.type = tarfile.SYMTYPE
        link.linkname = "python3.12"
        bundle.addfile(link)

    destination = tmp_path / "destination"
    destination.mkdir()
    _safe_extract(archive, destination)

    assert (destination / "python/bin/python3").is_symlink()
    assert (destination / "python/bin/python3").read_text(encoding="utf-8") == "pinned runtime"


@pytest.mark.parametrize(
    ("member_name", "link_name", "link_type"),
    [
        ("python/bin/python", "/tmp/escape", tarfile.SYMTYPE),
        ("python/bin/python", "../../../escape", tarfile.SYMTYPE),
        ("python/bin/python", "../../escape", tarfile.LNKTYPE),
    ],
)
def test_safe_extract_rejects_link_targets_outside_archive(
    tmp_path, member_name, link_name, link_type
):
    archive = tmp_path / "unsafe-runtime.tar.gz"
    with tarfile.open(archive, "w:gz") as bundle:
        link = tarfile.TarInfo(member_name)
        link.type = link_type
        link.linkname = link_name
        bundle.addfile(link)

    destination = tmp_path / "destination"
    destination.mkdir()
    with pytest.raises(ReleaseValidationError, match="release_archive_path_escape"):
        _safe_extract(archive, destination)


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


def test_installer_accepts_only_the_exact_beta5_signed_upgrade_contract(tmp_path):
    release, trust, plan = write_release(tmp_path)

    verified = source(release, trust).verify(plan)

    assert verified == {"verified": True, "release_version": "0.2.0-beta.6.7"}


def test_installer_rejects_private_key_material_anywhere_in_manifest(tmp_path):
    release, trust, plan = write_release(tmp_path)
    manifest_path = release / "release-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["runtime_proof_private_key"] = "must-never-be-packaged"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ReleaseValidationError, match="release_private_key_forbidden"):
        source(release, trust).verify(plan)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda contract: contract["journey_capabilities"].pop(),
        lambda contract: contract["result_schema_versions"].__setitem__(
            0, "claudian-remote.lifecycle-result/v1"
        ),
        lambda contract: contract["proof_schema_versions"].__setitem__(
            0, "attacker/proof/v9"
        ),
        lambda contract: contract["supported_legacy_lineages"][2].update(
            {"version": "unknown-lineage"}
        ),
        lambda contract: contract["supported_profiles"].append("local_lan"),
        lambda contract: contract["final_topology_boundary"].update(
            {"mode": "remote_vps"}
        ),
        lambda contract: contract["current_update_pairing_rows"][0].update(
            {"companion": "0.2.0-beta.4"}
        ),
        lambda contract: contract["adapter_rows"][0].update(
            {"profile_id": "unsupported-profile"}
        ),
        lambda contract: contract["helper_rows"][0].update(
            {"sha256": "0" * 64}
        ),
        lambda contract: contract["execution_constraints"].update(
            {"runtime_exact_paths": ["python3"]}
        ),
        lambda contract: contract["execution_constraints"].update(
            {"import_prefixes": ["relative/imports"]}
        ),
        lambda contract: contract["execution_constraints"].update(
            {"developer_checkout_dependency": "allowed"}
        ),
        lambda contract: contract.update(
            {"runtime_proof_private_key": "must-never-be-packaged"}
        ),
        lambda contract: contract["packaged_acceptance_rows"][2][
            "components"
        ].pop(),
    ],
)
def test_installer_rejects_changed_upgrade_capability_rows(tmp_path, mutate):
    release, trust, plan = write_release(tmp_path)
    manifest_path = release / "release-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    mutate(manifest["compatibility_set"]["upgrade_contract"])
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(
        ReleaseValidationError,
        match="upgrade_contract|release_private_key_forbidden",
    ):
        source(release, trust).verify(plan)


def test_installer_rejects_missing_mixed_or_substituted_beta5_assets(tmp_path):
    missing_release, missing_trust, missing_plan = write_release(tmp_path / "missing")
    manifest_path = missing_release / "release-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["assets"].pop()
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ReleaseValidationError, match="release_asset_set_invalid"):
        source(missing_release, missing_trust).verify(missing_plan)

    mixed_release, mixed_trust, mixed_plan = write_release(tmp_path / "mixed")
    manifest_path = mixed_release / "release-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["assets"][0]["name"] = "claudian-remote-plugin-0.2.0-beta.4.tar.gz"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ReleaseValidationError, match="release_asset_descriptor_invalid"):
        source(mixed_release, mixed_trust).verify(mixed_plan)

    helper_release, helper_trust, helper_plan = write_release(tmp_path / "helper")
    helper_path = (
        helper_release
        / "assets"
        / "claudian-remote-legacy-retirement-helper-0.2.0-beta.6.7.py"
    )
    helper_path.write_text("substituted helper", encoding="utf-8")
    with pytest.raises(ReleaseValidationError, match="release_asset_digest_mismatch"):
        source(helper_release, helper_trust).verify(helper_plan)


@pytest.mark.parametrize(
    ("field", "value"),
    [("sha256", "A" * 64), ("size", 1.5)],
)
def test_installer_rejects_bad_asset_hash_or_size_metadata(tmp_path, field, value):
    release, trust, plan = write_release(tmp_path)
    manifest_path = release / "release-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["assets"][0][field] = value
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ReleaseValidationError, match="release_asset_descriptor_invalid"):
        source(release, trust).verify(plan)


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


@pytest.mark.parametrize("versions", [None, ["2.2.6"], ["2.0.4", "2.2.6", "2.2.7", "2.2.8"]])
def test_installer_rejects_changed_claudian_allowlist(tmp_path, versions):
    release, trust, plan = write_release(tmp_path)
    manifest_path = release / "release-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["compatibility_set"]["claudian"]["supported_versions"] = versions
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ReleaseValidationError, match="release_contract_mismatch"):
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
