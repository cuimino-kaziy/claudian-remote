"""Safety boundary for closing the one supported Beta 4 recovery shape.

These tests intentionally exercise the transaction API directly.  A legacy
operation may be closed automatically only when the frozen v1 journal and the
live Mac state both prove that staging was the sole mutation.  Every
contradiction must fail closed without touching the old installation.
"""

from __future__ import annotations

import json
from pathlib import Path

from installer.claudian_remote_lifecycle.launchd import LaunchAgentManager
from installer.claudian_remote_lifecycle.transaction import LocalTailscaleTransaction
from installer.tests.test_compatibility_decode import OPERATION_ID, _artifact_set
from installer.tests.test_runtime_transaction import dependencies, plan


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n",
        encoding="utf-8",
    )


def _read_tree(root: Path) -> dict[str, bytes | str]:
    """Capture a small tree without following symlinks."""

    if not root.exists() and not root.is_symlink():
        return {}
    values: dict[str, bytes | str] = {}
    for path in sorted(root.rglob("*")):
        relative = str(path.relative_to(root))
        if path.is_symlink():
            values[relative] = "symlink:" + str(path.readlink())
        elif path.is_file():
            values[relative] = path.read_bytes()
        elif path.is_dir():
            values[relative] = "directory"
    return values


def _make_exact_beta4_host(
    tmp_path: Path,
    *,
    staging_present: bool = True,
):
    deps, launchctl = dependencies(tmp_path, revoked=[])
    deps.local_listener_absent_probe = lambda port: port == 8787
    layout = deps.layout
    layout.ensure()

    # Reuse the frozen Beta 4 transaction payload, but bind it to the regular
    # runtime-transaction plan fixture used by the production transaction.
    _paths, values = _artifact_set(tmp_path / "frozen-beta4", migration=False)
    selected_plan = plan()
    journal = dict(values["local_transaction"])
    journal["plan_id"] = selected_plan["plan_id"]
    _write_json(layout.state / f"{OPERATION_ID}.transaction.json", journal)

    partial = layout.staging / f"{OPERATION_ID}.partial"
    if staging_present:
        partial.mkdir()
        (partial / "staged-only.txt").write_text("inert staging\n", encoding="utf-8")

    vault = deps.vault_path(selected_plan["vault_id"])
    legacy = vault / ".obsidian" / "plugins" / "whale-agent-bridge"
    legacy.mkdir(parents=True)
    _write_json(legacy / "manifest.json", {"id": "whale-agent-bridge", "version": "0.1.0"})
    _write_json(legacy / "data.json", {"mobile_token": "legacy-token-must-not-be-used"})
    _write_json(vault / ".obsidian" / "community-plugins.json", ["whale-agent-bridge"])

    return (
        LocalTailscaleTransaction(deps),
        deps,
        launchctl,
        selected_plan,
        partial,
        vault,
    )


def test_exact_beta4_staging_only_probe_accepts_existing_partial(tmp_path):
    transaction, _deps, _launchctl, selected_plan, partial, _vault = (
        _make_exact_beta4_host(tmp_path)
    )

    assert partial.is_dir()
    assert transaction.verify_supported_v1_staging_only_recovery(
        selected_plan,
        operation_id=OPERATION_ID,
    ) is True


def test_exact_beta4_staging_only_probe_accepts_already_missing_partial(tmp_path):
    transaction, _deps, _launchctl, selected_plan, partial, _vault = (
        _make_exact_beta4_host(tmp_path, staging_present=False)
    )

    assert not partial.exists()
    assert transaction.verify_supported_v1_staging_only_recovery(
        selected_plan,
        operation_id=OPERATION_ID,
    ) is True


def test_probe_rejects_any_legacy_migration_journal(tmp_path):
    transaction, deps, _launchctl, selected_plan, _partial, _vault = (
        _make_exact_beta4_host(tmp_path)
    )
    _write_json(
        deps.layout.state / f"{OPERATION_ID}.legacy-plugin.json",
        {
            "migration_schema": "claudian-remote.legacy-plugin/v1",
            "phase": "pending_revocation",
        },
    )

    assert transaction.verify_supported_v1_staging_only_recovery(
        selected_plan,
        operation_id=OPERATION_ID,
    ) is False


def test_probe_rejects_current_plugin_enabled(tmp_path):
    transaction, deps, _launchctl, selected_plan, _partial, vault = (
        _make_exact_beta4_host(tmp_path)
    )
    current = vault / ".obsidian" / "plugins" / "claudian-remote"
    current.mkdir()
    _write_json(current / "manifest.json", {"id": "claudian-remote", "version": "0.2.0-beta.4"})
    _write_json(
        vault / ".obsidian" / "community-plugins.json",
        ["whale-agent-bridge", "claudian-remote"],
    )

    assert transaction.verify_supported_v1_staging_only_recovery(
        selected_plan,
        operation_id=OPERATION_ID,
    ) is False


def test_probe_rejects_loaded_managed_launch_agent(tmp_path):
    transaction, deps, launchctl, selected_plan, _partial, _vault = (
        _make_exact_beta4_host(tmp_path)
    )
    launchctl.bootstrap(
        LaunchAgentManager.RELAY_LABEL,
        deps.layout.relay_launch_agent,
    )

    assert transaction.verify_supported_v1_staging_only_recovery(
        selected_plan,
        operation_id=OPERATION_ID,
    ) is False


def test_probe_rejects_owned_tailscale_serve_route(tmp_path):
    transaction, deps, _launchctl, selected_plan, _partial, _vault = (
        _make_exact_beta4_host(tmp_path)
    )
    deps.tailscale.activate_serve(8787)

    assert transaction.verify_supported_v1_staging_only_recovery(
        selected_plan,
        operation_id=OPERATION_ID,
    ) is False


def test_probe_rejects_live_or_inconclusive_loopback_listener(tmp_path):
    transaction, deps, _launchctl, selected_plan, _partial, _vault = (
        _make_exact_beta4_host(tmp_path)
    )
    deps.local_listener_absent_probe = lambda _port: False

    assert transaction.verify_supported_v1_staging_only_recovery(
        selected_plan,
        operation_id=OPERATION_ID,
    ) is False


def test_probe_rejects_symlinked_operation_staging(tmp_path):
    transaction, deps, _launchctl, selected_plan, partial, _vault = (
        _make_exact_beta4_host(tmp_path, staging_present=False)
    )
    outside = tmp_path / "outside-staging"
    outside.mkdir()
    partial.symlink_to(outside, target_is_directory=True)

    assert transaction.verify_supported_v1_staging_only_recovery(
        selected_plan,
        operation_id=OPERATION_ID,
    ) is False
    assert outside.is_dir()


def test_narrow_rollback_only_removes_exact_partial_and_writes_terminal_journal(tmp_path):
    revoked: list[str] = []
    deps, launchctl = dependencies(tmp_path, revoked=revoked)
    deps.local_listener_absent_probe = lambda port: port == 8787
    layout = deps.layout
    layout.ensure()
    _paths, values = _artifact_set(tmp_path / "frozen-beta4", migration=False)
    selected_plan = plan()
    journal = dict(values["local_transaction"])
    journal["plan_id"] = selected_plan["plan_id"]
    journal_path = layout.state / f"{OPERATION_ID}.transaction.json"
    _write_json(journal_path, journal)

    partial = layout.staging / f"{OPERATION_ID}.partial"
    partial.mkdir()
    (partial / "staged-only.txt").write_text("delete only me\n", encoding="utf-8")
    sibling = layout.staging / "op-unrelated.partial"
    sibling.mkdir()
    (sibling / "keep.txt").write_text("keep me\n", encoding="utf-8")

    vault = deps.vault_path(selected_plan["vault_id"])
    legacy = vault / ".obsidian" / "plugins" / "whale-agent-bridge"
    legacy.mkdir(parents=True)
    _write_json(legacy / "manifest.json", {"id": "whale-agent-bridge"})
    _write_json(legacy / "data.json", {"mobile_token": "must-not-be-revoked"})
    _write_json(vault / ".obsidian" / "community-plugins.json", ["whale-agent-bridge"])

    launchd_remove_calls: list[bool] = []

    def record_launchd_remove():
        launchd_remove_calls.append(True)
        return {"changed": True, "ready": False}

    deps.launchd.remove_local_agents = record_launchd_remove
    before_vault = _read_tree(vault)
    before_sibling = _read_tree(sibling)

    outcome = LocalTailscaleTransaction(deps).rollback_supported_v1_staging_only(
        selected_plan,
        operation_id=OPERATION_ID,
    )

    assert outcome["state"] == "rolled_back"
    assert outcome["code"] == "rollback_completed"
    assert outcome["mutation_performed"] is True
    assert not partial.exists()
    assert _read_tree(sibling) == before_sibling
    assert _read_tree(vault) == before_vault
    assert launchd_remove_calls == []
    assert deps.tailscale.removed == 0
    assert revoked == []
    terminal = json.loads(journal_path.read_text(encoding="utf-8"))
    assert terminal == {**journal, "phase": "rolled_back"}
    assert launchctl.loaded == {}


def test_narrow_rollback_is_idempotent_after_verified_closure(tmp_path):
    transaction, _deps, _launchctl, selected_plan, partial, vault = (
        _make_exact_beta4_host(tmp_path)
    )

    first = transaction.rollback_supported_v1_staging_only(
        selected_plan,
        operation_id=OPERATION_ID,
    )
    after_first_vault = _read_tree(vault)
    second = transaction.rollback_supported_v1_staging_only(
        selected_plan,
        operation_id=OPERATION_ID,
    )

    assert first["state"] == "rolled_back"
    assert not partial.exists()
    assert transaction.verify_supported_v1_staging_only_recovery(
        selected_plan,
        operation_id=OPERATION_ID,
        closed=True,
    ) is True
    assert second["state"] == "rolled_back"
    assert second["code"] == "rollback_already_completed"
    assert second["mutation_performed"] is False
    assert _read_tree(vault) == after_first_vault
