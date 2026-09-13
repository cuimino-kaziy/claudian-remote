import re
from pathlib import Path

from installer.claudian_remote_lifecycle.model import COMMANDS


ROOT = Path(__file__).resolve().parents[2]
GUIDE = ROOT / "CLAUDIAN_REMOTE_INSTALL.md"


def test_guide_starts_with_inspect_and_references_every_real_cli_command():
    text = GUIDE.read_text(encoding="utf-8")
    commands = re.findall(r"claudian-remote-lifecycle ([a-z-]+)", text)
    assert commands[0] == "inspect"
    assert set(COMMANDS).issubset(set(commands))
    assert "one question" in text.lower() or "一次只问一个" in text
    assert "未知" in text and "失败关闭" in text


def test_every_actionable_result_and_gate_has_guide_copy():
    text = GUIDE.read_text(encoding="utf-8")
    result_codes = {
        "inspection_ready",
        "unsupported_desktop_os",
        "unsupported_claudian_version",
        "claudian_not_enabled",
        "vault_not_found",
        "vault_selection_required",
        "plan_prepared",
        "operation_status",
        "human_action_required",
        "resume_prepared",
        "operation_not_found",
        "lifecycle_operation_busy",
        "environment_drift",
        "secure_provisioning_missing",
        "trusted_lan_not_release_eligible",
        "obsidian_close_for_migration_required",
        "desktop_plugin_bootstrap_required",
        "uninstall_precondition_incomplete",
        "operation_not_implemented",
        "invalid_lifecycle_input",
    }
    gate_types = {
        "tailscale_install_required",
        "tailscale_login_required",
        "tailscale_https_consent_required",
        "vault_selection_required",
        "vps_host_authorization_required",
        "trusted_lan_consent_required",
        "pairing_approval_required",
        "pairing_admin_bootstrap_required",
        "desktop_plugin_bootstrap_required",
        "obsidian_close_for_migration_required",
        "legacy_authority_authorization_required",
        "purge_confirmation_required",
        "diagnostic_export_confirmation_required",
    }
    assert all(code in text for code in result_codes)
    assert all(gate in text for gate in gate_types)
    assert "不要让用户粘贴密码、令牌、私钥" in text
    assert "curl | shell" in text


def test_guide_explains_product_defaults_to_tailscale_and_minimizes_questions():
    text = GUIDE.read_text(encoding="utf-8")
    assert "Claudian 的移动端远程客户端" in text
    assert "类似在手机上使用 Codex" in text
    assert "默认使用免费的 Tailscale" in text
    assert "是否拥有并希望使用一台受支持的 VPS" not in text
    assert "由 Agent 继续操作" in text
    assert "我自己操作" in text
    assert "remote_vps" in text and "尚未开放" in text


def test_guide_uses_typed_retirement_outcomes_and_recovery_boundaries():
    text = GUIDE.read_text(encoding="utf-8")
    for outcome in ("not_applied", "retired", "inconclusive"):
        assert outcome in text
    # Three-way recovery copy, never interchanged.
    assert "finish_forward" in text
    assert "reconcile_retirement_outcome" in text
    assert "预边界回滚" in text or "rollback" in text
    # After dispatch, cancellation is unavailable and no new install may start.
    assert "cancellation_available" in text
    assert "派发后" in text


def test_guide_covers_capability_split_and_tailnet_fast_path():
    text = GUIDE.read_text(encoding="utf-8")
    assert "requires_capability" in text
    assert "browser_control" in text
    assert "computer_control" in text
    assert "快速路径" in text
    assert "CLI integration" in text
    # Unknown schema still stops and diagnoses; never ad-hoc or secret requests.
    assert "失败关闭" in text
    assert "diagnose" in text
