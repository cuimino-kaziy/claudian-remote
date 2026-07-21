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
        "operation_not_implemented",
        "invalid_lifecycle_input",
    }
    gate_types = {
        "github_auth_required",
        "tailscale_install_required",
        "tailscale_login_required",
        "tailscale_https_consent_required",
        "vault_selection_required",
        "vps_host_authorization_required",
        "trusted_lan_consent_required",
        "pairing_approval_required",
        "pairing_admin_bootstrap_required",
        "purge_confirmation_required",
    }
    assert all(code in text for code in result_codes)
    assert all(gate in text for gate in gate_types)
    assert "不要让用户粘贴密码、令牌、私钥" in text
    assert "curl | shell" in text
