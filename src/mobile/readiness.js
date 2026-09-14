const COPY = Object.freeze({
  ready: ["ready", "已就绪"],
  running: ["running", "正在运行"],
  pairing_required: ["blocked", "需要配对"],
  relay_offline: ["blocked", "Remote 未连接"],
  mac_offline: ["blocked", "Mac 离线"],
  vault_closed: ["blocked", "目标 Vault 未打开"],
  recovering: ["read_only", "正在校准"],
  compatibility_set_mismatch: ["read_only", "组件版本不匹配"],
  unsupported_claudian_version: ["read_only", "Claudian 版本不受支持"],
  required_capability_missing: ["read_only", "Claudian 能力缺失"],
  compatibility_mismatch: ["read_only", "兼容性不匹配"]
});

function activeTurn(state) {
  const conversation = state?.activeConversationId ? state.conversations?.[state.activeConversationId] : null;
  return conversation?.activeTurnId ? conversation.turns?.[conversation.activeTurnId] : null;
}

export function pairingStatusFromSettings(settings = {}) {
  return settings?.re_pair_required === true || !String(settings?.mobile_token || "").trim()
    ? "required"
    : "paired";
}

export function deriveReadiness(state = {}, { paired } = {}) {
  let reason = "ready";
  const isPaired = paired ?? state?.pairing?.status !== "required";
  if (!isPaired) reason = "pairing_required";
  else if (state?.transport?.status !== "connected") reason = "relay_offline";
  else if (state?.compatibility?.writable === false && state.compatibility.pending !== true) reason = COPY[state.compatibility.reason]
    ? state.compatibility.reason
    : "compatibility_mismatch";
  else if (state?.recovery?.required === true) reason = "recovering";
  else if (state?.presence?.mac?.status !== "online") reason = state?.presence?.mac?.reason === "vault_closed"
    ? "vault_closed"
    : "mac_offline";
  else if (state?.compatibility?.pending === true) reason = "recovering";
  else if (activeTurn(state)?.status === "running") reason = "running";
  const [status, label] = COPY[reason] || COPY.compatibility_mismatch;
  return {
    status,
    reason_code: reason,
    label,
    writable: reason === "ready" || reason === "running",
    remediation: state?.compatibility?.remediation || null
  };
}
