import { deriveReadiness } from "./readiness.js";
import { COMPATIBILITY_SET } from "../protocol/compatibility.js";

const COMPATIBILITY_REASONS = new Set([
  "ready", "compatibility_set_mismatch", "compatibility_mismatch",
  "unsupported_claudian_version", "required_capability_missing"
]);
const COMMAND_TYPES = new Set([
  "message.submit", "turn.stop", "turn.steer", "approval.respond",
  "history.list", "history.select", "history.new", "history.rename", "history.archive"
]);
const REJECTION_REASONS = new Set([
  ...COMPATIBILITY_REASONS,
  "rejected", "failed", "mac_offline", "session_mismatch", "connection_generation_mismatch",
  "expired", "stale_connection", "stale_session", "stale_revision", "stale_conversation", "stale_turn",
  "capability_missing", "delivery_conflict", "command_backpressure", "relay_shutting_down",
  "claudian_input_busy", "claudian_steer_busy", "claudian_steer_unsent"
]);

function allowlisted(value, allowed) {
  return allowed.has(value) ? value : "unknown";
}

function compatibilityReason(result) {
  return result?.writable === true ? "ready" : allowlisted(result?.reason, COMPATIBILITY_REASONS);
}

function layoutSample(value) {
  if (!value || typeof value !== "object") return null;
  const sample = {
    focusKind: ["composer", "history", "other", "outside", "none"].includes(value.focusKind) ? value.focusKind : "none"
  };
  for (const key of ["keyboardOpen", "keyboardAnimating", "historyVisible", "activeSurfaceVisible"]) {
    sample[key] = value[key] === true;
  }
  const numbers = [
    "innerHeight", "clientHeight", "visualHeight", "visualTop", "visualScale", "scrollY",
    "documentKeyboardHeight", "bodyKeyboardHeight", "rootKeyboardHeight", "appMaxHeight",
    "navbarHeight", "navbarBottomOffset", "safeAreaBottom",
    "wrapPaddingBottom", "visibleHeight", "visibleTop",
    ...["app", "leaf", "host", "root", "messages", "wrap", "row", "input", "history"]
      .flatMap((name) => [`${name}Top`, `${name}Height`])
  ];
  for (const key of numbers) {
    sample[key] = typeof value[key] === "number" && Number.isFinite(value[key])
      ? Math.round(value[key] * 10) / 10 : null;
  }
  return sample;
}

function digest(value) {
  const text = String(value || "");
  let hash = 0x811c9dc5;
  for (let index = 0; index < text.length; index += 1) {
    hash ^= text.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return text ? hash.toString(16).padStart(8, "0") : "none";
}

export function buildDiagnosticReport(state, attachment = null, now = new Date(), layout = null) {
  const conversation = state.conversations?.[state.activeConversationId] || null;
  const activeTurn = conversation?.activeTurnId ? conversation.turns?.[conversation.activeTurnId] : null;
  const attachmentItem = Array.isArray(attachment) ? attachment[0] : attachment;
  const capabilityMode = state.capabilities?.semantic_stream === true
    ? "streaming"
    : state.capabilities?.mode || "unknown";
  const readiness = deriveReadiness(state);
  const latestRejected = Object.values(state.commands || {})
    .filter((command) => command?.status === "rejected")
    .sort((left, right) => Number(right.createdAt || 0) - Number(left.createdAt || 0))[0];
  const lines = [
    "Claudian Remote v2 mobile report",
    `time=${now.toISOString()}`,
    "protocol=claudian.remote.v2",
    `client_plugin_version=${COMPATIBILITY_SET.plugin}`,
    `client_compatibility_set=${COMPATIBILITY_SET.id}`,
    `compatibility_mobile_relay=${compatibilityReason(state.compatibilityLayers?.mobileRelay)}`,
    `compatibility_mac_relay=${compatibilityReason(state.compatibilityLayers?.macRelay)}`,
    `compatibility_claudian=${compatibilityReason(state.compatibilityLayers?.claudian)}`,
    `latest_rejected_command_type=${latestRejected ? allowlisted(latestRejected.commandType, COMMAND_TYPES) : "none"}`,
    `latest_rejection_reason=${latestRejected ? allowlisted(latestRejected.errorCode, REJECTION_REASONS) : "none"}`,
    `transport_status=${state.transport?.status || "disconnected"}`,
    `readiness_status=${readiness.status}`,
    `readiness_reason=${readiness.reason_code}`,
    `mac_online=${state.presence?.mac?.status === "online"}`,
    `recovery_required=${Boolean(state.recovery?.required)}`,
    `cursor=${Number(state.relay?.appliedCursor || 0)}`,
    `epoch_hash=${digest(state.relay?.epoch)}`,
    `conversation_hash=${digest(state.activeConversationId)}`,
    `revision=${Number(conversation?.revision || 0)}`,
    `capability_mode=${capabilityMode}`,
    `active_turn_status=${activeTurn?.status || "idle"}`,
    `upload_status=${attachmentItem?.status || "none"}`
  ];
  if (layout) {
    lines.push(`layout_geometry=${JSON.stringify({
      samples: (Array.isArray(layout.samples) ? layout.samples.slice(-8) : []).map(layoutSample).filter(Boolean),
      lastFocused: layoutSample(layout.lastFocused)
    })}`);
  }
  return lines.join("\n");
}
