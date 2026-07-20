function digest(value) {
  const text = String(value || "");
  let hash = 0x811c9dc5;
  for (let index = 0; index < text.length; index += 1) {
    hash ^= text.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return text ? hash.toString(16).padStart(8, "0") : "none";
}

export function buildDiagnosticReport(state, attachment = null, now = new Date()) {
  const conversation = state.conversations?.[state.activeConversationId] || null;
  const activeTurn = conversation?.activeTurnId ? conversation.turns?.[conversation.activeTurnId] : null;
  const attachmentItem = Array.isArray(attachment) ? attachment[0] : attachment;
  const capabilityMode = state.capabilities?.semantic_stream === true
    ? "streaming"
    : state.capabilities?.mode || "unknown";
  const lines = [
    "Claudian Remote v2 mobile report",
    `time=${now.toISOString()}`,
    "protocol=claudian.remote.v2",
    `transport_status=${state.transport?.status || "disconnected"}`,
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
  return lines.join("\n");
}
