const PROTOCOL = "claudian.remote.v2";

export function createDeliveryId(randomUUID = globalThis.crypto?.randomUUID?.bind(globalThis.crypto)) {
  return `mobile-${randomUUID ? randomUUID() : `${Date.now()}-${Math.random().toString(36).slice(2)}`}`;
}

export function buildCommand(state, commandType, payload = {}, { now = () => Date.now(), randomUUID, deliveryId } = {}) {
  const mac = state?.presence?.mac || {};
  const conversation = state?.activeConversationId ? state.conversations?.[state.activeConversationId] : null;
  if (mac.status !== "online" || !mac.sessionId || !mac.connectionGeneration) throw new Error("mac_offline");
  if (state?.compatibility?.writable === false) throw new Error("compatibility_mismatch");
  if (!conversation) throw new Error("conversation_unavailable");
  const turnId = conversation.activeTurnId || undefined;
  const target = { conversation_id: conversation.id };
  if (turnId) target.turn_id = turnId;
  if (payload.approval_id) target.approval_id = payload.approval_id;
  const cleanPayload = { ...payload };
  return {
    protocol: PROTOCOL,
    kind: "command",
    command_type: commandType,
    delivery_id: String(deliveryId || createDeliveryId(randomUUID)),
    mac_session_id: mac.sessionId,
    mac_connection_generation: mac.connectionGeneration,
    expires_at: new Date(now() + 30_000).toISOString(),
    expected_revision: conversation.revision,
    target,
    payload: cleanPayload
  };
}
