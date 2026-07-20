const STORAGE_VERSION = 1;

export function recoveryMetadata(state) {
  return {
    version: STORAGE_VERSION,
    epoch: String(state?.relay?.epoch || ""),
    applied_cursor: Math.max(0, Number(state?.relay?.appliedCursor) || 0),
    active_conversation_id: state?.activeConversationId ? String(state.activeConversationId) : null
  };
}

export function restoreRecoveryMetadata(value) {
  if (!value || value.version !== STORAGE_VERSION) return { relay: { epoch: "", appliedCursor: 0 }, activeConversationId: null };
  return {
    relay: { epoch: String(value.epoch || ""), appliedCursor: Math.max(0, Number(value.applied_cursor) || 0) },
    activeConversationId: value.active_conversation_id ? String(value.active_conversation_id) : null
  };
}
