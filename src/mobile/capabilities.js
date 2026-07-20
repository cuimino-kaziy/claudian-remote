const CAPABILITY_KEYS = [
  "semantic_stream",
  "completion_barrier",
  "stop",
  "steer",
  "approval",
  "history_list",
  "history_select"
];

export function normalizeCapabilities(value = {}) {
  const source = value && typeof value === "object" ? value : {};
  return Object.fromEntries(CAPABILITY_KEYS.map((key) => [key, source[key] === true]));
}

export function isInteractiveReplica(state) {
  return state?.transport?.status === "connected"
    && state?.presence?.mac?.status === "online"
    && state?.compatibility?.writable !== false
    && state?.capabilities?.semantic_stream === true
    && state?.recovery?.required !== true;
}

export function controlAvailability(state) {
  const interactive = isInteractiveReplica(state);
  const turn = state?.activeConversationId
    ? state.conversations?.[state.activeConversationId]?.activeTurnId
    : null;
  const current = turn && state.conversations[state.activeConversationId]?.turns?.[turn];
  return {
    send: interactive,
    stop: interactive && state.capabilities.stop === true && current?.status === "running",
    steer: interactive && state.capabilities.steer === true && current?.status === "running",
    approval: interactive && state.capabilities.approval === true,
    history: interactive && state.capabilities.history_list === true,
    historySelect: interactive && state.capabilities.history_select === true && current?.status !== "running"
  };
}
