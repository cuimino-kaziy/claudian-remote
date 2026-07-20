const STORAGE_VERSION = 1;
const OFFLINE_CACHE_VERSION = 1;
export const DEFAULT_OFFLINE_CACHE_BYTES = 2 * 1024 * 1024;

function encodedBytes(value) {
  return new TextEncoder().encode(JSON.stringify(value)).byteLength;
}

function cleanText(value, maxLength = 256 * 1024) {
  return String(value || "").slice(0, maxLength);
}

function cachedMessage(message) {
  const blocks = {};
  const blockOrder = [];
  for (const blockId of message?.blockOrder || []) {
    const block = message?.blocks?.[blockId];
    if (block?.type !== "text") continue;
    const id = cleanText(block.id || blockId, 256);
    blockOrder.push(id);
    blocks[id] = { id, type: "text", text: cleanText(block.text) };
  }
  return {
    id: cleanText(message?.id, 256),
    role: message?.role === "user" ? "user" : "assistant",
    blockOrder,
    blocks
  };
}

function cachedTurn(turn) {
  const messages = {};
  const messageOrder = [];
  for (const messageId of turn?.messageOrder || []) {
    const message = cachedMessage(turn?.messages?.[messageId]);
    if (!message.blockOrder.length) continue;
    const id = message.id || cleanText(messageId, 256);
    message.id = id;
    messageOrder.push(id);
    messages[id] = message;
  }
  return {
    id: cleanText(turn?.id, 256),
    status: turn?.status === "completed" ? "completed" : "idle",
    messageOrder,
    messages,
    activityOrder: [], activities: {}, toolOrder: [], tools: {},
    approvalOrder: [], approvals: {}, artifactOrder: [], artifacts: {}
  };
}

function cachedConversation(conversation, fallbackId) {
  const turns = {};
  const turnOrder = [];
  for (const turnId of conversation?.turnOrder || []) {
    const turn = cachedTurn(conversation?.turns?.[turnId]);
    const id = turn.id || cleanText(turnId, 256);
    turn.id = id;
    turnOrder.push(id);
    turns[id] = turn;
  }
  const id = cleanText(conversation?.id || fallbackId, 256);
  return {
    id,
    title: cleanText(conversation?.title, 512),
    revision: Math.max(0, Number(conversation?.revision) || 0),
    activeTurnId: null,
    turnOrder,
    turns
  };
}

function trimOldestCachedContent(conversation) {
  const messageCount = conversation.turnOrder.reduce(
    (total, turnId) => total + (conversation.turns[turnId]?.messageOrder?.length || 0),
    0
  );
  for (const turnId of [...conversation.turnOrder]) {
    const turn = conversation.turns[turnId];
    if (!turn?.messageOrder?.length) {
      conversation.turnOrder = conversation.turnOrder.filter((id) => id !== turnId);
      delete conversation.turns[turnId];
      return true;
    }
    const messageId = turn.messageOrder[0];
    if (messageCount > 1) {
      turn.messageOrder.shift();
      delete turn.messages[messageId];
      if (!turn.messageOrder.length) {
        conversation.turnOrder = conversation.turnOrder.filter((id) => id !== turnId);
        delete conversation.turns[turnId];
      }
      return true;
    }
    const message = turn.messages[messageId];
    for (const blockId of [...(message?.blockOrder || [])].reverse()) {
      const block = message.blocks?.[blockId];
      if (block?.type !== "text" || block.text.length <= 64) continue;
      block.text = block.text.slice(-Math.max(64, Math.floor(block.text.length / 2)));
      return true;
    }
    return false;
  }
  return false;
}

function fitCachedConversation(cache, conversation, { activeId, updatedAt, limit }) {
  for (let attempts = 0; attempts < 128; attempts += 1) {
    const tentative = {
      ...cache,
      active_conversation_id: activeId,
      conversations: { ...cache.conversations, [conversation.id]: conversation },
      history: {
        ...cache.history,
        items: [...cache.history.items, { id: conversation.id, title: conversation.title, updated_at: updatedAt }]
      }
    };
    if (encodedBytes(tentative) <= limit) return conversation;
    if (!trimOldestCachedContent(conversation)) return null;
  }
  return null;
}

function cacheBase(now) {
  return {
    version: OFFLINE_CACHE_VERSION,
    stored_at: Number(now()),
    active_conversation_id: null,
    conversations: {},
    history: { items: [], nextPage: null, loaded: true }
  };
}

export function createOfflineReplicaCache(state, { maxBytes = DEFAULT_OFFLINE_CACHE_BYTES, now = Date.now } = {}) {
  const limit = Math.max(512, Number(maxBytes) || DEFAULT_OFFLINE_CACHE_BYTES);
  const cache = cacheBase(now);
  const activeId = state?.activeConversationId ? String(state.activeConversationId) : null;
  const historyItems = Array.isArray(state?.history?.items) ? state.history.items : [];
  const updatedAt = new Map(historyItems.map((item) => [String(item?.id || item?.conversation_id || ""), Number(item?.updated_at || item?.updatedAt || 0)]));
  const ids = Object.keys(state?.conversations || {}).sort((left, right) => {
    if (left === activeId) return -1;
    if (right === activeId) return 1;
    return (updatedAt.get(right) || 0) - (updatedAt.get(left) || 0);
  });

  for (const id of ids) {
    const conversation = fitCachedConversation(cache, cachedConversation(state.conversations[id], id), {
      activeId,
      updatedAt: updatedAt.get(id) || 0,
      limit
    });
    if (conversation) {
      cache.active_conversation_id = activeId;
      cache.conversations[conversation.id] = conversation;
      cache.history.items.push({ id: conversation.id, title: conversation.title, updated_at: updatedAt.get(id) || 0 });
    }
  }
  if (!cache.conversations[activeId]) cache.active_conversation_id = Object.keys(cache.conversations)[0] || null;
  return cache;
}

export function restoreOfflineReplicaCache(value) {
  if (!value || value.version !== OFFLINE_CACHE_VERSION || typeof value.conversations !== "object") {
    return {
      transport: { status: "disconnected" },
      presence: { mac: { status: "offline", sessionId: null, connectionGeneration: null } },
      activeConversationId: null,
      conversations: {},
      history: { items: [], nextPage: null, loaded: false },
      commands: {}
    };
  }
  return {
    transport: { status: "disconnected" },
    presence: { mac: { status: "offline", sessionId: null, connectionGeneration: null } },
    activeConversationId: value.active_conversation_id && value.conversations[value.active_conversation_id]
      ? String(value.active_conversation_id)
      : Object.keys(value.conversations)[0] || null,
    conversations: value.conversations,
    history: { items: Array.isArray(value.history?.items) ? value.history.items : [], nextPage: null, loaded: true },
    commands: {}
  };
}

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
