import { sha256 } from "../stream-normalizer.js";
import { normalizeCapabilities } from "./capabilities.js";
import { normalizeCompatibilityResult } from "../protocol/compatibility.js";

function cleanId(value, fallback = "unknown") {
  const text = String(value ?? "").slice(0, 256);
  return text || fallback;
}

const COMMAND_TRANSITIONS = {
  local_pending: new Set(["relay_accepted", "unknown", "desktop_accepted", "terminal", "rejected"]),
  relay_accepted: new Set(["desktop_accepted", "terminal", "rejected"]),
  unknown: new Set(["relay_accepted", "desktop_accepted", "terminal", "rejected"]),
  desktop_accepted: new Set(),
  terminal: new Set(),
  rejected: new Set()
};

const DESKTOP_ACCEPTED_STATUSES = new Set(["executed", "duplicate", "already_resolved"]);
const TERMINAL_STATUSES = new Set(["completed", "terminal"]);
const REJECTED_STATUSES = new Set([
  "rejected",
  "failed",
  "mac_offline",
  "session_mismatch",
  "connection_generation_mismatch",
  "expired",
  "stale_connection",
  "stale_session",
  "stale_revision",
  "stale_conversation",
  "stale_turn",
  "capability_missing",
  "delivery_conflict",
  "command_backpressure",
  "relay_shutting_down"
]);

function emptyConversation(id) {
  return {
    id,
    title: "",
    revision: 0,
    activeTurnId: null,
    turnOrder: [],
    turns: {}
  };
}

function emptyTurn(id) {
  return {
    id,
    status: "idle",
    messageOrder: [],
    messages: {},
    activityOrder: [],
    activities: {},
    toolOrder: [],
    tools: {},
    approvalOrder: [],
    approvals: {},
    artifactOrder: [],
    artifacts: {}
  };
}

function emptyMessage(id, role = "assistant", originDeliveryId = null) {
  return { id, role, originDeliveryId: originDeliveryId ? cleanId(originDeliveryId, null) : null, blockOrder: [], blocks: {} };
}

function messageIdentity(turnId, messageId) {
  return `${String(turnId)}\u0000${String(messageId)}`;
}

function orderedConversationMessages(conversation) {
  if (!conversation) return [];
  const messages = [];
  for (const turnId of conversation.turnOrder || []) {
    const turn = conversation.turns?.[turnId];
    if (!turn) continue;
    for (const messageId of turn.messageOrder || []) {
      const message = turn.messages?.[messageId];
      if (message) messages.push({ turnId, messageId, identity: messageIdentity(turnId, messageId), message });
    }
  }
  return messages;
}

function messageText(message) {
  return (message?.blockOrder || [])
    .map((blockId) => message.blocks?.[blockId])
    .filter((block) => block?.type === "text")
    .map((block) => String(block.text || ""))
    .join("");
}

function commandMatchesMessage(command, message) {
  const commandText = String(command?.text || "");
  const authoritativeText = messageText(message);
  if (!commandText) return authoritativeText.length > 0;
  return authoritativeText === commandText || authoritativeText.startsWith(`${commandText}\n\n@`);
}

export function createReplicaState(seed = {}) {
  return {
    relay: { epoch: "", appliedCursor: 0, ...(seed.relay || {}) },
    transport: { status: "disconnected", ...(seed.transport || {}) },
    presence: {
      mac: { status: "offline", sessionId: null, connectionGeneration: null },
      ...(seed.presence || {})
    },
    capabilities: normalizeCapabilities(seed.capabilities),
    compatibility: seed.compatibility || null,
    compatibilityMode: seed.compatibilityMode === true || seed.compatibility?.writable === false,
    pairing: { status: "paired", ...(seed.pairing || {}) },
    activeConversationId: seed.activeConversationId || null,
    viewingConversationId: seed.viewingConversationId || seed.activeConversationId || null,
    viewingPinned: seed.viewingPinned === true,
    conversations: seed.conversations || {},
    history: { items: [], nextPage: null, loaded: false, ...(seed.history || {}) },
    commands: seed.commands || {},
    recovery: { required: false, reason: null, requestedAtCursor: null, ...(seed.recovery || {}) },
    completionSignals: [],
    visible: seed.visible !== false
  };
}

function projectionToConversation(projection) {
  const source = projection?.conversation || {};
  const conversation = emptyConversation(cleanId(source.id, "conversation-pending"));
  conversation.title = String(source.title || "");
  conversation.revision = Math.max(0, Number(source.revision) || 0);
  for (const rawTurn of Array.isArray(projection?.turns) ? projection.turns : []) {
    const turn = emptyTurn(cleanId(rawTurn?.id, `turn-${conversation.id}`));
    turn.status = String(rawTurn?.status || "idle");
    for (const rawMessage of Array.isArray(rawTurn?.messages) ? rawTurn.messages : []) {
      const message = emptyMessage(
        cleanId(rawMessage?.id, `message-${turn.id}`),
        rawMessage?.role || "assistant",
        rawMessage?.origin_delivery_id || rawMessage?.originDeliveryId || null
      );
      for (const rawBlock of Array.isArray(rawMessage?.blocks) ? rawMessage.blocks : []) {
        const id = cleanId(rawBlock?.id, `block-${message.id}`);
        message.blockOrder.push(id);
        message.blocks[id] = { ...rawBlock, id };
      }
      turn.messageOrder.push(message.id);
      turn.messages[message.id] = message;
    }
    for (const rawActivity of Array.isArray(rawTurn?.current_operation?.activities) ? rawTurn.current_operation.activities : []) {
      const id = cleanId(rawActivity?.id, `activity-${turn.id}-${turn.activityOrder.length}`);
      if (!turn.activities[id]) turn.activityOrder.push(id);
      turn.activities[id] = { ...rawActivity, id };
    }
    for (const rawTool of Array.isArray(rawTurn?.current_operation?.tools) ? rawTurn.current_operation.tools : []) {
      const id = cleanId(rawTool?.id, `tool-${turn.id}-${turn.toolOrder.length}`);
      if (!turn.tools[id]) turn.toolOrder.push(id);
      turn.tools[id] = { ...rawTool, id, type: "tool" };
    }
    for (const rawApproval of Array.isArray(rawTurn?.approvals) ? rawTurn.approvals : []) {
      const id = cleanId(rawApproval?.approval_id || rawApproval?.id, `approval-${turn.id}-${turn.approvalOrder.length}`);
      if (!turn.approvals[id]) turn.approvalOrder.push(id);
      turn.approvals[id] = { ...rawApproval, id, approval_id: id };
    }
    for (const rawArtifact of Array.isArray(rawTurn?.artifacts) ? rawTurn.artifacts : []) {
      const id = cleanId(rawArtifact?.artifact_id || rawArtifact?.id, `artifact-${turn.id}-${turn.artifactOrder.length}`);
      if (!turn.artifacts[id]) turn.artifactOrder.push(id);
      turn.artifacts[id] = { ...rawArtifact, id, artifact_id: id };
    }
    conversation.turnOrder.push(turn.id);
    conversation.turns[turn.id] = turn;
    conversation.activeTurnId = turn.id;
  }
  return conversation;
}

function conversationToProjection(conversation) {
  return {
    conversation: { id: conversation.id, revision: conversation.revision, title: conversation.title || "" },
    turns: conversation.turnOrder.map((turnId) => {
      const turn = conversation.turns[turnId];
      return {
        id: turn.id,
        status: turn.status,
        messages: turn.messageOrder.map((messageId) => {
          const message = turn.messages[messageId];
          return {
            id: message.id,
            role: message.role,
            ...(message.originDeliveryId ? { origin_delivery_id: message.originDeliveryId } : {}),
            blocks: message.blockOrder.map((blockId) => message.blocks[blockId])
          };
        }),
        current_operation: {
          activities: turn.activityOrder.map((id) => turn.activities[id]).filter(Boolean),
          tools: (turn.toolOrder || []).map((id) => turn.tools?.[id]).filter(Boolean)
        },
        approvals: turn.approvalOrder.map((id) => turn.approvals[id]).filter(Boolean),
        artifacts: turn.artifactOrder.map((id) => turn.artifacts[id]).filter(Boolean)
      };
    })
  };
}

function mergeKeyframePages(pages) {
  const projections = pages.map((page) => page?.payload?.projection).filter(Boolean);
  if (projections.length === 1) return projections[0];
  const first = projections[0] || { conversation: {}, turns: [] };
  const turns = new Map();
  for (const projection of projections) {
    for (const turn of projection.turns || []) turns.set(String(turn.id), turn);
  }
  return { conversation: first.conversation, turns: Array.from(turns.values()) };
}

export class MobileReplica {
  constructor(seed = {}) {
    this.state = createReplicaState(seed);
    this.keyframes = new Map();
    this.completionSeen = new Set();
    this.listeners = new Set();
    this.notificationDepth = 0;
    this.notificationPending = false;
  }

  subscribe(listener) {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  notify(reason) {
    if (this.notificationDepth > 0) {
      this.notificationPending = true;
      return;
    }
    for (const listener of this.listeners) listener(this.state, reason);
  }

  flushNotifications(reason = "batch") {
    if (!this.notificationPending || this.notificationDepth > 0) return;
    this.notificationPending = false;
    for (const listener of this.listeners) listener(this.state, reason);
  }

  setVisible(visible) {
    this.state.visible = Boolean(visible);
  }

  setPairingStatus(status) {
    const normalized = status === "required" ? "required" : "paired";
    if (this.state.pairing?.status === normalized) return false;
    this.state.pairing = { status: normalized };
    this.notify("pairing");
    return true;
  }

  selectConversationForViewing(conversationId, { pinned = true } = {}) {
    const id = cleanId(conversationId, "");
    if (!id || !this.state.conversations[id]) return false;
    this.state.viewingConversationId = id;
    this.state.viewingPinned = Boolean(pinned && id !== this.state.activeConversationId);
    this.notify("history_view");
    return true;
  }

  drainCompletionSignals() {
    return this.state.completionSignals.splice(0, this.state.completionSignals.length);
  }

  claimRestoredDrafts(limit = Number.POSITIVE_INFINITY) {
    const drafts = [];
    const available = Object.values(this.state.commands)
      .filter((command) => command.preserveDraft && !command.draftRestored && command.text)
      .sort((a, b) => Number(a.createdAt || 0) - Number(b.createdAt || 0));
    for (const command of available) {
      if (drafts.length >= Math.max(0, Number(limit) || 0)) break;
      if (command.preserveDraft && !command.draftRestored && command.text) {
        command.draftRestored = true;
        drafts.push(command.text);
      }
    }
    return drafts;
  }

  beginCommand({ deliveryId, commandType, text = "", createdAt = Date.now() }) {
    const normalizedDeliveryId = String(deliveryId || "");
    const existingCommand = this.state.commands[normalizedDeliveryId];
    if (existingCommand) return existingCommand;
    const conversationId = this.state.activeConversationId || null;
    const authoritativeMessages = orderedConversationMessages(conversationId ? this.state.conversations[conversationId] : null);
    this.state.commands[normalizedDeliveryId] = {
      deliveryId: normalizedDeliveryId,
      commandType,
      status: "local_pending",
      text,
      createdAt,
      conversationId,
      authoritativeMessageCount: authoritativeMessages.length,
      baselineMatchingUserCount: commandType === "message.submit" && String(text || "")
        ? authoritativeMessages.filter(({ message }) => message.role === "user" && commandMatchesMessage({ text }, message)).length
        : null,
      preserveDraft: false
    };
    this.notify("command");
    return this.state.commands[normalizedDeliveryId];
  }

  requireReset(reason, cursor = this.state.relay.appliedCursor) {
    this.state.recovery = { required: true, reason: String(reason || "reset_required"), requestedAtCursor: cursor };
    this.notify("recovery");
    return { reset: true, reason: this.state.recovery.reason };
  }

  async applyFrame(frame) {
    if (!frame || typeof frame !== "object") return { ignored: true, reason: "invalid_frame" };
    if (frame.type === "authenticated") {
      this.state.transport.status = "connected";
      if (frame.compatibility) {
        this.state.compatibility = normalizeCompatibilityResult(frame.compatibility);
        this.state.compatibilityMode = this.state.compatibility.writable === false;
      }
      this.notify("transport");
      return { applied: true };
    }
    if (frame.type === "connection.changed") {
      this.state.transport.status = String(frame.status || "disconnected");
      if (this.state.transport.status !== "connected") this.markUnacceptedCommandsUnknown("connection_lost");
      this.notify("transport");
      return { applied: true };
    }
    if (frame.type === "event.batch") {
      const results = [];
      this.notificationDepth += 1;
      try {
        for (const child of Array.isArray(frame.events) ? frame.events : []) results.push(await this.applyFrame(child));
      } finally {
        this.notificationDepth -= 1;
        this.flushNotifications("batch");
      }
      return { batch: true, results };
    }
    if (frame.type === "reset_required") {
      if (frame.epoch) this.state.relay.epoch = String(frame.epoch);
      return this.requireReset(frame.reason || "reset_required", Number(frame.high_water) || this.state.relay.appliedCursor);
    }
    if (frame.type === "presence.changed") {
      if (frame.role === "mac") {
        this.state.presence.mac = {
          status: frame.status === "online" ? "online" : "offline",
          sessionId: frame.mac_session_id || null,
          connectionGeneration: Number(frame.mac_connection_generation) || null,
          reason: frame.reason === "vault_closed" ? "vault_closed" : null
        };
        if (frame.compatibility) {
          this.state.compatibility = normalizeCompatibilityResult(frame.compatibility);
          this.state.compatibilityMode = this.state.compatibility.writable === false;
        }
        if (frame.status !== "online") this.rejectUnacceptedCommands("mac_offline");
        this.notify("presence");
      }
      return { applied: true };
    }
    if (["relay.accepted", "command.rejected", "command.receipt", "command.unknown"].includes(frame.type)) {
      return this.applyCommandFrame(frame);
    }
    if (frame.type !== "event.committed") return { ignored: true, reason: "unknown_frame" };

    const epoch = String(frame.epoch || "");
    const cursor = Number(frame.cursor) || 0;
    if (!epoch || cursor < 1 || !frame.event) return this.requireReset("invalid_committed_frame");
    if (this.state.relay.epoch && this.state.relay.epoch !== epoch) return this.requireReset("epoch_mismatch", cursor);
    this.state.relay.epoch = epoch;
    if (cursor <= this.state.relay.appliedCursor) return { ignored: true, reason: "duplicate_cursor" };
    if (this.state.recovery.required && !["keyframe.page", "keyframe.final"].includes(frame.event.event_type)) {
      return { ignored: true, reason: "waiting_for_keyframe" };
    }

    const result = await this.applyEvent(frame.event, { replayed: frame.replayed === true });
    if (result.reset) return result;
    if (result.advanceCursor !== false) this.state.relay.appliedCursor = cursor;
    this.notify("event");
    return { applied: true, cursor, ...result };
  }

  applyCommandFrame(frame) {
    const receipt = frame.type === "command.receipt" ? (frame.receipt || {}) : frame;
    const deliveryId = String(frame.delivery_id || receipt.delivery_id || "");
    if (!deliveryId) return { ignored: true, reason: "missing_delivery_id" };
    const command = this.state.commands[deliveryId] || {
      deliveryId,
      commandType: "unknown",
      status: "local_pending",
      text: "",
      createdAt: Date.now(),
      preserveDraft: false
    };
    const status = String(receipt.status || "");
    let nextStatus = "unknown";
    if (frame.type === "relay.accepted") nextStatus = "relay_accepted";
    else if (frame.type === "command.rejected" || REJECTED_STATUSES.has(status)) nextStatus = "rejected";
    else if (frame.type === "command.unknown" || status === "delivery_unknown" || status === "unknown") nextStatus = "unknown";
    else if (DESKTOP_ACCEPTED_STATUSES.has(status)) nextStatus = "desktop_accepted";
    else if (TERMINAL_STATUSES.has(status)) nextStatus = "terminal";
    this.transitionCommand(command, nextStatus, {
      errorCode: receipt.error_code || frame.error || (nextStatus === "rejected" ? status || "rejected" : null),
      desktopStatus: nextStatus === "desktop_accepted" ? status : null
    });
    if (receipt.capability) command.capability = cleanId(receipt.capability, "unknown");
    this.state.commands[deliveryId] = command;
    if (String(command.commandType || "").startsWith("history.") && Array.isArray(receipt.items)) {
      const items = receipt.items.map((item) => ({
        ...item,
        conversation_id: cleanId(item?.conversation_id || item?.id, "")
      })).filter((item) => item.conversation_id);
      this.state.history = { items, nextPage: receipt.next_page ?? null, loaded: true };
      for (const item of items) {
        const conversation = this.state.conversations[item.conversation_id];
        if (conversation) conversation.title = String(item.title || conversation.title || "");
      }
      const activeId = cleanId(receipt.active_conversation_id, "");
      if (activeId) {
        this.ensureConversation(activeId);
        this.state.activeConversationId = activeId;
        if (["history.new", "history.select"].includes(command.commandType)) {
          this.state.viewingConversationId = activeId;
          this.state.viewingPinned = false;
        }
      }
      if (receipt.capabilities && typeof receipt.capabilities === "object") {
        this.state.capabilities = normalizeCapabilities({ ...this.state.capabilities, ...receipt.capabilities });
      }
    }
    this.notify("command");
    return { applied: true, command };
  }

  transitionCommand(command, nextStatus, { errorCode = null, desktopStatus = null } = {}) {
    const currentStatus = COMMAND_TRANSITIONS[command.status] ? command.status : "unknown";
    if (currentStatus === nextStatus || !COMMAND_TRANSITIONS[currentStatus].has(nextStatus)) return false;
    command.status = nextStatus;
    if (nextStatus === "rejected") {
      command.errorCode = errorCode || "rejected";
      command.preserveDraft = command.commandType === "message.submit";
      return true;
    }
    command.preserveDraft = false;
    delete command.errorCode;
    delete command.ambiguityReason;
    if (nextStatus === "unknown") {
      command.ambiguityReason = errorCode || "delivery_unknown";
    } else if (nextStatus === "desktop_accepted") {
      command.desktopStatus = desktopStatus || "executed";
    }
    return true;
  }

  markCommandUnknown(deliveryId, reason = "delivery_unknown") {
    const command = this.state.commands[String(deliveryId || "")];
    if (!command) return null;
    if (this.transitionCommand(command, "unknown", { errorCode: reason })) this.notify("command");
    return command;
  }

  markUnacceptedCommandsUnknown(reason) {
    for (const command of Object.values(this.state.commands)) {
      if (command.status === "local_pending") {
        this.transitionCommand(command, "unknown", { errorCode: reason });
      }
    }
  }

  rejectUnacceptedCommands(reason) {
    for (const command of Object.values(this.state.commands)) {
      if (["local_pending", "relay_accepted"].includes(command.status)) {
        this.transitionCommand(command, "rejected", { errorCode: reason });
      }
    }
  }

  ensureConversation(id) {
    const conversationId = cleanId(id, "conversation-pending");
    if (!this.state.conversations[conversationId]) this.state.conversations[conversationId] = emptyConversation(conversationId);
    return this.state.conversations[conversationId];
  }

  ensureTurn(conversation, id) {
    const turnId = cleanId(id, `turn-${conversation.id}`);
    if (!conversation.turns[turnId]) {
      conversation.turns[turnId] = emptyTurn(turnId);
      conversation.turnOrder.push(turnId);
    }
    conversation.activeTurnId = turnId;
    return conversation.turns[turnId];
  }

  ensureMessage(turn, id, role = "assistant") {
    const messageId = cleanId(id, `message-${turn.id}`);
    if (!turn.messages[messageId]) {
      turn.messages[messageId] = emptyMessage(messageId, role);
      turn.messageOrder.push(messageId);
    }
    return turn.messages[messageId];
  }

  async applyEvent(event, { replayed = false } = {}) {
    const type = String(event?.event_type || "");
    const entity = event?.entity || {};
    const payload = event?.payload || {};
    const revision = Math.max(0, Number(event?.revision) || 0);
    if (type === "keyframe.page") {
      const id = cleanId(payload.keyframe_id, "keyframe");
      const staging = this.keyframes.get(id) || { pageCount: Number(payload.page_count) || 0, pages: new Map() };
      if (staging.pageCount !== Number(payload.page_count) || Number(payload.page_index) >= staging.pageCount) return this.requireReset("invalid_keyframe_page");
      staging.pages.set(Number(payload.page_index), event);
      this.keyframes.set(id, staging);
      return { advanceCursor: false, staged: true };
    }
    if (type === "keyframe.final") return this.applyKeyframeFinal(event);

    const conversation = this.ensureConversation(entity.conversation_id);
    if (revision < conversation.revision) return { ignored: true, reason: "stale_revision" };
    const turn = entity.turn_id ? this.ensureTurn(conversation, entity.turn_id) : null;

    if (type === "capability.state") {
      this.state.capabilities = normalizeCapabilities({
        ...this.state.capabilities,
        semantic_stream: payload.mode === "streaming",
        steer: payload.supports_turn_steer,
        history_list: payload.supports_history,
        history_select: payload.supports_history,
        history_new: payload.supports_history_new,
        history_rename: payload.supports_history_rename,
        history_archive: payload.supports_history_archive,
        stop: payload.supports_stop,
        approval: payload.supports_approval
      });
      this.state.compatibilityMode = payload.mode === "compatibility";
      if (typeof payload.writable === "boolean") {
        this.state.compatibility = {
          writable: payload.writable,
          mode: payload.writable ? "streaming" : "read_only",
          reason: String(payload.reason || (payload.writable ? "ready" : "compatibility_mismatch")),
          current_version: payload.current_version || null,
          required_version: payload.required_version || null,
          missing_capabilities: Array.isArray(payload.missing_capabilities) ? [...payload.missing_capabilities] : [],
          remediation: payload.remediation || null
        };
      }
    } else if (type === "conversation.activated") {
      conversation.title = String(payload.title || conversation.title || "");
      this.state.activeConversationId = conversation.id;
      this.state.viewingConversationId = conversation.id;
      this.state.viewingPinned = false;
    } else if (type === "history.list") {
      this.state.history = {
        items: (Array.isArray(payload.items) ? payload.items : []).map((item) => ({
          ...item,
          conversation_id: cleanId(item?.conversation_id || item?.id, "")
        })).filter((item) => item.conversation_id),
        nextPage: payload.next_page ?? null,
        loaded: true
      };
    } else if (type === "turn.started" && turn) {
      turn.status = "running";
      turn.activityOrder = [];
      turn.activities = {};
      turn.toolOrder = [];
      turn.tools = {};
      if (!this.state.activeConversationId) this.state.activeConversationId = conversation.id;
      if (!this.state.viewingConversationId) this.state.viewingConversationId = this.state.activeConversationId;
    } else if (type === "activity.updated" && turn) {
      const id = cleanId(entity.block_id || `${payload.stage || "activity"}-${turn.activityOrder.length}`);
      if (!turn.activities[id]) turn.activityOrder.push(id);
      turn.activities[id] = { id, ...payload };
    } else if (["tool.started", "tool.completed"].includes(type) && turn) {
      const id = cleanId(entity.block_id, `tool-${payload.tool_name || turn.toolOrder.length}`);
      if (!turn.tools[id]) turn.toolOrder.push(id);
      turn.tools[id] = {
        id,
        type: "tool",
        name: payload.tool_name,
        label: payload.label,
        status: payload.status,
        duration_ms: payload.duration_ms,
        summary: payload.summary
      };
    } else if (["text.delta", "text.replace"].includes(type) && turn) {
      const message = this.ensureMessage(turn, entity.message_id);
      const id = cleanId(entity.block_id, `text-${message.id}`);
      const block = message.blocks[id] || { id, type: "text", text: "", revision: 0 };
      if (!message.blocks[id]) message.blockOrder.push(id);
      if (type === "text.delta") {
        if (Number(payload.base_revision) !== conversation.revision || Number(payload.offset) !== block.text.length || revision !== conversation.revision + 1) {
          return this.requireReset("text_delta_mismatch");
        }
        block.text += String(payload.text || "");
      } else block.text = String(payload.text || "");
      block.revision = revision;
      message.blocks[id] = block;
    } else if (["approval.requested", "approval.resolved"].includes(type) && turn) {
      const id = cleanId(payload.approval_id || entity.approval_id, `approval-${turn.id}`);
      if (!turn.approvals[id]) turn.approvalOrder.push(id);
      turn.approvals[id] = { id, ...turn.approvals[id], ...payload };
    } else if (type === "artifact.available" && turn) {
      const id = cleanId(payload.artifact_id, `artifact-${turn.id}`);
      if (!turn.artifacts[id]) turn.artifactOrder.push(id);
      turn.artifacts[id] = { id, ...payload };
    } else if (["turn.completed", "turn.interrupted", "turn.failed"].includes(type) && turn) {
      turn.status = type === "turn.completed" ? "completed" : type === "turn.interrupted" ? "interrupted" : "failed";
      const completionIdentity = `${conversation.id}\u0000${turn.id}`;
      if (type === "turn.completed" && !replayed && this.state.visible && !this.completionSeen.has(completionIdentity)) {
        this.completionSeen.add(completionIdentity);
        this.state.completionSignals.push({ turnId: turn.id, conversationId: conversation.id });
      }
    } else if (type === "command.receipt") {
      this.applyCommandFrame({ type: "command.receipt", receipt: payload });
    }
    conversation.revision = Math.max(conversation.revision, revision);
    return { eventType: type };
  }

  async applyKeyframeFinal(event) {
    const payload = event.payload || {};
    const id = cleanId(payload.keyframe_id, "keyframe");
    const staging = this.keyframes.get(id);
    if (!staging || staging.pageCount !== Number(payload.page_count) || staging.pages.size !== staging.pageCount) return this.requireReset("incomplete_keyframe");
    const pages = Array.from(staging.pages.entries()).sort(([a], [b]) => a - b).map(([, page]) => page);
    const projection = mergeKeyframePages(pages);
    let checksum;
    try { checksum = await sha256(projection); }
    catch { return this.requireReset("keyframe_checksum_unavailable"); }
    if (checksum !== payload.checksum) return this.requireReset("keyframe_checksum_mismatch");
    const conversation = projectionToConversation(projection);
    this.state.conversations = { ...this.state.conversations, [conversation.id]: conversation };
    this.state.activeConversationId = conversation.id;
    if (!this.state.viewingPinned || !this.state.conversations[this.state.viewingConversationId]) {
      this.state.viewingConversationId = conversation.id;
      this.state.viewingPinned = false;
    }
    this.state.recovery = { required: false, reason: null, requestedAtCursor: null };
    this.keyframes.delete(id);

    // Older desktop captures do not carry origin_delivery_id and may rewrite
    // every message id during recovery. Count matching user prompts instead of
    // trusting cross-keyframe ids, then claim only the next matching occurrence.
    const authoritativeMessages = orderedConversationMessages(conversation);
    const claimedMessageIds = new Set(
      authoritativeMessages
        .filter(({ message }) => message.originDeliveryId)
        .map(({ identity }) => identity)
    );
    const pendingCommands = Object.values(this.state.commands)
      .filter((command) => command.commandType === "message.submit"
        && command.reconciled !== true
        && command.conversationId === conversation.id)
      .sort((a, b) => Number(a.createdAt || 0) - Number(b.createdAt || 0));
    for (const command of pendingCommands) {
      if (!String(command.text || "") || !Number.isInteger(command.baselineMatchingUserCount)) continue;
      const matchingUsers = authoritativeMessages.filter(({ message }) =>
        message.role === "user" && commandMatchesMessage(command, message)
      );
      const match = matchingUsers.slice(command.baselineMatchingUserCount).find(({ identity, message }) =>
        !message.originDeliveryId && !claimedMessageIds.has(identity)
      );
      if (!match) continue;
      match.message.originDeliveryId = command.deliveryId;
      claimedMessageIds.add(match.identity);
    }

    for (const turnId of conversation.turnOrder) {
      const turn = conversation.turns[turnId];
      for (const messageId of turn.messageOrder) {
        const message = turn.messages[messageId];
        if (!message.originDeliveryId) continue;
        const command = this.state.commands[message.originDeliveryId];
        if (command) {
          const transitioned = this.transitionCommand(command, "desktop_accepted", { desktopStatus: "keyframe_origin" });
          if (transitioned || ["desktop_accepted", "terminal"].includes(command.status)) command.reconciled = true;
        }
      }
    }
    return { keyframe: true };
  }

  projection(conversationId = this.state.activeConversationId) {
    const conversation = conversationId ? this.state.conversations[conversationId] : null;
    return conversation ? conversationToProjection(conversation) : null;
  }
}
