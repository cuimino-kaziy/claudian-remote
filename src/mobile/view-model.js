import { controlAvailability } from "./capabilities.js";
import { deriveReadiness } from "./readiness.js";

export const MOBILE_HEADER_MAX_PX = 56;
export const AUTO_SCROLL_THRESHOLD_PX = 96;

export function shouldFollowBottom({ scrollHeight = 0, clientHeight = 0, scrollTop = 0 }, threshold = AUTO_SCROLL_THRESHOLD_PX) {
  return scrollHeight - clientHeight - scrollTop <= threshold;
}

function messageText(message) {
  return message.blockOrder
    .map((id) => message.blocks[id])
    .filter((block) => block?.type === "text")
    .map((block) => block.text || "")
    .join("");
}

export function activeConversationModel(state) {
  const viewedId = state.viewingConversationId && state.conversations?.[state.viewingConversationId]
    ? state.viewingConversationId
    : state.activeConversationId;
  const conversation = viewedId ? state.conversations[viewedId] : null;
  const executionConversation = state.activeConversationId ? state.conversations[state.activeConversationId] : null;
  const executionTurn = executionConversation?.activeTurnId
    ? executionConversation.turns?.[executionConversation.activeTurnId]
    : null;
  const turns = conversation ? conversation.turnOrder.map((id) => conversation.turns[id]).filter(Boolean) : [];
  const messages = [];
  for (const turn of turns) {
    for (const messageId of turn.messageOrder) {
      const message = turn.messages[messageId];
      messages.push({
        key: message.originDeliveryId ? `delivery:${message.originDeliveryId}` : `message:${turn.id}:${message.id}`,
        turnId: turn.id,
        id: message.id,
        role: message.role || "assistant",
        text: messageText(message),
        blocks: message.blockOrder.map((id) => message.blocks[id]).filter(Boolean)
      });
    }
  }
  const pendingCommands = Object.values(state.commands || {})
    .filter((command) => command.commandType === "message.submit"
      && command.status !== "reconciled"
      && command.reconciled !== true
      && (!command.conversationId || command.conversationId === conversation?.id))
    .sort((a, b) => {
      const positionDifference = Number(a.authoritativeMessageCount ?? messages.length) - Number(b.authoritativeMessageCount ?? messages.length);
      return positionDifference || Number(a.createdAt || 0) - Number(b.createdAt || 0);
    });
  let inserted = 0;
  for (const command of pendingCommands) {
    const position = Math.max(0, Math.min(Number(command.authoritativeMessageCount ?? messages.length), messages.length));
    messages.splice(Math.min(position + inserted, messages.length), 0, {
      key: `delivery:${command.deliveryId}`,
      turnId: null,
      id: command.deliveryId,
      role: "user",
      text: command.text,
      blocks: [{ id: `text-${command.deliveryId}`, type: "text", text: command.text }],
      deliveryStatus: command.status,
      deliveryError: command.errorCode || null
    });
    inserted += 1;
  }
  return {
    id: conversation?.id || null,
    title: conversation?.title || "Claudian",
    revision: conversation?.revision || 0,
    turns,
    messages,
    currentTurn: conversation?.activeTurnId ? conversation.turns[conversation.activeTurnId] : null,
    executionConversationId: executionConversation?.id || null,
    executionTurn,
    browsingHistory: Boolean(conversation?.id && executionConversation?.id && conversation.id !== executionConversation.id),
    controls: controlAvailability(state),
    macOnline: state.transport?.status === "connected" && state.presence?.mac?.status === "online",
    transportStatus: state.transport?.status || "disconnected",
    compatibilityMode: state.compatibilityMode === true,
    recovering: state.recovery?.required === true,
    readiness: deriveReadiness(state)
  };
}

export function currentOperationModel(turn) {
  if (!turn) return { running: false, entries: [] };
  const entriesById = new Map();
  for (const id of turn.activityOrder) {
    const entry = turn.activities[id];
    if (entry) entriesById.set(entry.id || id, entry);
  }
  for (const id of turn.toolOrder || []) {
    const entry = turn.tools?.[id];
    if (entry) entriesById.set(entry.id || id, { stage: "tool", ...entry });
  }
  const entries = Array.from(entriesById.values());
  return { running: turn.status === "running", status: turn.status, entries };
}

export function shouldShowOperationCard(model) {
  return Boolean(model?.running || model?.entries?.length);
}
