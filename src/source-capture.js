import { safeText, safeToolSummary, sha256 } from "./stream-normalizer.js";
import {
  claudianManifest,
  evaluateClaudianCompatibility
} from "./protocol/compatibility.js";

const WRAP = Symbol.for("claudian.remote.v2.wrap");

function contextFor(tab, message) {
  const conversationId = tab?.conversationId || tab?.state?.currentConversationId || "conversation-pending";
  const turnId = tab?.state?.remoteTurnId || `turn-${conversationId}`;
  return {
    conversationId,
    turnId,
    messageId: message?.id || `message-${turnId}`,
    blockId: tab?.state?.currentTextBlockId || `text-${message?.id || turnId}`
  };
}

export function safeKeyframe(claudian, tab, { turnStatus = null, projectionState = null, originDeliveryIds = null } = {}) {
  const conversationId = tab?.conversationId || tab?.state?.currentConversationId || "conversation-pending";
  const turnId = String(tab?.state?.remoteTurnId || `turn-${conversationId}`);
  const conversation = claudian?.getConversationSync?.(conversationId);
  const messages = (tab?.state?.messages || conversation?.messages || []).map((message) => {
    const messageId = String(message.id || "message");
    const originDeliveryId = originDeliveryIds?.get(`${conversationId}\u0000${messageId}`) || null;
    const blocks = [{ id: `text-${messageId}`, type: "text", text: safeText(message.displayContent || message.content || "") }];
    for (const tool of message.toolCalls || []) {
      const summary = safeToolSummary(tool);
      blocks.push({ id: `tool-${summary.id}`, type: "tool", name: summary.name, label: summary.label, status: summary.status });
    }
    return {
      id: messageId,
      role: ["user", "assistant", "system"].includes(message.role) ? message.role : "system",
      ...(originDeliveryId ? { origin_delivery_id: originDeliveryId } : {}),
      blocks
    };
  });
  const observed = projectionState || {};
  const observedOperation = observed.current_operation || {};
  const observedTools = Array.isArray(observedOperation.tools) ? observedOperation.tools : [];
  return {
    conversation: { id: String(conversationId), title: safeText(conversation?.title || ""), revision: 0 },
    turns: [{
      id: turnId,
      status: turnStatus || observed.status || (tab?.state?.isStreaming ? "running" : "completed"),
      messages,
      current_operation: {
        activities: (Array.isArray(observedOperation.activities) ? observedOperation.activities : []).map((item) => ({ ...item })),
        tools: observedTools.map((item) => ({ ...item }))
      },
      approvals: (Array.isArray(observed.approvals) ? observed.approvals : []).map((item) => ({
        ...item,
        ...(item.options ? { options: item.options.map((option) => ({ ...option })) } : {})
      })),
      artifacts: (Array.isArray(observed.artifacts) ? observed.artifacts : []).map((item) => ({ ...item }))
    }]
  };
}

export class SourceCapture {
  constructor({ claudian, normalizer, diagnostic = () => {} }) {
    this.claudian = claudian;
    this.normalizer = normalizer;
    this.diagnostic = diagnostic;
    this.restorers = new Map();
    this.pendingDeliveries = new Map();
    this.originDeliveryIds = new Map();
    this.compatibilityMode = false;
    this.compatibilityState = null;
  }

  expectDelivery(tab, deliveryId, content) {
    if (!tab || !deliveryId) return;
    const baseline = new Set((tab?.state?.messages || []).map((message) => String(message?.id || "")));
    const pending = this.pendingDeliveries.get(tab) || [];
    pending.push({ deliveryId: String(deliveryId), content: String(content || ""), baseline });
    this.pendingDeliveries.set(tab, pending);
  }

  resolvePendingDeliveries(tab) {
    const pending = this.pendingDeliveries.get(tab);
    if (!pending?.length) return;
    const conversationId = tab?.conversationId || tab?.state?.currentConversationId || "conversation-pending";
    const messages = tab?.state?.messages || [];
    const unresolved = [];
    for (const delivery of pending) {
      const candidates = messages.filter((message) => {
        const messageId = String(message?.id || "");
        return message?.role === "user"
          && messageId
          && !delivery.baseline.has(messageId)
          && !this.originDeliveryIds.has(`${conversationId}\u0000${messageId}`);
      });
      const exact = candidates.find((message) => String(message.displayContent || message.content || "") === delivery.content);
      const match = exact || (candidates.length === 1 ? candidates[0] : null);
      if (!match) {
        unresolved.push(delivery);
        continue;
      }
      this.originDeliveryIds.set(`${conversationId}\u0000${String(match.id)}`, delivery.deliveryId);
    }
    if (unresolved.length) this.pendingDeliveries.set(tab, unresolved);
    else this.pendingDeliveries.delete(tab);
  }

  capabilities(tab) {
    const input = tab?.controllers?.inputController;
    const stream = tab?.controllers?.streamController;
    const conversation = tab?.controllers?.conversationController;
    const provider = input?.getActiveCapabilities?.() || {};
    return {
      semantic_stream: typeof stream?.handleStreamChunk === "function",
      completion_barrier: typeof input?.sendMessage === "function",
      stop: typeof input?.cancelStreaming === "function",
      steer: Boolean(provider.supportsTurnSteer && typeof input?.steerQueuedMessage === "function"),
      approval: typeof input?.handleApprovalRequest === "function",
      history_list: typeof this.claudian?.getConversationList === "function",
      history_select: typeof conversation?.switchTo === "function"
    };
  }

  compatibility(tab) {
    const result = evaluateClaudianCompatibility({
      manifest: claudianManifest(this.claudian),
      capabilities: this.capabilities(tab)
    });
    this.compatibilityState = result;
    this.compatibilityMode = !result.writable;
    return result;
  }

  async emitKeyframe(tab, { turnStatus = null } = {}) {
    if (!tab) throw new TypeError("active_claudian_tab_required");
    await this.normalizer.flushText();
    this.resolvePendingDeliveries(tab);
    const context = contextFor(tab, tab?.state?.messages?.at?.(-1));
    const document = safeKeyframe(this.claudian, tab, {
      turnStatus,
      projectionState: this.normalizer.projectionForTurn?.(context),
      originDeliveryIds: this.originDeliveryIds
    });
    // page + final each consume one conversation revision.  The authoritative
    // projection must describe the revision after both keyframe events so the
    // next text.delta base_revision matches the calibrated mobile replica.
    document.conversation.revision = this.normalizer.revisionFor(document.conversation.id) + 2;
    const checksum = await sha256(document);
    const keyframeId = `kf-${context.turnId}-${this.normalizer.sourceSequence + 1}`;
    await this.normalizer.emit("keyframe.page", context, {
      keyframe_id: keyframeId,
      page_index: 0,
      page_count: 1,
      projection: document
    });
    await this.normalizer.emit("keyframe.final", context, {
      keyframe_id: keyframeId,
      page_count: 1,
      revision: document.conversation.revision,
      checksum
    });
    return { keyframe_id: keyframeId, checksum, revision: document.conversation.revision };
  }

  async emitBootstrap(tab) {
    if (!tab) throw new TypeError("active_claudian_tab_required");
    const capabilities = this.capabilities(tab);
    const compatibility = this.compatibility(tab);
    const context = contextFor(tab, tab?.state?.messages?.at?.(-1));
    // Keyframe first: a Relay subscriber in reset mode promotes to live on the
    // final page, then receives the capability/activation events below.
    const keyframe = await this.emitKeyframe(tab);
    await this.normalizer.emit("capability.state", context, {
      mode: compatibility.writable ? "streaming" : "compatibility",
      supports_turn_steer: capabilities.steer,
      supports_history: capabilities.history_list && capabilities.history_select,
      supports_stop: capabilities.stop,
      supports_approval: capabilities.approval,
      reason: compatibility.reason,
      writable: compatibility.writable,
      current_version: compatibility.current_version,
      required_version: compatibility.required_version,
      missing_capabilities: compatibility.missing_capabilities,
      remediation: compatibility.remediation
    });
    const conversation = this.claudian?.getConversationSync?.(context.conversationId);
    await this.normalizer.emit("conversation.activated", context, {
      conversation_id: context.conversationId,
      title: safeText(conversation?.title || "")
    });
    return keyframe;
  }

  instrument(tab) {
    if (!tab) return this.capabilities(tab);
    if (this.restorers.has(tab)) {
      const current = this.compatibility(tab);
      if (current.writable) return this.capabilities(tab);
      const restore = this.restorers.get(tab);
      restore();
      this.restorers.delete(tab);
      this.diagnostic({
        type: "compatibility_mode",
        reason: current.reason,
        current_version: current.current_version,
        required_version: current.required_version
      });
      return this.capabilities(tab);
    }
    const compatibility = this.compatibility(tab);
    if (!compatibility.writable) {
      this.diagnostic({
        type: "compatibility_mode",
        reason: compatibility.reason,
        current_version: compatibility.current_version,
        required_version: compatibility.required_version
      });
      return this.capabilities(tab);
    }
    const input = tab?.controllers?.inputController;
    const stream = tab?.controllers?.streamController;
    if (!input || !stream || typeof stream.handleStreamChunk !== "function" || typeof input.sendMessage !== "function") {
      this.compatibilityMode = true;
      this.diagnostic({ type: "compatibility_mode", reason: "required_hook_missing" });
      return this.capabilities(tab);
    }
    if (stream[WRAP] || input[WRAP]) return this.capabilities(tab);
    const originalChunk = stream.handleStreamChunk;
    const originalSend = input.sendMessage;
    const originalCancel = typeof input.cancelStreaming === "function" ? input.cancelStreaming : null;
    const normalizer = this.normalizer;
    const capture = this;
    const wrappedChunk = async function remotePostCommit(chunk, message) {
      const result = await originalChunk.call(this, chunk, message);
      try {
        await normalizer.observePostCommit(chunk, message, contextFor(tab, message));
      } catch (error) {
        capture.compatibilityMode = true;
        capture.diagnostic({ type: "source_hook_failed", error_type: error?.name || "Error" });
      }
      return result;
    };
    const wrappedCancel = originalCancel && function remoteCancelStreaming(...args) {
      if (tab?.state?.isStreaming) {
        try {
          const context = contextFor(tab, tab?.state?.messages?.at?.(-1));
          normalizer.noteTerminalHint?.(context.conversationId, "interrupted", {
            queued_draft_returned: Boolean(tab?.state?.queuedMessage)
          });
        } catch (error) {
          capture.compatibilityMode = true;
          capture.diagnostic({ type: "cancel_hook_failed", error_type: error?.name || "Error" });
        }
      }
      return originalCancel.apply(this, args);
    };
    const wrappedSend = async function remoteCompletionBarrier(...args) {
      const wasStreaming = Boolean(tab?.state?.isStreaming);
      if (!wasStreaming) {
        try {
          const context = contextFor(tab, tab?.state?.messages?.at?.(-1));
          await normalizer.emit("turn.started", context, {
            status: "running",
            started_at: new Date(normalizer.clock()).toISOString()
          });
        } catch (error) {
          capture.compatibilityMode = true;
          capture.diagnostic({ type: "start_hook_failed", error_type: error?.name || "Error" });
        }
      }
      const result = await originalSend.apply(this, args);
      if (!wasStreaming) {
        try {
          const context = contextFor(tab, tab?.state?.messages?.at?.(-1));
          const terminalHint = normalizer.consumeTerminalHint?.(context.conversationId) || { status: "completed" };
          const terminal = typeof terminalHint === "string" ? terminalHint : terminalHint.status;
          normalizer.finalizeTurnProjection?.(context, terminal);
          const keyframe = await capture.emitKeyframe(tab, { turnStatus: terminal });
          const checksum = keyframe.checksum;
          if (terminal === "failed") {
            await normalizer.emit("turn.failed", context, { status: "failed", error_code: "provider_error", message: "Desktop agent reported an error" });
          } else if (terminal === "interrupted") {
            await normalizer.emit("turn.interrupted", context, {
              status: "interrupted",
              queued_draft_returned: Boolean(terminalHint?.queued_draft_returned)
            });
          } else {
            await normalizer.emit("turn.completed", context, { status: "completed", checksum });
          }
        } catch (error) {
          capture.compatibilityMode = true;
          capture.diagnostic({ type: "completion_hook_failed", error_type: error?.name || "Error" });
        }
      }
      return result;
    };
    stream.handleStreamChunk = wrappedChunk;
    input.sendMessage = wrappedSend;
    if (wrappedCancel) input.cancelStreaming = wrappedCancel;
    stream[WRAP] = wrappedChunk;
    input[WRAP] = wrappedSend;
    this.restorers.set(tab, () => {
      if (stream.handleStreamChunk === wrappedChunk) stream.handleStreamChunk = originalChunk;
      if (input.sendMessage === wrappedSend) input.sendMessage = originalSend;
      if (wrappedCancel && input.cancelStreaming === wrappedCancel) input.cancelStreaming = originalCancel;
      delete stream[WRAP];
      delete input[WRAP];
    });
    return this.capabilities(tab);
  }

  refresh(tabs) {
    const active = new Set(tabs || []);
    for (const tab of active) this.instrument(tab);
    for (const [tab, restore] of this.restorers) {
      if (!active.has(tab)) {
        restore();
        this.restorers.delete(tab);
      }
    }
  }

  unload() {
    for (const restore of this.restorers.values()) restore();
    this.restorers.clear();
    this.pendingDeliveries.clear();
    this.originDeliveryIds.clear();
  }
}

export function discoverClaudianTabs(claudian) {
  const tabs = [];
  for (const view of claudian?.getAllViews?.() || []) {
    const manager = view?.getTabManager?.();
    if (manager?.getActiveTab?.()) tabs.push(manager.getActiveTab());
    const all = typeof manager?.getAllTabs === "function"
      ? manager.getAllTabs()
      : manager?.tabs instanceof Map
        ? manager.tabs.values()
        : manager?.tabs || [];
    for (const tab of all) if (tab && !tabs.includes(tab)) tabs.push(tab);
  }
  return tabs;
}
