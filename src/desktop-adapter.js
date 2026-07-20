import { canonicalJson, safeText } from "./stream-normalizer.js";

function outcome(status, command, extra = {}) {
  return { delivery_id: command?.delivery_id || null, status, ...extra };
}

function currentConversationId(tab) {
  return tab?.conversationId || tab?.state?.currentConversationId || null;
}

export class DesktopAdapter {
  constructor({ claudian, capture, getActiveTab, macSessionId, connectionGeneration, clock = () => Date.now(), maxReceipts = 1024 }) {
    this.claudian = claudian;
    this.capture = capture;
    this.getActiveTab = getActiveTab;
    this.macSessionId = macSessionId || null;
    this.connectionGeneration = connectionGeneration || null;
    this.clock = clock;
    this.maxReceipts = maxReceipts;
    this.receipts = new Map();
    this.pendingApprovals = new Map();
    this.approvalRestorers = new Map();
  }

  bindTransport({ mac_session_id: sessionId, mac_connection_generation: generation }) {
    if (typeof sessionId !== "string" || !sessionId || !Number.isInteger(generation) || generation < 1) {
      throw new TypeError("invalid_transport_binding");
    }
    const changed = this.macSessionId !== sessionId || this.connectionGeneration !== generation;
    this.macSessionId = sessionId;
    this.connectionGeneration = generation;
    if (changed) this.receipts.clear();
    return { mac_session_id: sessionId, mac_connection_generation: generation };
  }

  invalidateTransport({ mac_session_id: sessionId, mac_connection_generation: generation } = {}) {
    if (sessionId && sessionId !== this.macSessionId) return false;
    if (generation && generation !== this.connectionGeneration) return false;
    this.macSessionId = null;
    this.connectionGeneration = null;
    this.receipts.clear();
    return true;
  }

  instrumentApprovals(tab) {
    const input = tab?.controllers?.inputController;
    if (!input || this.approvalRestorers.has(tab) || typeof input.handleApprovalRequest !== "function") return;
    const original = input.handleApprovalRequest;
    const adapter = this;
    const wrapped = async function remoteApproval(toolName, toolInput, description, approvalOptions) {
      const approvalId = `approval-${adapter.clock()}-${Math.random().toString(36).slice(2, 8)}`;
      const rawOptions = Array.isArray(approvalOptions?.decisionOptions) ? approvalOptions.decisionOptions : [
        { label: "Allow", value: "allow", decision: { type: "approve", scope: "turn" } },
        { label: "Deny", value: "deny", decision: "cancel" }
      ];
      const options = rawOptions.slice(0, 16).map((item, index) => ({
        id: String(item.value || `option-${index}`), label: safeText(item.label || `Option ${index + 1}`), decision: item.decision
      }));
      let settled = false;
      let remoteResolve;
      const remote = new Promise((resolve) => { remoteResolve = resolve; });
      adapter.pendingApprovals.set(approvalId, {
        resolve(value) {
          if (settled) return;
          settled = true;
          adapter.pendingApprovals.delete(approvalId);
          const selected = options.find((item) => item.id === value);
          remoteResolve(selected?.decision ?? (value === "deny" ? "cancel" : { type: "select-option", value }));
        }
      });
      const conversationId = currentConversationId(tab);
      const context = { conversationId, turnId: tab?.state?.remoteTurnId || `turn-${conversationId}` };
      await adapter.capture.normalizer.emit("approval.requested", context, {
        approval_id: approvalId, title: `允许 ${safeText(toolName || "工具")}？`,
        options: options.map(({ id, label }) => ({ id, label })), status: "pending"
      });
      const desktop = Promise.resolve(original.call(this, toolName, toolInput, description, approvalOptions));
      const decision = await Promise.race([desktop, remote]);
      if (!settled) { settled = true; adapter.pendingApprovals.delete(approvalId); }
      await adapter.capture.normalizer.emit("approval.resolved", context, {
        approval_id: approvalId, selected: "resolved", status: "resolved", resolved_by: "first_response"
      });
      return decision;
    };
    input.handleApprovalRequest = wrapped;
    this.approvalRestorers.set(tab, () => { if (input.handleApprovalRequest === wrapped) input.handleApprovalRequest = original; });
  }

  refreshApprovals(tabs) {
    const active = new Set(tabs || []);
    for (const tab of active) this.instrumentApprovals(tab);
    for (const [tab, restore] of this.approvalRestorers) {
      if (!active.has(tab)) { restore(); this.approvalRestorers.delete(tab); }
    }
  }

  unload() {
    for (const restore of this.approvalRestorers.values()) restore();
    this.approvalRestorers.clear();
    this.pendingApprovals.clear();
  }

  remember(command, result) {
    this.receipts.set(command.delivery_id, { fingerprint: canonicalJson(command), result });
    while (this.receipts.size > this.maxReceipts) this.receipts.delete(this.receipts.keys().next().value);
    return result;
  }

  preflight(command, tab) {
    if (!this.macSessionId || !this.connectionGeneration) return outcome("mac_offline", command);
    if (command.mac_session_id !== this.macSessionId) return outcome("session_mismatch", command);
    if (command.mac_connection_generation !== this.connectionGeneration) return outcome("connection_generation_mismatch", command);
    if (Date.parse(command.expires_at) <= this.clock()) return outcome("expired", command);
    if (!tab) return outcome("mac_offline", command);
    const conversationId = currentConversationId(tab);
    if (command.target?.conversation_id !== conversationId) return outcome("stale_conversation", command);
    const revision = this.capture.normalizer.revisionFor(conversationId);
    if (command.expected_revision !== revision) return outcome("stale_revision", command, { current_revision: revision });
    const turnId = tab?.state?.remoteTurnId || `turn-${conversationId}`;
    if (command.target?.turn_id && command.target.turn_id !== turnId) return outcome("stale_turn", command);
    return null;
  }

  async execute(command) {
    const prior = this.receipts.get(command.delivery_id);
    if (prior) {
      return prior.fingerprint === canonicalJson(command)
        ? { ...prior.result, status: "duplicate" }
        : outcome("rejected", command, { error_code: "delivery_conflict" });
    }
    const tab = this.getActiveTab();
    const failed = this.preflight(command, tab);
    if (failed) return this.remember(command, failed);
    const input = tab.controllers?.inputController;
    const conversation = tab.controllers?.conversationController;
    let result;
    switch (command.command_type) {
      case "message.submit": {
        const queued = Boolean(tab.state?.isStreaming);
        const attachmentLines = (Array.isArray(command.payload.attachment_refs) ? command.payload.attachment_refs : [])
          .map((item) => String(item?.vault_path || ""))
          .filter((path) => path && !path.startsWith("/") && !path.split("/").includes(".."))
          .map((path) => `@${path}`);
        const content = [String(command.payload.text || ""), attachmentLines.join("\n")].filter(Boolean).join("\n\n");
        // Claudian's sendMessage promise resolves only after the whole turn is
        // saved.  Desktop acceptance must not wait for model completion: the
        // SourceCapture wrapper owns the final keyframe/terminal barrier.
        this.capture.expectDelivery?.(tab, command.delivery_id, content);
        Promise.resolve(input.sendMessage({ content })).catch((error) => {
          this.capture.diagnostic?.({ type: "remote_submit_failed", error_type: error?.name || "Error" });
        });
        result = outcome("executed", command, { queued });
        break;
      }
      case "turn.stop":
        if (!tab.state?.isStreaming) result = outcome("already_resolved", command);
        else { input.cancelStreaming(); result = outcome("executed", command); }
        break;
      case "turn.steer": {
        const capabilities = input.getActiveCapabilities?.() || {};
        if (!capabilities.supportsTurnSteer || typeof input.steerQueuedMessage !== "function") {
          result = outcome("capability_missing", command, { capability: "turn_steer" });
        } else {
          if (command.payload.text) await input.sendMessage({ content: command.payload.text });
          await input.steerQueuedMessage();
          result = outcome("executed", command);
        }
        break;
      }
      case "approval.respond": {
        const approval = this.pendingApprovals.get(command.target.approval_id || command.payload.approval_id);
        if (!approval) result = outcome("already_resolved", command);
        else { approval.resolve(command.payload.value); result = outcome("executed", command); }
        break;
      }
      case "history.list":
        result = outcome("executed", command, { items: (this.claudian.getConversationList?.() || []).map((item) => ({
          conversation_id: item.id, title: safeText(item.title || ""), updated_at: item.updatedAt || null, message_count: item.messageCount || 0
        })) });
        break;
      case "history.select":
        if (tab.state?.isStreaming) result = outcome("rejected", command, { error_code: "streaming_history_switch_forbidden" });
        else if (typeof conversation?.switchTo !== "function") result = outcome("capability_missing", command, { capability: "history_select" });
        else { await conversation.switchTo(command.payload.conversation_id); result = outcome("executed", command); }
        break;
      case "keyframe.request":
        result = outcome("executed", command, await this.capture.emitKeyframe(tab));
        break;
      default:
        result = outcome("rejected", command, { error_code: "unknown_command_type" });
    }
    return this.remember(command, result);
  }
}
