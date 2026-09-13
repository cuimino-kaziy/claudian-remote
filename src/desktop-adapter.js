import { canonicalJson, safeText } from "./stream-normalizer.js";
import { canSubmitToClaudian, claudianManifest } from "./protocol/compatibility.js";

function outcome(status, command, extra = {}) {
  return { delivery_id: command?.delivery_id || null, status, ...extra };
}

function currentConversationId(tab) {
  return tab?.conversationId || tab?.state?.currentConversationId || null;
}

function historyItems(claudian) {
  return (claudian?.getConversationList?.() || []).map((item) => ({
    conversation_id: String(item?.id || ""),
    title: safeText(item?.title || ""),
    updated_at: item?.updatedAt || item?.lastResponseAt || null,
    message_count: Math.max(0, Number(item?.messageCount) || 0),
    archived: item?.archived === true
  })).filter((item) => item.conversation_id);
}

export function historyCapabilities(claudian, tab) {
  const conversation = tab?.controllers?.conversationController;
  return {
    history_list: typeof claudian?.getConversationList === "function",
    history_select: typeof conversation?.switchTo === "function",
    history_new: typeof claudian?.createConversation === "function" && typeof conversation?.switchTo === "function",
    history_rename: typeof claudian?.renameConversation === "function",
    // Supported Claudian versions have permanent delete but no archive API. Never map
    // archive to delete or to updateConversation: its persisted metadata
    // allowlist does not retain an archived marker.
    history_archive: typeof claudian?.archiveConversation === "function"
  };
}

function historyReceipt(command, claudian, tab, extra = {}) {
  return outcome("executed", command, {
    items: historyItems(claudian),
    active_conversation_id: currentConversationId(tab),
    capabilities: historyCapabilities(claudian, tab),
    ...extra
  });
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
    this.steersInFlight = new WeakSet();
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
      const defaultOptions = claudianManifest(adapter.claudian).version === "2.2.6" ? [
        { label: "Allow once", value: "allow", decision: "allow" },
        { label: "Deny", value: "deny", decision: "deny" }
      ] : [
        { label: "Allow", value: "allow", decision: { type: "approve", scope: "turn" } },
        { label: "Deny", value: "deny", decision: "cancel" }
      ];
      const rawOptions = Array.isArray(approvalOptions?.decisionOptions) ? approvalOptions.decisionOptions : defaultOptions;
      const options = rawOptions.slice(0, 16).map((item, index) => ({
        id: String(item.value || `option-${index}`), label: safeText(item.label || `Option ${index + 1}`), decision: item.decision
      }));
      let settled = false;
      let remoteResolve;
      const remote = new Promise((resolve) => { remoteResolve = resolve; });
      adapter.pendingApprovals.set(approvalId, {
        resolve(value) {
          const selected = options.find((item) => item.id === value);
          if (settled || !selected) return false;
          settled = true;
          adapter.pendingApprovals.delete(approvalId);
          remoteResolve(selected.decision ?? { type: "select-option", value });
          return true;
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
    const compatibility = this.capture.compatibility?.(tab);
    if (compatibility?.writable === false) {
      return outcome("compatibility_mismatch", command, {
        error_code: compatibility.reason,
        current_version: compatibility.current_version,
        required_version: compatibility.required_version,
        remediation: compatibility.remediation
      });
    }
    const conversationId = currentConversationId(tab);
    if (command.target?.conversation_id !== conversationId) return outcome("stale_conversation", command);
    const revision = this.capture.normalizer.revisionFor(conversationId);
    if (command.expected_revision !== revision) return outcome("stale_revision", command, { current_revision: revision });
    const turnId = tab?.state?.remoteTurnId || `turn-${conversationId}`;
    if (command.target?.turn_id && command.target.turn_id !== turnId) return outcome("stale_turn", command);
    return null;
  }

  async steerWithNativeReceipt(command, tab, input) {
    const coordinator = input.getExecutionCoordinator?.();
    const clone = input.cloneQueuedMessage;
    if (typeof coordinator?.steer !== "function" || typeof clone !== "function") return outcome("capability_missing", command, { capability: "turn_steer" });
    if (this.steersInFlight.has(input)) return outcome("rejected", command, { error_code: "claudian_steer_busy" });
    this.steersInFlight.add(input);
    const conversationId = currentConversationId(tab);
    const original = coordinator.steer;
    let message;
    let pending;
    let accepted = false;
    const wrapped = async function (submission, ...args) {
      const candidate = input.pendingSteersByConversation?.get(conversationId);
      const matches = message && candidate?.message === message
        && candidate.coordinator === this && candidate.inputRecordId === submission?.inputRecordId;
      // Keep the object itself: native correlation may release its map entry
      // before steerQueuedMessage's void-returning promise settles.
      if (matches) pending = candidate;
      const result = await original.call(this, submission, ...args);
      if (matches && result === true) accepted = true;
      return result;
    };
    try {
      let queued = tab.state?.queuedMessage;
      if (command.payload.text) {
        const sending = input.sendMessage({ content: command.payload.text });
        queued = tab.state?.queuedMessage;
        await sending;
      }
      if (!queued || tab.state?.queuedMessage !== queued) {
        return outcome("unknown", command, { error_code: "claudian_steer_unconfirmed" });
      }
      if (!tab.state?.isStreaming || !canSubmitToClaudian(this.claudian, tab) || input.canSteerQueuedMessage?.() === false) {
        return outcome("rejected", command, { error_code: "claudian_steer_busy" });
      }
      coordinator.steer = wrapped;
      // Native 2.2.6 clones this call's queue synchronously, before its first
      // await. Observe that object only; concurrent desktop Steer is unrelated.
      const captureClone = function (...args) {
        const cloned = clone.apply(this, args);
        message ??= cloned;
        return cloned;
      };
      let steering;
      input.cloneQueuedMessage = captureClone;
      try { steering = input.steerQueuedMessage(); }
      finally { if (input.cloneQueuedMessage === captureClone) input.cloneQueuedMessage = clone; }
      await steering;
    } catch {
      // Native disposition below decides whether a failure was definitely
      // unsent. Never requeue here: post-handoff failures can already be sent.
    } finally {
      if (coordinator.steer === wrapped) coordinator.steer = original;
      this.steersInFlight.delete(input);
    }
    if (accepted || pending?.providerDisposition === "accepted-awaiting-correlation") return outcome("executed", command);
    if (pending?.providerDisposition === "definitely-unsent") return outcome("rejected", command, { error_code: "claudian_steer_unsent" });
    return outcome("unknown", command, { error_code: "claudian_steer_unconfirmed" });
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
        if (!canSubmitToClaudian(this.claudian, tab)) {
          result = outcome("rejected", command, { error_code: "claudian_input_busy" });
          break;
        }
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
        } else if (!tab.state?.isStreaming) {
          result = outcome("already_resolved", command);
        } else if (!canSubmitToClaudian(this.claudian, tab) || input.canSteerQueuedMessage?.() === false) {
          result = outcome("rejected", command, { error_code: "claudian_steer_busy" });
        } else if (claudianManifest(this.claudian).version === "2.2.6") {
          result = await this.steerWithNativeReceipt(command, tab, input);
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
        else result = approval.resolve(command.payload.value)
          ? outcome("executed", command)
          : outcome("rejected", command, { error_code: "invalid_approval_option" });
        break;
      }
      case "history.list":
        if (typeof this.claudian?.getConversationList !== "function") {
          result = outcome("capability_missing", command, { capability: "history_list" });
        } else result = historyReceipt(command, this.claudian, tab);
        break;
      case "history.select":
        if (tab.state?.isStreaming) result = outcome("rejected", command, { error_code: "streaming_history_switch_forbidden" });
        else if (typeof conversation?.switchTo !== "function") result = outcome("capability_missing", command, { capability: "history_select" });
        else {
          const selectedId = String(command.payload.conversation_id || "");
          await conversation.switchTo(selectedId);
          result = currentConversationId(tab) === selectedId
            ? historyReceipt(command, this.claudian, tab)
            : outcome("rejected", command, { error_code: "history_select_not_confirmed" });
        }
        break;
      case "history.new": {
        const capabilities = historyCapabilities(this.claudian, tab);
        if (tab.state?.isStreaming) result = outcome("rejected", command, { error_code: "streaming_history_switch_forbidden" });
        else if (!capabilities.history_new) result = outcome("capability_missing", command, { capability: "history_new" });
        else {
          const current = this.claudian.getConversationSync?.(currentConversationId(tab));
          const created = await this.claudian.createConversation(current?.providerId ? { providerId: current.providerId } : undefined);
          const createdId = String(created?.id || "");
          if (!createdId) result = outcome("rejected", command, { error_code: "history_new_not_confirmed" });
          else {
            await conversation.switchTo(createdId);
            result = currentConversationId(tab) === createdId
              ? historyReceipt(command, this.claudian, tab, { created_conversation_id: createdId })
              : outcome("rejected", command, { error_code: "history_new_not_confirmed" });
          }
        }
        break;
      }
      case "history.rename": {
        if (typeof this.claudian?.renameConversation !== "function") {
          result = outcome("capability_missing", command, { capability: "history_rename" });
          break;
        }
        const conversationId = String(command.payload.conversation_id || "");
        const title = String(command.payload.title || "").trim().slice(0, 200);
        if (!conversationId || !title) {
          result = outcome("rejected", command, { error_code: "invalid_history_rename" });
          break;
        }
        await this.claudian.renameConversation(conversationId, title);
        const authoritative = historyItems(this.claudian).find((item) => item.conversation_id === conversationId);
        result = authoritative?.title === safeText(title)
          ? historyReceipt(command, this.claudian, tab, { renamed_conversation_id: conversationId })
          : outcome("rejected", command, { error_code: "history_rename_not_confirmed" });
        break;
      }
      case "history.archive": {
        if (typeof this.claudian?.archiveConversation !== "function") {
          result = outcome("capability_missing", command, { capability: "history_archive" });
          break;
        }
        const conversationId = String(command.payload.conversation_id || "");
        await this.claudian.archiveConversation(conversationId);
        const authoritative = historyItems(this.claudian).find((item) => item.conversation_id === conversationId);
        result = !authoritative || authoritative.archived
          ? historyReceipt(command, this.claudian, tab, { archived_conversation_id: conversationId })
          : outcome("rejected", command, { error_code: "history_archive_not_confirmed" });
        break;
      }
      case "keyframe.request":
        result = outcome("executed", command, await this.capture.emitKeyframe(tab));
        break;
      default:
        result = outcome("rejected", command, { error_code: "unknown_command_type" });
    }
    return this.remember(command, result);
  }
}
