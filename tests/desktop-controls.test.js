import assert from "node:assert/strict";
import test from "node:test";
import { DesktopAdapter } from "../src/desktop-adapter.js";

const expiry = "2099-01-01T00:00:00Z";

function setup({ streaming = false, steer = true, archive = false } = {}) {
  const calls = [];
  const events = [];
  const tab = {
    conversationId: "conv-1",
    session: { acceptsIntents: true },
    state: { isStreaming: streaming, currentConversationId: "conv-1", remoteTurnId: "turn-1", queuedMessage: null, messages: [] },
    controllers: {
      inputController: {
        async sendMessage(value) { calls.push(["send", value]); tab.state.queuedMessage = value; },
        cancelStreaming() { calls.push(["stop"]); },
        async steerQueuedMessage() { calls.push(["steer"]); },
        async handleApprovalRequest() { return new Promise(() => {}); },
        getActiveCapabilities: () => ({ supportsTurnSteer: steer })
      },
      conversationController: {
        async switchTo(id) {
          calls.push(["select", id]);
          tab.conversationId = id;
          tab.state.currentConversationId = id;
        }
      }
    }
  };
  const normalizer = { revisionFor: () => 4, emit: async (type, context, payload) => events.push({ type, context, payload }) };
  const conversations = [{ id: "conv-1", providerId: "claude", title: "One", updatedAt: 1, messageCount: 2 }];
  const claudian = {
    manifest: { id: "realclaudian", version: "2.2.6" },
    getConversationList: () => conversations.map((item) => ({ ...item })),
    getConversationSync: (id) => conversations.find((item) => item.id === id) || null,
    async createConversation() {
      calls.push(["new"]);
      const created = { id: "conv-2", providerId: "claude", title: "New Chat", updatedAt: 2, messageCount: 0 };
      conversations.unshift(created);
      return created;
    },
    async renameConversation(id, title) {
      calls.push(["rename", id, title]);
      const item = conversations.find((candidate) => candidate.id === id);
      if (item) item.title = title;
    },
    async deleteConversation(id) { calls.push(["delete", id]); }
  };
  if (archive) {
    claudian.archiveConversation = async (id) => {
      calls.push(["archive", id]);
      const item = conversations.find((candidate) => candidate.id === id);
      if (item) item.archived = true;
    };
  }
  const adapter = new DesktopAdapter({ claudian, capture: { normalizer }, getActiveTab: () => tab, macSessionId: "session-a", connectionGeneration: 7, clock: () => 0 });
  return { adapter, calls, tab, events };
}

function command(type, payload = {}, target = {}) {
  return {
    protocol: "claudian.remote.v2", kind: "command", command_type: type,
    delivery_id: `delivery-${type}`, mac_session_id: "session-a", mac_connection_generation: 7,
    expires_at: expiry, expected_revision: 4, target: { conversation_id: "conv-1", ...target }, payload
  };
}

test("2.0.4 submit preserves Claudian normal queue and the legacy void Steer contract", async () => {
  const { adapter, calls } = setup({ streaming: true });
  adapter.claudian.manifest.version = "2.0.4";
  assert.deepEqual(await adapter.execute(command("message.submit", { text: "queued" })), { delivery_id: "delivery-message.submit", status: "executed", queued: true });
  assert.deepEqual(calls[0], ["send", { content: "queued" }]);
  assert.equal((await adapter.execute(command("turn.steer", { text: "now" }, { turn_id: "turn-1" }))).status, "executed");
  assert.deepEqual(calls.slice(1), [["send", { content: "now" }], ["steer"]]);
});

// Model the native 2.2.6 void-returning controller: pending objects can be
// released before its promise settles, and only definitely-unsent input is restored.
function nativeSteerSetup({ accepted = true, failure, releasePending = false, finishTurn = false, providerAccepted = false, beforeHandoff } = {}) {
  const context = setup({ streaming: true });
  const { tab, calls } = context;
  const input = tab.controllers.inputController;
  const pendingByConversation = input.pendingSteersByConversation = new Map();
  const coordinator = {
    async steer() {
      if (finishTurn) tab.state.isStreaming = false;
      if (providerAccepted) pendingByConversation.get("conv-1").providerDisposition = "accepted-awaiting-correlation";
      if (failure) throw failure;
      return accepted;
    }
  };
  input.getExecutionCoordinator = () => coordinator;
  input.canSteerQueuedMessage = () => tab.state.isStreaming && !pendingByConversation.has("conv-1");
  input.cloneQueuedMessage = (message) => ({ ...message });
  input.steerQueuedMessage = async () => {
    calls.push(["steer"]);
    if (!tab.state.queuedMessage || !input.canSteerQueuedMessage()) return;
    const message = input.cloneQueuedMessage(tab.state.queuedMessage);
    tab.state.queuedMessage = null;
    await beforeHandoff?.(message);
    const pending = { coordinator, message, inputRecordId: `native-${message.content}`, providerDisposition: "awaiting-result" };
    pendingByConversation.set("conv-1", pending);
    try {
      const result = await coordinator.steer({ inputRecordId: pending.inputRecordId, text: message.content });
      if (result) pending.providerDisposition = "accepted-awaiting-correlation";
      else if (pending.providerDisposition !== "accepted-awaiting-correlation") pending.providerDisposition = "definitely-unsent";
    } catch (error) {
      if (pending.providerDisposition !== "accepted-awaiting-correlation") {
        pending.providerDisposition = error === failure && error.preHandoff
          ? "definitely-unsent" : "ambiguous-awaiting-reconciliation";
      }
    }
    if (pending.providerDisposition === "definitely-unsent") {
      if (tab.state.isStreaming) tab.state.queuedMessage = message;
      else tab.state.draft = message.content;
      pendingByConversation.delete("conv-1");
    } else if (releasePending) pendingByConversation.delete("conv-1");
  };
  return { ...context, input, coordinator };
}

test("2.2.6 Steer receipts use native acceptance and retain rejected or ambiguous input without resending", async () => {
  for (const [options, expected, restored] of [
    [{}, "executed", false],
    [{ releasePending: true }, "executed", false],
    [{ accepted: false }, "rejected", true],
    [{ failure: Object.assign(new Error("before provider"), { preHandoff: true }) }, "rejected", true],
    [{ failure: new Error("handoff outcome unknown") }, "unknown", false],
    [{ failure: new Error("handoff outcome unknown"), releasePending: true }, "unknown", false],
    [{ accepted: false, providerAccepted: true, releasePending: true }, "executed", false],
    [{ failure: new Error("late error"), providerAccepted: true, releasePending: true }, "executed", false],
    [{ finishTurn: true, releasePending: true }, "executed", false],
    [{ accepted: false, finishTurn: true }, "rejected", true]
  ]) {
    const { adapter, tab, input, coordinator, calls } = nativeSteerSetup(options);
    const original = coordinator.steer;
    const request = command("turn.steer", { text: "keep once" }, { turn_id: "turn-1" });
    assert.equal((await adapter.execute(request)).status, expected, JSON.stringify(options));
    assert.equal(coordinator.steer, original);
    assert.equal(Boolean(tab.state.queuedMessage || tab.state.draft), restored);
    if (restored) assert.equal(tab.state.queuedMessage?.content || tab.state.draft, "keep once");
    assert.equal((await adapter.execute(request)).status, "duplicate");
    assert.deepEqual(calls, [["send", { content: "keep once" }], ["steer"]]);
    if (expected === "unknown" && !options.releasePending) {
      assert.equal(input.pendingSteersByConversation.get("conv-1").providerDisposition, "ambiguous-awaiting-reconciliation");
    }
  }
});

test("2.2.6 Steer rechecks admission after queueing without consuming or resending native input", async () => {
  for (const finishTurn of [false, true]) {
    const { adapter, tab, input, calls } = nativeSteerSetup();
    const originalSend = input.sendMessage;
    input.sendMessage = async (value) => {
      await originalSend(value);
      if (finishTurn) tab.state.isStreaming = false;
      else tab.session.acceptsIntents = false;
    };
    const result = await adapter.execute(command("turn.steer", { text: "preserve queue" }));
    assert.equal(result.status, "rejected");
    assert.equal(tab.state.queuedMessage.content, "preserve queue");
    assert.deepEqual(calls, [["send", { content: "preserve queue" }]]);
  }
});

test("2.2.6 Steer never infers acceptance from a void return or an absent pending record", async () => {
  const { adapter, input, tab } = nativeSteerSetup();
  input.steerQueuedMessage = async () => { tab.state.queuedMessage = null; };
  assert.equal((await adapter.execute(command("turn.steer", { text: "unconfirmed" }))).status, "unknown");
});

test("2.2.6 an unrelated desktop Steer cannot supply acceptance for the remote queue item", async () => {
  for (const throwBeforeHandoff of [false, true]) {
    let resume;
    const paused = new Promise((resolve) => { resume = resolve; });
    const { adapter, input, tab, coordinator } = nativeSteerSetup({
      beforeHandoff: async (message) => {
        if (message.content !== "remote") return;
        await paused;
        if (throwBeforeHandoff) throw new Error("submission preparation failed");
      }
    });
    coordinator.steer = async (submission) => submission.text === "desktop";
    const clone = input.cloneQueuedMessage;
    const remote = adapter.execute(command("turn.steer", { text: "remote" }));
    await new Promise(setImmediate);
    assert.equal(input.cloneQueuedMessage, clone, "clone hook must be restored before asynchronous work");
    tab.state.queuedMessage = { content: "desktop" };
    await input.steerQueuedMessage();
    resume();
    assert.equal((await remote).status, throwBeforeHandoff ? "unknown" : "rejected");
  }
});

test("2.2.6 Steer does not offer a retry when its queue was consumed or replaced while awaiting submission", async () => {
  for (const streaming of [false, true]) {
    const { adapter, tab, input } = nativeSteerSetup();
    input.sendMessage = async () => {
      tab.state.queuedMessage = { content: "remote" };
      await Promise.resolve();
      tab.state.isStreaming = streaming;
      tab.state.queuedMessage = { content: "unrelated later input" };
    };
    assert.equal((await adapter.execute(command("turn.steer", { text: "remote" }))).status, "unknown");
    assert.equal(tab.state.queuedMessage.content, "unrelated later input");
  }
});

test("ready Vault attachments are referenced in the explicit user submission", async () => {
  const { adapter, calls } = setup();
  const result = await adapter.execute(command("message.submit", {
    text: "summarize this",
    attachment_refs: [{ upload_id: "upload-12345678", vault_path: "Claudian Remote/Uploads/report.md", label: "report.md" }]
  }));
  assert.equal(result.status, "executed");
  assert.deepEqual(calls[0], ["send", { content: "summarize this\n\n@Claudian Remote/Uploads/report.md" }]);
});

test("stop, history list/select, approval and keyframe use existing desktop controllers", async () => {
  const { adapter, calls, tab } = setup({ streaming: true });
  assert.equal((await adapter.execute(command("turn.stop", {}, { turn_id: "turn-1" }))).status, "executed");
  assert.deepEqual(calls[0], ["stop"]);
  assert.equal((await adapter.execute(command("history.list", { page: 0 }))).items[0].conversation_id, "conv-1");
  assert.equal((await adapter.execute(command("history.select", { conversation_id: "conv-2" }))).error_code, "streaming_history_switch_forbidden");
  tab.state.isStreaming = false;
  const second = command("history.select", { conversation_id: "conv-2" }); second.delivery_id += "-2";
  assert.equal((await adapter.execute(second)).status, "executed");
  assert.deepEqual(calls.at(-1), ["select", "conv-2"]);
});

test("history new and rename use Claudian 2.2.6 public APIs and return authoritative history", async () => {
  const { adapter, calls, tab } = setup();
  const created = await adapter.execute(command("history.new"));
  assert.equal(created.status, "executed");
  assert.equal(created.active_conversation_id, "conv-2");
  assert.deepEqual(calls.slice(0, 2), [["new"], ["select", "conv-2"]]);
  assert.equal(created.items[0].conversation_id, "conv-2");

  const rename = command("history.rename", { conversation_id: "conv-2", title: "Renamed" });
  rename.delivery_id = "delivery-history.rename";
  rename.target.conversation_id = tab.state.currentConversationId;
  const renamed = await adapter.execute(rename);
  assert.equal(renamed.status, "executed");
  assert.deepEqual(calls.at(-1), ["rename", "conv-2", "Renamed"]);
  assert.equal(renamed.items.find((item) => item.conversation_id === "conv-2").title, "Renamed");
});

test("history archive fails closed when Claudian has no archive capability and never deletes", async () => {
  const { adapter, calls } = setup();
  const archive = command("history.archive", { conversation_id: "conv-1" });
  archive.delivery_id = "delivery-history.archive";
  const result = await adapter.execute(archive);
  assert.deepEqual(result, {
    delivery_id: "delivery-history.archive",
    status: "capability_missing",
    capability: "history_archive"
  });
  assert.equal(calls.some(([name]) => name === "delete"), false);
});

test("session, connection generation, revision, turn, expiry, and capabilities are checked again locally", async () => {
  const { adapter } = setup({ streaming: true, steer: false });
  const cases = [
    [{ ...command("message.submit", { text: "x" }), mac_session_id: "old" }, "session_mismatch"],
    [{ ...command("message.submit", { text: "x" }), delivery_id: "generation", mac_connection_generation: 6 }, "connection_generation_mismatch"],
    [{ ...command("message.submit", { text: "x" }), delivery_id: "revision", expected_revision: 3 }, "stale_revision"],
    [command("turn.stop", {}, { turn_id: "old-turn" }), "stale_turn"],
    [{ ...command("message.submit", { text: "x" }), delivery_id: "expired", expires_at: "1960-01-01T00:00:00Z" }, "expired"],
    [command("turn.steer", { text: "x" }, { turn_id: "turn-1" }), "capability_missing"]
  ];
  for (const [input, expected] of cases) assert.equal((await adapter.execute(input)).status, expected);
});

test("same delivery is idempotent and conflicting body is rejected", async () => {
  const { adapter, calls } = setup();
  const input = command("message.submit", { text: "once" });
  assert.equal((await adapter.execute(input)).status, "executed");
  assert.equal((await adapter.execute(input)).status, "duplicate");
  assert.equal((await adapter.execute({ ...input, payload: { text: "different" } })).error_code, "delivery_conflict");
  assert.equal(calls.length, 1);
});

test("desktop acceptance does not wait for the full sendMessage completion barrier", async () => {
  let release;
  const saving = new Promise((resolve) => { release = resolve; });
  const { tab, adapter } = setup();
  tab.controllers.inputController.sendMessage = async () => saving;

  const accepted = await Promise.race([
    adapter.execute(command("message.submit", { text: "hello" })),
    new Promise((_, reject) => setTimeout(() => reject(new Error("acceptance waited for completion")), 20))
  ]);

  assert.equal(accepted.status, "executed");
  release();
});

test("Companion transport bind invalidates an old generation in the same Mac session", async () => {
  const { adapter } = setup();
  adapter.bindTransport({ mac_session_id: "session-a", mac_connection_generation: 8 });
  const stale = command("message.submit", { text: "must not execute late" });
  stale.delivery_id = "old-generation";
  assert.equal((await adapter.execute(stale)).status, "connection_generation_mismatch");
  stale.mac_connection_generation = 8;
  stale.delivery_id = "current-generation";
  assert.equal((await adapter.execute(stale)).status, "executed");
  assert.equal(adapter.invalidateTransport({ mac_session_id: "session-a", mac_connection_generation: 7 }), false);
  assert.equal(adapter.invalidateTransport({ mac_session_id: "session-a", mac_connection_generation: 8 }), true);
  stale.delivery_id = "after-disconnect";
  assert.equal((await adapter.execute(stale)).status, "mac_offline");
});

test("approval wrapper exposes only safe options and first authoritative result wins", async () => {
  const { adapter, tab, events } = setup({ streaming: true });
  adapter.instrumentApprovals(tab);
  const decision = tab.controllers.inputController.handleApprovalRequest(
    "exec /Users/example/private", { command: "secret shell", token: "sk-abcdefghijkl" },
    "never emit this description", { decisionOptions: [{ label: "Allow /Users/example/private", value: "allow", decision: "allow" }] }
  );
  await new Promise((resolve) => setTimeout(resolve, 0));
  const approvalId = [...adapter.pendingApprovals.keys()][0];
  const input = command("approval.respond", { approval_id: approvalId, value: "allow" }, { turn_id: "turn-1", approval_id: approvalId });
  input.delivery_id = "approval-first";
  assert.equal((await adapter.execute(input)).status, "executed");
  assert.equal(await decision, "allow");
  input.delivery_id = "approval-second";
  assert.equal((await adapter.execute(input)).status, "already_resolved");
  const serialized = JSON.stringify(events);
  assert.equal(serialized.includes("secret shell"), false);
  assert.equal(serialized.includes("never emit this description"), false);
  assert.equal(serialized.includes("/Users/"), false);
  assert.equal(serialized.includes("sk-abcdefghijkl"), false);
  assert.match(serialized, /\[local path hidden\]/);
});

test("2.2.6 paused intent admission rejects submission without reporting success", async () => {
  const { adapter, tab, calls } = setup();
  tab.session = { acceptsIntents: false };
  const result = await adapter.execute(command("message.submit", { text: "keep this draft" }));
  assert.equal(result.status, "rejected");
  assert.equal(result.error_code, "claudian_input_busy");
  assert.deepEqual(calls, []);
});

test("default approvals use version-native decisions and reject unoffered options", async () => {
  for (const [version, value, expected] of [
    ["2.2.6", "allow", "allow"], ["2.2.6", "deny", "deny"],
    ["2.0.4", "allow", { type: "approve", scope: "turn" }], ["2.0.4", "deny", "cancel"]
  ]) {
    const { adapter, tab } = setup({ streaming: true });
    adapter.claudian.manifest = { version };
    adapter.instrumentApprovals(tab);
    const pending = tab.controllers.inputController.handleApprovalRequest("Read", {}, "Read a file");
    await new Promise((resolve) => setImmediate(resolve));
    const approvalId = [...adapter.pendingApprovals.keys()][0];
    const invalid = command("approval.respond", { value: "unoffered" }, { approval_id: approvalId });
    invalid.delivery_id = "invalid-approval";
    assert.equal((await adapter.execute(invalid)).error_code, "invalid_approval_option");
    assert.equal(adapter.pendingApprovals.has(approvalId), true);
    assert.equal((await adapter.execute(command("approval.respond", { value }, { approval_id: approvalId }))).status, "executed");
    assert.deepEqual(await pending, expected);
  }
});

test("Claudian 2.2.6 rejects blocked input and steer without queueing text", async () => {
  for (const field of ["isCreatingConversation", "isSwitchingConversation", "isRewinding"]) {
    const { adapter, tab, calls } = setup({ streaming: true });
    tab.state[field] = true;
    assert.equal((await adapter.execute(command("message.submit", { text: "blocked" }))).error_code, "claudian_input_busy");
    assert.equal((await adapter.execute(command("turn.steer", { text: "blocked" }))).error_code, "claudian_steer_busy");
    assert.deepEqual(calls, []);
  }
  const busy = setup({ streaming: true });
  busy.tab.controllers.inputController.canSteerQueuedMessage = () => false;
  assert.equal((await busy.adapter.execute(command("turn.steer", { text: "blocked" }))).error_code, "claudian_steer_busy");
  assert.deepEqual(busy.calls, []);
  const idle = setup();
  assert.equal((await idle.adapter.execute(command("turn.steer", { text: "too late" }))).status, "already_resolved");
  assert.deepEqual(idle.calls, []);
});
