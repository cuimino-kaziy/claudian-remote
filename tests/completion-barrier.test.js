import assert from "node:assert/strict";
import test from "node:test";
import { DesktopAdapter } from "../src/desktop-adapter.js";
import { SourceCapture } from "../src/source-capture.js";
import { SemanticStreamNormalizer } from "../src/stream-normalizer.js";

function supportedClaudian(tab, value = {}) {
  tab.session = { acceptsIntents: true };
  const input = tab.controllers.inputController;
  if (typeof input.cancelStreaming !== "function") input.cancelStreaming = () => {};
  if (typeof input.steerQueuedMessage !== "function") input.steerQueuedMessage = async () => {};
  if (typeof input.handleApprovalRequest !== "function") input.handleApprovalRequest = async () => "cancel";
  if (typeof input.handleExecutionEvent !== "function") input.handleExecutionEvent = async () => {};
  const activeCapabilities = input.getActiveCapabilities?.bind(input);
  input.getActiveCapabilities = () => ({ ...(activeCapabilities?.() || {}), supportsTurnSteer: true });
  return { manifest: { id: "realclaudian", version: "2.2.6" }, ...value };
}

test("Claudian 2.2.6 ignored submissions produce no remote turn or completion", async () => {
  for (const blocked of ["paused", "missing_session", "isCreatingConversation", "isSwitchingConversation", "isRewinding"]) {
    const events = [];
    let calls = 0;
    const tab = {
      conversationId: "conv", state: { isStreaming: false, messages: [] },
      controllers: {
        streamController: { async handleStreamChunk() {} },
        inputController: { async sendMessage() { calls += 1; } },
        conversationController: { async switchTo() {} }
      }
    };
    const claudian = supportedClaudian(tab, { getConversationList: () => [] });
    if (blocked === "paused") tab.session.acceptsIntents = false;
    else if (blocked === "missing_session") delete tab.session;
    else tab.state[blocked] = true;
    const normalizer = new SemanticStreamNormalizer({ sourceInstanceId: "admission", emit: (event) => events.push(event) });
    const capture = new SourceCapture({ claudian, normalizer });
    capture.instrument(tab);
    await tab.controllers.inputController.sendMessage({ content: "ignored" });
    assert.equal(calls, 1, "desktop controller still owns its admission check");
    assert.deepEqual(events, [], blocked);
    capture.unload();
    normalizer.dispose();
  }
});

for (const [nativeType, terminalType, errorCode] of [
  ["execution_error", "turn.failed", "provider_error"],
  ["cancelled", "turn.interrupted"],
  ["turn_completed", "turn.completed"],
  [null, "turn.failed", "completion_unconfirmed"]
]) test(`2.2.6 ${nativeType || "missing terminal"} stays truthful after save`, async () => {
  const events = [];
  const nativeCalls = [];
  let releaseSave;
  const saved = new Promise((resolve) => { releaseSave = resolve; });
  const message = { id: "native-message", role: "assistant", content: "safe answer" };
  const tab = {
    conversationId: "conv-native", state: { isStreaming: false, messages: [message] },
    controllers: {
      streamController: { async handleStreamChunk() { assert.fail("native terminal events do not convert to chunks"); } },
      inputController: {
        async handleExecutionEvent(event) { nativeCalls.push([this, event]); return "native-result"; },
        async sendMessage() {
          tab.state.isStreaming = true;
          if (nativeType) {
            assert.equal(await this.handleExecutionEvent({ type: nativeType, raw: "private-provider-data" }), "native-result");
          }
          await saved;
          tab.state.isStreaming = false;
          return "saved-result";
        }
      },
      conversationController: { async switchTo() {} }
    }
  };
  const claudian = supportedClaudian(tab, { getConversationList: () => [] });
  const normalizer = new SemanticStreamNormalizer({ sourceInstanceId: "native-terminal", emit: (event) => events.push(event) });
  const capture = new SourceCapture({ claudian, normalizer });
  const input = tab.controllers.inputController;
  const originalEvent = input.handleExecutionEvent;
  capture.instrument(tab);
  const wrappedEvent = input.handleExecutionEvent;
  capture.instrument(tab);
  assert.equal(input.handleExecutionEvent, wrappedEvent);
  assert.notEqual(wrappedEvent, originalEvent);
  const pending = input.sendMessage({ content: "question" });
  try {
    await new Promise(setImmediate);
    assert.deepEqual(events.map((event) => event.event_type), ["turn.started"]);
    releaseSave();
    assert.equal(await pending, "saved-result");
    const terminals = events.filter((event) => ["turn.completed", "turn.failed", "turn.interrupted"].includes(event.event_type));
    assert.equal(terminals.length, 1);
    assert.equal(terminals[0].event_type, terminalType);
    if (errorCode) assert.equal(terminals[0].payload.error_code, errorCode);
    assert.equal(events.find((event) => event.event_type === "keyframe.page").payload.projection.turns[0].status, terminalType.slice(5));
    assert.ok(events.findIndex((event) => event.event_type === "keyframe.final") < events.indexOf(terminals[0]));
    assert.equal(JSON.stringify(events).includes("private-provider-data"), false);
    assert.equal(nativeCalls.length, nativeType ? 1 : 0);
    if (nativeType) assert.equal(nativeCalls[0][0], input);
  } finally {
    releaseSave();
    await pending;
    capture.refresh([]);
    assert.equal(input.handleExecutionEvent, originalEvent);
    capture.instrument(tab);
    capture.unload();
    assert.equal(input.handleExecutionEvent, originalEvent);
    normalizer.dispose();
  }
});

test("2.2.6 admits before yielding and a queued send preserves native terminal evidence", async () => {
  const events = [];
  let releaseStart;
  let releaseSave;
  const startPublished = new Promise((resolve) => { releaseStart = resolve; });
  const saved = new Promise((resolve) => { releaseSave = resolve; });
  let turns = 0;
  let queued = 0;
  const tab = {
    conversationId: "conv", state: { isStreaming: false, messages: [] },
    controllers: {
      streamController: { async handleStreamChunk() {} },
      inputController: {
        async sendMessage() {
          if (!tab.session.acceptsIntents) return;
          if (tab.state.isStreaming) { queued += 1; return; }
          turns += 1;
          tab.state.isStreaming = true;
          await this.handleExecutionEvent({ type: "turn_completed" });
          await saved;
          tab.state.isStreaming = false;
        }
      },
      conversationController: { async switchTo() {} }
    }
  };
  const claudian = supportedClaudian(tab, { getConversationList: () => [] });
  const normalizer = new SemanticStreamNormalizer({
    sourceInstanceId: "admission-order",
    emit: (event) => {
      events.push(event);
      if (event.event_type === "turn.started") {
        queueMicrotask(() => { tab.session.acceptsIntents = false; });
        return startPublished;
      }
    }
  });
  const capture = new SourceCapture({ claudian, normalizer });
  capture.instrument(tab);
  const pending = tab.controllers.inputController.sendMessage({ content: "first" });
  try {
    assert.equal(turns, 1, "native admission must precede the first async yield");
    await tab.controllers.inputController.sendMessage({ content: "queue" });
    assert.equal(queued, 1);
    releaseSave();
    await new Promise(setImmediate);
    assert.equal(events.some((event) => event.event_type === "turn.completed"), false);
    releaseStart();
    await pending;
    assert.equal(events.filter((event) => event.event_type === "turn.started").length, 1);
    assert.equal(events.filter((event) => event.event_type === "turn.completed").length, 1);
  } finally {
    releaseStart();
    releaseSave();
    await pending;
    capture.unload();
    normalizer.dispose();
  }
});

test("native auto-continuation keeps the shared turn running until the latest save barrier", async () => {
  const events = [];
  let releaseContinuation;
  let continuation;
  const continuationSave = new Promise((resolve) => { releaseContinuation = resolve; });
  const tab = {
    conversationId: "conv", state: { isStreaming: false, messages: [] },
    controllers: {
      streamController: { async handleStreamChunk() {} },
      inputController: {
        async sendMessage({ content }) {
          tab.state.isStreaming = true;
          await this.handleExecutionEvent({ type: content === "outer" ? "turn_completed" : "execution_error" });
          if (content === "outer") {
            tab.state.isStreaming = false;
            continuation = this.sendMessage({ content: "continuation" });
          } else {
            await continuationSave;
            tab.state.isStreaming = false;
          }
        }
      },
      conversationController: { async switchTo() {} }
    }
  };
  const claudian = supportedClaudian(tab, { getConversationList: () => [] });
  const normalizer = new SemanticStreamNormalizer({ sourceInstanceId: "continuation", emit: (event) => events.push(event) });
  const capture = new SourceCapture({ claudian, normalizer });
  capture.instrument(tab);
  try {
    await tab.controllers.inputController.sendMessage({ content: "outer" });
    assert.equal(events.some((event) => /keyframe\.|turn\.(completed|failed|interrupted)$/.test(event.event_type)), false);
    assert.equal(normalizer.projectionForTurn({ conversationId: "conv", turnId: "turn-conv" }).status, "running");
    releaseContinuation();
    await continuation;
    assert.deepEqual(events.filter((event) => /turn\.(completed|failed)$/.test(event.event_type)).map((event) => event.event_type), ["turn.failed"]);
  } finally {
    releaseContinuation();
    await continuation;
    capture.unload();
    normalizer.dispose();
  }
});

for (const version of ["2.0.4", "2.2.6"]) test(`${version} provider done is observable but completion waits for sendMessage save barrier`, async () => {
  const events = [];
  let releaseSave;
  const saved = new Promise((resolve) => { releaseSave = resolve; });
  const message = { id: "message-1", role: "assistant", content: "answer", toolCalls: [] };
  const tab = {
    conversationId: "conv-1",
    state: { isStreaming: false, messages: [message] },
    controllers: {
      streamController: { async handleStreamChunk() {} },
      inputController: {
        async sendMessage() {
          if (version === "2.2.6") await this.handleExecutionEvent({ type: "turn_completed" });
          await saved;
        },
        getActiveCapabilities: () => ({})
      },
      conversationController: { switchTo() {} }
    }
  };
  const claudian = supportedClaudian(tab, { getConversationSync: () => ({ title: "Demo", messages: [message] }), getConversationList: () => [] });
  claudian.manifest.version = version;
  if (version === "2.0.4") {
    delete tab.session;
    delete tab.controllers.inputController.handleExecutionEvent;
  }
  const normalizer = new SemanticStreamNormalizer({ sourceInstanceId: "bridge-test", emit: (event) => events.push(event) });
  const capture = new SourceCapture({ claudian, normalizer });
  capture.instrument(tab);
  await tab.controllers.streamController.handleStreamChunk({ type: "done" }, message);
  const pending = tab.controllers.inputController.sendMessage({ content: "question" });
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(events.some((event) => event.event_type === "turn.completed"), false);
  releaseSave();
  await pending;
  const types = events.map((event) => event.event_type);
  assert.ok(types.indexOf("keyframe.final") < types.indexOf("turn.completed"));
  const commit = events.find((event) => event.event_type === "keyframe.final");
  const complete = events.find((event) => event.event_type === "turn.completed");
  assert.equal(complete.payload.checksum, commit.payload.checksum);
});

test("queued send does not emit a false completion barrier", async () => {
  const events = [];
  const tab = {
    conversationId: "conv-1", state: { isStreaming: true, messages: [] },
    controllers: {
      streamController: { async handleStreamChunk() {} },
      inputController: { async sendMessage() {}, getActiveCapabilities: () => ({}) },
      conversationController: { switchTo() {} }
    }
  };
  const normalizer = new SemanticStreamNormalizer({ sourceInstanceId: "bridge-test", emit: (event) => events.push(event) });
  const capture = new SourceCapture({ claudian: supportedClaudian(tab, { getConversationSync: () => null, getConversationList: () => [] }), normalizer });
  capture.instrument(tab);
  await tab.controllers.inputController.sendMessage({ content: "queued" });
  assert.equal(events.some((event) => event.event_type === "turn.completed"), false);
});

test("legacy 2.0.4 error chunk converges to one failed terminal without a session", async () => {
  const events = [];
  const message = { id: "message-1", role: "assistant", content: "", toolCalls: [] };
  const tab = {
    conversationId: "conv-1", state: { isStreaming: false, messages: [message] },
    controllers: {
      streamController: { async handleStreamChunk() {} },
      inputController: { async sendMessage() {}, getActiveCapabilities: () => ({}) },
      conversationController: { switchTo() {} }
    }
  };
  const normalizer = new SemanticStreamNormalizer({ sourceInstanceId: "bridge-test", emit: (event) => events.push(event) });
  const claudian = supportedClaudian(tab, { getConversationSync: () => ({ title: "Demo", messages: [message] }), getConversationList: () => [] });
  claudian.manifest.version = "2.0.4";
  delete tab.session;
  delete tab.controllers.inputController.handleExecutionEvent;
  const capture = new SourceCapture({ claudian, normalizer });
  capture.instrument(tab);
  await tab.controllers.streamController.handleStreamChunk({ type: "error", content: "private provider failure" }, message);
  await tab.controllers.inputController.sendMessage({ content: "question" });
  const terminals = events.filter((event) => ["turn.completed", "turn.failed", "turn.interrupted"].includes(event.event_type));
  assert.equal(terminals.length, 1);
  assert.equal(terminals[0].event_type, "turn.failed");
  assert.equal(events.find((event) => event.event_type === "keyframe.page").payload.projection.turns[0].status, "failed");
  assert.equal(JSON.stringify(events).includes("private provider failure"), false);
});

test("late repeated stop overrides native completion before the save barrier", async () => {
  const events = [];
  let release;
  const cancelled = new Promise((resolve) => { release = resolve; });
  let cancelCalls = 0;
  const message = { id: "message-stop", role: "assistant", content: "partial", toolCalls: [] };
  const tab = {
    conversationId: "conv-stop",
    state: { isStreaming: false, currentConversationId: "conv-stop", remoteTurnId: "turn-stop", queuedMessage: null, messages: [message] },
    controllers: {
      streamController: { async handleStreamChunk() {} },
      inputController: {
        async sendMessage() {
          tab.state.isStreaming = true;
          tab.state.queuedMessage = { content: "queued draft stays on desktop" };
          await this.handleExecutionEvent({ type: "turn_completed" });
          await cancelled;
          tab.state.isStreaming = false;
        },
        cancelStreaming() {
          cancelCalls += 1;
          tab.state.queuedMessage = null;
          release();
        },
        getActiveCapabilities: () => ({})
      },
      conversationController: { switchTo() {} }
    }
  };
  const claudian = supportedClaudian(tab, { getConversationSync: () => ({ title: "Demo", messages: [message] }), getConversationList: () => [] });
  const normalizer = new SemanticStreamNormalizer({ sourceInstanceId: "bridge-test", emit: (event) => events.push(event) });
  const capture = new SourceCapture({ claudian, normalizer });
  capture.instrument(tab);
  const adapter = new DesktopAdapter({
    claudian,
    capture,
    getActiveTab: () => tab,
    macSessionId: "session-stop",
    connectionGeneration: 1
  });

  const pending = tab.controllers.inputController.sendMessage({ content: "question" });
  await new Promise((resolve) => setTimeout(resolve, 0));
  const remoteStop = adapter.execute({
    protocol: "claudian.remote.v2",
    kind: "command",
    command_type: "turn.stop",
    delivery_id: "delivery-stop",
    mac_session_id: "session-stop",
    mac_connection_generation: 1,
    expires_at: "2099-01-01T00:00:00Z",
    expected_revision: normalizer.revisionFor("conv-stop"),
    target: { conversation_id: "conv-stop", turn_id: "turn-stop" },
    payload: {}
  });
  tab.controllers.inputController.cancelStreaming();
  assert.equal((await remoteStop).status, "executed");
  await pending;

  const terminals = events.filter((event) => ["turn.completed", "turn.interrupted", "turn.failed"].includes(event.event_type));
  assert.equal(cancelCalls, 2);
  assert.equal(terminals.length, 1);
  assert.equal(terminals[0].event_type, "turn.interrupted");
  assert.deepEqual(terminals[0].payload, { status: "interrupted", queued_draft_returned: true });
  const finalIndex = events.findIndex((event) => event.event_type === "keyframe.final");
  assert.ok(finalIndex >= 0 && finalIndex < events.indexOf(terminals[0]));
  const page = events.find((event) => event.event_type === "keyframe.page");
  assert.equal(page.payload.projection.turns[0].status, "interrupted");
  await capture.emitKeyframe(tab);
  const recoveryPage = events.filter((event) => event.event_type === "keyframe.page").at(-1);
  assert.equal(recoveryPage.payload.projection.turns[0].status, "interrupted");
});

test("completion keyframe carries the observed mobile-safe operation, approvals, and artifacts", async () => {
  const events = [];
  let release;
  const saved = new Promise((resolve) => { release = resolve; });
  const message = { id: "message-state", role: "assistant", content: "answer", toolCalls: [] };
  const tab = {
    conversationId: "conv-state",
    state: { isStreaming: false, currentConversationId: "conv-state", remoteTurnId: "turn-state", messages: [message] },
    controllers: {
      streamController: { async handleStreamChunk() {} },
      inputController: {
        async sendMessage() {
          tab.state.isStreaming = true;
          await this.handleExecutionEvent({ type: "turn_completed" });
          await saved;
          tab.state.isStreaming = false;
        },
        cancelStreaming() {},
        getActiveCapabilities: () => ({})
      },
      conversationController: { switchTo() {} }
    }
  };
  const claudian = supportedClaudian(tab, { getConversationSync: () => ({ title: "Stateful", messages: [message] }), getConversationList: () => [] });
  const normalizer = new SemanticStreamNormalizer({ sourceInstanceId: "bridge-test", emit: (event) => events.push(event) });
  const capture = new SourceCapture({ claudian, normalizer });
  capture.instrument(tab);

  const pending = tab.controllers.inputController.sendMessage({ content: "question" });
  await new Promise((resolve) => setTimeout(resolve, 0));
  const base = { conversationId: "conv-state", turnId: "turn-state", messageId: "message-state" };
  await normalizer.emit("activity.updated", { ...base, blockId: "activity-read" }, { stage: "reading", label: "正在读取文件", detail: "2 个文件", status: "running" });
  await normalizer.emit("tool.started", { ...base, blockId: "tool-read" }, { tool_name: "read", label: "正在使用 read", status: "running", started_at: "2026-07-15T00:00:00.000Z" });
  await normalizer.emit("tool.completed", { ...base, blockId: "tool-read" }, { tool_name: "read", label: "已完成 read", status: "completed", duration_ms: 12, summary: "操作已完成" });
  normalizer.recordProjectionEvent("tool.completed", { ...base, blockId: "tool-read" }, {
    tool_name: "read", label: "已完成 read", status: "completed",
    command: "synthetic-command-must-not-project", raw_input: { path: "/synthetic/private" }
  });
  await normalizer.emit("approval.requested", { ...base, approvalId: "approval-pending" }, {
    approval_id: "approval-pending", title: "允许写入？", options: [{ id: "allow", label: "允许" }], status: "pending"
  });
  await normalizer.emit("approval.requested", { ...base, approvalId: "approval-resolved" }, {
    approval_id: "approval-resolved", title: "允许运行？", options: [{ id: "deny", label: "拒绝" }], status: "pending"
  });
  await normalizer.emit("approval.resolved", { ...base, approvalId: "approval-resolved" }, {
    approval_id: "approval-resolved", selected: "deny", status: "resolved", resolved_by: "desktop"
  });
  await normalizer.emit("artifact.available", base, {
    artifact_id: "artifact-note", kind: "markdown", label: "结果.md", vault_path: "Claudian Remote/Uploads/结果.md", size: 128
  });
  release();
  await pending;

  const finalIndex = events.findIndex((event) => event.event_type === "keyframe.final");
  const terminalIndex = events.findIndex((event) => event.event_type === "turn.completed");
  assert.ok(finalIndex >= 0 && finalIndex < terminalIndex);
  const turn = events.find((event) => event.event_type === "keyframe.page").payload.projection.turns[0];
  assert.equal(turn.status, "completed");
  assert.deepEqual(turn.current_operation.activities[0], {
    id: "activity-read", stage: "reading", label: "正在读取文件", detail: "2 个文件", status: "completed"
  });
  assert.deepEqual(turn.current_operation.tools[0], {
    id: "tool-read", tool_name: "read", label: "已完成 read", status: "completed",
    started_at: "2026-07-15T00:00:00.000Z", duration_ms: 12, summary: "操作已完成"
  });
  assert.equal(turn.approvals.length, 2);
  assert.equal(turn.approvals.find((approval) => approval.id === "approval-pending").status, "pending");
  assert.deepEqual(turn.approvals.find((approval) => approval.id === "approval-resolved"), {
    id: "approval-resolved", approval_id: "approval-resolved", title: "允许运行？",
    options: [{ id: "deny", label: "拒绝" }], selected: "deny", status: "resolved", resolved_by: "desktop"
  });
  assert.deepEqual(turn.artifacts, [{
    id: "artifact-note", artifact_id: "artifact-note", kind: "markdown", label: "结果.md",
    vault_path: "Claudian Remote/Uploads/结果.md", size: 128
  }]);
  assert.equal(JSON.stringify(turn).includes("queued draft"), false);
  assert.equal(JSON.stringify(turn).includes("synthetic-command-must-not-project"), false);
});
