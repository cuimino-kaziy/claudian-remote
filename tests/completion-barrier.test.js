import assert from "node:assert/strict";
import test from "node:test";
import { DesktopAdapter } from "../src/desktop-adapter.js";
import { SourceCapture } from "../src/source-capture.js";
import { SemanticStreamNormalizer } from "../src/stream-normalizer.js";

function supportedClaudian(tab, value = {}) {
  const input = tab.controllers.inputController;
  if (typeof input.cancelStreaming !== "function") input.cancelStreaming = () => {};
  if (typeof input.steerQueuedMessage !== "function") input.steerQueuedMessage = async () => {};
  if (typeof input.handleApprovalRequest !== "function") input.handleApprovalRequest = async () => "cancel";
  const activeCapabilities = input.getActiveCapabilities?.bind(input);
  input.getActiveCapabilities = () => ({ ...(activeCapabilities?.() || {}), supportsTurnSteer: true });
  return { manifest: { id: "realclaudian", version: "2.0.4" }, ...value };
}

test("provider done is observable but completion waits for sendMessage save barrier", async () => {
  const events = [];
  let releaseSave;
  const saved = new Promise((resolve) => { releaseSave = resolve; });
  const message = { id: "message-1", role: "assistant", content: "answer", toolCalls: [] };
  const tab = {
    conversationId: "conv-1",
    state: { isStreaming: false, messages: [message] },
    controllers: {
      streamController: { async handleStreamChunk() {} },
      inputController: { async sendMessage() { await saved; }, getActiveCapabilities: () => ({}) },
      conversationController: { switchTo() {} }
    }
  };
  const claudian = supportedClaudian(tab, { getConversationSync: () => ({ title: "Demo", messages: [message] }), getConversationList: () => [] });
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

test("error chunk converges to one failed terminal instead of completed plus failed", async () => {
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
  const capture = new SourceCapture({ claudian: supportedClaudian(tab, { getConversationSync: () => ({ title: "Demo", messages: [message] }), getConversationList: () => [] }), normalizer });
  capture.instrument(tab);
  await tab.controllers.streamController.handleStreamChunk({ type: "error", content: "private provider failure" }, message);
  await tab.controllers.inputController.sendMessage({ content: "question" });
  const terminals = events.filter((event) => ["turn.completed", "turn.failed", "turn.interrupted"].includes(event.event_type));
  assert.equal(terminals.length, 1);
  assert.equal(terminals[0].event_type, "turn.failed");
  assert.equal(events.find((event) => event.event_type === "keyframe.page").payload.projection.turns[0].status, "failed");
  assert.equal(JSON.stringify(events).includes("private provider failure"), false);
});

test("repeated stop emits one interrupted terminal after an interrupted final keyframe", async () => {
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
