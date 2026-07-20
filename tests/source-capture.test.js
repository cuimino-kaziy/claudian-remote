import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import vm from "node:vm";
import test from "node:test";
import { DesktopAdapter } from "../src/desktop-adapter.js";
import { SourceCapture, discoverClaudianTabs, safeKeyframe } from "../src/source-capture.js";
import { canonicalJson, SemanticStreamNormalizer, sha256 } from "../src/stream-normalizer.js";

function fixture() {
  const events = [];
  const tab = {
    conversationId: "conv-1",
    state: { isStreaming: true, messages: [] },
    controllers: {
      streamController: {
        async handleStreamChunk(chunk, message) {
          if (chunk.type === "text") message.content += chunk.content;
          if (chunk.type === "thinking") message.privateReasoning = chunk.content;
        }
      },
      inputController: {
        getActiveCapabilities: () => ({ supportsTurnSteer: true }),
        async sendMessage() {}, cancelStreaming() {}, steerQueuedMessage() {}, handleApprovalRequest() {}
      },
      conversationController: { async switchTo() {} }
    }
  };
  const claudian = {
    getConversationSync: () => ({ id: "conv-1", title: "Demo", messages: tab.state.messages }),
    getConversationList: () => [],
    getAllViews: () => [{ getTabManager: () => ({ getActiveTab: () => tab, tabs: [tab] }) }]
  };
  const normalizer = new SemanticStreamNormalizer({ sourceInstanceId: "bridge-test", emit: (event) => events.push(event), batchMs: 1 });
  return { events, tab, claudian, normalizer };
}

test("real Claudian 2.0.4 bundle contains every private hook used by the bridge", (t) => {
  const bundle = process.env.CLAUDIAN_BUNDLE_PATH || path.join(
    os.homedir(), "Library", "Mobile Documents", "iCloud~md~obsidian", "Documents", "Vault",
    ".obsidian", "plugins", "Claudian", "main.js"
  );
  if (!fs.existsSync(bundle)) return t.skip("installed Claudian bundle is unavailable");
  const text = fs.readFileSync(bundle, "utf8");
  for (const marker of ["handleStreamChunk", "sendMessage", "cancelStreaming", "steerQueuedMessage", "getConversationList", "getConversationSync", "async switchTo(id)"]) {
    assert.ok(text.includes(marker), `missing real bundle marker: ${marker}`);
  }
});

test("generated Obsidian entry exports the plugin class directly", () => {
  const bundle = fs.readFileSync(path.resolve(import.meta.dirname, "../main.js"), "utf8");
  const module = { exports: {} };
  const Plugin = class {};
  const ItemView = class {};
  const Modal = class {};
  const PluginSettingTab = class {};
  vm.runInNewContext(bundle, {
    module, exports: module.exports, require: (name) => {
      assert.equal(name, "obsidian");
      return {
        Plugin,
        ItemView,
        Modal,
        PluginSettingTab,
        Setting: class {},
        Component: class {},
        MarkdownRenderer: {},
        Notice: class {},
        Platform: { isMobileApp: false }
      };
    },
    console, crypto: globalThis.crypto, TextEncoder, setTimeout, clearTimeout, setInterval, clearInterval
  });
  assert.equal(typeof module.exports, "function");
  assert.ok(module.exports.prototype instanceof Plugin);
});

test("desktop keyframe route emits a complete bootstrap with capabilities", () => {
  const source = fs.readFileSync(path.resolve(import.meta.dirname, "../src/plugin.js"), "utf8");
  const handler = source.match(/const keyframeHandler[\s\S]*?const keyframeRoute/)?.[0] || "";
  assert.match(handler, /capture\.emitBootstrap\(tab\)/);
  assert.doesNotMatch(handler, /capture\.emitKeyframe\(tab\)/);
});

test("post-commit capture observes canonical text and never emits raw thinking", async () => {
  const { events, tab, claudian, normalizer } = fixture();
  const capture = new SourceCapture({ claudian, normalizer });
  capture.instrument(tab);
  const message = { id: "message-1", content: "", toolCalls: [] };
  await tab.controllers.streamController.handleStreamChunk({ type: "thinking", content: "private chain" }, message);
  await tab.controllers.streamController.handleStreamChunk({ type: "text", content: "safe reply" }, message);
  await normalizer.flushText();
  assert.equal(message.content, "safe reply");
  assert.ok(events.some((event) => event.event_type === "text.delta" && event.payload.text === "safe reply"));
  assert.equal(JSON.stringify(events).includes("private chain"), false);
});

test("a new run resets projected operations and bootstrap never promotes historical message tools", async () => {
  const events = [];
  const normalizer = new SemanticStreamNormalizer({ sourceInstanceId: "bridge-reset", emit: (event) => events.push(event) });
  const context = { conversationId: "conv-reset", turnId: "shared-turn", messageId: "assistant", blockId: "operation" };
  await normalizer.emit("turn.started", context, { status: "running" });
  await normalizer.emit("activity.updated", context, { stage: "old", label: "旧活动", status: "completed" });
  await normalizer.emit("tool.completed", context, { tool_name: "old", label: "旧工具", status: "completed" });
  await normalizer.emit("turn.completed", context, { status: "completed" });
  await normalizer.emit("turn.started", context, { status: "running" });

  const current = normalizer.projectionForTurn(context).current_operation;
  assert.deepEqual(current.activities, []);
  assert.deepEqual(current.tools, []);

  const historicalMessage = {
    id: "historical-assistant", role: "assistant", content: "旧回答",
    toolCalls: [{ id: "historical-tool", name: "read", status: "completed" }]
  };
  const tab = { conversationId: "conv-reset", state: { remoteTurnId: "shared-turn", messages: [historicalMessage] } };
  const projection = safeKeyframe(
    { getConversationSync: () => ({ title: "Reset", messages: tab.state.messages }) },
    tab,
    { projectionState: normalizer.projectionForTurn(context) }
  );
  assert.deepEqual(projection.turns[0].current_operation.tools, []);
});

test("source firewall redacts absolute Mac paths with spaces and alternate roots while preserving Vault-relative links", () => {
  const content = [
    "[Mobile note](file:///Users/example/Library/Mobile Documents/iCloud~md~obsidian/Documents/Vault/Study Notes/Today.md)",
    '"/Volumes/Archive Drive/Notes/a.md"',
    '"/Applications/Obsidian.app/Contents/MacOS/Obsidian"',
    '"/private/var/folders/cache/report.json"',
    '"/tmp/claudian jobs/report.txt"',
    '"/Library/Application Support/Claudian/state.db"',
    '"/System/Library/CoreServices/Finder.app"',
    '"/opt/claudian remote/config.json"',
    "Keep [[Study Notes/Today]] and [relative](Study Notes/Today.md).",
    "Keep https://example.com/tmp/page and project/Users/example/note.md."
  ].join("\n");
  const tab = { conversationId: "conv-paths", state: { messages: [{ id: "message-paths", role: "assistant", content }] } };
  const claudian = { getConversationSync: () => ({ title: "Paths", messages: tab.state.messages }) };

  const serialized = JSON.stringify(safeKeyframe(claudian, tab));

  for (const leaked of ["file:///Users/", "Mobile Documents", "/Volumes/", "/Applications/", "/private/", "/tmp/claudian", "/Library/", "/System/", "/opt/"]) {
    assert.equal(serialized.includes(leaked), false, `leaked ${leaked}`);
  }
  assert.match(serialized, /\[local path hidden\]/);
  assert.match(serialized, /\[\[Study Notes\/Today\]\]/);
  assert.match(serialized, /\[relative\]\(Study Notes\/Today\.md\)/);
  assert.match(serialized, /https:\/\/example\.com\/tmp\/page/);
  assert.match(serialized, /project\/Users\/example\/note\.md/);
});

test("configured opaque role credential is redacted from live deltas and keyframes", async (t) => {
  const credential = "synthetic-opaque-mobile-role-value-7Qx9";
  const events = [];
  const normalizer = new SemanticStreamNormalizer({
    sourceInstanceId: "bridge-secret-test",
    exactSecrets: new Set([credential]),
    emit: (event) => events.push(event),
    batchMs: 1
  });
  t.after(() => normalizer.dispose?.());
  const context = { conversationId: "conv-secret", turnId: "turn-secret", messageId: "message-secret", blockId: "text-secret" };
  const content = [
    `mobile_token=${credential}`,
    `Authorization: ${credential}`,
    `X-Mobile-Token: ${credential}`,
    `Bare value: ${credential}`,
    "[Mobile file](file:///Users/example/Library/Mobile Documents/iCloud~md~obsidian/Documents/Vault/Secret Note.md)"
  ].join("\n");

  await normalizer.observeText({ content }, context);
  await normalizer.flushText();
  const tab = { conversationId: "conv-secret", state: { messages: [{ id: "message-secret", role: "assistant", content }] } };
  const claudian = { getConversationSync: () => ({ title: `Session ${credential}`, messages: tab.state.messages }) };
  const liveSerialized = JSON.stringify(events);
  const keyframeSerialized = JSON.stringify(safeKeyframe(claudian, tab));

  for (const serialized of [liveSerialized, keyframeSerialized]) {
    assert.equal(serialized.includes(credential), false);
    assert.equal(serialized.includes("Mobile Documents"), false);
    assert.match(serialized, /\[secret hidden\]/);
    assert.match(serialized, /\[local path hidden\]/);
  }
});

test("desktop plugin injects, refreshes, and disposes the configured source-firewall credential", () => {
  const source = fs.readFileSync(path.resolve(import.meta.dirname, "../src/plugin.js"), "utf8");
  assert.match(source, /exactSecrets:\s*this\.sourceFirewallSecrets\(\)/);
  assert.match(source, /normalizer\?\.setExactSecrets\(this\.sourceFirewallSecrets\(\)\)/);
  assert.match(source, /normalizer\?\.dispose\(\)/);
});

test("idle send emits turn.started before streamed progress and terminal events", async () => {
  const { events, tab, claudian, normalizer } = fixture();
  tab.state.isStreaming = false;
  tab.controllers.inputController.sendMessage = async () => {
    const message = { id: "message-started", role: "assistant", content: "", toolCalls: [] };
    tab.state.messages.push(message);
    tab.state.isStreaming = true;
    await tab.controllers.streamController.handleStreamChunk({ type: "text", content: "hello" }, message);
    tab.state.isStreaming = false;
  };
  const capture = new SourceCapture({ claudian, normalizer });
  capture.instrument(tab);

  await tab.controllers.inputController.sendMessage({ content: "start" });

  const types = events.map((event) => event.event_type);
  for (const type of ["turn.started", "text.delta", "keyframe.final", "turn.completed"]) {
    assert.notEqual(types.indexOf(type), -1, `missing ${type}: ${types.join(",")}`);
  }
  assert.ok(types.indexOf("turn.started") < types.indexOf("text.delta"), types.join(","));
  assert.ok(types.indexOf("text.delta") < types.indexOf("keyframe.final"), types.join(","));
  assert.ok(types.indexOf("keyframe.final") < types.indexOf("turn.completed"), types.join(","));
});

test("remote submission keyframe binds the authoritative user message to its delivery", async () => {
  const { events, tab, claudian, normalizer } = fixture();
  tab.state.isStreaming = false;
  tab.state.remoteTurnId = "turn-1";
  tab.controllers.inputController.sendMessage = async ({ content }) => {
    const user = { id: "user-remote", role: "user", content, toolCalls: [] };
    const assistant = { id: "assistant-remote", role: "assistant", content: "", toolCalls: [] };
    tab.state.messages.push(user, assistant);
    tab.state.isStreaming = true;
    await tab.controllers.streamController.handleStreamChunk({ type: "text", content: "answer" }, assistant);
    tab.state.isStreaming = false;
  };
  const capture = new SourceCapture({ claudian, normalizer });
  capture.instrument(tab);
  const adapter = new DesktopAdapter({
    claudian,
    capture,
    getActiveTab: () => tab,
    macSessionId: "session-a",
    connectionGeneration: 1
  });
  const command = {
    protocol: "claudian.remote.v2",
    kind: "command",
    command_type: "message.submit",
    delivery_id: "mobile-delivery-1",
    mac_session_id: "session-a",
    mac_connection_generation: 1,
    expires_at: "2099-01-01T00:00:00Z",
    expected_revision: 0,
    target: { conversation_id: "conv-1", turn_id: "turn-1" },
    payload: { text: "question" }
  };

  assert.equal((await adapter.execute(command)).status, "executed");
  for (let index = 0; index < 20 && !events.some((event) => event.event_type === "keyframe.page"); index += 1) {
    await new Promise((resolve) => setTimeout(resolve, 1));
  }

  const page = events.find((event) => event.event_type === "keyframe.page");
  const user = page?.payload?.projection?.turns?.[0]?.messages?.find((message) => message.id === "user-remote");
  assert.equal(user?.origin_delivery_id, "mobile-delivery-1");
});

test("capture is idempotent and restores removed and unloaded tabs", () => {
  const { tab, claudian, normalizer } = fixture();
  const original = tab.controllers.streamController.handleStreamChunk;
  const originalCancel = tab.controllers.inputController.cancelStreaming;
  const capture = new SourceCapture({ claudian, normalizer });
  capture.refresh(discoverClaudianTabs(claudian));
  const wrapped = tab.controllers.streamController.handleStreamChunk;
  const wrappedCancel = tab.controllers.inputController.cancelStreaming;
  assert.notEqual(wrappedCancel, originalCancel);
  capture.refresh(discoverClaudianTabs(claudian));
  assert.equal(tab.controllers.streamController.handleStreamChunk, wrapped);
  assert.equal(tab.controllers.inputController.cancelStreaming, wrappedCancel);
  capture.refresh([]);
  assert.equal(tab.controllers.streamController.handleStreamChunk, original);
  assert.equal(tab.controllers.inputController.cancelStreaming, originalCancel);
  capture.instrument(tab);
  capture.unload();
  assert.equal(tab.controllers.streamController.handleStreamChunk, original);
  assert.equal(tab.controllers.inputController.cancelStreaming, originalCancel);
});

test("tab discovery uses the real Claudian TabManager getAllTabs contract", () => {
  const first = { id: "tab-1" };
  const second = { id: "tab-2" };
  const claudian = { getAllViews: () => [{ getTabManager: () => ({ getActiveTab: () => first, getAllTabs: () => [first, second] }) }] };
  assert.deepEqual(discoverClaudianTabs(claudian), [first, second]);
});

test("hook failure does not reject the desktop handler and enters compatibility mode", async () => {
  const { tab, claudian } = fixture();
  const diagnostics = [];
  const capture = new SourceCapture({
    claudian,
    normalizer: { observePostCommit: async () => { throw new Error("normalizer failed"); }, revisionFor: () => 0 },
    diagnostic: (item) => diagnostics.push(item)
  });
  capture.instrument(tab);
  const message = { id: "message-1", content: "" };
  await assert.doesNotReject(() => tab.controllers.streamController.handleStreamChunk({ type: "text", content: "desktop survives" }, message));
  assert.equal(message.content, "desktop survives");
  assert.equal(capture.compatibilityMode, true);
  assert.deepEqual(diagnostics[0], { type: "source_hook_failed", error_type: "Error" });
});

test("JavaScript checksum matches the shared Python known digest", async () => {
  const root = path.resolve(import.meta.dirname, "..");
  const keyframeFixture = JSON.parse(fs.readFileSync(path.join(root, "gateway/protocol/fixtures/v2/replay-gap-keyframe.json"), "utf8"));
  assert.equal(await sha256(keyframeFixture.projection), keyframeFixture.checksum);
  const withTransport = { ...keyframeFixture.projection, epoch: "ignored", cursor: 99, transport: { replayed: true }, checksum: "ignored" };
  assert.equal(canonicalJson(withTransport), canonicalJson(keyframeFixture.projection));
});

test("captured JavaScript events pass the executable Python v2 contract", async () => {
  const { events, tab, claudian, normalizer } = fixture();
  const capture = new SourceCapture({ claudian, normalizer });
  capture.instrument(tab);
  const message = { id: "message-1", content: "", toolCalls: [] };
  await tab.controllers.streamController.handleStreamChunk({ type: "text", content: "hello" }, message);
  await normalizer.flushText();
  const root = path.resolve(import.meta.dirname, "..");
  const checked = spawnSync("python3", ["-c", "import json,sys; from gateway.protocol.stream_protocol import validate_event; [validate_event(x) for x in json.load(sys.stdin)]"], {
    cwd: root, input: JSON.stringify(events), encoding: "utf8"
  });
  assert.equal(checked.status, 0, checked.stderr);
});
