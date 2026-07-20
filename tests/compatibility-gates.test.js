import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

import {
  COMPATIBILITY_SET,
  evaluateClaudianCompatibility,
  evaluateCompatibilitySet
} from "../src/protocol/compatibility.js";
import { buildCommand } from "../src/mobile/command-builder.js";
import { controlAvailability } from "../src/mobile/capabilities.js";
import { MobileReplica } from "../src/mobile/reducer.js";
import { DesktopAdapter } from "../src/desktop-adapter.js";
import { SourceCapture } from "../src/source-capture.js";
import { SemanticStreamNormalizer } from "../src/stream-normalizer.js";

const fixture = JSON.parse(fs.readFileSync(
  path.resolve(import.meta.dirname, "fixtures/claudian-2.0.4-compatibility.json"),
  "utf8"
));

function requiredCapabilities(overrides = {}) {
  return Object.fromEntries(fixture.required_capabilities.map((key) => [key, overrides[key] ?? true]));
}

function writableState() {
  return {
    transport: { status: "connected" },
    presence: { mac: { status: "online", sessionId: "mac", connectionGeneration: 1 } },
    compatibility: { writable: true, reason: "ready", remediation: null },
    capabilities: requiredCapabilities(),
    recovery: { required: false },
    activeConversationId: "conv",
    conversations: {
      conv: { id: "conv", revision: 4, activeTurnId: "turn", turnOrder: ["turn"], turns: { turn: { id: "turn", status: "idle" } } }
    }
  };
}

test("versioned Claudian 2.0.4 fixture is the only writable manifest", () => {
  const supported = evaluateClaudianCompatibility({
    manifest: fixture.claudian,
    capabilities: requiredCapabilities()
  });
  assert.equal(supported.writable, true);
  assert.equal(supported.current_version, "2.0.4");
  assert.equal(supported.required_version, "2.0.4");
  assert.deepEqual(COMPATIBILITY_SET, fixture.compatibility_set);

  for (const version of ["2.0.3", "2.0.5", "", null]) {
    const result = evaluateClaudianCompatibility({
      manifest: { id: "realclaudian", version },
      capabilities: requiredCapabilities()
    });
    assert.equal(result.writable, false);
    assert.equal(result.reason, "unsupported_claudian_version");
    assert.equal(result.required_version, "2.0.4");
  }
});

test("supported version still fails closed when a required writable capability is absent", () => {
  const result = evaluateClaudianCompatibility({
    manifest: fixture.claudian,
    capabilities: requiredCapabilities({ stop: false })
  });
  assert.equal(result.writable, false);
  assert.equal(result.reason, "required_capability_missing");
  assert.deepEqual(result.missing_capabilities, ["stop"]);
});

test("every component, protocol, and configuration schema mismatch has precise read-only remediation", () => {
  assert.equal(evaluateCompatibilitySet(COMPATIBILITY_SET).writable, true);
  for (const field of ["plugin", "companion", "relay", "protocol", "configuration_schema"]) {
    const actual = { ...COMPATIBILITY_SET, [field]: field === "configuration_schema" ? 2 : "mismatch" };
    const result = evaluateCompatibilitySet(actual);
    assert.equal(result.writable, false, field);
    assert.equal(result.reason, "compatibility_set_mismatch", field);
    assert.deepEqual(result.mismatches.map((item) => item.component), [field]);
    assert.match(result.remediation, /update/i);
  }
});

test("mixed compatibility preserves cached history but disables every state-changing control", async () => {
  const replica = new MobileReplica({
    ...writableState(),
    history: { items: [{ conversation_id: "old", title: "Cached" }], loaded: true }
  });
  await replica.applyFrame({
    type: "authenticated",
    compatibility: { ...COMPATIBILITY_SET, relay: "0.1.0" }
  });
  assert.equal(replica.state.history.items[0].title, "Cached");
  assert.equal(replica.state.compatibility.writable, false);
  assert.deepEqual(controlAvailability(replica.state), {
    send: false, stop: false, steer: false, approval: false, history: false, historySelect: false
  });
  assert.throws(() => buildCommand(replica.state, "message.submit", { text: "blocked" }), /compatibility_mismatch/);
});

test("matching handshake metadata allows commands without weakening session and revision binding", () => {
  const state = writableState();
  const command = buildCommand(state, "message.submit", { text: "hello" }, { deliveryId: "delivery", now: () => 0 });
  assert.equal(command.protocol, COMPATIBILITY_SET.protocol);
  assert.equal(command.mac_session_id, "mac");
  assert.equal(command.expected_revision, 4);
});

test("unsupported Claudian bootstrap preserves diagnostics and history while desktop mutation fails closed", async () => {
  const events = [];
  let sendCalls = 0;
  const tab = {
    conversationId: "conv",
    state: { isStreaming: false, remoteTurnId: "turn", messages: [] },
    controllers: {
      streamController: { async handleStreamChunk() {} },
      inputController: {
        async sendMessage() { sendCalls += 1; },
        cancelStreaming() {},
        steerQueuedMessage() {},
        handleApprovalRequest() {},
        getActiveCapabilities: () => ({ supportsTurnSteer: true })
      },
      conversationController: { async switchTo() {} }
    }
  };
  const claudian = {
    manifest: { id: "realclaudian", version: "2.0.5" },
    getConversationSync: () => ({ id: "conv", title: "Cached diagnostics", messages: [] }),
    getConversationList: () => [{ id: "conv", title: "Cached diagnostics" }]
  };
  const normalizer = new SemanticStreamNormalizer({ sourceInstanceId: "compatibility-test", emit: (event) => events.push(event) });
  const capture = new SourceCapture({ claudian, normalizer });
  capture.instrument(tab);
  await capture.emitBootstrap(tab);

  const capability = events.find((event) => event.event_type === "capability.state");
  assert.equal(capability.payload.writable, false);
  assert.equal(capability.payload.current_version, "2.0.5");
  assert.equal(capability.payload.required_version, "2.0.4");
  assert.ok(events.some((event) => event.event_type === "keyframe.page"));

  const adapter = new DesktopAdapter({
    claudian,
    capture,
    getActiveTab: () => tab,
    macSessionId: "mac",
    connectionGeneration: 1
  });
  const result = await adapter.execute({
    protocol: "claudian.remote.v2",
    kind: "command",
    command_type: "message.submit",
    delivery_id: "blocked",
    mac_session_id: "mac",
    mac_connection_generation: 1,
    expires_at: "2099-01-01T00:00:00Z",
    expected_revision: normalizer.revisionFor("conv"),
    target: { conversation_id: "conv", turn_id: "turn" },
    payload: { text: "must not run" }
  });
  assert.equal(result.status, "compatibility_mismatch");
  assert.equal(result.current_version, "2.0.5");
  assert.equal(sendCalls, 0);
  normalizer.dispose();
});

test("an instrumented tab is unwrapped immediately when its Claudian version drifts", () => {
  const originalChunk = async function originalChunk() {};
  const originalSend = async function originalSend() {};
  const tab = {
    conversationId: "conv",
    state: { messages: [] },
    controllers: {
      streamController: { handleStreamChunk: originalChunk },
      inputController: {
        sendMessage: originalSend,
        cancelStreaming() {},
        steerQueuedMessage() {},
        handleApprovalRequest() {},
        getActiveCapabilities: () => ({ supportsTurnSteer: true })
      },
      conversationController: { async switchTo() {} }
    }
  };
  const claudian = {
    manifest: { id: "realclaudian", version: "2.0.4" },
    getConversationList: () => []
  };
  const normalizer = new SemanticStreamNormalizer({ sourceInstanceId: "drift-test", emit: () => {} });
  const capture = new SourceCapture({ claudian, normalizer });

  capture.instrument(tab);
  assert.notEqual(tab.controllers.streamController.handleStreamChunk, originalChunk);
  assert.notEqual(tab.controllers.inputController.sendMessage, originalSend);

  claudian.manifest.version = "2.0.5";
  capture.instrument(tab);
  assert.equal(tab.controllers.streamController.handleStreamChunk, originalChunk);
  assert.equal(tab.controllers.inputController.sendMessage, originalSend);
  assert.equal(capture.compatibilityState.writable, false);
  normalizer.dispose();
});
