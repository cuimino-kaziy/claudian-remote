import assert from "node:assert/strict";
import test from "node:test";
import {
  BRIDGE_SUBPROTOCOL,
  CompanionChannel,
  DesktopBridgeRouter,
  bridgeProof
} from "../src/desktop/companion-channel.js";

class FakeSocket {
  constructor(url, protocol) {
    this.url = url;
    this.protocol = protocol;
    this.sent = [];
    this.readyState = 1;
  }
  send(value) { this.sent.push(JSON.parse(value)); }
  close() { this.readyState = 3; }
  receive(frame) { this.onmessage?.({ data: JSON.stringify(frame) }); }
}

function fixture() {
  const events = [];
  const calls = [];
  const tab = { conversationId: "conv-1", state: { currentConversationId: "conv-1" } };
  const adapter = {
    bindTransport(value) { calls.push(["bind", value]); return value; },
    invalidateTransport(value) { calls.push(["invalidate", value]); return true; },
    async execute(value) { calls.push(["command", value]); return { delivery_id: value.delivery_id, status: "executed" }; }
  };
  const capture = {
    compatibility: () => ({ writable: true }),
    async emitBootstrap() {
      events.push({ event_type: "keyframe.final", source: { sequence: events.length + 1 } });
      return { checksum: "sha256:" + "0".repeat(64) };
    }
  };
  return {
    events,
    calls,
    router: new DesktopBridgeRouter({
      adapter,
      capture,
      getActiveTab: () => tab,
      evaluateCompatibility: () => ({ writable: true }),
      componentSet: { id: "beta-set" },
      importUpload: async (value) => ({ vault_path: value.display_name })
    })
  };
}

test("fixed-subprotocol challenge auth never puts credentials in URL or subprotocol", async () => {
  let socket;
  const channel = new CompanionChannel({
    endpoint: "ws://127.0.0.1:27124/bridge",
    credentialProvider: async () => ({ credential_id: "bridge-a", secret: "CANARY-BRIDGE-SECRET" }),
    router: fixture().router,
    webSocketFactory: (url, protocol) => (socket = new FakeSocket(url, protocol)),
    proof: async () => "proof-value"
  });
  channel.connect();
  socket.receive({ type: "auth.challenge", nonce: "nonce-a" });
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(socket.url, "ws://127.0.0.1:27124/bridge");
  assert.equal(socket.protocol, BRIDGE_SUBPROTOCOL);
  assert.equal(JSON.stringify([socket.url, socket.protocol]).includes("CANARY"), false);
  assert.deepEqual(socket.sent[0], {
    type: "auth.response", credential_id: "bridge-a", nonce: "nonce-a", proof: "proof-value"
  });
});

test("bridge proof is deterministic without exposing the secret", async () => {
  const first = await bridgeProof("secret-value", "nonce-a");
  const second = await bridgeProof("secret-value", "nonce-a");
  assert.equal(first, second);
  assert.notEqual(first, "secret-value");
});

test("the legacy adapter fixture and loopback router produce equivalent command receipts", async () => {
  const oldFixture = fixture();
  const nextFixture = fixture();
  const command = { delivery_id: "delivery-a", command_type: "turn.stop" };
  const oldResult = await oldFixture.router.adapter.execute(command);
  const nextResult = await nextFixture.router.handle("command.execute", command);
  assert.deepEqual(nextResult, oldResult);
  assert.deepEqual(nextFixture.calls, [["command", command]]);
});

test("bind, cutover, and rollback each produce one keyframe and invalidate the prior generation", async () => {
  const subject = fixture();
  const binding = { mac_session_id: "session-a", mac_connection_generation: 1, compatibility: { id: "beta-set" } };
  const bound = await subject.router.handle("transport.bind", binding);
  assert.equal(bound.compatibility.writable, true);
  assert.equal(subject.events.length, 1);
  await subject.router.handle("transport.cutover", { ...binding, mac_connection_generation: 2 });
  assert.equal(subject.events.length, 2);
  assert.deepEqual(subject.calls.slice(1, 3).map((item) => item[0]), ["invalidate", "bind"]);
  await subject.router.handle("transport.rollback", { ...binding, mac_connection_generation: 3 });
  assert.equal(subject.events.length, 3);
});

test("unauthenticated channel neither publishes events nor handles requests", async () => {
  let socket;
  const subject = fixture();
  const channel = new CompanionChannel({
    endpoint: "ws://127.0.0.1:27124/bridge",
    credentialProvider: async () => ({ credential_id: "bridge-a", secret: "secret" }),
    router: subject.router,
    webSocketFactory: (url, protocol) => (socket = new FakeSocket(url, protocol)),
    proof: async () => "proof"
  });
  channel.connect();
  assert.equal(channel.publish({ source: { sequence: 1 } }), false);
  socket.receive({ type: "request", request_id: "request-a", operation: "command.execute", payload: { delivery_id: "x" } });
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(subject.calls.length, 0);
  assert.equal(socket.sent.length, 0);
});
