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
    endpoint: "ws://127.0.0.1:27125/bridge",
    credentialProvider: async () => ({ credential_id: "bridge-a", secret: "CANARY-BRIDGE-SECRET" }),
    router: fixture().router,
    webSocketFactory: (url, protocol) => (socket = new FakeSocket(url, protocol)),
    proof: async () => "proof-value"
  });
  channel.connect();
  socket.receive({ type: "auth.challenge", nonce: "nonce-a" });
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(socket.url, "ws://127.0.0.1:27125/bridge");
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
    endpoint: "ws://127.0.0.1:27125/bridge",
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

test("authenticated plugin sends Pairing Admin operations through the Companion proxy", async () => {
  let socket;
  const channel = new CompanionChannel({
    credentialProvider: async () => ({ credential_id: "bridge-a", secret: "secret" }),
    router: fixture().router,
    webSocketFactory: (url, protocol) => (socket = new FakeSocket(url, protocol)),
    proof: async () => "proof"
  });
  channel.connect();
  socket.receive({ type: "auth.accepted", generation: 1 });
  const pending = channel.management("pairing.devices", {});
  const request = socket.sent.at(-1);
  assert.equal(request.type, "management.request");
  assert.equal(request.operation, "pairing.devices");
  socket.receive({ type: "management.response", request_id: request.request_id, ok: true, result: { devices: [] } });
  assert.deepEqual(await pending, { devices: [] });
});

test("natural bridge close rejects pending management immediately", async () => {
  let socket;
  const channel = new CompanionChannel({
    credentialProvider: async () => ({ credential_id: "bridge-a", secret: "secret" }),
    router: fixture().router,
    webSocketFactory: (url, protocol) => (socket = new FakeSocket(url, protocol)),
    proof: async () => "proof"
  });
  channel.connect();
  socket.receive({ type: "auth.accepted", generation: 1 });
  const pending = channel.management("pairing.devices", {});
  socket.onclose?.();
  await assert.rejects(pending, /bridge_disconnected/);
  assert.equal(channel.managementPending.size, 0);
});

test("a delayed challenge from a replaced socket cannot authenticate the new socket", async () => {
  const sockets = [];
  let releaseCredential;
  const credential = new Promise((resolve) => { releaseCredential = resolve; });
  const channel = new CompanionChannel({
    credentialProvider: async () => await credential,
    router: fixture().router,
    webSocketFactory: (url, protocol) => {
      const socket = new FakeSocket(url, protocol);
      sockets.push(socket);
      return socket;
    },
    proof: async () => "proof"
  });
  const oldSocket = channel.connect();
  oldSocket.receive({ type: "auth.challenge", nonce: "old-nonce" });
  const currentSocket = channel.connect();
  releaseCredential({ credential_id: "bridge-a", secret: "secret" });
  await new Promise((resolve) => setTimeout(resolve, 0));

  assert.equal(sockets.length, 2);
  assert.deepEqual(oldSocket.sent, []);
  assert.deepEqual(currentSocket.sent, []);
  assert.equal(channel.authenticated, false);
});

test("a delayed request from a replaced socket cannot reply on the new socket", async () => {
  const sockets = [];
  let releaseRequest;
  const router = {
    async handle() {
      return await new Promise((resolve) => { releaseRequest = resolve; });
    }
  };
  const channel = new CompanionChannel({
    credentialProvider: async () => ({ credential_id: "bridge-a", secret: "secret" }),
    router,
    webSocketFactory: (url, protocol) => {
      const socket = new FakeSocket(url, protocol);
      sockets.push(socket);
      return socket;
    },
    proof: async () => "proof"
  });
  const oldSocket = channel.connect();
  oldSocket.receive({ type: "auth.accepted", generation: 1 });
  oldSocket.receive({ type: "request", request_id: "old-request", operation: "command.execute", payload: {} });
  await new Promise((resolve) => setTimeout(resolve, 0));
  const currentSocket = channel.connect();
  releaseRequest({ status: "executed" });
  await new Promise((resolve) => setTimeout(resolve, 0));

  assert.deepEqual(oldSocket.sent, []);
  assert.deepEqual(currentSocket.sent, []);
});

test("management requests apply bounded backpressure", async () => {
  let socket;
  const channel = new CompanionChannel({
    credentialProvider: async () => ({ credential_id: "bridge-a", secret: "secret" }),
    router: fixture().router,
    webSocketFactory: (url, protocol) => (socket = new FakeSocket(url, protocol)),
    proof: async () => "proof"
  });
  channel.connect();
  socket.receive({ type: "auth.accepted", generation: 1 });
  const pending = Array.from({ length: 16 }, () => channel.management("pairing.devices", {}));
  await assert.rejects(channel.management("pairing.devices", {}), /management_backpressure/);
  channel.disconnect();
  await Promise.allSettled(pending);
});

test("natural close reconnects with bounded exponential backoff", () => {
  const sockets = [];
  const timers = [];
  const channel = new CompanionChannel({
    credentialProvider: async () => ({ credential_id: "bridge-a", secret: "secret" }),
    router: fixture().router,
    webSocketFactory: (url, protocol) => {
      const socket = new FakeSocket(url, protocol);
      sockets.push(socket);
      return socket;
    },
    proof: async () => "proof",
    setTimeoutFn: (callback, delay) => {
      const timer = { callback, delay, cancelled: false };
      timers.push(timer);
      return timer;
    },
    clearTimeoutFn: (timer) => { timer.cancelled = true; },
    reconnectMinMs: 500,
    reconnectMaxMs: 2000
  });

  const first = channel.connect();
  first.onclose();
  assert.equal(timers[0].delay, 500);
  timers[0].callback();
  assert.equal(sockets.length, 2);
  sockets[1].onclose();
  assert.equal(timers[1].delay, 1000);
  timers[1].callback();
  sockets[2].receive({ type: "auth.accepted", generation: 1 });
  sockets[2].onclose();
  assert.equal(timers[2].delay, 500);
});

test("explicit disconnect cancels reconnect and never opens another socket", () => {
  const sockets = [];
  const timers = [];
  const channel = new CompanionChannel({
    credentialProvider: async () => ({ credential_id: "bridge-a", secret: "secret" }),
    router: fixture().router,
    webSocketFactory: (url, protocol) => {
      const socket = new FakeSocket(url, protocol);
      sockets.push(socket);
      return socket;
    },
    proof: async () => "proof",
    setTimeoutFn: (callback, delay) => {
      const timer = { callback, delay, cancelled: false };
      timers.push(timer);
      return timer;
    },
    clearTimeoutFn: (timer) => { timer.cancelled = true; }
  });

  const socket = channel.connect();
  socket.onclose();
  channel.disconnect();
  assert.equal(timers[0].cancelled, true);
  timers[0].callback();
  assert.equal(sockets.length, 1);
});
