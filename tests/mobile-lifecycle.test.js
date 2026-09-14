import assert from "node:assert/strict";
import test from "node:test";

import { MobileReplica } from "../src/mobile/reducer.js";
import { MobileRecoveryController } from "../src/mobile/recovery.js";
import { RemoteClient } from "../src/mobile/remote-client.js";
import { createObsidianFetch } from "../src/mobile/obsidian-http.js";
import { COMPATIBILITY_SET } from "../src/protocol/compatibility.js";
import { deriveReadiness, pairingStatusFromSettings } from "../src/mobile/readiness.js";
import { buildDiagnosticReport } from "../src/mobile/diagnostic-report.js";
import { DeviceStore } from "../src/storage/device-store.js";

class FakeTimers {
  constructor() { this.jobs = new Map(); this.next = 1; }
  setTimeout(fn, delay) { const id = this.next++; this.jobs.set(id, { fn, delay }); return id; }
  clearTimeout(id) { this.jobs.delete(id); }
}

class FakeClient {
  constructor() { this.connects = []; this.closes = []; this.keyframeRequests = []; this.onClose = () => {}; }
  async connect(coordinates) { this.connects.push(coordinates); }
  requestKeyframe(reason) { this.keyframeRequests.push(reason); return true; }
  close(reason) { this.closes.push(reason); }
}

test("foreground authentication requests an authoritative bootstrap", async () => {
  const client = new FakeClient();
  const replica = new MobileReplica({ relay: { epoch: "epoch", appliedCursor: 63 }, activeConversationId: "conv" });
  const lifecycle = new MobileRecoveryController({ client, replica, timers: new FakeTimers() });

  await lifecycle.setVisible(true);
  assert.deepEqual(client.keyframeRequests, []);
  await replica.applyFrame({ type: "authenticated" });
  assert.deepEqual(client.keyframeRequests, ["foreground_recalibrate"]);

  await lifecycle.dispose();
});

test("foreground recalibrates once and hidden cancels retry/render lifecycle", async () => {
  const client = new FakeClient();
  const replica = new MobileReplica({ relay: { epoch: "epoch", appliedCursor: 9 } });
  const timers = new FakeTimers();
  const persisted = [];
  const lifecycle = new MobileRecoveryController({ client, replica, timers, random: () => 0.5, persist: async (state) => persisted.push(state.relay.appliedCursor) });

  await lifecycle.setVisible(true);
  assert.deepEqual(client.connects, [{ epoch: "epoch", cursor: 9 }]);
  client.onClose();
  client.onClose();
  assert.equal(timers.jobs.size, 1);

  await lifecycle.setVisible(false);
  assert.equal(timers.jobs.size, 0);
  assert.equal(replica.state.visible, false);
  assert.deepEqual(persisted, [9]);

  await lifecycle.setVisible(true);
  assert.equal(client.connects.length, 2);
  assert.ok(client.closes.includes("foreground_recalibrate"));
});

test("dispose leaves no socket or reconnect timer", async () => {
  const client = new FakeClient();
  const lifecycle = new MobileRecoveryController({ client, replica: new MobileReplica(), timers: new FakeTimers() });
  await lifecycle.setVisible(true);
  client.onClose();
  await lifecycle.dispose();
  assert.equal(lifecycle.timer, null);
  assert.equal(client.closes.at(-1), "unload");
});

class FakeWebSocket {
  static instances = [];
  constructor(url, protocol) {
    this.url = url;
    this.protocol = protocol;
    this.readyState = 0;
    this.listeners = new Map();
    this.sent = [];
    FakeWebSocket.instances.push(this);
  }
  addEventListener(type, listener) { this.listeners.set(type, listener); }
  send(value) { this.sent.push(JSON.parse(value)); }
  open() { this.readyState = 1; this.listeners.get("open")?.({}); }
  close(code = 1000, reason = "") { this.readyState = 3; this.listeners.get("close")?.({ code, reason }); }
}

test("remote client keeps credentials out of WebSocket URL and authenticates with one-time ticket first", async () => {
  FakeWebSocket.instances = [];
  const requests = [];
  const fetchImpl = async (url, options) => {
    requests.push({ url, options });
    return {
      ok: true,
      status: url.endsWith("/commands") ? 202 : 201,
      async json() { return url.endsWith("/commands") ? { ok: true, type: "relay.accepted" } : { ticket: "single-use-ticket" }; }
    };
  };
  const client = new RemoteClient({
    baseUrl: "https://relay.example",
    tokenProvider: () => "private-role-token",
    deviceId: "iphone",
    clientInstanceId: "view",
    fetchImpl,
    WebSocketImpl: FakeWebSocket
  });
  await client.connect({ epoch: "epoch", cursor: 7 });
  const socket = FakeWebSocket.instances[0];
  assert.equal(socket.url, "wss://relay.example/api/v2/ws/mobile");
  assert.equal(socket.url.includes("ticket"), false);
  assert.equal(socket.url.includes("token"), false);
  socket.open();
  assert.deepEqual(socket.sent[0], {
    type: "authenticate", role: "mobile", ticket: "single-use-ticket", device_id: "iphone",
    client_instance_id: "view", epoch: "epoch", cursor: 7, compatibility: COMPATIBILITY_SET
  });
  assert.equal(requests[0].options.headers.Authorization, "Bearer private-role-token");
  await client.submit({ delivery_id: "delivery" });
  assert.deepEqual(JSON.parse(requests[1].options.body), {
    command: { delivery_id: "delivery" },
    compatibility: COMPATIBILITY_SET
  });
});

test("network disconnect and foreground recovery reuse the persisted device credential", async () => {
  const values = new Map();
  const store = new DeviceStore({ storage: {
    getItem: (key) => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, String(value)),
    removeItem: (key) => values.delete(key)
  } });
  store.write("identity", { mobile_token: "durable-device-token", device_id: "iphone", client_instance_id: "view" });
  const before = JSON.stringify(store.read("identity"));
  const requests = [];
  const client = new RemoteClient({
    baseUrl: "https://relay.example", tokenProvider: () => store.read("identity").mobile_token,
    deviceId: "iphone", clientInstanceId: "view", WebSocketImpl: FakeWebSocket,
    fetchImpl: async (url, options) => {
      requests.push({ url, authorization: options.headers.Authorization, ...JSON.parse(options.body) });
      return { ok: true, json: async () => ({ ticket: `ticket-${requests.length}` }) };
    }
  });
  const timers = new FakeTimers();
  const lifecycle = new MobileRecoveryController({ client, replica: new MobileReplica(), timers });
  await lifecycle.setVisible(true);
  client.socket.close(1006, "network disconnected");
  assert.equal(timers.jobs.size, 1);
  const [timerId, retry] = [...timers.jobs.entries()][0];
  timers.jobs.delete(timerId);
  retry.fn();
  await new Promise(setImmediate);
  await lifecycle.setVisible(false);
  await lifecycle.setVisible(true);
  assert.equal(requests.length, 3);
  for (const request of requests) {
    assert.equal(request.url, "https://relay.example/api/v2/ws-ticket");
    assert.equal(request.authorization, "Bearer durable-device-token");
    assert.equal(request.device_id, "iphone");
    assert.equal(request.client_instance_id, "view");
  }
  assert.equal(JSON.stringify(store.read("identity")), before);
  await lifecycle.dispose();
});

test("Obsidian native HTTP adapter keeps bounded binary chunks and disables CORS-dependent fetch", async () => {
  const seen = [];
  const adapter = createObsidianFetch(async (request) => {
    seen.push(request);
    return { status: 202, headers: {}, json: { ok: true }, text: "", arrayBuffer: new ArrayBuffer(0) };
  });
  const body = new Uint8Array([1, 2, 3]);
  const response = await adapter("https://relay.example/api/v2/uploads/id/chunks/0", { method: "PUT", headers: { Authorization: "Bearer private" }, body });
  assert.equal(response.ok, true);
  assert.equal(seen[0].throw, false);
  assert.ok(seen[0].body instanceof ArrayBuffer);
  assert.deepEqual(Array.from(new Uint8Array(seen[0].body)), [1, 2, 3]);
});

test("UI and Agent diagnostics share one structured readiness reason vocabulary", () => {
  const base = {
    transport: { status: "connected" },
    presence: { mac: { status: "online", sessionId: "mac", connectionGeneration: 1 } },
    compatibility: { writable: true, reason: "ready" },
    capabilities: { semantic_stream: true },
    recovery: { required: false },
    activeConversationId: "conv",
    conversations: { conv: { id: "conv", activeTurnId: null, turns: {} } }
  };
  const cases = [
    [{ ...base, pairing: { status: "required" } }, "pairing_required"],
    [{ ...base, transport: { status: "disconnected" } }, "relay_offline"],
    [{ ...base, compatibility: { writable: false, reason: "compatibility_set_mismatch" } }, "compatibility_set_mismatch"],
    [{ ...base, presence: { mac: { status: "offline", reason: "vault_closed" } } }, "vault_closed"],
    [{ ...base, presence: { mac: { status: "offline" } } }, "mac_offline"],
    [base, "ready"]
  ];
  for (const [state, expected] of cases) {
    assert.equal(deriveReadiness(state).reason_code, expected);
    assert.match(buildDiagnosticReport(state), new RegExp(`readiness_reason=${expected}`));
  }
});

test("device settings derive pairing-required readiness without a test-only seed", () => {
  assert.equal(pairingStatusFromSettings({ mobile_token: "", re_pair_required: false }), "required");
  assert.equal(pairingStatusFromSettings({ mobile_token: "token", re_pair_required: true }), "required");
  assert.equal(pairingStatusFromSettings({ mobile_token: "token", re_pair_required: false }), "paired");
});
