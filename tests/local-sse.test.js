import assert from "node:assert/strict";
import test from "node:test";
import { BoundedEventRing, LocalSseHub, formatSse } from "../src/local-sse.js";

function event(sequence, text = "x") {
  return { source: { instance_id: "bridge", sequence }, payload: { text } };
}

test("SSE formatter supports UTF-8 and CR/LF multi-line data", () => {
  assert.equal(
    formatSse({ id: 7, event: "semantic", data: "第一行\r\n第二行\r第三行" }),
    "id: 7\nevent: semantic\ndata: 第一行\ndata: 第二行\ndata: 第三行\n\n"
  );
});

test("bounded ring replays strictly after Last-Event-ID and signals retained gap", () => {
  const ring = new BoundedEventRing({ maxEvents: 2, maxBytes: 10000 });
  ring.append(event(1)); ring.append(event(2)); ring.append(event(3));
  assert.deepEqual(ring.replayAfter(2).items.map((item) => item.id), [3]);
  assert.deepEqual(ring.replayAfter(0).items.map((item) => item.id), [2, 3]);
  assert.deepEqual(ring.replayAfter(1), { resync: false, items: ring.items });
  assert.equal(ring.replayAfter("bad").reason, "invalid_last_event_id");
});

test("local gap writes resync, live event, keepalive comment, and closes cleanly", () => {
  const callbacks = [];
  const timers = { setInterval: (fn) => (callbacks.push(fn), callbacks.length), clearInterval() {} };
  const ring = new BoundedEventRing({ maxEvents: 1 });
  ring.append(event(10));
  const writes = [];
  const response = { setHeader() {}, flushHeaders() {}, write: (value) => writes.push(value), end: () => writes.push("END"), on() {} };
  const hub = new LocalSseHub({ ring, timers });
  const close = hub.open(response, 2);
  assert.match(writes[0], /event: resync/);
  hub.publish(event(11, "你好"));
  assert.match(writes[1], /id: 11/);
  callbacks[0]();
  assert.equal(writes[2], ": keepalive\n\n");
  close();
  assert.equal(writes.at(-1), "END");
});

test("oversized event and excess subscribers are rejected without corrupting ring", () => {
  const ring = new BoundedEventRing({ maxBytes: 32 });
  assert.throws(() => ring.append(event(1, "x".repeat(100))), /byte budget/);
  assert.equal(ring.items.length, 0);
  const timers = { setInterval: () => 1, clearInterval() {} };
  const response = { setHeader() {}, write() {}, end() {}, on() {} };
  const hub = new LocalSseHub({ maxSubscribers: 1, timers });
  hub.open(response);
  assert.throws(() => hub.open(response), /too_many_sse_subscribers/);
  hub.closeAll();
});
