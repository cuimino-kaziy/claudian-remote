import assert from "node:assert/strict";
import test from "node:test";

import { FrameRenderScheduler } from "../src/mobile/render-scheduler.js";

test("multiple streaming updates collapse into one frame render", () => {
  const frames = [];
  let renders = 0;
  const scheduler = new FrameRenderScheduler({
    render: () => { renders += 1; },
    requestFrame: (callback) => { frames.push(callback); return frames.length; },
    cancelFrame: () => {}
  });

  scheduler.request();
  scheduler.request();
  scheduler.request();
  assert.equal(frames.length, 1);
  assert.equal(renders, 0);
  frames.shift()();
  assert.equal(renders, 1);
});

test("dispose cancels a queued render and blocks later requests", () => {
  const frames = new Map();
  const cancelled = [];
  let nextId = 0;
  let renders = 0;
  const scheduler = new FrameRenderScheduler({
    render: () => { renders += 1; },
    requestFrame: (callback) => { const id = ++nextId; frames.set(id, callback); return id; },
    cancelFrame: (id) => { cancelled.push(id); frames.delete(id); }
  });

  scheduler.request();
  scheduler.dispose();
  scheduler.request();
  assert.deepEqual(cancelled, [1]);
  assert.equal(frames.size, 0);
  assert.equal(renders, 0);
});
