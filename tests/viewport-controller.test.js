import assert from "node:assert/strict";
import test from "node:test";

import { computeViewportMetrics, MobileViewportController } from "../src/mobile/viewport-controller.js";

class FakeEventTarget {
  constructor() {
    this.listeners = new Map();
  }

  addEventListener(type, listener) {
    if (!this.listeners.has(type)) this.listeners.set(type, new Set());
    this.listeners.get(type).add(listener);
  }

  removeEventListener(type, listener) {
    this.listeners.get(type)?.delete(listener);
  }

  dispatch(type) {
    for (const listener of this.listeners.get(type) || []) listener({ type, target: this });
  }
}

class FakeElement extends FakeEventTarget {
  constructor(rect, parentElement = null) {
    super();
    this.rect = rect;
    this.parentElement = parentElement;
    this.isConnected = true;
    this.scrollTop = 0;
    this.scrollLeft = 0;
    this.offsetHeight = rect.height || 0;
    this.properties = new Map();
    this.style = {
      setProperty: (name, value) => this.properties.set(name, value),
      getPropertyValue: (name) => this.properties.get(name) || ""
    };
    this.classes = new Set();
    this.classList = {
      toggle: (name, enabled) => enabled ? this.classes.add(name) : this.classes.delete(name)
    };
  }

  getBoundingClientRect() {
    return { ...this.rect };
  }
}

function viewportHarness() {
  const frames = new Map();
  const resizeObservers = [];
  let frameId = 0;
  let now = 0;
  const visualViewport = new FakeEventTarget();
  visualViewport.offsetTop = 0;
  visualViewport.height = 800;
  const windowObject = new FakeEventTarget();
  windowObject.innerHeight = 800;
  windowObject.visualViewport = visualViewport;
  windowObject.performance = { now: () => now };
  windowObject.requestAnimationFrame = (callback) => {
    const id = ++frameId;
    frames.set(id, callback);
    return id;
  };
  windowObject.cancelAnimationFrame = (id) => frames.delete(id);
  windowObject.ResizeObserver = class {
    constructor(callback) {
      this.callback = callback;
      this.observed = new Set();
      resizeObservers.push(this);
    }
    observe(node) { this.observed.add(node); }
    disconnect() {}
  };
  const host = new FakeElement({ top: 0, bottom: 800, height: 800 });
  const root = new FakeElement({ top: 0, bottom: 800, height: 800 }, host);
  const composer = new FakeElement({ top: 728, bottom: 792, height: 64 }, root);
  const input = new FakeElement({ top: 740, bottom: 780, height: 40 }, composer);
  const messages = new FakeElement({ top: 52, bottom: 800, height: 748 }, root);
  const flushFrame = (advance = 16) => {
    const entry = frames.entries().next().value;
    assert.ok(entry, "expected a queued viewport reconciliation frame");
    const [id, callback] = entry;
    frames.delete(id);
    now += advance;
    callback(now);
  };
  const resize = (node) => {
    for (const observer of resizeObservers) {
      if (observer.observed.has(node)) observer.callback([{ target: node }]);
    }
  };
  return { frames, visualViewport, windowObject, root, composer, input, messages, flushFrame, resize };
}

test("visual viewport occlusion, not focus, identifies an open keyboard", () => {
  const metrics = computeViewportMetrics({
    rootTop: 100,
    rootBottom: 844,
    viewportTop: 0,
    viewportHeight: 520,
    layoutHeight: 844
  });

  assert.equal(metrics.keyboardOpen, true);
  assert.equal(metrics.bottomOcclusion, 324);
  assert.equal(metrics.visibleHeight, 420);
});

test("keyboard dismissal clears stale occlusion even when the input remains focused", () => {
  const metrics = computeViewportMetrics({
    rootTop: 100,
    rootBottom: 844,
    viewportTop: 0,
    viewportHeight: 844,
    layoutHeight: 844
  });

  assert.equal(metrics.keyboardOpen, false);
  assert.equal(metrics.bottomOcclusion, 0);
  assert.equal(metrics.visibleHeight, 744);
});

test("visual viewport offset is included when calculating the visible bottom", () => {
  const metrics = computeViewportMetrics({
    rootTop: 80,
    rootBottom: 820,
    viewportTop: 44,
    viewportHeight: 620,
    layoutHeight: 844
  });

  assert.equal(metrics.viewportBottom, 664);
  assert.equal(metrics.bottomOcclusion, 156);
  assert.equal(metrics.visibleHeight, 584);
});

test("focus detects a late keyboard viewport change and constrains the shell to the visible viewport", () => {
  const harness = viewportHarness();
  const controller = new MobileViewportController(harness);
  controller.start();

  harness.input.dispatch("focus");
  harness.flushFrame();
  harness.visualViewport.height = 500;
  harness.flushFrame();

  assert.equal(harness.root.style.getPropertyValue("--cr-keyboard-occlusion"), "0px");
  assert.equal(harness.root.style.getPropertyValue("--cr-visible-height"), "500px");
  assert.equal(harness.root.classes.has("is-keyboard-open"), true);
  controller.dispose();
});

test("blur keeps sampling until a late keyboard dismissal clears state", () => {
  const harness = viewportHarness();
  const controller = new MobileViewportController(harness);
  controller.start();
  harness.visualViewport.height = 500;
  harness.visualViewport.dispatch("resize");
  harness.flushFrame();
  assert.equal(harness.root.style.getPropertyValue("--cr-keyboard-occlusion"), "0px");

  harness.input.dispatch("blur");
  harness.flushFrame();
  harness.visualViewport.height = 800;
  harness.flushFrame();

  assert.equal(harness.root.style.getPropertyValue("--cr-keyboard-occlusion"), "0px");
  assert.equal(harness.root.classes.has("is-keyboard-open"), false);
  controller.dispose();
});

test("keyboard state stays open when Obsidian asynchronously shrinks both host and layout viewport", () => {
  const harness = viewportHarness();
  const controller = new MobileViewportController(harness);
  controller.start();
  harness.visualViewport.height = 500;
  harness.visualViewport.dispatch("resize");
  harness.flushFrame();
  assert.equal(harness.root.style.getPropertyValue("--cr-keyboard-occlusion"), "0px");

  harness.root.rect = { top: 0, bottom: 500, height: 500 };
  harness.windowObject.innerHeight = 500;
  harness.resize(harness.root);

  assert.equal(harness.root.style.getPropertyValue("--cr-keyboard-occlusion"), "0px");
  assert.equal(harness.root.style.getPropertyValue("--cr-visible-height"), "500px");
  assert.equal(harness.root.classes.has("is-keyboard-open"), true);
  controller.dispose();
});

test("keyboard dismissal releases a shell that is still constrained to the old visible height", () => {
  const harness = viewportHarness();
  const controller = new MobileViewportController(harness);
  controller.start();

  harness.input.dispatch("focus");
  harness.visualViewport.height = 500;
  harness.windowObject.innerHeight = 500;
  harness.visualViewport.dispatch("resize");
  harness.flushFrame();
  harness.root.rect = { top: 0, bottom: 500, height: 500 };
  harness.resize(harness.root);
  assert.equal(harness.root.classes.has("is-keyboard-open"), true);

  harness.visualViewport.height = 800;
  harness.windowObject.innerHeight = 800;
  harness.visualViewport.dispatch("resize");
  harness.flushFrame();

  assert.equal(harness.root.classes.has("is-keyboard-open"), false);
  assert.equal(harness.root.style.getPropertyValue("--cr-visible-height"), "500px");
  controller.dispose();
});

test("focused input never fights the native Obsidian ancestor scroll position", () => {
  const harness = viewportHarness();
  const controller = new MobileViewportController(harness);
  controller.start();

  harness.input.dispatch("focus");
  harness.root.parentElement.scrollTop = 120;
  harness.flushFrame();

  assert.equal(harness.root.parentElement.scrollTop, 120);
  controller.dispose();
});
