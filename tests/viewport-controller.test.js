import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";

import { computeViewportMetrics, MobileViewportController } from "../src/mobile/viewport-controller.js";
import { buildDiagnosticReport } from "../src/mobile/diagnostic-report.js";

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

  setCssProps(props) { for (const [name, value] of Object.entries(props)) this.style.setProperty(name, value); }

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

test("Obsidian native keyboard CSS is detected without focus or viewport resize and never deducted twice", () => {
  const harness = viewportHarness();
  const { root, windowObject, visualViewport, input } = harness;
  const host = root.parentElement;
  windowObject.innerHeight = visualViewport.height = 874;
  root.ownerDocument = { documentElement: { clientHeight: 874 } };
  windowObject.getComputedStyle = (node) => node.style;
  host.rect = { top: 114, bottom: 874, height: 760 };
  root.properties.set("--keyboard-height", "0px");
  const controller = new MobileViewportController(harness);
  controller.start();
  assert.equal(controller.keyboardOpen, false);

  // Recorded iOS geometry: only the native CSS host shrinks; every viewport
  // remains 874px and keyboard/safe-area properties both become 328px.
  root.properties.set("--keyboard-height", "328px");
  root.properties.set("--safe-area-inset-bottom", "328px");
  host.rect = { top: 114, bottom: 546, height: 432 };
  harness.resize(host);
  assert.equal(controller.focused, false);
  assert.equal(controller.keyboardOpen, true, "native keyboard evidence must work without composer focus");
  assert.equal(root.classes.has("is-keyboard-open"), true);
  assert.equal(root.style.getPropertyValue("--cr-visible-height"), "432px", "the host has already deducted the 328px keyboard");
  assert.equal(root.style.getPropertyValue("--cr-visible-top"), "0px");
  assert.equal(root.style.getPropertyValue("--cr-keyboard-occlusion"), "0px");

  // During the native animation app max-height temporarily returns to 100vh.
  root.properties.set("--keyboard-height", "1px");
  host.rect = { top: 114, bottom: 874, height: 760 };
  harness.resize(host);
  assert.equal(controller.keyboardOpen, true);
  assert.equal(root.style.getPropertyValue("--cr-visible-height"), "760px");

  input.dispatch("focus");
  root.properties.set("--keyboard-height", "0px");
  harness.resize(host);
  assert.equal(controller.focused, true, "keyboard dismissal need not blur the input");
  assert.equal(controller.keyboardOpen, false, "safe-area alone is not keyboard evidence");
  assert.equal(root.classes.has("is-keyboard-open"), false);
  assert.equal(root.style.getPropertyValue("--cr-visible-height"), "760px");
  assert.equal(windowObject.innerHeight, 874);
  assert.equal(visualViewport.height, 874);

  // A non-Obsidian host still uses the existing visual viewport fallback.
  root.properties.delete("--keyboard-height");
  visualViewport.height = 546;
  visualViewport.dispatch("resize");
  harness.flushFrame();
  assert.equal(controller.keyboardOpen, true);
  assert.equal(root.style.getPropertyValue("--cr-visible-height"), "432px");
  visualViewport.height = 874;
  visualViewport.dispatch("resize");
  harness.flushFrame();
  assert.equal(controller.keyboardOpen, false);
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
  assert.equal(harness.root.style.getPropertyValue("--cr-visible-height"), "800px");
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


test("host bounds preserve native bottom navigation and release partial keyboard constraints", () => {
  const harness = viewportHarness();
  harness.root.parentElement.rect = { top: 40, bottom: 744, height: 704 };
  harness.root.rect = { top: 40, bottom: 500, height: 460 };
  harness.visualViewport.height = 620;
  const controller = new MobileViewportController(harness);
  controller.start();
  assert.equal(harness.root.style.getPropertyValue("--cr-visible-height"), "580px");
  harness.visualViewport.height = 800;
  controller.update();
  assert.equal(harness.root.style.getPropertyValue("--cr-visible-height"), "704px");
  assert.equal(harness.root.style.getPropertyValue("--cr-keyboard-occlusion"), "0px");
  controller.dispose();
});


test("rotation discards the portrait keyboard baseline before landscape dismissal", () => {
  const harness = viewportHarness();
  const controller = new MobileViewportController(harness);
  const size = (height) => {
    harness.visualViewport.height = height;
    harness.windowObject.innerHeight = height;
    harness.root.rect = harness.root.parentElement.rect = { top: 0, bottom: height, height };
    harness.visualViewport.dispatch("resize");
  };
  size(780);
  controller.start();
  harness.input.dispatch("focus");
  size(500);
  harness.flushFrame();
  assert.equal(controller.keyboardOpen, true);
  size(250);
  harness.windowObject.dispatch("orientationchange");
  harness.flushFrame();
  size(390);
  harness.input.dispatch("blur");
  harness.flushFrame();
  assert.equal(controller.keyboardOpen, false);
  assert.equal(harness.root.classes.has("is-keyboard-open"), false);
  assert.equal(harness.root.style.getPropertyValue("--cr-visible-height"), "390px");
  controller.dispose();
});

test("a panned visual viewport positions both shell edges without reusing its previous offset", () => {
  const harness = viewportHarness();
  harness.root.parentElement.rect = { top: 44, bottom: 448, height: 404 };
  harness.root.rect = { top: 44, bottom: 193, height: 149 };
  harness.visualViewport.offsetTop = 120;
  harness.visualViewport.height = 500;
  const controller = new MobileViewportController(harness);
  controller.start();
  const assertBounds = (top, height) => {
    assert.equal(harness.root.style.getPropertyValue("--cr-visible-top"), `${top}px`);
    assert.equal(harness.root.style.getPropertyValue("--cr-visible-height"), `${height}px`);
    assert.equal(44 + top + height, 448, "composer remains at the host's visible bottom");
  };
  assertBounds(76, 328);

  harness.root.rect = { top: 120, bottom: 448, height: 328 };
  controller.update();
  assertBounds(76, 328);
  harness.visualViewport.offsetTop = 0;
  controller.update();
  assertBounds(0, 404);
  controller.dispose();
});

test("measured shell dimensions cannot grow an auto-height host and overlays share native nav clearance", async () => {
  const css = await readFile(new URL("../styles.css", import.meta.url), "utf8");
  const rule = (selector) => css.slice(css.indexOf(`${selector} {`)).split("}")[0];
  const shell = rule(".claudian-remote-shell");
  assert.match(shell, /position:\s*absolute/);
  assert.match(shell, /height:\s*var\(--cr-visible-height,\s*100%\)/);
  assert.match(shell, /top:\s*var\(--cr-visible-top,\s*0px\)/);
  assert.doesNotMatch(shell, /max-height:/);
  assert.match(rule(".claudian-remote-composer-wrap"), /var\(--cr-native-bottom-space\)/);
  assert.match(rule(".claudian-remote-overlay"), /inset:\s*0 0 var\(--cr-native-bottom-space\) 0/);
  assert.match(rule(".claudian-remote-shell.is-keyboard-open"), /--cr-native-bottom-space:\s*0px/);
});

test("layout diagnostics are bounded, preserve composer and history focus, and export only allowed values", async () => {
  const harness = viewportHarness();
  const { root, composer, input, messages, windowObject } = harness;
  const body = new FakeElement({ top: 0, height: 800 });
  const documentElement = new FakeElement({ top: 0, height: 800 });
  documentElement.clientHeight = 800;
  const app = new FakeElement({ top: 0, height: 500 });
  const leaf = new FakeElement({ top: 40, height: 460 });
  const overlay = new FakeElement({ top: 40, height: 460 }, root);
  overlay.classList.contains = (name) => name === "is-open";
  const history = new FakeElement({ top: 40, height: 460 }, overlay);
  const search = new FakeElement({ top: 100, height: 44 }, history);
  const outside = new FakeElement({ top: 20, height: 44 });
  const row = new FakeElement({ top: 420, height: 52 }, composer);
  const contains = function(node) { for (; node; node = node.parentElement) if (node === this) return true; return false; };
  root.contains = composer.contains = history.contains = contains;
  input.matches = search.matches = outside.matches = () => true;
  root.querySelector = (selector) => ({ ".claudian-remote-messages": messages, ".claudian-remote-history": history })[selector];
  root.closest = (selector) => selector === ".app-container" ? app : leaf;
  composer.querySelector = () => row;
  body.classList.contains = () => false;
  const doc = root.ownerDocument = { body, documentElement, activeElement: input };
  windowObject.getComputedStyle = (node) => node.style;
  documentElement.properties.set("--keyboard-height", "300px");
  body.properties.set("--keyboard-height", "290px");
  root.properties.set("--keyboard-height", "280px");
  root.properties.set("--navbar-height", "48px");
  root.properties.set("--navbar-bottom-offset", "max(34px, 12px)");
  root.properties.set("--safe-area-inset-bottom", "34px");
  app.properties.set("max-height", "500px");
  composer.properties.set("padding-bottom", "312px");
  input.value = search.value = "PRIVATE-DRAFT-CANARY";
  const controller = new MobileViewportController(harness);
  controller.start();
  const first = controller.getLayoutDiagnostics();
  assert.equal(first.lastFocused.focusKind, "composer");
  assert.equal(first.lastFocused.documentKeyboardHeight, 300);
  assert.equal(first.lastFocused.bodyKeyboardHeight, 290);
  assert.equal(first.lastFocused.rootKeyboardHeight, 280);
  assert.equal(first.lastFocused.navbarHeight, 48);
  assert.equal(first.lastFocused.navbarBottomOffset, null);
  assert.equal(first.lastFocused.safeAreaBottom, 34);
  assert.equal(first.lastFocused.wrapPaddingBottom, 312);
  controller.update();
  assert.equal(controller.getLayoutDiagnostics().samples.length, 1, "identical frames are deduplicated");

  messages.rect.height = 0;
  controller.update();
  root.properties.set("--keyboard-height", "260px");
  controller.update();
  assert.equal(controller.getLayoutDiagnostics().lastFocused.rootKeyboardHeight, 260, "equal minimum heights retain the newer settled keyboard sample");
  documentElement.properties.set("--keyboard-height", "0px");
  body.properties.set("--keyboard-height", "0px");
  root.properties.set("--keyboard-height", "0px");
  composer.properties.set("padding-bottom", "34px");
  for (let index = 0; index < 12; index += 1) {
    messages.rect.height = 600 + index;
    controller.update();
  }
  const afterKeyboardHide = controller.getLayoutDiagnostics();
  assert.equal(doc.activeElement, input, "iOS keyboard dismissal can retain input focus");
  assert.equal(afterKeyboardHide.samples.length, 8);
  assert.equal(afterKeyboardHide.samples.at(-1).messagesHeight, 611);
  assert.equal(afterKeyboardHide.lastFocused.messagesHeight, 0, "normal frames after hide-without-blur must not overwrite the constrained geometry");
  assert.equal(afterKeyboardHide.lastFocused.rootKeyboardHeight, 260);
  assert.equal(afterKeyboardHide.lastFocused.wrapPaddingBottom, 312);

  doc.activeElement = search;
  root.dispatch("focusin");
  assert.equal(controller.getLayoutDiagnostics().lastFocused.focusKind, "history");
  assert.equal(controller.getLayoutDiagnostics().lastFocused.historyHeight, 460);
  assert.equal(controller.getLayoutDiagnostics().lastFocused.historyVisible, true);
  assert.equal(controller.getLayoutDiagnostics().lastFocused.activeSurfaceVisible, true);
  root.dispatch("focusout");
  doc.activeElement = body;
  await Promise.resolve();
  for (let index = 0; index < 12; index += 1) {
    messages.rect.height = 100 + index;
    controller.update();
  }
  const afterBlur = controller.getLayoutDiagnostics();
  assert.equal(afterBlur.samples.length, 8);
  assert.equal(afterBlur.samples.at(-1).focusKind, "none");
  assert.equal(afterBlur.lastFocused.focusKind, "history", "opening diagnostics cannot discard the keyboard-era sample");
  afterBlur.lastFocused.historyHeight = -999;
  assert.equal(controller.getLayoutDiagnostics().lastFocused.historyHeight, 460, "callers cannot mutate stored samples");
  doc.activeElement = outside;
  controller.captureGeometry();
  assert.equal(controller.getLayoutDiagnostics().lastFocused.focusKind, "outside");

  const poisoned = { ...first.lastFocused, focusKind: "PRIVATE-DRAFT-CANARY", inputTop: "PRIVATE-DRAFT-CANARY", secret: input.value };
  const report = buildDiagnosticReport({}, null, new Date(0), { samples: [...afterBlur.samples, poisoned], lastFocused: poisoned, url: input.value });
  assert.doesNotMatch(report, /PRIVATE-DRAFT-CANARY|secret|\"url\"/);
  const exported = JSON.parse(report.split("layout_geometry=")[1]);
  assert.equal(exported.samples.length, 8);
  assert.equal(exported.lastFocused.focusKind, "none");
  assert.equal(exported.lastFocused.inputTop, null);
  assert.ok(Object.values(exported.lastFocused).every((value) => value == null || typeof value === "number" || typeof value === "boolean" || value === "none"));
  controller.dispose();
  assert.equal(root.listeners.get("focusin").size, 0);
  assert.equal(root.listeners.get("focusout").size, 0);
});
