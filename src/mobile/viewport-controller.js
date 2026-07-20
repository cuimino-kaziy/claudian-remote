const KEYBOARD_THRESHOLD_PX = 80;
const KEYBOARD_SETTLE_MS = 900;
const VIEWPORT_SETTLE_MS = 360;

function finite(value, fallback = 0) {
  return Number.isFinite(Number(value)) ? Number(value) : fallback;
}

export function computeViewportMetrics({
  rootTop = 0,
  rootBottom = 0,
  viewportTop = 0,
  viewportHeight = 0,
  layoutHeight = 0,
  keyboardThreshold = KEYBOARD_THRESHOLD_PX
} = {}) {
  const top = finite(rootTop);
  const bottom = Math.max(top, finite(rootBottom, top));
  const visualTop = Math.max(0, finite(viewportTop));
  const visualHeight = Math.max(0, finite(viewportHeight));
  const viewportBottom = visualTop + visualHeight;
  const visibleTop = Math.max(top, visualTop);
  const visibleBottom = Math.min(bottom, viewportBottom);
  const bottomOcclusion = Math.max(0, bottom - visibleBottom);
  const layoutOcclusion = Math.max(0, finite(layoutHeight, bottom) - viewportBottom);
  return {
    viewportBottom,
    visibleTop,
    visibleBottom,
    visibleHeight: Math.max(0, visibleBottom - visibleTop),
    bottomOcclusion,
    keyboardOpen: Math.max(bottomOcclusion, layoutOcclusion) >= keyboardThreshold
  };
}

function addListener(target, type, listener, options, disposers) {
  if (!target?.addEventListener) return;
  target.addEventListener(type, listener, options);
  disposers.push(() => target.removeEventListener(type, listener, options));
}

export class MobileViewportController {
  constructor({ root, composer, input, messages, windowObject = globalThis.window } = {}) {
    this.root = root;
    this.composer = composer;
    this.input = input;
    this.messages = messages;
    this.window = windowObject;
    this.visualViewport = windowObject?.visualViewport;
    this.requestFrame = windowObject?.requestAnimationFrame?.bind(windowObject) || ((callback) => setTimeout(callback, 0));
    this.cancelFrame = windowObject?.cancelAnimationFrame?.bind(windowObject) || clearTimeout;
    this.clock = windowObject?.performance?.now?.bind(windowObject.performance) || Date.now;
    this.disposers = [];
    this.frame = null;
    this.settleUntil = 0;
    this.keyboardOpen = false;
    this.focused = false;
    this.baselineHeight = 0;
    this.closeWaiters = new Set();
  }

  start() {
    if (!this.root || !this.composer || !this.input || this.started) return;
    this.started = true;
    this.onViewportChange = () => this.settle(VIEWPORT_SETTLE_MS);
    this.onFocus = () => {
      this.focused = true;
      this.settle(KEYBOARD_SETTLE_MS);
    };
    this.onBlur = () => {
      this.focused = false;
      this.settle(KEYBOARD_SETTLE_MS);
    };
    addListener(this.visualViewport, "resize", this.onViewportChange, { passive: true }, this.disposers);
    addListener(this.visualViewport, "scroll", this.onViewportChange, { passive: true }, this.disposers);
    addListener(this.window, "resize", this.onViewportChange, { passive: true }, this.disposers);
    addListener(this.window, "orientationchange", this.onViewportChange, { passive: true }, this.disposers);
    addListener(this.input, "focus", this.onFocus, undefined, this.disposers);
    addListener(this.input, "blur", this.onBlur, undefined, this.disposers);
    const ResizeObserverClass = this.window?.ResizeObserver || globalThis.ResizeObserver;
    if (ResizeObserverClass) {
      this.resizeObserver = new ResizeObserverClass(() => {
        // Obsidian resizes its view container after the visual viewport event.
        // Reconcile in the observer callback (before paint) so an old keyboard
        // offset is never applied to the already-shrunken host for one frame.
        this.update();
        this.settle(VIEWPORT_SETTLE_MS);
      });
      this.resizeObserver.observe(this.composer);
      this.resizeObserver.observe(this.root);
      if (this.root.parentElement) this.resizeObserver.observe(this.root.parentElement);
      this.disposers.push(() => this.resizeObserver?.disconnect());
    }
    this.update();
  }

  settle(durationMs = VIEWPORT_SETTLE_MS) {
    if (!this.started) return;
    this.settleUntil = Math.max(this.settleUntil, this.clock() + durationMs);
    this.schedule();
  }

  schedule() {
    if (!this.started || this.frame != null) return;
    this.frame = this.requestFrame(() => {
      this.frame = null;
      this.update();
      if (this.started && this.clock() < this.settleUntil) this.schedule();
      else this.settleUntil = 0;
    });
  }

  update() {
    if (!this.started || !this.root?.isConnected) return;
    const rect = this.root.getBoundingClientRect();
    const visual = this.visualViewport;
    const layoutHeight = finite(this.window?.innerHeight, rect.bottom);
    const viewportHeight = visual?.height || layoutHeight;
    const rootHeight = Math.max(0, rect.height || rect.bottom - rect.top);
    // Do not include rootHeight here: while the plugin's keyboard class is
    // constraining the shell, that height is an effect of the keyboard state,
    // not independent evidence that the keyboard is still open.
    const currentEnvelope = Math.min(viewportHeight, layoutHeight);
    const baselineCandidate = Math.max(viewportHeight, layoutHeight, rootHeight);
    if (!this.baselineHeight || (!this.focused && !this.keyboardOpen)) this.baselineHeight = baselineCandidate;
    const metrics = computeViewportMetrics({
      rootTop: rect.top,
      rootBottom: rect.bottom,
      viewportTop: visual?.offsetTop || 0,
      viewportHeight,
      layoutHeight
    });
    const wasOpen = this.keyboardOpen;
    const transitioningOcclusion = (this.focused || wasOpen)
      ? Math.max(0, this.baselineHeight - currentEnvelope)
      : 0;
    this.keyboardOpen = metrics.keyboardOpen || transitioningOcclusion >= KEYBOARD_THRESHOLD_PX;
    this.root.classList.toggle("is-keyboard-open", this.keyboardOpen);
    // Obsidian Mobile already resizes/pans its WKWebView for the keyboard.
    // Moving the composer by the same occlusion a second time fights native
    // focus handling and can leave the textarea off-screen or unfocusable.
    this.root.style.setProperty("--cr-keyboard-occlusion", "0px");
    this.root.style.setProperty("--cr-visible-height", `${Math.round(metrics.visibleHeight)}px`);
    if (wasOpen && !this.keyboardOpen) {
      for (const resolve of this.closeWaiters) resolve();
      this.closeWaiters.clear();
    }
  }

  async dismissKeyboard(timeoutMs = 1000) {
    this.input?.blur?.();
    this.schedule();
    if (!this.keyboardOpen) return;
    await new Promise((resolve) => {
      const timer = setTimeout(() => {
        this.closeWaiters.delete(done);
        resolve();
      }, timeoutMs);
      const done = () => {
        clearTimeout(timer);
        resolve();
      };
      this.closeWaiters.add(done);
    });
  }

  dispose() {
    this.started = false;
    this.settleUntil = 0;
    if (this.frame != null) this.cancelFrame(this.frame);
    this.frame = null;
    for (const dispose of this.disposers.splice(0)) dispose();
    for (const resolve of this.closeWaiters) resolve();
    this.closeWaiters.clear();
  }
}
