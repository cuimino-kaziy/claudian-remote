const KEYBOARD_THRESHOLD_PX = 80;
const KEYBOARD_SETTLE_MS = 900;
const VIEWPORT_SETTLE_MS = 360;

function finite(value, fallback = 0) {
  return Number.isFinite(Number(value)) ? Number(value) : fallback;
}

function geometryNumber(value) {
  return typeof value === "number" && Number.isFinite(value) ? Math.round(value * 10) / 10 : null;
}

function cssPixels(value) {
  const text = String(value || "").trim();
  return /^-?(?:\d+\.?\d*|\.\d+)(?:px)?$/.test(text) ? geometryNumber(Number.parseFloat(text)) : null;
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
  constructor({ root, composer, input, windowObject = globalThis.window } = {}) {
    this.root = root;
    this.composer = composer;
    this.input = input;
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
    this.geometrySamples = [];
    this.lastFocusedGeometry = null;
    this.geometryFocusKind = "none";
    this.lastGeometryKey = "";
  }

  start() {
    if (!this.root || !this.composer || !this.input || this.started) return;
    this.started = true;
    this.onViewportChange = () => this.settle(VIEWPORT_SETTLE_MS);
    this.onOrientationChange = () => {
      this.baselineHeight = 0;
      this.keyboardOpen = false;
      this.settle(VIEWPORT_SETTLE_MS);
    };
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
    addListener(this.window, "orientationchange", this.onOrientationChange, { passive: true }, this.disposers);
    addListener(this.window?.screen?.orientation, "change", this.onOrientationChange, { passive: true }, this.disposers);
    addListener(this.input, "focus", this.onFocus, undefined, this.disposers);
    addListener(this.input, "blur", this.onBlur, undefined, this.disposers);
    // Sampling focus does not alter keyboard/layout behavior. Keep constrained
    // input geometry before opening the report dismisses the native keyboard.
    addListener(this.root, "focusin", () => this.captureGeometry(), undefined, this.disposers);
    addListener(this.root, "focusout", () => {
      this.captureGeometry();
      queueMicrotask(() => this.captureGeometry());
    }, undefined, this.disposers);
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
    // The positioned shell does not contribute to its host's intrinsic size.
    // Measure only that host: the shell may retain an earlier height/top offset.
    const hostRect = (this.root.parentElement || this.root).getBoundingClientRect();
    const visual = this.visualViewport;
    const layoutHeight = finite(this.window?.innerHeight, hostRect.bottom);
    const viewportHeight = visual?.height || layoutHeight;
    const rootHeight = Math.max(0, hostRect.bottom - hostRect.top);
    // Do not include rootHeight here: while the plugin's keyboard class is
    // constraining the shell, that height is an effect of the keyboard state,
    // not independent evidence that the keyboard is still open.
    const currentEnvelope = Math.min(viewportHeight, layoutHeight);
    const baselineCandidate = Math.max(viewportHeight, layoutHeight, rootHeight);
    if (!this.baselineHeight || (!this.focused && !this.keyboardOpen)) this.baselineHeight = baselineCandidate;
    const metrics = computeViewportMetrics({
      rootTop: hostRect.top,
      rootBottom: hostRect.bottom,
      viewportTop: visual?.offsetTop || 0,
      viewportHeight,
      layoutHeight
    });
    const wasOpen = this.keyboardOpen;
    const transitioningOcclusion = (this.focused || wasOpen)
      ? Math.max(0, this.baselineHeight - currentEnvelope)
      : 0;
    // Obsidian iOS can resize only its CSS host while both viewport heights
    // stay unchanged. This inherited value is evidence, not another inset.
    const nativeKeyboardHeight = cssPixels(this.window?.getComputedStyle?.(this.root)?.getPropertyValue("--keyboard-height"));
    this.keyboardOpen = nativeKeyboardHeight > 0 || metrics.keyboardOpen || transitioningOcclusion >= KEYBOARD_THRESHOLD_PX;
    this.root.classList.toggle("is-keyboard-open", this.keyboardOpen);
    // Obsidian Mobile already resizes/pans its WKWebView for the keyboard.
    // Moving the composer by the same occlusion a second time fights native
    // focus handling and can leave the textarea off-screen or unfocusable.
    this.root.style.setProperty("--cr-keyboard-occlusion", "0px");
    this.root.style.setProperty("--cr-visible-top", `${Math.round(metrics.visibleTop - hostRect.top)}px`);
    this.root.style.setProperty("--cr-visible-height", `${Math.round(metrics.visibleHeight)}px`);
    this.captureGeometry();
  }

  captureGeometry() {
    if (!this.started || !this.root?.isConnected) return;
    const doc = this.root.ownerDocument || this.window?.document;
    const style = (node) => node ? this.window?.getComputedStyle?.(node) : null;
    const property = (node, name) => cssPixels(style(node)?.getPropertyValue(name));
    const history = this.root.querySelector?.(".claudian-remote-history");
    const details = this.root.querySelector?.(".claudian-remote-details");
    const active = doc?.activeElement;
    let focusKind = "none";
    if (active?.matches?.("input, textarea")) {
      focusKind = !this.root.contains?.(active) ? "outside"
        : this.composer.contains?.(active) ? "composer"
          : history?.contains?.(active) ? "history" : "other";
    }
    const historyVisible = history?.parentElement?.classList.contains?.("is-open") === true;
    const detailsVisible = details?.parentElement?.classList.contains?.("is-open") === true;
    const app = this.root.closest?.(".app-container");
    const sample = {
      focusKind,
      keyboardOpen: this.keyboardOpen,
      keyboardAnimating: doc?.body?.classList.contains?.("keyboard-animating") === true,
      historyVisible,
      activeSurfaceVisible: historyVisible || detailsVisible,
      innerHeight: geometryNumber(this.window?.innerHeight),
      clientHeight: geometryNumber(doc?.documentElement?.clientHeight),
      visualHeight: geometryNumber(this.visualViewport?.height),
      visualTop: geometryNumber(this.visualViewport?.offsetTop),
      visualScale: geometryNumber(this.visualViewport?.scale),
      scrollY: geometryNumber(this.window?.scrollY),
      documentKeyboardHeight: property(doc?.documentElement, "--keyboard-height"),
      bodyKeyboardHeight: property(doc?.body, "--keyboard-height"),
      rootKeyboardHeight: property(this.root, "--keyboard-height"),
      navbarHeight: property(this.root, "--navbar-height"),
      navbarBottomOffset: property(this.root, "--navbar-bottom-offset"),
      safeAreaBottom: property(this.root, "--safe-area-inset-bottom"),
      appMaxHeight: property(app, "max-height"),
      wrapPaddingBottom: property(this.composer, "padding-bottom"),
      visibleHeight: cssPixels(this.root.style.getPropertyValue("--cr-visible-height")),
      visibleTop: cssPixels(this.root.style.getPropertyValue("--cr-visible-top"))
    };
    for (const [name, node] of [
      ["app", app], ["leaf", this.root.closest?.(".workspace-leaf-content")],
      ["host", this.root.parentElement], ["root", this.root],
      ["messages", this.root.querySelector?.(".claudian-remote-messages")],
      ["wrap", this.composer], ["row", this.composer.querySelector?.(".claudian-remote-composer")],
      ["input", this.input], ["history", history]
    ]) {
      const rect = node?.getBoundingClientRect?.();
      sample[`${name}Top`] = geometryNumber(rect?.top);
      sample[`${name}Height`] = geometryNumber(rect?.height);
    }
    const key = JSON.stringify(sample);
    if (key !== this.lastGeometryKey) {
      this.lastGeometryKey = key;
      this.geometrySamples.push(sample);
      if (this.geometrySamples.length > 8) this.geometrySamples.shift();
    }
    // lastFocused retains the most constrained message viewport in this focus
    // session: iOS may hide the keyboard without blurring the input. Newer ties
    // retain settled keyboard values; normal restored frames cannot replace it.
    if (focusKind !== "none" && (
      focusKind !== this.geometryFocusKind || !this.lastFocusedGeometry ||
      this.lastFocusedGeometry.messagesHeight === null ||
      (sample.messagesHeight !== null && sample.messagesHeight <= this.lastFocusedGeometry.messagesHeight)
    )) this.lastFocusedGeometry = sample;
    this.geometryFocusKind = focusKind;
  }

  getLayoutDiagnostics() {
    this.captureGeometry();
    return {
      samples: this.geometrySamples.map((sample) => ({ ...sample })),
      lastFocused: this.lastFocusedGeometry ? { ...this.lastFocusedGeometry } : null
    };
  }

  dispose() {
    this.started = false;
    this.settleUntil = 0;
    if (this.frame != null) this.cancelFrame(this.frame);
    this.frame = null;
    for (const dispose of this.disposers.splice(0)) dispose();
  }
}
