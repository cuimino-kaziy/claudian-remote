export class FrameRenderScheduler {
  constructor({ render, requestFrame, cancelFrame, windowObject = globalThis } = {}) {
    this.render = render;
    this.requestFrame = typeof requestFrame === "function"
      ? requestFrame
      : windowObject.requestAnimationFrame?.bind(windowObject) || ((callback) => setTimeout(callback, 0));
    this.cancelFrame = typeof cancelFrame === "function"
      ? cancelFrame
      : windowObject.cancelAnimationFrame?.bind(windowObject) || clearTimeout;
    this.frame = null;
    this.disposed = false;
  }

  request() {
    if (this.disposed || this.frame != null) return;
    this.frame = this.requestFrame(() => {
      this.frame = null;
      if (!this.disposed) this.render?.();
    });
  }

  flush() {
    if (this.disposed) return;
    if (this.frame != null) this.cancelFrame(this.frame);
    this.frame = null;
    this.render?.();
  }

  dispose() {
    this.disposed = true;
    if (this.frame != null) this.cancelFrame(this.frame);
    this.frame = null;
  }
}
