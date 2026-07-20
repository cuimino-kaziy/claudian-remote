import { Component, MarkdownRenderer } from "obsidian";
import { RenderGeneration, renderDelay } from "./render-policy.js";

const PASSIVE_MEDIA_SELECTOR = "img, source, audio, video, iframe, embed, object";
const REQUEST_ATTRIBUTES = ["src", "srcset", "poster", "data"];

function sanitizePassiveMedia(root) {
  for (const element of root.querySelectorAll(PASSIVE_MEDIA_SELECTOR)) {
    for (const attribute of REQUEST_ATTRIBUTES) element.removeAttribute(attribute);
  }
}

function createPlainTextPlaceholder(markdown) {
  const wrapper = document.createElement("div");
  wrapper.className = "claudian-remote-markdown-inner claudian-remote-markdown-pending";
  wrapper.textContent = markdown;
  return wrapper;
}

export class StreamingMarkdownRenderer {
  constructor({ app, sourcePath = "", throttleMs = 250, onRendered = () => {}, timers = globalThis }) {
    this.app = app;
    this.sourcePath = sourcePath;
    this.throttleMs = throttleMs;
    this.onRendered = onRendered;
    this.timers = timers;
    this.generation = new RenderGeneration();
    this.lastRenderedAt = 0;
    this.timer = null;
    this.component = null;
    this.pending = null;
    this.rendering = false;
  }

  schedule(container, markdown, { final = false } = {}) {
    const text = String(markdown || "");
    if (!container.firstChild) {
      container.replaceChildren(createPlainTextPlaceholder(text));
      this.onRendered();
    }
    const generation = this.generation.next();
    this.pending = { container, markdown: text, generation, final };
    if (this.timer) this.timers.clearTimeout(this.timer);
    this.timer = null;
    this.requestRender();
  }

  requestRender() {
    if (this.rendering || !this.pending || this.timer) return;
    const delay = renderDelay({
      final: this.pending.final,
      elapsedMs: Date.now() - this.lastRenderedAt,
      throttleMs: this.throttleMs
    });
    if (delay === 0) void this.renderPending();
    else this.timer = this.timers.setTimeout(() => { this.timer = null; void this.renderPending(); }, delay);
  }

  async renderPending() {
    if (this.rendering) return;
    const pending = this.pending;
    if (!pending) return;
    this.pending = null;
    this.rendering = true;
    const wrapper = document.createElement("div");
    wrapper.className = "claudian-remote-markdown-inner markdown-rendered";
    let component = null;
    try {
      let renderFailed = false;
      try {
        component = new Component();
        component.load();
        await MarkdownRenderer.render(this.app, pending.markdown, wrapper, this.sourcePath, component);
      } catch {
        component?.unload();
        renderFailed = true;
      }
      if (renderFailed) {
        if (!this.generation.isCurrent(pending.generation)) return;
        wrapper.textContent = pending.markdown;
        this.commit(pending, wrapper, null);
        return;
      }
      if (!this.generation.isCurrent(pending.generation)) {
        component.unload();
        return;
      }
      sanitizePassiveMedia(wrapper);
      this.commit(pending, wrapper, component);
    } finally {
      this.rendering = false;
      this.requestRender();
    }
  }

  commit(pending, wrapper, component) {
    const old = this.component;
    pending.container.replaceChildren(wrapper);
    this.component = component;
    this.lastRenderedAt = Date.now();
    old?.unload();
    this.onRendered();
  }

  dispose() {
    this.generation.invalidate();
    if (this.timer) this.timers.clearTimeout(this.timer);
    this.timer = null;
    this.pending = null;
    this.component?.unload();
    this.component = null;
  }
}
