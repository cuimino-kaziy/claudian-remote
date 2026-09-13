import { Component, MarkdownRenderer } from "obsidian";
import { RenderGeneration, renderDelay } from "./render-policy.js";

const PASSIVE_MEDIA_SELECTOR = "img, source, audio, video, iframe, embed, object";
const REQUEST_ATTRIBUTES = ["src", "srcset", "poster", "data"];
const PASSIVE_MEDIA_HTML = /^<\s*\/?\s*(?:img|source|audio|video|track|picture|iframe|embed|object|svg|image|feimage|use|script|link|input|style)\b/i;

function sanitizePassiveMedia(root) {
  for (const element of root.querySelectorAll(PASSIVE_MEDIA_SELECTOR)) {
    for (const attribute of REQUEST_ATTRIBUTES) element.removeAttribute(attribute);
  }
}

function neutralizeInlineMedia(markdownLine) {
  let output = "";
  let inlineCodeTicks = 0;
  for (let index = 0; index < markdownLine.length;) {
    if (markdownLine[index] === "`") {
      let end = index + 1;
      while (markdownLine[end] === "`") end += 1;
      const ticks = end - index;
      if (inlineCodeTicks === ticks) inlineCodeTicks = 0;
      else if (inlineCodeTicks === 0 && markdownLine.indexOf("`".repeat(ticks), end) !== -1) inlineCodeTicks = ticks;
      output += markdownLine.slice(index, end);
      index = end;
      continue;
    }
    if (inlineCodeTicks === 0 && markdownLine[index] === "!" && markdownLine[index + 1] === "[") {
      let slashCount = 0;
      for (let cursor = index - 1; cursor >= 0 && markdownLine[cursor] === "\\"; cursor -= 1) slashCount += 1;
      if (slashCount % 2 === 0) output += "\\";
      output += "![";
      index += 2;
      continue;
    }
    if (inlineCodeTicks === 0 && markdownLine[index] === "<" && PASSIVE_MEDIA_HTML.test(markdownLine.slice(index))) {
      output += "&lt;";
      index += 1;
      continue;
    }
    output += markdownLine[index];
    index += 1;
  }
  return output;
}

function neutralizePassiveMedia(markdown) {
  let fence = null;
  return String(markdown).split("\n").map((line) => {
    const marker = line.match(/^ {0,3}(`{3,}|~{3,})/);
    if (fence) {
      if (marker && marker[1][0] === fence.character && marker[1].length >= fence.length) fence = null;
      return line;
    }
    if (marker) {
      fence = { character: marker[1][0], length: marker[1].length };
      return line;
    }
    if (/^(?: {4}|\t)/.test(line)) return line;
    return neutralizeInlineMedia(line);
  }).join("\n");
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
        await MarkdownRenderer.render(
          this.app,
          neutralizePassiveMedia(pending.markdown),
          wrapper,
          this.sourcePath,
          component
        );
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
