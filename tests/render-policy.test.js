import assert from "node:assert/strict";
import test from "node:test";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

import esbuild from "esbuild";

import { RenderGeneration, renderDelay } from "../src/mobile/render-policy.js";

class FakeElement {
  constructor(tagName = "div") {
    this.tagName = tagName.toUpperCase();
    this.attributes = new Map();
    this.children = [];
    this.className = "";
    this.textContent = "";
    this.beforeReplace = null;
  }

  setAttribute(name, value) {
    this.attributes.set(name, String(value));
  }

  getAttribute(name) {
    return this.attributes.get(name) ?? null;
  }

  hasAttribute(name) {
    return this.attributes.has(name);
  }

  removeAttribute(name) {
    this.attributes.delete(name);
  }

  append(...children) {
    this.children.push(...children);
  }

  replaceChildren(...children) {
    this.beforeReplace?.(children);
    this.children = children;
  }

  get firstChild() {
    return this.children[0] || null;
  }

  querySelectorAll(selector) {
    const tagNames = new Set(selector.split(",").map((part) => part.trim().toUpperCase()));
    const matches = [];
    const visit = (node) => {
      for (const child of node.children) {
        if (tagNames.has(child.tagName)) matches.push(child);
        visit(child);
      }
    };
    visit(this);
    return matches;
  }
}

async function rendererHarness(render) {
  const output = (await esbuild.build({
    entryPoints: [fileURLToPath(new URL("../src/mobile/markdown-renderer.js", import.meta.url))],
    bundle: true,
    write: false,
    format: "cjs",
    platform: "browser",
    plugins: [{
      name: "obsidian-renderer-test-double",
      setup(build) {
        build.onResolve({ filter: /^obsidian$/ }, () => ({ path: "obsidian", namespace: "test" }));
        build.onLoad({ filter: /.*/, namespace: "test" }, () => ({
          loader: "js",
          contents: `
            export class Component {
              constructor() {
                this.loadCount = 0;
                this.unloadCount = 0;
                globalThis.__components.push(this);
              }
              load() { this.loadCount += 1; }
              unload() { this.unloadCount += 1; }
            }
            export const MarkdownRenderer = {
              render(...args) { return globalThis.__render(...args); }
            };
          `
        }));
      }
    }]
  })).outputFiles[0].text;
  const components = [];
  const module = { exports: {} };
  vm.runInNewContext(output, {
    module,
    exports: module.exports,
    __components: components,
    __render: render,
    document: { createElement: (tagName) => new FakeElement(tagName) },
    console,
    Date,
    setTimeout,
    clearTimeout
  });
  return { ...module.exports, components };
}

async function waitFor(predicate, message = "condition was not reached") {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    if (predicate()) return;
    await new Promise((resolve) => setImmediate(resolve));
  }
  assert.fail(message);
}

test("final Markdown rendering bypasses throttle", () => {
  assert.equal(renderDelay({ final: true, elapsedMs: 1, throttleMs: 250 }), 0);
  assert.equal(renderDelay({ final: false, elapsedMs: 100, throttleMs: 250 }), 150);
});

test("new assistant text is visible before asynchronous Markdown rendering settles", async (t) => {
  let release;
  const { StreamingMarkdownRenderer } = await rendererHarness(async () => {
    await new Promise((resolve) => { release = resolve; });
  });
  const container = new FakeElement();
  const renderer = new StreamingMarkdownRenderer({ app: {} });
  t.after(() => renderer.dispose());

  renderer.schedule(container, "立即可见的回复", { final: true });

  assert.equal(container.children.length, 1);
  assert.equal(container.children[0].textContent, "立即可见的回复");
  release();
  await waitFor(() => renderer.rendering === false);
});

test("older asynchronous render generation can never replace newer content", () => {
  const guard = new RenderGeneration();
  const old = guard.next();
  const current = guard.next();
  assert.equal(guard.isCurrent(old), false);
  assert.equal(guard.isCurrent(current), true);
  guard.invalidate();
  assert.equal(guard.isCurrent(current), false);
});

test("streaming Markdown keeps one render in flight and drains only the latest final content", async (t) => {
  const calls = [];
  const releases = [];
  let inFlight = 0;
  let maxInFlight = 0;
  const { StreamingMarkdownRenderer } = await rendererHarness(async (_app, markdown, wrapper) => {
    calls.push(markdown);
    wrapper.textContent = `rendered:${markdown}`;
    inFlight += 1;
    maxInFlight = Math.max(maxInFlight, inFlight);
    await new Promise((resolve) => releases.push(resolve));
    inFlight -= 1;
  });
  const container = new FakeElement();
  const renderer = new StreamingMarkdownRenderer({ app: {}, throttleMs: 10_000 });
  t.after(() => renderer.dispose());

  renderer.schedule(container, "first delta");
  for (let index = 0; index < 20; index += 1) {
    renderer.schedule(container, `superseded delta ${index}`);
  }
  renderer.schedule(container, "authoritative final", { final: true });

  assert.deepEqual(calls, ["first delta"]);
  assert.equal(maxInFlight, 1);
  releases.shift()();
  await waitFor(() => calls.length === 2, "latest final render did not drain");
  assert.deepEqual(calls, ["first delta", "authoritative final"]);
  assert.equal(maxInFlight, 1);
  releases.shift()();
  await waitFor(() => inFlight === 0 && container.children.length === 1);
  assert.equal(container.children[0].textContent, "rendered:authoritative final");
});

test("current-generation Markdown failure replaces content and unloads both components consistently", async (t) => {
  let shouldFail = false;
  let rendered = 0;
  const { StreamingMarkdownRenderer, components } = await rendererHarness(async (_app, markdown, wrapper) => {
    if (shouldFail) throw new Error("synthetic Markdown failure");
    wrapper.textContent = `rendered:${markdown}`;
  });
  const container = new FakeElement();
  const renderer = new StreamingMarkdownRenderer({
    app: {},
    throttleMs: 10_000,
    onRendered: () => { rendered += 1; }
  });
  t.after(() => renderer.dispose());

  renderer.schedule(container, "valid", { final: true });
  await waitFor(() => rendered === 1);
  assert.equal(components[0].unloadCount, 0);

  shouldFail = true;
  renderer.schedule(container, "plain fallback", { final: true });
  await waitFor(() => rendered === 2, "failure fallback did not report a completed render");

  assert.equal(container.children[0].textContent, "plain fallback");
  assert.equal(components[0].unloadCount, 1, "previous successful Component leaked");
  assert.equal(components[1].unloadCount, 1, "failed Component leaked");
});

test("rendered Markdown strips passive request attributes before insertion but preserves links and text", async (t) => {
  const media = [];
  let relativeLink;
  let safeLink;
  let safeText;
  let rendered = 0;
  const { StreamingMarkdownRenderer } = await rendererHarness(async (_app, _markdown, wrapper) => {
    safeText = new FakeElement("p");
    safeText.textContent = "safe answer";
    safeLink = new FakeElement("a");
    safeLink.setAttribute("href", "https://example.test/open-after-click");
    safeLink.textContent = "explicit link";
    relativeLink = new FakeElement("a");
    relativeLink.setAttribute("href", "notes/today.md");
    relativeLink.textContent = "vault-relative link";
    const fixtures = [
      ["img", { src: "https://tracker.test/pixel", srcset: "https://tracker.test/2x 2x" }],
      ["source", { src: "https://media.test/source", srcset: "https://media.test/source-2x 2x" }],
      ["audio", { src: "https://media.test/audio" }],
      ["video", { src: "https://media.test/video", poster: "https://media.test/poster" }],
      ["iframe", { src: "https://frame.test/embed" }],
      ["embed", { src: "https://embed.test/content" }],
      ["object", { data: "https://object.test/content" }]
    ];
    for (const [tagName, attributes] of fixtures) {
      const element = new FakeElement(tagName);
      for (const [name, value] of Object.entries(attributes)) element.setAttribute(name, value);
      media.push(element);
    }
    wrapper.append(safeText, safeLink, relativeLink, ...media);
  });
  const container = new FakeElement();
  container.beforeReplace = () => {
    for (const element of media) {
      for (const attribute of ["src", "srcset", "poster", "data"]) {
        assert.equal(element.hasAttribute(attribute), false, `${element.tagName}.${attribute} survived before insertion`);
      }
    }
  };
  const renderer = new StreamingMarkdownRenderer({ app: {}, onRendered: () => { rendered += 1; } });
  t.after(() => renderer.dispose());

  renderer.schedule(container, "model Markdown", { final: true });
  await waitFor(() => rendered === 1);

  assert.equal(safeText.textContent, "safe answer");
  assert.equal(safeLink.getAttribute("href"), "https://example.test/open-after-click");
  assert.equal(safeLink.textContent, "explicit link");
  assert.equal(relativeLink.getAttribute("href"), "notes/today.md");
});

test("passive media syntax is neutralized before Obsidian can render or preload it", async (t) => {
  const requests = [];
  let renderedMarkdown = "";
  let rendered = 0;
  const { StreamingMarkdownRenderer } = await rendererHarness(async (_app, markdown, wrapper) => {
    renderedMarkdown = markdown;
    if (/(^|[^\\])!\[[^\]]*\]\s*(?:\(|\[)/m.test(markdown)) requests.push("markdown-image");
    if (/<\s*(?:img|source|audio|video|iframe|embed|object)\b/i.test(markdown)) requests.push("raw-html-media");
    wrapper.textContent = markdown;
  });
  const container = new FakeElement();
  const renderer = new StreamingMarkdownRenderer({ app: {}, onRendered: () => { rendered += 1; } });
  t.after(() => renderer.dispose());

  renderer.schedule(container, [
    "![tracking pixel](https://tracker.test/pixel)",
    "![reference image][remote]",
    "<img src=\"https://tracker.test/raw\" srcset=\"https://tracker.test/raw-2x 2x\">",
    "<video poster=\"https://media.test/poster\"><source src=\"https://media.test/movie\"></video>",
    "<iframe src=\"https://frame.test/embed\"></iframe>",
    "<object data=\"https://object.test/content\"></object>",
    "[explicit link](https://example.test/open-after-click)",
    "[remote]: https://tracker.test/reference"
  ].join("\n"), { final: true });
  await waitFor(() => rendered === 1);

  assert.deepEqual(requests, []);
  assert.match(renderedMarkdown, /\[explicit link\]\(https:\/\/example\.test\/open-after-click\)/);
  assert.doesNotMatch(renderedMarkdown, /<\s*(?:img|source|audio|video|iframe|embed|object)\b/i);
});
