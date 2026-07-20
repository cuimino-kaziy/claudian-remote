import assert from "node:assert/strict";
import test from "node:test";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

import esbuild from "esbuild";

class FakeElement {
  constructor(tagName) {
    this.tagName = tagName.toUpperCase();
    this.className = "";
    this.textContent = "";
    this.children = [];
    this.dataset = {};
    this.attributes = {};
    this.listeners = {};
    this.parentNode = null;
    this.hidden = false;
    this.open = false;
    this.scrollHeight = 900;
    this.clientHeight = 600;
    this.scrollTop = 300;
  }

  get firstElementChild() {
    return this.children[0] || null;
  }

  addEventListener(type, listener) {
    (this.listeners[type] ||= []).push(listener);
  }

  setAttribute(name, value) {
    this.attributes[name] = String(value);
  }

  getAttribute(name) {
    return this.attributes[name] ?? null;
  }

  removeAttribute(name) {
    delete this.attributes[name];
  }

  append(...children) {
    for (const child of children) this.attach(child, this.children.length);
  }

  prepend(...children) {
    for (const child of children.reverse()) this.attach(child, 0);
  }

  replaceChildren(...children) {
    for (const child of this.children) child.parentNode = null;
    this.children = [];
    this.append(...children);
  }

  attach(child, index) {
    child.remove();
    this.children.splice(index, 0, child);
    child.parentNode = this;
  }

  remove() {
    if (!this.parentNode) return;
    const index = this.parentNode.children.indexOf(this);
    if (index >= 0) this.parentNode.children.splice(index, 1);
    this.parentNode = null;
  }
}

let bundlePromise;

async function messageListBundle() {
  bundlePromise ||= esbuild.build({
    entryPoints: [fileURLToPath(new URL("../src/mobile/components/message-list.js", import.meta.url))],
    bundle: true,
    write: false,
    format: "cjs",
    platform: "browser",
    plugins: [{
      name: "streaming-markdown-test-double",
      setup(build) {
        build.onResolve({ filter: /^\.\.\/markdown-renderer\.js$/ }, () => ({ path: "markdown-renderer", namespace: "test" }));
        build.onLoad({ filter: /.*/, namespace: "test" }, () => ({
          loader: "js",
          contents: `
            export class StreamingMarkdownRenderer {
              constructor(options) {
                this.options = options;
                this.calls = [];
                this.disposed = false;
                globalThis.__renderers.push(this);
              }
              schedule(container, markdown, options) { this.calls.push({ container, markdown, options }); }
              dispose() { this.disposed = true; }
            }
          `
        }));
      }
    }]
  });
  return (await bundlePromise).outputFiles[0].text;
}

async function harness() {
  const renderers = [];
  const frames = new Map();
  const cancelledFrames = [];
  let nextFrame = 1;
  const module = { exports: {} };
  vm.runInNewContext(await messageListBundle(), {
    module,
    exports: module.exports,
    __renderers: renderers,
    document: { createElement: (tagName) => new FakeElement(tagName) },
    requestAnimationFrame(callback) {
      const id = nextFrame;
      nextFrame += 1;
      frames.set(id, callback);
      return id;
    },
    cancelAnimationFrame(id) {
      cancelledFrames.push(id);
      frames.delete(id);
    }
  });
  return { ...module.exports, renderers, frames, cancelledFrames };
}

function model({ status = "running", text = "same text", activityLabel = "正在读取" } = {}) {
  const turn = {
    id: "turn-1",
    status,
    activityOrder: ["activity-1"],
    activities: { "activity-1": { id: "activity-1", label: activityLabel, status: status === "running" ? "running" : "completed" } },
    messageOrder: ["message-1"],
    messages: { "message-1": { id: "message-1", blockOrder: [], blocks: {} } },
    approvalOrder: [],
    approvals: {},
    artifactOrder: [],
    artifacts: {}
  };
  return {
    turns: [turn],
    messages: [{ key: "message:turn-1:message-1", turnId: "turn-1", role: "assistant", text }],
    controls: { approval: true }
  };
}

function modelWithControls({ approvalStatus = "pending", artifactLabel = "结果.md" } = {}) {
  const value = model();
  const turn = value.turns[0];
  turn.approvalOrder = ["approval-1"];
  turn.approvals = {
    "approval-1": {
      id: "approval-1",
      title: "允许写入？",
      status: approvalStatus,
      options: [{ id: "allow", label: "允许" }]
    }
  };
  turn.artifactOrder = ["artifact-1"];
  turn.artifacts = {
    "artifact-1": {
      id: "artifact-1",
      kind: "markdown",
      label: artifactLabel,
      vault_path: "Claudian Remote/结果.md"
    }
  };
  return value;
}

function byClass(parent, className) {
  return parent.children.find((child) => child.className.split(/\s+/).includes(className));
}

function detailsFor(card) {
  return card.tagName === "DETAILS" ? card : card.children.find((child) => child.tagName === "DETAILS");
}

test("operation card keeps stable turn nodes and a user-collapsed state across deltas", async (t) => {
  const { MessageList } = await harness();
  const container = new FakeElement("div");
  const messages = new MessageList(container, { app: {} });
  t.after(() => messages.dispose());

  messages.render(model());
  const firstCard = byClass(messages.list, "claudian-remote-activity");
  const firstDetails = detailsFor(firstCard);
  assert.equal(firstDetails.open, true);
  firstDetails.open = false;

  messages.render(model({ activityLabel: "正在读取新片段" }));
  const updatedCard = byClass(messages.list, "claudian-remote-activity");
  const updatedDetails = detailsFor(updatedCard);

  assert.equal(updatedCard, firstCard, "turn activity root was rebuilt");
  assert.equal(updatedDetails, firstDetails, "turn details node was rebuilt");
  assert.equal(updatedDetails.open, false, "user collapse state was lost on delta");
  assert.equal(updatedDetails.firstElementChild.textContent, "正在读取新片段");
});

test("scroll-to-bottom coalesces to one animation frame and dispose cancels it", async () => {
  const { MessageList, frames, cancelledFrames } = await harness();
  const container = new FakeElement("div");
  const messages = new MessageList(container, { app: {} });

  messages.scrollToBottom();
  messages.scrollToBottom();
  messages.afterContentChange();

  assert.equal(frames.size, 1, "multiple scroll frames were queued");
  const [frameId] = frames.keys();
  messages.dispose();
  assert.deepEqual(cancelledFrames, [frameId]);
  assert.equal(frames.size, 0);
});

test("queued bottom-follow is abandoned if the user scrolls away before the frame", async (t) => {
  const { MessageList, frames } = await harness();
  const container = new FakeElement("div");
  const messages = new MessageList(container, { app: {} });
  t.after(() => messages.dispose());
  messages.el.scrollTop = 120;
  messages.scrollToBottom();
  messages.following = false;

  frames.values().next().value();

  assert.equal(messages.el.scrollTop, 120);
});

test("running-to-final transition schedules authoritative Markdown when text is unchanged", async (t) => {
  const { MessageList, renderers } = await harness();
  const container = new FakeElement("div");
  const messages = new MessageList(container, { app: {} });
  t.after(() => messages.dispose());

  messages.render(model({ status: "running", text: "unchanged" }));
  assert.equal(renderers.length, 1);
  assert.equal(renderers[0].calls.length, 1);
  assert.equal(renderers[0].calls[0].options.final, false);

  messages.render(model({ status: "completed", text: "unchanged" }));

  assert.equal(renderers[0].calls.length, 2);
  assert.equal(renderers[0].calls[1].markdown, "unchanged");
  assert.equal(renderers[0].calls[1].options.final, true);
});

test("unchanged approval and artifact controls keep stable nodes across streaming deltas", async (t) => {
  const { MessageList } = await harness();
  const container = new FakeElement("div");
  const messages = new MessageList(container, { app: {} });
  t.after(() => messages.dispose());

  messages.render(modelWithControls());
  const approval = byClass(messages.list, "claudian-remote-approval");
  const artifact = byClass(messages.list, "claudian-remote-artifact");

  messages.render(modelWithControls());

  assert.equal(byClass(messages.list, "claudian-remote-approval"), approval);
  assert.equal(byClass(messages.list, "claudian-remote-artifact"), artifact);
});

test("approval and artifact nodes refresh only when their authoritative model changes", async (t) => {
  const { MessageList } = await harness();
  const container = new FakeElement("div");
  const messages = new MessageList(container, { app: {} });
  t.after(() => messages.dispose());

  messages.render(modelWithControls());
  const approval = byClass(messages.list, "claudian-remote-approval");
  const artifact = byClass(messages.list, "claudian-remote-artifact");

  messages.render(modelWithControls({ approvalStatus: "resolved", artifactLabel: "最终结果.md" }));

  assert.notEqual(byClass(messages.list, "claudian-remote-approval"), approval);
  assert.notEqual(byClass(messages.list, "claudian-remote-artifact"), artifact);
});
