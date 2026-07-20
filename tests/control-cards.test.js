import assert from "node:assert/strict";
import test from "node:test";

import { buildCommand } from "../src/mobile/command-builder.js";
import { activityCard } from "../src/mobile/components/activity-card.js";
import { currentOperationModel, shouldShowOperationCard } from "../src/mobile/view-model.js";

function withFakeDocument(callback) {
  const previous = globalThis.document;
  globalThis.document = {
    createElement(tag) {
      return {
        tagName: tag.toUpperCase(), className: "", textContent: "", children: [], dataset: {}, attributes: {}, open: false,
        get firstElementChild() { return this.children[0] || null; },
        append(...children) { this.children.push(...children); },
        replaceChildren(...children) { this.children = children; },
        setAttribute(name, value) { this.attributes[name] = String(value); },
        removeAttribute(name) { delete this.attributes[name]; }
      };
    }
  };
  try { return callback(); }
  finally { globalThis.document = previous; }
}

function onlineState() {
  return {
    transport: { status: "connected" },
    presence: { mac: { status: "online", sessionId: "mac-session", connectionGeneration: 3 } },
    activeConversationId: "conv",
    conversations: { conv: { id: "conv", revision: 8, activeTurnId: "turn", turns: {} } }
  };
}

test("mobile controls remain bound to current Mac generation and revision", () => {
  const command = buildCommand(onlineState(), "turn.steer", { text: "now" }, { now: () => 0, randomUUID: () => "id" });
  assert.equal(command.delivery_id, "mobile-id");
  assert.equal(command.mac_connection_generation, 3);
  assert.equal(command.expected_revision, 8);
  assert.deepEqual(command.target, { conversation_id: "conv", turn_id: "turn" });
  assert.equal(command.expires_at, "1970-01-01T00:00:30.000Z");
});

test("message command accepts a preallocated delivery id for attachment reservation", () => {
  const command = buildCommand(
    onlineState(),
    "message.submit",
    { text: "with file", attachment_refs: [{ upload_id: "upload" }] },
    { now: () => 0, deliveryId: "mobile-reserved" }
  );
  assert.equal(command.delivery_id, "mobile-reserved");
  assert.equal(command.payload.attachment_refs[0].upload_id, "upload");
});

test("operation model uses only current-operation activity and tool ids", () => {
  const turn = {
    status: "running",
    activityOrder: ["read"], activities: { read: { id: "read", label: "正在读取", status: "completed" } },
    toolOrder: ["current-tool"], tools: { "current-tool": { id: "current-tool", label: "正在检索", status: "running" } },
    messageOrder: ["message"], messages: {
      message: { blockOrder: ["historical-tool"], blocks: { "historical-tool": { id: "historical-tool", type: "tool", label: "历史工具", status: "completed" } } }
    }
  };
  const model = currentOperationModel(turn);
  assert.equal(model.running, true);
  assert.deepEqual(model.entries.map((item) => item.id), ["read", "current-tool"]);
});

test("running turn shows a breathing status before the first activity event", () => {
  const model = currentOperationModel({
    status: "running", activityOrder: [], activities: {}, messageOrder: [], messages: {}
  });
  assert.equal(shouldShowOperationCard(model), true);
  const card = withFakeDocument(() => activityCard(model));
  assert.equal(card.tagName, "DIV");
  assert.match(card.className, /is-running/);
  assert.equal(card.children[0].textContent, "正在思考…");
  assert.equal(card.attributes["aria-busy"], "true");
});

test("offline commands fail locally and cannot become a delayed queue", () => {
  const state = onlineState();
  state.presence.mac.status = "offline";
  assert.throws(() => buildCommand(state, "message.submit", { text: "later" }), /mac_offline/);
});
