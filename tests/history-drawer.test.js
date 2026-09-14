import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";

import { filterHistoryItems } from "../src/mobile/components/history-drawer.js";

const items = [
  { conversation_id: "one", title: "Weekly Report", message_count: 4 },
  { id: "two", title: "Project Notes", message_count: 2 },
  { conversation_id: "three", title: "", message_count: 0 }
];

test("history search is local, case insensitive, and accepts legacy cached ids", () => {
  assert.deepEqual(filterHistoryItems(items, "report").map((item) => item.conversation_id), ["one"]);
  assert.deepEqual(filterHistoryItems(items, "PROJECT").map((item) => item.conversation_id), ["two"]);
  assert.deepEqual(filterHistoryItems(items, "").map((item) => item.conversation_id), ["one", "two", "three"]);
});

test("history surface exposes new rename archive select but no permanent delete", async () => {
  const source = await readFile(new URL("../src/mobile/components/history-drawer.js", import.meta.url), "utf8");
  assert.match(source, /onNew/);
  assert.match(source, /onRename/);
  assert.match(source, /onArchive/);
  assert.match(source, /onSelect/);
  assert.doesNotMatch(source, /onDelete|deleteConversation|history\.delete/);
});

test("active and archived history scopes search independently without losing cached ids", () => {
  const history = [...items, { id: "archived", title: "Report archive", archived: true }];
  assert.deepEqual(filterHistoryItems(history, "report", "active").map((item) => item.conversation_id), ["one"]);
  assert.deepEqual(filterHistoryItems(history, "report", "archived").map((item) => item.conversation_id), ["archived"]);
  assert.equal(filterHistoryItems(history, "", "all").length, 4);
});

class FakeElement extends EventTarget {
  constructor(tag) {
    super();
    this.tagName = tag.toUpperCase();
    this.children = [];
    this.attributes = {};
    this.dataset = {};
    this.value = "";
    this.classList = { toggle() {} };
    this.focusCount = 0;
  }
  append(...nodes) { for (const node of nodes) { node.parentElement = this; this.children.push(node); } }
  replaceChildren(...nodes) { this.children = []; this.append(...nodes); }
  setAttribute(key, value) { this.attributes[key] = String(value); }
  focus() { this.focusCount += 1; document.activeElement = this; }
}

test("history refresh and repeated open preserve the search field and its focus", async (t) => {
  const prior = globalThis.document;
  globalThis.document = { createElement: (tag) => new FakeElement(tag), activeElement: null };
  t.after(() => { globalThis.document = prior; });
  const { HistoryDrawer } = await import("../src/mobile/components/history-drawer.js");
  const calls = [];
  const drawer = new HistoryDrawer(new FakeElement("div"), {
    onClose() {}, onRefresh() {}, onSelect: () => calls.push("select"), onNew() {}, onRename() {}, onArchive() {}, onSettings() {}, onActions() {}
  });
  drawer.render({ loaded: true, items }, "one", { history: true }, "one");
  drawer.setOpen(true);
  assert.equal(document.activeElement, drawer.sheet);
  const search = drawer.search;
  search.focus();
  search.value = "report";
  search.dispatchEvent(new Event("input"));
  drawer.setOpen(true);
  assert.equal(document.activeElement, search);
  drawer.render({ loaded: true, items: [...items, { id: "new", title: "Another Report" }] }, "one", { history: true }, "one");
  assert.equal(drawer.search, search);
  assert.equal(search.value, "report");
  assert.equal(document.activeElement, search);
  assert.equal(drawer.list.children.length, 2);
  assert.deepEqual(calls, []);
  drawer.setOpen(false);
  drawer.setOpen(true);
  assert.equal(document.activeElement, drawer.sheet);
  assert.equal(drawer.sheet.focusCount, 2);
});
