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
