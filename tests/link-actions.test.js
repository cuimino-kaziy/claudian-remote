import assert from "node:assert/strict";
import test from "node:test";

import { classifyLink, handleContentAction } from "../src/mobile/link-actions.js";

test("Vault links and relative Markdown open through Obsidian", () => {
  assert.deepEqual(classifyLink("Notes/today.md"), { kind: "vault", target: "Notes/today.md" });
  assert.deepEqual(classifyLink("", { internalTarget: "Project/Plan" }), { kind: "vault", target: "Project/Plan" });
  const opened = [];
  const anchor = { dataset: { href: "Project/Plan" }, getAttribute: () => "" };
  handleContentAction({ app: { workspace: { openLinkText: (...args) => opened.push(args) }, metadataCache: { getFirstLinkpathDest: () => ({ path: "Project/Plan.md" }) } }, sourcePath: "Inbox/source.md", anchor });
  assert.deepEqual(opened, [["Project/Plan", "Inbox/source.md", false]]);
});

test("only HTTP(S) leaves the Vault and local or dangerous schemes are blocked", () => {
  assert.deepEqual(classifyLink("https://example.com/doc"), { kind: "external", href: "https://example.com/doc" });
  assert.equal(classifyLink("javascript:alert(1)").kind, "blocked");
  assert.equal(classifyLink("file:///Users/example/private.md").kind, "blocked");
  assert.equal(classifyLink("/Users/example/private.md").kind, "blocked");
  assert.equal(classifyLink("obsidian://open?vault=x").kind, "blocked");
  assert.equal(classifyLink("bad%ZZ").kind, "blocked");
});

test("missing Vault destination returns a stable non-opening action", () => {
  const opened = [];
  const anchor = { dataset: { href: "Missing/Note" }, getAttribute: () => "" };
  const action = handleContentAction({
    app: { workspace: { openLinkText: (...args) => opened.push(args) }, metadataCache: { getFirstLinkpathDest: () => null } },
    anchor
  });
  assert.deepEqual(action, { kind: "missing", target: "Missing/Note" });
  assert.deepEqual(opened, []);
});
