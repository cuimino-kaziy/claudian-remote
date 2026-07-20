import assert from "node:assert/strict";
import test from "node:test";

import { createObsidianFetch } from "../src/mobile/obsidian-http.js";

function deferred() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
}

test("Obsidian HTTP adapter rejects promptly when an attachment request is aborted", async () => {
  const pending = deferred();
  const controller = new AbortController();
  const fetchImpl = createObsidianFetch(() => pending.promise);
  const request = fetchImpl("https://relay.example/upload", { signal: controller.signal });

  controller.abort(new Error("upload_cancelled"));

  await assert.rejects(request, /upload_cancelled/);
  pending.resolve({ status: 200, headers: {}, json: {}, text: "", arrayBuffer: new ArrayBuffer(0) });
});
