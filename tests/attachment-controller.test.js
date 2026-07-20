import assert from "node:assert/strict";
import test from "node:test";

import { AttachmentController } from "../src/mobile/attachment-controller.js";
import { IncrementalSha256, sha256Hex } from "../src/mobile/sha256-stream.js";

function namedBlob(bytes, name = "notes.md") {
  const blob = new Blob([bytes]);
  Object.defineProperty(blob, "name", { value: name });
  return blob;
}

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

test("incremental SHA-256 is stable across arbitrary chunk boundaries", () => {
  const bytes = new TextEncoder().encode("abc");
  assert.equal(sha256Hex(bytes), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  const hash = new IncrementalSha256();
  hash.update(bytes.subarray(0, 1));
  hash.update(bytes.subarray(1));
  assert.equal(hash.digestHex(), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
});

test("one attachment streams bounded chunks and waits for Mac artifact before becoming sendable", async () => {
  const calls = [];
  let offset = 0;
  let index = 0;
  const fetchImpl = async (url, options) => {
    calls.push({ url, options });
    if (url.endsWith("/api/v2/uploads")) return response(201, { upload_id: "upload-12345678", next_offset: 0, next_index: 0 });
    if (url.includes("/chunks/")) {
      const bytes = options.body;
      assert.ok(bytes.byteLength <= 1024 * 1024);
      assert.equal(Number(options.headers["X-Upload-Offset"]), offset);
      assert.equal(Number(url.split("/").at(-1)), index);
      offset += bytes.byteLength;
      index += 1;
      return response(200, { next_offset: offset, next_index: index });
    }
    if (url.endsWith("/finalize")) return response(200, { ok: true, status: "ready_for_mac" });
    throw new Error(`unexpected ${url}`);
  };
  const session = { mac_session_id: "mac", mac_connection_generation: 2 };
  const controller = new AttachmentController({
    baseUrl: "https://relay.example", tokenProvider: () => "private", getSession: () => session,
    fetchImpl, chunkBytes: 64 * 1024
  });
  const file = namedBlob(new Uint8Array(70 * 1024), "../../notes.md");
  await controller.upload(file);
  assert.equal(controller.snapshot()[0].status, "importing");
  assert.deepEqual(controller.references(), []);
  assert.equal(controller.onArtifact({ artifact_id: "upload-12345678", vault_path: "Claudian Remote/Uploads/notes-upload-1.md", kind: "markdown" }), true);
  assert.deepEqual(controller.references(), [{ upload_id: "upload-12345678", vault_path: "Claudian Remote/Uploads/notes-upload-1.md", label: "../../notes.md" }]);
  assert.equal(calls.filter((call) => call.url.includes("/chunks/")).length, 2);
  assert.equal(calls.every((call) => !call.url.includes("private")), true);
});

test("paused upload can resume only inside the original Mac connection generation", async () => {
  let session = { mac_session_id: "mac", mac_connection_generation: 1 };
  let chunkAttempts = 0;
  const fetchImpl = async (url, options) => {
    if (url.endsWith("/api/v2/uploads")) return response(201, { upload_id: "upload-abcdefgh", next_offset: 0, next_index: 0 });
    if (url.includes("/chunks/")) {
      chunkAttempts += 1;
      if (chunkAttempts === 1) throw new Error("network_lost");
      return response(200, { next_offset: options.body.byteLength, next_index: 1 });
    }
    if (url.endsWith("/finalize")) return response(200, { ok: true });
    return response(200, {});
  };
  const controller = new AttachmentController({ baseUrl: "https://relay.example", tokenProvider: () => "token", getSession: () => session, fetchImpl });
  await assert.rejects(() => controller.upload(namedBlob(new Uint8Array(100))), /network_lost/);
  assert.equal(controller.snapshot()[0].status, "paused");
  session = { mac_session_id: "mac", mac_connection_generation: 2 };
  await assert.rejects(() => controller.resume(), /session_changed/);
});

test("cancel during hashing stops before an upload request can start", async () => {
  const read = deferred();
  const calls = [];
  const file = {
    name: "slow.md",
    type: "text/markdown",
    size: 4,
    slice() { return { arrayBuffer: () => read.promise }; }
  };
  const controller = new AttachmentController({
    baseUrl: "https://relay.example",
    tokenProvider: () => "token",
    getSession: () => ({ mac_session_id: "mac", mac_connection_generation: 1 }),
    fetchImpl: async (...args) => { calls.push(args); return response(500, {}); }
  });

  const uploading = controller.upload(file);
  await Promise.resolve();
  await controller.cancel();
  read.resolve(new Uint8Array([1, 2, 3, 4]).buffer);

  await assert.rejects(uploading, /upload_cancelled/);
  assert.deepEqual(controller.snapshot(), []);
  assert.equal(calls.length, 0);
});

test("cancel aborts an in-flight upload creation request", async () => {
  const started = deferred();
  const pending = deferred();
  let requestSignal;
  const controller = new AttachmentController({
    baseUrl: "https://relay.example",
    tokenProvider: () => "token",
    getSession: () => ({ mac_session_id: "mac", mac_connection_generation: 1 }),
    fetchImpl: async (_url, options) => {
      requestSignal = options.signal;
      started.resolve();
      return pending.promise;
    }
  });

  const uploading = controller.upload(namedBlob(new Uint8Array([1])));
  await started.promise;
  await controller.cancel();
  const wasAborted = requestSignal?.aborted === true;
  pending.resolve(response(201, { upload_id: "upload-cancelled", next_offset: 0, next_index: 0 }));

  await assert.rejects(uploading, /upload_cancelled/);
  assert.equal(wasAborted, true);
  assert.deepEqual(controller.snapshot(), []);
});

test("cancel aborts an in-flight chunk request and deletes the server upload", async () => {
  const chunkStarted = deferred();
  const pendingChunk = deferred();
  let chunkSignal;
  let deleted = false;
  const controller = new AttachmentController({
    baseUrl: "https://relay.example",
    tokenProvider: () => "token",
    getSession: () => ({ mac_session_id: "mac", mac_connection_generation: 1 }),
    fetchImpl: async (url, options) => {
      if (url.endsWith("/api/v2/uploads")) return response(201, { upload_id: "upload-in-flight", next_offset: 0, next_index: 0 });
      if (options.method === "DELETE") { deleted = true; return response(204, {}); }
      if (url.includes("/chunks/")) {
        chunkSignal = options.signal;
        chunkStarted.resolve();
        return pendingChunk.promise;
      }
      if (url.endsWith("/finalize")) return response(200, { ok: true });
      throw new Error(`unexpected ${url}`);
    }
  });

  const uploading = controller.upload(namedBlob(new Uint8Array([1, 2, 3])));
  await chunkStarted.promise;
  await controller.cancel();
  const wasAborted = chunkSignal?.aborted === true;
  pendingChunk.resolve(response(200, { next_offset: 3, next_index: 1 }));

  await assert.rejects(uploading, /upload_cancelled/);
  assert.equal(wasAborted, true);
  assert.equal(deleted, true);
  assert.deepEqual(controller.snapshot(), []);
});

test("ready attachment reservation is single-use per delivery and releasable after rejection", async () => {
  const controller = new AttachmentController({
    baseUrl: "https://relay.example",
    tokenProvider: () => "token",
    getSession: () => ({ mac_session_id: "mac", mac_connection_generation: 1 }),
    fetchImpl: async (url) => url.endsWith("/api/v2/uploads")
      ? response(201, { upload_id: "upload-reserved", next_offset: 0, next_index: 0 })
      : response(200, { ok: true })
  });
  await controller.upload(namedBlob(new Uint8Array()));
  controller.onArtifact({ artifact_id: "upload-reserved", vault_path: "Claudian Remote/Uploads/notes.md", kind: "markdown" });

  const first = controller.reserveReady("delivery-a");
  assert.equal(first.length, 1);
  assert.deepEqual(controller.reserveReady("delivery-a"), []);
  assert.deepEqual(controller.reserveReady("delivery-b"), []);
  assert.equal(controller.snapshot()[0].reserved, true);
  assert.equal(controller.releaseReservation("delivery-b"), false);
  assert.equal(controller.releaseReservation("delivery-a"), true);
  assert.equal(controller.snapshot()[0].reserved, false);

  assert.equal(controller.reserveReady("delivery-b").length, 1);
  assert.deepEqual(controller.consumeReservation("delivery-a"), []);
  assert.equal(controller.snapshot().length, 1);
  assert.equal(controller.consumeReservation("delivery-b").length, 1);
  assert.deepEqual(controller.consumeReservation("delivery-b"), []);
  assert.deepEqual(controller.snapshot(), []);
});

function response(status, body) {
  return { ok: status >= 200 && status < 300, status, async json() { return body; } };
}
