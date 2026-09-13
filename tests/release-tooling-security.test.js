import assert from "node:assert/strict";
import test from "node:test";
import { storeSigningKeyInKeychain } from "../release/packaging/signing-key-source.mjs";
import { verifyRuntimeAsset } from "../release/packaging/verify-runtime-assets.mjs";

test("release signing key is supplied over stdin and an existing key is not overwritten", () => {
  const secret = "private-key-material";
  let invocation;
  storeSigningKeyInKeychain(secret, "f".repeat(64), {
    platform: "darwin",
    spawn(command, commandArguments, options) {
      invocation = { command, commandArguments, options };
      return { status: 0 };
    }
  });

  assert.equal(invocation.command, "security");
  assert.equal(invocation.commandArguments.at(-1), "-w");
  assert.equal(invocation.commandArguments.includes("-U"), false);
  assert.equal(invocation.commandArguments.includes(secret), false);
  assert.equal(invocation.options.input, `${secret}\n${secret}\n`);
});

test("release signing key initialization fails closed when Keychain refuses the insert", () => {
  assert.throws(
    () => storeSigningKeyInKeychain("secret", "f".repeat(64), {
      platform: "darwin",
      spawn: () => ({ status: 45 })
    }),
    /existing key was not replaced/
  );
});

test("runtime asset verification has a per-asset timeout with target context", async () => {
  const target = {
    platform: "darwin",
    arch: "arm64",
    python: {
      url: "https://downloads.example/python.tar.gz",
      sha256: "a".repeat(64)
    }
  };
  // AbortSignal.timeout's timer is unref'd, so it does not keep the Node event
  // loop alive on its own; in a busy CI loop the abort could be starved before
  // the fake fetch settles. Keep the loop alive from the fetch side so the
  // production default per-asset timeout deterministically fires the abort.
  const fetchImpl = (_url, { signal }) => new Promise((_resolve, reject) => {
    const keepAlive = setInterval(() => {}, 60_000);
    signal.addEventListener("abort", () => {
      clearInterval(keepAlive);
      reject(signal.reason);
    }, { once: true });
  });

  await assert.rejects(
    verifyRuntimeAsset(target, "python", { fetchImpl, timeoutMs: 10 }),
    /darwin\/arm64 python verification failed/
  );
});
