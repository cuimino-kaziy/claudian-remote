import assert from "node:assert/strict";
import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRequire } from "node:module";
import test from "node:test";

import { consumeBridgeBootstrap, defaultBridgeBootstrapPath } from "../src/desktop/bridge-bootstrap.js";

function fixture(overrides = {}) {
  return {
    bootstrap_schema: "claudian-remote.bridge-bootstrap/v1",
    installation_id: "installation-a",
    vault_id: "vault-a",
    endpoint: "https://mac.tailnet.ts.net",
    endpoint_audience: "claudian-remote:local_tailscale:installation-a",
    bridge_credential_id: "installation-a:bridge",
    bridge_secret: "a".repeat(48),
    expires_at: 2_000_000,
    ...overrides
  };
}

function create(value, mode = 0o600) {
  const directory = fs.mkdtempSync(join(tmpdir(), "bridge-bootstrap-"));
  const path = join(directory, "bridge-bootstrap.json");
  fs.writeFileSync(path, JSON.stringify(value), { mode });
  fs.chmodSync(path, mode);
  return path;
}

test("desktop consumes a bound one-time bridge identity and deletes the envelope", () => {
  const path = create(fixture());
  const value = consumeBridgeBootstrap({ path, fs, now: () => 1_999_500_000, expectedVaultId: "vault-a" });
  assert.equal(value.credential_id, "installation-a:bridge");
  assert.equal(value.secret, "a".repeat(48));
  assert.equal(fs.existsSync(path), false);
});

test("invalid permissions or profile binding fail closed and still delete the envelope", () => {
  for (const [value, mode, expected] of [
    [fixture(), 0o644, "bridge_bootstrap_permissions_invalid"],
    [fixture({ endpoint_audience: "wrong" }), 0o600, "bridge_bootstrap_invalid"],
    [fixture({ expires_at: 1 }), 0o600, "bridge_bootstrap_invalid"]
  ]) {
    const path = create(value, mode);
    assert.throws(() => consumeBridgeBootstrap({ path, fs, now: () => 1_999_500_000, expectedVaultId: "vault-a" }), new RegExp(expected));
    assert.equal(fs.existsSync(path), false);
  }
});

test("default bootstrap path is Vault-scoped so another open Vault cannot consume it", () => {
  const priorRequire = globalThis.require;
  globalThis.require = createRequire(import.meta.url);
  try {
    const first = defaultBridgeBootstrapPath("vault-a");
    const second = defaultBridgeBootstrapPath("vault-b");
    assert.notEqual(first, second);
    assert.match(first, /bridge-bootstrap\.[a-f0-9]{24}\.json$/);
    assert.equal(defaultBridgeBootstrapPath(), first.replace(/bridge-bootstrap\.[a-f0-9]{24}\.json$/, "bridge-bootstrap.json"));
  } finally {
    if (priorRequire === undefined) delete globalThis.require;
    else globalThis.require = priorRequire;
  }
});
