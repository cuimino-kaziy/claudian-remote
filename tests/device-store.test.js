import assert from "node:assert/strict";
import test from "node:test";

import {
  DeviceStore,
  migrateLegacySynchronizedState
} from "../src/storage/device-store.js";
import {
  DEFAULT_SYNC_PREFERENCES,
  sanitizeSyncPreferences
} from "../src/storage/sync-preferences.js";

function memoryStorage() {
  const values = new Map();
  return {
    getItem(key) { return values.has(key) ? values.get(key) : null; },
    setItem(key, value) { values.set(key, String(value)); },
    removeItem(key) { values.delete(key); }
  };
}

test("synchronized preferences contain only the explicit safe allowlist", () => {
  const saved = sanitizeSyncPreferences({
    ...DEFAULT_SYNC_PREFERENCES,
    vault_id: "vault-public-id",
    connection_mode: "remote_vps",
    notifications_enabled: false,
    relay_base_url: "https://private.example.invalid",
    mobile_token: "canary-mobile-token",
    relayToken: "canary-relay-token",
    device_id: "canary-device",
    client_instance_id: "canary-client",
    remote_v2_recovery: { applied_cursor: 44 },
    cache: { body: "private body" },
    upload_directory: "/Users/example/private-vault",
    pairing_claim: "claim-secret",
    bridge_credential: "bridge-secret",
    arbitrary: "must-not-sync"
  });

  assert.deepEqual(saved, {
    schema_version: 2,
    vault_id: "vault-public-id",
    connection_mode: "remote_vps",
    notifications_enabled: false,
    haptics_enabled: true
  });
  const encoded = JSON.stringify(saved);
  for (const forbidden of ["token", "device", "client", "cursor", "cache", "path", "claim", "credential", "private.example"]) {
    assert.equal(encoded.toLowerCase().includes(forbidden), false, forbidden);
  }
});

test("a local path cannot masquerade as the synchronized Vault identity", () => {
  assert.equal(sanitizeSyncPreferences({ vault_id: "/Users/example/Private Vault" }).vault_id, "");
});

test("device store fails closed when web storage is unavailable", () => {
  const failing = new DeviceStore({
    storage: {
      getItem() { throw new Error("denied"); },
      setItem() { throw new Error("denied"); },
      removeItem() { throw new Error("denied"); }
    }
  });
  assert.equal(failing.read("identity"), null);
  assert.equal(failing.write("identity", { mobile_token: "secret" }), false);
  assert.equal(failing.remove("identity"), false);
});

test("legacy shared token migration revokes and requires re-pair exactly once", async () => {
  const deviceStore = new DeviceStore({ storage: memoryStorage(), namespace: "test" });
  const revokeCalls = [];
  const legacy = {
    relay_base_url: "https://relay.example.invalid",
    mobile_token: "legacy-shared-secret",
    device_id: "legacy-device",
    client_instance_id: "legacy-client",
    remote_v2_recovery: { applied_cursor: 9 },
    upload_directory: "/private/path",
    notifications_enabled: true
  };

  const first = await migrateLegacySynchronizedState({
    synchronized: legacy,
    deviceStore,
    revokeLegacyCredential: async (credential) => revokeCalls.push(credential)
  });
  const second = await migrateLegacySynchronizedState({
    synchronized: legacy,
    deviceStore,
    revokeLegacyCredential: async (credential) => revokeCalls.push(credential)
  });

  assert.equal(revokeCalls.length, 1);
  assert.equal(revokeCalls[0], "legacy-shared-secret");
  assert.deepEqual(first.synchronized, sanitizeSyncPreferences(legacy));
  assert.deepEqual(second.synchronized, first.synchronized);
  assert.equal(first.rePairRequired, true);
  assert.equal(second.alreadyCompleted, true);
  assert.equal(deviceStore.read("migration").legacy_shared_token_v1.completed, true);
  assert.equal(deviceStore.read("identity"), null);
  assert.doesNotMatch(JSON.stringify(first.synchronized), /legacy|secret|private\/path/);
});

test("a synchronized Mac payload cannot overwrite device-local iPhone identity", () => {
  const deviceStore = new DeviceStore({ storage: memoryStorage(), namespace: "iphone" });
  deviceStore.write("identity", { device_id: "iphone-device", mobile_token: "iphone-secret" });

  const synchronized = sanitizeSyncPreferences({
    vault_id: "shared-vault",
    device_id: "mac-device",
    mobile_token: "mac-secret"
  });

  assert.equal(synchronized.vault_id, "shared-vault");
  assert.deepEqual(deviceStore.read("identity"), { device_id: "iphone-device", mobile_token: "iphone-secret" });
  assert.doesNotMatch(JSON.stringify(synchronized), /mac-device|mac-secret/);
});

test("revocation and purge clear cache while keeping ordinary synchronized preferences separate", () => {
  const deviceStore = new DeviceStore({ storage: memoryStorage(), namespace: "iphone" });
  deviceStore.write("identity", { mobile_token: "secret" });
  deviceStore.write("offline-cache", { body: "cached" });
  deviceStore.write("recovery", { cursor: 4 });
  assert.equal(deviceStore.clearRevokedDevice(), true);
  assert.equal(deviceStore.read("identity"), null);
  assert.equal(deviceStore.read("offline-cache"), null);
  assert.equal(deviceStore.read("recovery"), null);
});
