import assert from "node:assert/strict";
import test from "node:test";

import { MobilePairingController, parsePairingDeepLink } from "../src/mobile/pairing-controller.js";
import { DeviceStore } from "../src/storage/device-store.js";

function storage() {
  const values = new Map();
  return {
    getItem(key) { return values.get(key) || null; },
    setItem(key, value) { values.set(key, String(value)); },
    removeItem(key) { values.delete(key); }
  };
}

function response(status, body) {
  return { ok: status >= 200 && status < 300, status, async json() { return body; } };
}

function setup() {
  const calls = [];
  const deviceStore = new DeviceStore({ storage: storage(), namespace: "pairing-test" });
  deviceStore.write("offline-cache", { old: true });
  const controller = new MobilePairingController({
    fetchImpl: async (url, options) => {
      calls.push({ url, options, body: JSON.parse(options.body) });
      if (url.endsWith("/redeem")) {
        return response(202, { claim_id: "claim-a", status: "approved", redemption_handle: "redemption-secret", expires_at: 100 });
      }
      return response(200, {
        credential_id: "credential-a",
        credential: "new-durable-device-credential",
        generation: 2
      });
    },
    profileProvider: () => ({
      relay_base_url: "https://relay.example.invalid",
      installation_id: "installation-a",
      vault_id: "vault-a",
      endpoint_audience: "claudian-remote:local_tailscale:installation-a"
    }),
    deviceContext: () => ({ device_id: "iphone-a", device_name: "Alice's iPhone" }),
    deviceStore
  });
  return { controller, deviceStore, calls };
}

test("deep link and short code collect credentials immediately without a Mac approval request", async () => {
  const link = "obsidian://claudian-remote?claim_id=claim-a&claim_token=temporary-claim&relay_base_url=https%3A%2F%2Frelay.example.invalid&installation_id=installation-a&vault_id=vault-a&endpoint_audience=claudian-remote%3Alocal_tailscale%3Ainstallation-a";
  const parsed = parsePairingDeepLink(link);
  assert.deepEqual(parsed, {
    claim_id: "claim-a",
    claim_token: "temporary-claim",
    relay_base_url: "https://relay.example.invalid",
    installation_id: "installation-a",
    vault_id: "vault-a",
    endpoint_audience: "claudian-remote:local_tailscale:installation-a"
  });

  const deep = setup();
  await deep.controller.acceptDeepLink(link);
  assert.equal(deep.calls[0].body.claim_token, "temporary-claim");
  assert.deepEqual(deep.controller.diagnosticSummary(), { status: "approved" });
  assert.doesNotMatch(JSON.stringify(deep.controller), /temporary-claim/);
  assert.equal((await deep.controller.pollUntilComplete({ maxAttempts: 1 })).paired, true);

  const manual = setup();
  await manual.controller.acceptShortCode("abcd-2345");
  assert.equal(manual.calls[0].body.short_code, "ABCD-2345");
  assert.equal("getUserMedia" in manual.controller, false);
  assert.equal((await manual.controller.pollUntilComplete({ maxAttempts: 1 })).paired, true);
  for (const { calls } of [deep, manual]) {
    assert.equal(calls.length, 2);
    assert.ok(calls[1].url.endsWith("/complete"));
  }
});

test("a fresh phone also supports pending claims on a legacy Relay through Obsidian requestUrl", async () => {
  const calls = [];
  const deviceStore = new DeviceStore({ storage: storage(), namespace: "fresh-phone" });
  let completion = 0;
  const controller = new MobilePairingController({
    requestImpl: async (options) => {
      calls.push(options);
      if (options.url.endsWith("/redeem")) return {
        status: 202,
        json: {
          claim_id: "claim-a",
          redemption_handle: "redemption-secret",
          expires_at: 100,
          profile: {
            installation_id: "installation-a",
            vault_id: "vault-a",
            endpoint_audience: "claudian-remote:local_tailscale:installation-a"
          }
        }
      };
      completion += 1;
      if (completion === 1) return { status: 202, json: { status: "pending_approval" } };
      return { status: 200, json: {
        credential_id: "credential-a",
        credential: "new-durable-device-credential",
        generation: 1
      } };
    },
    profileProvider: () => ({ vault_id: "vault-a" }),
    deviceContext: () => ({ device_id: "iphone-a", device_name: "Fresh iPhone" }),
    deviceStore
  });
  const link = "obsidian://claudian-remote?claim_id=claim-a&claim_token=temporary-claim&relay_base_url=https%3A%2F%2Frelay.example.invalid&installation_id=installation-a&vault_id=vault-a&endpoint_audience=claudian-remote%3Alocal_tailscale%3Ainstallation-a";

  await controller.acceptDeepLink(link);
  const result = await controller.pollUntilComplete({ intervalMs: 0, maxAttempts: 2 });

  assert.equal(result.paired, true);
  assert.equal(calls[0].url, "https://relay.example.invalid/api/v2/pairing/redeem");
  assert.equal(deviceStore.read("connection-profile").endpoint, "https://relay.example.invalid");
  assert.equal(deviceStore.read("connection-profile").vault_id, "vault-a");
  assert.doesNotMatch(JSON.stringify(controller), /temporary-claim/);
});

test("deep-link pairing rejects a different synced Vault before sending the claim", async () => {
  let called = false;
  const controller = new MobilePairingController({
    fetchImpl: async () => { called = true; return response(500, {}); },
    profileProvider: () => ({ vault_id: "vault-b" }),
    deviceContext: () => ({ device_id: "iphone-a", device_name: "Phone" }),
    deviceStore: new DeviceStore({ storage: storage(), namespace: "wrong-vault" })
  });
  const link = "obsidian://claudian-remote?claim_id=claim-a&claim_token=temporary-claim&relay_base_url=https%3A%2F%2Frelay.example.invalid&installation_id=installation-a&vault_id=vault-a&endpoint_audience=claudian-remote%3Alocal_tailscale%3Ainstallation-a";
  await assert.rejects(() => controller.acceptDeepLink(link), /pairing_wrong_vault/);
  assert.equal(called, false);
});

test("approved credential replaces revoked identity and never restores the old cache", async () => {
  const { controller, deviceStore } = setup();
  await controller.acceptShortCode("ABCD2345");
  const result = await controller.complete();
  assert.deepEqual(result, { paired: true, credential_id: "credential-a", device_id: "iphone-a" });
  assert.equal(deviceStore.read("identity").mobile_token, "new-durable-device-credential");
  assert.equal(deviceStore.read("identity").endpoint_audience, "claudian-remote:local_tailscale:installation-a");
  assert.equal(deviceStore.read("offline-cache"), null);
  assert.deepEqual(controller.diagnosticSummary(), { status: "idle" });
});

test("native pairing keeps HTTP errors available and bounds an unreachable Relay request", async (t) => {
  const { controller } = setup();
  controller.requestImpl = async (options) => {
    assert.equal(options.throw, false);
    return { status: 400, json: { error: "claim_expired" } };
  };
  await assert.rejects(controller.acceptShortCode("TEST1234"), /claim_expired/);
  controller.requestImpl = () => new Promise(() => {});
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const pending = controller.acceptShortCode("TEST1234");
  const rejected = assert.rejects(pending, /pairing_request_timeout/);
  t.mock.timers.tick(15000);
  await rejected;
  assert.equal(controller.pending, null);
});
