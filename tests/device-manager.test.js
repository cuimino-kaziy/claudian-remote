import assert from "node:assert/strict";
import test from "node:test";

import { DesktopDeviceManager } from "../src/desktop/device-manager.js";

function response(body) {
  return { ok: true, async json() { return body; } };
}

test("Mac manager requires explicit approval and clears claim UI state", async () => {
  const calls = [];
  const manager = new DesktopDeviceManager({
    relayBaseUrl: "https://relay.example.invalid",
    credentialProvider: () => ({ secret: "admin-secret" }),
    fetchImpl: async (url, options) => {
      calls.push({ url, options });
      if (url.endsWith("/claims")) return response({
        claim_id: "claim-a",
        short_code: "ABCD2345",
        deep_link: "obsidian://claudian-remote?claim_id=claim-a&claim_token=temporary",
        expires_at: "2030-01-01T00:00:00Z"
      });
      return response({ ok: true, status: "approved", credential_id: "credential-a" });
    }
  });
  const claim = await manager.createClaim();
  assert.equal(claim.short_code, "ABCD2345");
  await manager.approve("claim-a", "iphone-a");
  assert.deepEqual(manager.diagnosticSummary(), { pairing: "idle" });
  assert.equal(calls[1].options.body, JSON.stringify({ device_id: "iphone-a" }));
  assert.doesNotMatch(JSON.stringify(manager.diagnosticSummary()), /temporary|admin-secret|ABCD2345/);
});

test("expired claims disappear and revocation carries only device identity", async () => {
  const calls = [];
  const manager = new DesktopDeviceManager({
    relayBaseUrl: "https://relay.example.invalid",
    credentialProvider: () => "admin-secret",
    now: () => 2_000_000,
    fetchImpl: async (url, options) => {
      calls.push({ url, options });
      return response({ ok: true, credential_ids: ["credential-a"], closed_connections: 1 });
    }
  });
  manager.activeClaim = { claim_id: "claim-a", short_code: "ABCD2345", expires_at: 1 };
  assert.deepEqual(manager.diagnosticSummary(), { pairing: "idle" });
  await manager.revoke("iphone-a", "device_lost");
  assert.match(calls[0].url, /devices\/iphone-a\/revoke$/);
  assert.equal(calls[0].options.body, JSON.stringify({ reason: "device_lost" }));
});

test("manager resolves the current profile per request and supports inspect revoke and re-pair", async () => {
  const calls = [];
  let endpoint = "https://relay-one.example.invalid";
  const manager = new DesktopDeviceManager({
    profileProvider: () => ({
      relay_base_url: endpoint,
      installation_id: "installation-a",
      vault_id: "vault-a",
      endpoint_audience: "claudian-remote:local_tailscale:installation-a"
    }),
    credentialProvider: () => ({
      secret: "admin-secret",
      installation_id: "installation-a",
      vault_id: "vault-a",
      endpoint_audience: "claudian-remote:local_tailscale:installation-a"
    }),
    requestImpl: async (options) => {
      calls.push(options);
      if (options.method === "GET") return { status: 200, json: { devices: [{ device_id: "iphone-a", status: "active" }] } };
      if (options.url.endsWith("/claims")) return { status: 201, json: {
        claim_id: "claim-b", short_code: "EFGH6789", deep_link: "obsidian://claudian-remote?claim_id=claim-b", expires_at: "2030-01-01T00:00:00Z"
      } };
      return { status: 200, json: { ok: true } };
    }
  });

  assert.deepEqual(await manager.devices(), [{ device_id: "iphone-a", status: "active" }]);
  endpoint = "https://relay-two.example.invalid";
  await manager.revoke("iphone-a", "lost_device");
  await manager.createClaim();

  assert.match(calls[0].url, /^https:\/\/relay-one/);
  assert.match(calls[1].url, /^https:\/\/relay-two/);
  assert.match(calls[2].url, /^https:\/\/relay-two/);
  assert.equal(calls[0].headers.Authorization, "Bearer admin-secret");
});
