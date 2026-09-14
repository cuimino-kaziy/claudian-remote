import test from "node:test";
import assert from "node:assert/strict";
import { COMPATIBILITY_SET } from "../src/protocol/compatibility.js";
import { buildDiagnosticReport } from "../src/mobile/diagnostic-report.js";

test("mobile diagnostic report contains coordinates only", () => {
  const report = buildDiagnosticReport({
    activeConversationId: "private-conversation-id",
    transport: { status: "connected" },
    presence: { mac: { status: "online" } },
    recovery: { required: false },
    relay: { appliedCursor: 42, epoch: "private-epoch" },
    capabilities: { mode: "live" },
    conversations: {
      "private-conversation-id": {
        revision: 9,
        activeTurnId: "turn-private",
        turns: { "turn-private": { status: "running", messages: { x: { text: "secret body" } } } }
      }
    }
  }, { status: "ready", displayName: "private.pdf" }, new Date("2026-07-15T00:00:00Z"));

  assert.match(report, /transport_status=connected/);
  assert.match(report, /cursor=42/);
  assert.doesNotMatch(report, /private-conversation-id|private-epoch|secret body|private\.pdf/);
});

test("diagnostics describe normalized capabilities and attachment snapshots truthfully", () => {
  const report = buildDiagnosticReport({
    capabilities: { semantic_stream: true },
    conversations: {},
    presence: { mac: { status: "offline" } }
  }, [{ status: "uploading", name: "private.pdf" }], new Date("2026-07-15T00:00:00Z"));

  assert.match(report, /capability_mode=streaming/);
  assert.match(report, /upload_status=uploading/);
  assert.doesNotMatch(report, /private\.pdf/);
});

test("diagnostic export never emits seeded secrets or absolute paths", () => {
  const canary = "CANARY-SECRET-DO-NOT-EXPORT";
  const absolutePath = "/Users/example/Private Vault/secret.md";
  const state = {
    activeConversationId: absolutePath,
    transport: { status: "disconnected", error: canary },
    presence: { mac: { status: "offline", path: absolutePath } },
    relay: { appliedCursor: 7, epoch: canary },
    capabilities: { mode: "offline", debug: canary },
    conversations: {
      [absolutePath]: {
        revision: 1,
        activeTurnId: "turn",
        turns: { turn: { status: "completed", messages: { one: { text: canary } } } }
      }
    }
  };
  const report = buildDiagnosticReport(state, { status: "failed", path: absolutePath, error: canary });
  assert.doesNotMatch(report, new RegExp(`${canary}|Users/example|Private Vault`));
});

test("diagnostics include the loaded client version and allowlisted compatibility and rejection reasons", () => {
  const report = buildDiagnosticReport({
    compatibilityLayers: {
      mobileRelay: { writable: false, reason: "compatibility_set_mismatch" },
      macRelay: { writable: true, reason: "ready" },
      claudian: null
    },
    commands: {
      first: { status: "rejected", commandType: "history.list", errorCode: "stale_revision", createdAt: 1 },
      last: { status: "rejected", commandType: "message.submit", errorCode: "compatibility_mismatch", createdAt: 2, text: "PRIVATE-BODY", deliveryId: "PRIVATE-ID" }
    }
  });
  assert.ok(report.includes(`client_plugin_version=${COMPATIBILITY_SET.plugin}`));
  assert.ok(report.includes(`client_compatibility_set=${COMPATIBILITY_SET.id}`));
  assert.match(report, /compatibility_mobile_relay=compatibility_set_mismatch/);
  assert.match(report, /compatibility_mac_relay=ready/);
  assert.match(report, /compatibility_claudian=unknown/);
  assert.match(report, /latest_rejected_command_type=message.submit/);
  assert.match(report, /latest_rejection_reason=compatibility_mismatch/);
  assert.doesNotMatch(report, /PRIVATE-BODY|PRIVATE-ID/);
});

test("diagnostic reason projection never exports arbitrary error strings or component metadata", () => {
  const canary = "CANARY-SECRET-NOT-AN-ERROR-CODE";
  const report = buildDiagnosticReport({
    compatibilityLayers: {
      mobileRelay: { writable: false, reason: canary, actual: { plugin: canary }, remediation: canary },
      macRelay: { writable: true, reason: canary },
      claudian: { writable: false, reason: "/Users/example/Private Vault/credential" }
    },
    commands: { private: { status: "rejected", commandType: canary, errorCode: canary, text: canary, createdAt: 2 } }
  });
  assert.match(report, /compatibility_mobile_relay=unknown/);
  assert.match(report, /latest_rejected_command_type=unknown/);
  assert.match(report, /latest_rejection_reason=unknown/);
  assert.doesNotMatch(report, /CANARY|Users\/example|Private Vault/);
});
