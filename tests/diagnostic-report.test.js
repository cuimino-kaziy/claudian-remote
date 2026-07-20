import test from "node:test";
import assert from "node:assert/strict";
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
