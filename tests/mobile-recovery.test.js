import assert from "node:assert/strict";
import test from "node:test";

import { MobileReplica } from "../src/mobile/reducer.js";
import {
  createOfflineReplicaCache,
  recoveryMetadata,
  restoreOfflineReplicaCache,
  restoreRecoveryMetadata
} from "../src/mobile/persistence.js";
import { sha256 } from "../src/stream-normalizer.js";

test("reset freezes updates until a checksummed keyframe atomically replaces projection", async () => {
  const replica = new MobileReplica({
    conversations: { old: { id: "old", title: "old", revision: 1, activeTurnId: null, turnOrder: [], turns: {} } },
    activeConversationId: "old"
  });
  await replica.applyFrame({ type: "reset_required", reason: "retention_gap", epoch: "epoch-b", high_water: 20 });
  const projection = {
    conversation: { id: "new", title: "new title", revision: 7 },
    turns: [{ id: "turn", status: "completed", messages: [{ id: "message", role: "assistant", blocks: [{ id: "text", type: "text", text: "complete" }] }] }]
  };
  const checksum = await sha256(projection);
  const page = {
    protocol: "claudian.remote.v2", kind: "event", event_type: "keyframe.page",
    source: { instance_id: "bridge", sequence: 20 }, entity: { conversation_id: "new", turn_id: "turn" }, revision: 7,
    payload: { keyframe_id: "kf", page_index: 0, page_count: 1, projection }
  };
  const final = {
    protocol: "claudian.remote.v2", kind: "event", event_type: "keyframe.final",
    source: { instance_id: "bridge", sequence: 21 }, entity: { conversation_id: "new", turn_id: "turn" }, revision: 7,
    payload: { keyframe_id: "kf", page_count: 1, revision: 7, checksum }
  };
  await replica.applyFrame({ type: "event.committed", epoch: "epoch-b", cursor: 21, event: page });
  assert.equal(replica.state.activeConversationId, "old");
  assert.equal(replica.state.relay.appliedCursor, 0);
  await replica.applyFrame({ type: "event.committed", epoch: "epoch-b", cursor: 22, event: final });
  assert.equal(replica.state.activeConversationId, "new");
  assert.equal(replica.state.recovery.required, false);
  assert.equal(replica.state.relay.appliedCursor, 22);
  assert.equal(replica.projection("new").turns[0].messages[0].blocks[0].text, "complete");
});

test("bad keyframe checksum never mutates the current projection", async () => {
  const replica = new MobileReplica({ activeConversationId: "old" });
  await replica.applyFrame({ type: "reset_required", reason: "gap", epoch: "epoch" });
  const projection = { conversation: { id: "new", title: "", revision: 1 }, turns: [] };
  const base = { protocol: "claudian.remote.v2", kind: "event", source: { instance_id: "b", sequence: 1 }, entity: { conversation_id: "new" }, revision: 1 };
  await replica.applyFrame({ type: "event.committed", epoch: "epoch", cursor: 1, event: { ...base, event_type: "keyframe.page", payload: { keyframe_id: "kf", page_index: 0, page_count: 1, projection } } });
  const result = await replica.applyFrame({ type: "event.committed", epoch: "epoch", cursor: 2, event: { ...base, event_type: "keyframe.final", payload: { keyframe_id: "kf", page_count: 1, revision: 1, checksum: `sha256:${"0".repeat(64)}` } } });
  assert.equal(result.reason, "keyframe_checksum_mismatch");
  assert.equal(replica.state.activeConversationId, "old");
});

test("persistence contains calibration coordinates only", () => {
  const state = {
    relay: { epoch: "epoch", appliedCursor: 42 }, activeConversationId: "conv",
    token: "never", draft: "private draft", conversations: { conv: { body: "private body" } }
  };
  const saved = recoveryMetadata(state);
  assert.deepEqual(saved, { version: 1, epoch: "epoch", applied_cursor: 42, active_conversation_id: "conv" });
  assert.equal(JSON.stringify(saved).includes("private"), false);
  assert.deepEqual(restoreRecoveryMetadata(saved), { relay: { epoch: "epoch", appliedCursor: 42 }, activeConversationId: "conv" });
});

test("offline cache is bounded, body-readable, and never contains queue or attachment binaries", () => {
  const state = {
    activeConversationId: "recent",
    commands: { delayed: { text: "must never queue" } },
    conversations: {
      old: {
        id: "old", title: "Old", revision: 1, activeTurnId: "old-turn", turnOrder: ["old-turn"],
        turns: {
          "old-turn": {
            id: "old-turn", status: "completed", messageOrder: ["old-message"],
            messages: { "old-message": { id: "old-message", role: "assistant", blockOrder: ["old-text"], blocks: { "old-text": { id: "old-text", type: "text", text: "x".repeat(1200) } } } }
          }
        }
      },
      recent: {
        id: "recent", title: "Recent", revision: 2, activeTurnId: "turn", turnOrder: ["turn"],
        turns: {
          turn: {
            id: "turn", status: "completed", messageOrder: ["text", "binary"],
            messages: {
              text: { id: "text", role: "assistant", blockOrder: ["body"], blocks: { body: { id: "body", type: "text", text: "offline readable" } } },
              binary: { id: "binary", role: "assistant", blockOrder: ["blob"], blocks: { blob: { id: "blob", type: "attachment", data: "data:application/octet-stream;base64,SECRET-BINARY" } } }
            },
            artifacts: { private: { bytes: "SECRET-BINARY" } }, artifactOrder: ["private"]
          }
        }
      }
    },
    history: { items: [{ id: "old", updated_at: 1 }, { id: "recent", updated_at: 2 }], loaded: true }
  };

  const cache = createOfflineReplicaCache(state, { maxBytes: 900, now: () => 123 });
  const encoded = JSON.stringify(cache);
  assert.ok(Buffer.byteLength(encoded) <= 900);
  assert.doesNotMatch(encoded, /must never queue|SECRET-BINARY|data:application|"commands"/);
  assert.match(encoded, /offline readable/);
  const restored = restoreOfflineReplicaCache(cache);
  assert.equal(restored.transport.status, "disconnected");
  assert.equal(restored.presence.mac.status, "offline");
  assert.deepEqual(restored.commands, {});
  assert.deepEqual(restored.conversations.recent.turns.turn.artifactOrder, []);
  assert.equal(restored.conversations.recent.turns.turn.messages.text.blocks.body.text, "offline readable");
});

test("offline cache can be cleared for purge or device revocation", () => {
  const state = {
    activeConversationId: "conversation",
    conversations: { conversation: { id: "conversation", title: "Cached", revision: 1, activeTurnId: null, turnOrder: [], turns: {} } }
  };
  const cache = createOfflineReplicaCache(state, { maxBytes: 4096 });
  assert.equal(Object.keys(restoreOfflineReplicaCache(cache).conversations).length, 1);
  assert.deepEqual(restoreOfflineReplicaCache(null).conversations, {});
});

test("an oversized active conversation keeps its newest readable text instead of dropping the conversation", () => {
  const state = {
    activeConversationId: "active",
    conversations: {
      active: {
        id: "active", title: "Active", revision: 1, activeTurnId: "turn", turnOrder: ["turn"],
        turns: {
          turn: {
            id: "turn", status: "completed", messageOrder: ["message"],
            messages: {
              message: {
                id: "message", role: "assistant", blockOrder: ["text"],
                blocks: { text: { id: "text", type: "text", text: `${"x".repeat(4000)}NEWEST-TAIL` } }
              }
            }
          }
        }
      }
    }
  };
  const cache = createOfflineReplicaCache(state, { maxBytes: 900 });
  const encoded = JSON.stringify(cache);
  assert.ok(Buffer.byteLength(encoded) <= 900);
  assert.equal(cache.active_conversation_id, "active");
  assert.match(encoded, /NEWEST-TAIL/);
});

test("legacy cache history ids migrate to canonical conversation_id without losing readable content", () => {
  const legacy = {
    version: 1,
    stored_at: 1,
    active_conversation_id: "legacy",
    conversations: {
      legacy: { id: "legacy", title: "Cached", revision: 1, activeTurnId: null, turnOrder: [], turns: {} }
    },
    history: { items: [{ id: "legacy", title: "Cached", updated_at: 1 }], loaded: true }
  };
  const restored = restoreOfflineReplicaCache(legacy);
  assert.equal(restored.activeConversationId, "legacy");
  assert.deepEqual(restored.history.items, [{ conversation_id: "legacy", title: "Cached", updated_at: 1 }]);
});
