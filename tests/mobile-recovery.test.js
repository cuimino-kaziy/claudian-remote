import assert from "node:assert/strict";
import test from "node:test";

import { MobileReplica } from "../src/mobile/reducer.js";
import { recoveryMetadata, restoreRecoveryMetadata } from "../src/mobile/persistence.js";
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
