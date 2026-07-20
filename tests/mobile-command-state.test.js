import assert from "node:assert/strict";
import test from "node:test";

import { MobileReplica } from "../src/mobile/reducer.js";
import { sha256 } from "../src/stream-normalizer.js";
import { activeConversationModel, currentOperationModel } from "../src/mobile/view-model.js";

async function applyKeyframe(replica, projection, { epoch = "epoch", cursor = 1, keyframeId = "kf" } = {}) {
  const checksum = await sha256(projection);
  const conversationId = projection.conversation.id;
  const turnId = projection.turns[0]?.id;
  const base = {
    protocol: "claudian.remote.v2",
    kind: "event",
    source: { instance_id: "bridge", sequence: cursor },
    entity: { conversation_id: conversationId, ...(turnId ? { turn_id: turnId } : {}) },
    revision: projection.conversation.revision
  };
  await replica.applyFrame({
    type: "event.committed",
    epoch,
    cursor,
    event: {
      ...base,
      event_type: "keyframe.page",
      payload: { keyframe_id: keyframeId, page_index: 0, page_count: 1, projection }
    }
  });
  await replica.applyFrame({
    type: "event.committed",
    epoch,
    cursor: cursor + 1,
    event: {
      ...base,
      source: { ...base.source, sequence: cursor + 1 },
      event_type: "keyframe.final",
      payload: { keyframe_id: keyframeId, page_count: 1, revision: projection.conversation.revision, checksum }
    }
  });
}

test("command state distinguishes relay acceptance from desktop acceptance", async () => {
  const replica = new MobileReplica();
  replica.beginCommand({ deliveryId: "delivery", commandType: "message.submit", text: "hello" });
  await replica.applyFrame({ type: "relay.accepted", delivery_id: "delivery", status: "routed" });
  assert.equal(replica.state.commands.delivery.status, "relay_accepted");
  await replica.applyFrame({ type: "command.receipt", receipt: { delivery_id: "delivery", status: "executed" } });
  assert.equal(replica.state.commands.delivery.status, "desktop_accepted");
});

test("late relay acceptance cannot regress desktop acceptance", async () => {
  const replica = new MobileReplica();
  replica.beginCommand({ deliveryId: "delivery", commandType: "message.submit", text: "hello" });
  await replica.applyFrame({ type: "command.receipt", receipt: { delivery_id: "delivery", status: "executed" } });
  await replica.applyFrame({ type: "relay.accepted", delivery_id: "delivery", status: "routed" });
  assert.equal(replica.state.commands.delivery.status, "desktop_accepted");
  assert.equal(replica.state.commands.delivery.desktopStatus, "executed");
});

test("beginning the same delivery again cannot reset terminal state or replace its body", async () => {
  const replica = new MobileReplica();
  replica.beginCommand({ deliveryId: "delivery", commandType: "message.submit", text: "original" });
  await replica.applyFrame({ type: "command.receipt", receipt: { delivery_id: "delivery", status: "executed" } });
  const repeated = replica.beginCommand({ deliveryId: "delivery", commandType: "message.submit", text: "different" });
  assert.equal(repeated.status, "desktop_accepted");
  assert.equal(repeated.text, "original");
  assert.equal(Object.keys(replica.state.commands).length, 1);
});

test("explicit rejection is terminal against late acceptance or receipt", async () => {
  const replica = new MobileReplica();
  replica.beginCommand({ deliveryId: "delivery", commandType: "message.submit", text: "restore me" });
  await replica.applyFrame({ type: "command.rejected", delivery_id: "delivery", status: "mac_offline" });
  await replica.applyFrame({ type: "relay.accepted", delivery_id: "delivery", status: "routed" });
  await replica.applyFrame({ type: "command.receipt", receipt: { delivery_id: "delivery", status: "executed" } });
  assert.equal(replica.state.commands.delivery.status, "rejected");
  assert.equal(replica.state.commands.delivery.errorCode, "mac_offline");
  assert.equal(replica.state.commands.delivery.preserveDraft, true);
});

test("network ambiguity becomes unknown without restoring a draft or changing delivery id", async () => {
  const replica = new MobileReplica();
  replica.beginCommand({ deliveryId: "same-delivery", commandType: "message.submit", text: "do not resend" });
  await replica.applyFrame({ type: "command.unknown", delivery_id: "same-delivery", error: "connection_lost" });
  const command = replica.state.commands["same-delivery"];
  assert.equal(command.status, "unknown");
  assert.equal(command.deliveryId, "same-delivery");
  assert.equal(command.preserveDraft, false);
  assert.deepEqual(replica.claimRestoredDrafts(), []);
  await replica.applyFrame({ type: "relay.accepted", delivery_id: "same-delivery", status: "routed" });
  assert.equal(command.status, "relay_accepted");
});

test("session loss restores unaccepted message text for manual retry only", async () => {
  const replica = new MobileReplica();
  replica.beginCommand({ deliveryId: "pending", commandType: "message.submit", text: "keep me" });
  await replica.applyFrame({ type: "relay.accepted", delivery_id: "pending", status: "routed" });
  await replica.applyFrame({ type: "presence.changed", role: "mac", status: "offline" });
  const command = replica.state.commands.pending;
  assert.equal(command.status, "rejected");
  assert.equal(command.preserveDraft, true);
  assert.equal(command.text, "keep me");
  assert.equal(Object.keys(replica.state.commands).length, 1);
});

test("an older identical keyframe message cannot reconcile a new pending delivery", async () => {
  const replica = new MobileReplica();
  replica.beginCommand({ deliveryId: "new-delivery", commandType: "message.submit", text: "OK" });
  const projection = {
    conversation: { id: "conv", title: "History", revision: 4 },
    turns: [{
      id: "old-turn",
      status: "completed",
      messages: [{ id: "old-message", role: "user", blocks: [{ id: "old-text", type: "text", text: "OK" }] }]
    }]
  };
  await applyKeyframe(replica, projection);
  assert.equal(replica.state.commands["new-delivery"].status, "local_pending");
});

test("keyframe origin delivery id authoritatively reconciles only that delivery", async () => {
  const replica = new MobileReplica();
  replica.beginCommand({ deliveryId: "matching-delivery", commandType: "message.submit", text: "OK" });
  replica.beginCommand({ deliveryId: "same-text-other-delivery", commandType: "message.submit", text: "OK" });
  const projection = {
    conversation: { id: "conv", title: "History", revision: 5 },
    turns: [{
      id: "turn",
      status: "completed",
      messages: [{
        id: "message",
        role: "user",
        origin_delivery_id: "matching-delivery",
        blocks: [{ id: "text", type: "text", text: "OK" }]
      }]
    }]
  };
  await applyKeyframe(replica, projection);
  assert.equal(replica.state.commands["matching-delivery"].status, "desktop_accepted");
  assert.equal(replica.state.commands["matching-delivery"].desktopStatus, "keyframe_origin");
  assert.equal(replica.state.commands["matching-delivery"].reconciled, true);
  assert.equal(replica.state.commands["same-text-other-delivery"].status, "local_pending");
});

test("a live assistant reply stays below the pending user submission that started it", () => {
  const replica = new MobileReplica({
    activeConversationId: "conv",
    conversations: {
      conv: {
        id: "conv", title: "Ordering", revision: 1, activeTurnId: "turn", turnOrder: ["turn"],
        turns: {
          turn: {
            id: "turn", status: "running", messageOrder: ["old-user", "old-assistant"],
            messages: {
              "old-user": { id: "old-user", role: "user", blockOrder: ["old-user-text"], blocks: { "old-user-text": { id: "old-user-text", type: "text", text: "旧问题" } } },
              "old-assistant": { id: "old-assistant", role: "assistant", blockOrder: ["old-assistant-text"], blocks: { "old-assistant-text": { id: "old-assistant-text", type: "text", text: "旧回答" } } }
            },
            activityOrder: [], activities: {}, toolOrder: [], tools: {}, approvalOrder: [], approvals: {}, artifactOrder: [], artifacts: {}
          }
        }
      }
    }
  });

  replica.beginCommand({ deliveryId: "new-delivery", commandType: "message.submit", text: "我的新问题", createdAt: 10 });
  const turn = replica.state.conversations.conv.turns.turn;
  turn.messageOrder.push("live-assistant");
  turn.messages["live-assistant"] = {
    id: "live-assistant", role: "assistant", blockOrder: ["live-text"],
    blocks: { "live-text": { id: "live-text", type: "text", text: "新回复正在生成" } }
  };

  const model = activeConversationModel(replica.state);
  assert.deepEqual(model.messages.map((message) => `${message.role}:${message.text}`), [
    "user:旧问题",
    "assistant:旧回答",
    "user:我的新问题",
    "assistant:新回复正在生成"
  ]);
  assert.equal(model.messages[2].key, "delivery:new-delivery");
});

test("a legacy keyframe without origin reconciles only the new matching user message", async () => {
  const replica = new MobileReplica();
  const initialProjection = {
    conversation: { id: "conv", title: "Legacy", revision: 1 },
    turns: [{
      id: "turn", status: "completed",
      messages: [
        { id: "old-user", role: "user", blocks: [{ id: "old-user-text", type: "text", text: "重复问题" }] },
        { id: "old-assistant", role: "assistant", blocks: [{ id: "old-assistant-text", type: "text", text: "旧回答" }] }
      ]
    }]
  };
  await applyKeyframe(replica, initialProjection, { cursor: 1, keyframeId: "initial" });
  replica.beginCommand({ deliveryId: "new-delivery", commandType: "message.submit", text: "重复问题", createdAt: 10 });
  await replica.applyFrame({ type: "command.receipt", receipt: { delivery_id: "new-delivery", status: "executed" } });

  const finalProjection = {
    conversation: { id: "conv", title: "Legacy", revision: 2 },
    turns: [{
      id: "turn", status: "completed",
      messages: [
        { id: "old-user", role: "user", blocks: [{ id: "old-user-text", type: "text", text: "重复问题" }] },
        { id: "old-assistant", role: "assistant", blocks: [{ id: "old-assistant-text", type: "text", text: "旧回答" }] },
        { id: "new-user", role: "user", blocks: [{ id: "new-user-text", type: "text", text: "重复问题" }] },
        { id: "new-assistant", role: "assistant", blocks: [{ id: "new-assistant-text", type: "text", text: "新回答" }] }
      ]
    }]
  };
  await applyKeyframe(replica, finalProjection, { cursor: 3, keyframeId: "final" });

  const command = replica.state.commands["new-delivery"];
  const model = activeConversationModel(replica.state);
  assert.equal(command.reconciled, true);
  assert.deepEqual(model.messages.map((message) => `${message.role}:${message.text}`), [
    "user:重复问题",
    "assistant:旧回答",
    "user:重复问题",
    "assistant:新回答"
  ]);
  assert.equal(model.messages[0].key, "message:turn:old-user");
  assert.equal(model.messages[2].key, "delivery:new-delivery");
});

test("a remapped recovery keyframe cannot bind a new delivery to an old identical prompt", async () => {
  const replica = new MobileReplica();
  await applyKeyframe(replica, {
    conversation: { id: "conv", title: "Remapped", revision: 1 },
    turns: [{
      id: "turn", status: "completed",
      messages: [
        { id: "old-user-id", role: "user", blocks: [{ id: "old-user-text", type: "text", text: "测试" }] },
        { id: "old-assistant-id", role: "assistant", blocks: [{ id: "old-assistant-text", type: "text", text: "旧回答" }] }
      ]
    }]
  }, { cursor: 1, keyframeId: "before-remap" });
  replica.beginCommand({ deliveryId: "current-delivery", commandType: "message.submit", text: "测试", createdAt: 10 });

  await applyKeyframe(replica, {
    conversation: { id: "conv", title: "Remapped", revision: 2 },
    turns: [{
      id: "turn", status: "running",
      messages: [
        { id: "codex-msg-0", role: "user", blocks: [{ id: "codex-text-0", type: "text", text: "测试" }] },
        { id: "codex-msg-1", role: "assistant", blocks: [{ id: "codex-text-1", type: "text", text: "旧回答" }] }
      ]
    }]
  }, { cursor: 3, keyframeId: "same-history-new-ids" });

  assert.notEqual(replica.state.commands["current-delivery"].reconciled, true);
  assert.deepEqual(activeConversationModel(replica.state).messages.map((message) => `${message.role}:${message.text}`), [
    "user:测试",
    "assistant:旧回答",
    "user:测试"
  ]);

  await applyKeyframe(replica, {
    conversation: { id: "conv", title: "Remapped", revision: 3 },
    turns: [{
      id: "turn", status: "completed",
      messages: [
        { id: "codex-msg-0", role: "user", blocks: [{ id: "codex-text-0", type: "text", text: "测试" }] },
        { id: "codex-msg-1", role: "assistant", blocks: [{ id: "codex-text-1", type: "text", text: "旧回答" }] },
        { id: "codex-msg-2", role: "user", blocks: [{ id: "codex-text-2", type: "text", text: "测试" }] },
        { id: "codex-msg-3", role: "assistant", blocks: [{ id: "codex-text-3", type: "text", text: "新回答" }] }
      ]
    }]
  }, { cursor: 5, keyframeId: "completed-turn" });

  const model = activeConversationModel(replica.state);
  assert.equal(replica.state.commands["current-delivery"].reconciled, true);
  assert.equal(model.messages[2].key, "delivery:current-delivery");
  assert.deepEqual(model.messages.map((message) => `${message.role}:${message.text}`), [
    "user:测试",
    "assistant:旧回答",
    "user:测试",
    "assistant:新回答"
  ]);
});

test("failed message drafts can be claimed one at a time without dropping earlier drafts", async () => {
  const replica = new MobileReplica();
  replica.beginCommand({ deliveryId: "first", commandType: "message.submit", text: "first draft", createdAt: 1 });
  replica.beginCommand({ deliveryId: "second", commandType: "message.submit", text: "second draft", createdAt: 2 });
  await replica.applyFrame({ type: "command.rejected", delivery_id: "first", status: "rejected" });
  await replica.applyFrame({ type: "command.rejected", delivery_id: "second", status: "rejected" });

  assert.deepEqual(replica.claimRestoredDrafts(1), ["first draft"]);
  assert.deepEqual(replica.claimRestoredDrafts(1), ["second draft"]);
  assert.deepEqual(replica.claimRestoredDrafts(1), []);
});

test("authoritative keyframe restores operations approvals and artifacts after recovery", async () => {
  const replica = new MobileReplica();
  const projection = {
    conversation: { id: "conv-controls", title: "Controls", revision: 9 },
    turns: [{
      id: "turn-controls",
      status: "interrupted",
      messages: [{ id: "message", role: "assistant", blocks: [{ id: "text", type: "text", text: "partial" }] }],
      current_operation: {
        activities: [{ id: "read", label: "已读取", status: "interrupted" }],
        tools: [{ id: "search", label: "搜索 Vault", status: "completed" }]
      },
      approvals: [{ approval_id: "approval", title: "允许操作", status: "pending", options: [{ id: "yes", label: "允许" }] }],
      artifacts: [{ artifact_id: "artifact", kind: "markdown", label: "Result.md", vault_path: "Result.md" }]
    }]
  };

  await applyKeyframe(replica, projection);

  const turn = replica.state.conversations["conv-controls"].turns["turn-controls"];
  assert.deepEqual(currentOperationModel(turn).entries.map((entry) => entry.id), ["read", "search"]);
  assert.equal(turn.approvals.approval.title, "允许操作");
  assert.equal(turn.artifacts.artifact.vault_path, "Result.md");
});

test("replay and interrupted terminal events never trigger completion signal", async () => {
  const replica = new MobileReplica({ visible: true });
  const events = [
    { event_type: "turn.started", revision: 1, payload: { status: "running", started_at: "now" } },
    { event_type: "turn.completed", revision: 1, payload: { status: "completed", checksum: `sha256:${"0".repeat(64)}` } },
    { event_type: "turn.interrupted", revision: 1, payload: { status: "interrupted", queued_draft_returned: false } }
  ].map((event, index) => ({
    protocol: "claudian.remote.v2", kind: "event", source: { instance_id: "bridge", sequence: index + 1 },
    entity: { conversation_id: "conv", turn_id: `turn-${index}` }, ...event
  }));
  await replica.applyFrame({ type: "event.committed", epoch: "epoch", cursor: 1, replayed: true, event: events[0] });
  await replica.applyFrame({ type: "event.committed", epoch: "epoch", cursor: 2, replayed: true, event: events[1] });
  await replica.applyFrame({ type: "event.committed", epoch: "epoch", cursor: 3, replayed: false, event: events[2] });
  assert.deepEqual(replica.state.completionSignals, []);
});
