import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { MobileReplica } from "../src/mobile/reducer.js";
import { SourceCapture } from "../src/source-capture.js";
import { SemanticStreamNormalizer } from "../src/stream-normalizer.js";
import { currentOperationModel } from "../src/mobile/view-model.js";

const fixtureUrl = new URL("../gateway/protocol/fixtures/v2/semantic-stream.json", import.meta.url);

test("semantic recorder converges to the final authoritative keyframe", async () => {
  const fixture = JSON.parse(await readFile(fixtureUrl, "utf8"));
  const replica = new MobileReplica({ visible: true });
  let cursor = 0;
  for (const event of fixture.events) {
    cursor += 1;
    await replica.applyFrame({ type: "event.committed", epoch: "epoch-a", cursor, replayed: false, event });
  }

  const projection = replica.projection("conv-1");
  assert.equal(projection.conversation.title, "示例");
  assert.equal(projection.turns[0].status, "completed");
  assert.equal(projection.turns[0].messages[0].blocks[0].text, "修订后的完整回答。");
  assert.equal(replica.state.relay.appliedCursor, fixture.events.length);
  assert.deepEqual(replica.state.completionSignals, [{ turnId: "turn-1", conversationId: "conv-1" }]);

  const duplicate = await replica.applyFrame({
    type: "event.committed", epoch: "epoch-a", cursor, replayed: false,
    event: fixture.events.at(-1)
  });
  assert.equal(duplicate.reason, "duplicate_cursor");
  assert.equal(replica.state.completionSignals.length, 1);
});

test("text delta requires exact base revision and offset", async () => {
  const replica = new MobileReplica();
  await replica.applyFrame({
    type: "event.committed", epoch: "epoch-a", cursor: 1,
    event: {
      protocol: "claudian.remote.v2", kind: "event", event_type: "turn.started",
      source: { instance_id: "bridge", sequence: 1 },
      entity: { conversation_id: "conv", turn_id: "turn" }, revision: 1,
      payload: { status: "running", started_at: "2099-01-01T00:00:00Z" }
    }
  });
  const result = await replica.applyFrame({
    type: "event.committed", epoch: "epoch-a", cursor: 2,
    event: {
      protocol: "claudian.remote.v2", kind: "event", event_type: "text.delta",
      source: { instance_id: "bridge", sequence: 2 },
      entity: { conversation_id: "conv", turn_id: "turn", message_id: "message", block_id: "text" }, revision: 2,
      payload: { text: "lost", base_revision: 1, offset: 9 }
    }
  });
  assert.equal(result.reason, "text_delta_mismatch");
  assert.equal(replica.state.recovery.required, true);
  assert.equal(replica.state.relay.appliedCursor, 1);
});

test("event batch preserves committed ordering", async () => {
  const fixture = JSON.parse(await readFile(fixtureUrl, "utf8"));
  const replica = new MobileReplica();
  const frames = fixture.events.slice(0, 2).map((event, index) => ({
    type: "event.committed", epoch: "epoch-a", cursor: index + 1, event
  }));
  await replica.applyFrame({ type: "event.batch", events: frames });
  assert.equal(replica.state.relay.appliedCursor, 2);
  assert.equal(replica.projection("conv-1").turns[0].messages[0].blocks[0].text, "初始回答");
});

test("event batch publishes one replica notification after all children converge", async () => {
  const fixture = JSON.parse(await readFile(fixtureUrl, "utf8"));
  const replica = new MobileReplica();
  const notifications = [];
  replica.subscribe((_state, reason) => notifications.push(reason));
  const frames = fixture.events.slice(0, 3).map((event, index) => ({
    type: "event.committed", epoch: "epoch-a", cursor: index + 1, event
  }));

  await replica.applyFrame({ type: "event.batch", events: frames });

  assert.deepEqual(notifications, ["batch"]);
  assert.equal(replica.state.relay.appliedCursor, 3);
});

test("an explicit recovery keyframe calibrates the base revision for the next live delta", async () => {
  const events = [];
  const normalizer = new SemanticStreamNormalizer({ sourceInstanceId: "bridge", emit: (event) => events.push(event) });
  const tab = { conversationId: "conv", state: { remoteTurnId: "turn", isStreaming: true, messages: [] } };
  const capture = new SourceCapture({ claudian: { getConversationSync: () => ({ title: "Demo", messages: [] }) }, normalizer });
  await capture.emitKeyframe(tab);
  const message = { id: "message", content: "next" };
  await normalizer.observeText(message, { conversationId: "conv", turnId: "turn", messageId: "message", blockId: "text" });
  await normalizer.flushText();
  assert.equal(events.at(-1).payload.base_revision, 2);
  assert.equal(events.at(-1).revision, 3);

  const replica = new MobileReplica();
  for (const [index, event] of events.entries()) {
    const result = await replica.applyFrame({ type: "event.committed", epoch: "epoch", cursor: index + 1, event });
    assert.notEqual(result.reset, true);
  }
  assert.equal(replica.projection("conv").turns[0].messages[0].blocks[0].text, "next");
});

test("a new run clears the previous operation before accepting live activity and tools", async () => {
  const replica = new MobileReplica({
    activeConversationId: "conv",
    conversations: {
      conv: {
        id: "conv", title: "Operations", revision: 1, activeTurnId: "turn", turnOrder: ["turn"],
        turns: {
          turn: {
            id: "turn", status: "completed", messageOrder: [], messages: {},
            activityOrder: ["old-activity"], activities: { "old-activity": { id: "old-activity", label: "旧活动", status: "completed" } },
            toolOrder: ["old-tool"], tools: { "old-tool": { id: "old-tool", label: "旧工具", status: "completed" } },
            approvalOrder: [], approvals: {}, artifactOrder: [], artifacts: {}
          }
        }
      }
    }
  });
  const base = {
    protocol: "claudian.remote.v2", kind: "event", source: { instance_id: "bridge", sequence: 1 },
    entity: { conversation_id: "conv", turn_id: "turn" }
  };
  await replica.applyFrame({
    type: "event.committed", epoch: "epoch", cursor: 1,
    event: { ...base, event_type: "turn.started", revision: 2, payload: { status: "running" } }
  });
  let turn = replica.state.conversations.conv.turns.turn;
  assert.deepEqual(currentOperationModel(turn).entries, []);

  await replica.applyFrame({
    type: "event.committed", epoch: "epoch", cursor: 2,
    event: {
      ...base, source: { ...base.source, sequence: 2 }, entity: { ...base.entity, message_id: "assistant", block_id: "new-tool" },
      event_type: "tool.started", revision: 3,
      payload: { tool_name: "search", label: "正在检索", status: "running" }
    }
  });
  turn = replica.state.conversations.conv.turns.turn;
  assert.deepEqual(currentOperationModel(turn).entries.map((entry) => entry.id), ["new-tool"]);
  assert.equal(turn.toolOrder[0], "new-tool");
});
