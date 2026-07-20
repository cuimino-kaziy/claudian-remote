const PROTOCOL = "claudian.remote.v2";
const ABSOLUTE_PATH_START = /(?:file:\/\/(?:localhost)?(?=\/))?\/(?:Users|Volumes|Applications|private|tmp|Library|System|opt)(?=\/|$)/gi;
const PATH_START_BOUNDARY = /[\s("'`<>{}\[\]=:]/;
const PATH_END_BOUNDARY = new Set(["\n", "\r", "\t", "\f", "\v", '"', "'", "`", "<", ">", ")", "]", "}"]);
const TOKEN = /(?:Bearer\s+[A-Za-z0-9._~+/=-]{8,}|\b(?:sk|ghp|github_pat|xox[baprs])[-_][A-Za-z0-9_-]{12,}|\bclaudian_(?:ticket|token)[-_][A-Za-z0-9_-]{12,})/gi;
const ACTIVE_EXACT_SECRETS = new Map();

function exactSecretSet(values) {
  if (values == null) return new Set();
  const iterable = typeof values === "string"
    ? [values]
    : typeof values?.[Symbol.iterator] === "function"
      ? values
      : [];
  return new Set(Array.from(iterable, (value) => String(value ?? "")).filter(Boolean));
}

function registerExactSecrets(values) {
  for (const secret of values) ACTIVE_EXACT_SECRETS.set(secret, (ACTIVE_EXACT_SECRETS.get(secret) || 0) + 1);
}

function unregisterExactSecrets(values) {
  for (const secret of values) {
    const remaining = (ACTIVE_EXACT_SECRETS.get(secret) || 0) - 1;
    if (remaining > 0) ACTIVE_EXACT_SECRETS.set(secret, remaining);
    else ACTIVE_EXACT_SECRETS.delete(secret);
  }
}

function redactExactSecrets(value, extraSecrets) {
  const secrets = new Set([...ACTIVE_EXACT_SECRETS.keys(), ...exactSecretSet(extraSecrets)]);
  let redacted = value;
  for (const secret of [...secrets].sort((left, right) => right.length - left.length)) {
    redacted = redacted.split(secret).join("[secret hidden]");
  }
  return redacted;
}

function redactAbsolutePaths(value) {
  let output = "";
  let cursor = 0;
  for (const match of value.matchAll(ABSOLUTE_PATH_START)) {
    const start = match.index;
    if (start < cursor) continue;
    if (start > 0 && !PATH_START_BOUNDARY.test(value[start - 1])) continue;
    let end = start + match[0].length;
    while (end < value.length && !PATH_END_BOUNDARY.has(value[end])) end += 1;
    while (end > start + match[0].length && /\s/.test(value[end - 1])) end -= 1;
    output += `${value.slice(cursor, start)}[local path hidden]`;
    cursor = end;
  }
  return output ? output + value.slice(cursor) : value;
}

export function safeText(value, exactSecrets = []) {
  const withoutExactSecrets = redactExactSecrets(String(value ?? ""), exactSecrets);
  return redactAbsolutePaths(withoutExactSecrets).replace(TOKEN, "[secret hidden]");
}

export function canonicalJson(value) {
  const normalize = (item) => {
    if (Array.isArray(item)) return item.map(normalize);
    if (item && typeof item === "object") {
      return Object.fromEntries(Object.keys(item).filter((key) => !["cursor", "epoch", "received_at", "transport", "checksum"].includes(key)).sort().map((key) => [key, normalize(item[key])]));
    }
    if (item === null || typeof item === "string" || typeof item === "boolean" || Number.isFinite(item)) return item;
    throw new TypeError("keyframe contains a non-canonical value");
  };
  return JSON.stringify(normalize(value));
}

export async function sha256(value) {
  const bytes = new TextEncoder().encode(canonicalJson(value));
  const digest = await globalThis.crypto.subtle.digest("SHA-256", bytes);
  return `sha256:${Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

function stableId(value, fallback) {
  const text = String(value || "").replace(/[^A-Za-z0-9._-]/g, "-").slice(0, 128);
  return text || fallback;
}

function latestText(message) {
  if (!message) return "";
  if (typeof message.content === "string") return message.content;
  const blocks = Array.isArray(message.contentBlocks) ? message.contentBlocks : [];
  return blocks.filter((block) => block?.type === "text").map((block) => block.content || "").join("");
}

function mobileSafeFields(payload, fields) {
  const safe = {};
  for (const field of fields) {
    const value = payload?.[field];
    if (typeof value === "string") safe[field] = safeText(value);
    else if (typeof value === "boolean" || value === null || Number.isFinite(value)) safe[field] = value;
  }
  return safe;
}

function mobileSafeOptions(options) {
  if (!Array.isArray(options)) return null;
  return options.slice(0, 16).map((option, index) => ({
    id: stableId(option?.id, `option-${index}`),
    label: safeText(option?.label || `Option ${index + 1}`)
  }));
}

export class SemanticStreamNormalizer {
  constructor({ sourceInstanceId, emit, exactSecrets = [], batchMs = 40, batchBytes = 8192, clock = () => Date.now(), timers = globalThis } = {}) {
    this.sourceInstanceId = stableId(sourceInstanceId, `bridge-${clock()}`);
    this.emitSink = emit || (() => {});
    this.batchMs = batchMs;
    this.batchBytes = batchBytes;
    this.clock = clock;
    this.timers = timers;
    this.sourceSequence = 0;
    this.revisions = new Map();
    this.lastText = new Map();
    this.pendingText = new Map();
    this.terminalHints = new Map();
    this.turnProjections = new Map();
    this.exactSecrets = new Set();
    this.setExactSecrets(exactSecrets);
  }

  setExactSecrets(values) {
    unregisterExactSecrets(this.exactSecrets);
    this.exactSecrets = exactSecretSet(values);
    registerExactSecrets(this.exactSecrets);
  }

  dispose() {
    unregisterExactSecrets(this.exactSecrets);
    this.exactSecrets.clear();
    this.terminalHints.clear();
    this.turnProjections.clear();
  }

  turnProjection(context, create = false) {
    const conversationId = stableId(context?.conversationId, "");
    const turnId = stableId(context?.turnId, "");
    if (!conversationId || !turnId) return null;
    const key = `${conversationId}\u0000${turnId}`;
    if (!this.turnProjections.has(key) && create) {
      this.turnProjections.set(key, { activities: new Map(), tools: new Map(), approvals: new Map(), artifacts: new Map() });
    }
    return this.turnProjections.get(key) || null;
  }

  recordProjectionEvent(type, context, payload) {
    const projection = this.turnProjection(context, true);
    if (!projection) return;
    if (type === "turn.started") {
      projection.status = "running";
      projection.activities.clear();
      projection.tools.clear();
    } else if (["turn.completed", "turn.interrupted", "turn.failed"].includes(type)) {
      projection.status = type === "turn.completed" ? "completed" : type === "turn.interrupted" ? "interrupted" : "failed";
    } else if (type === "activity.updated") {
      const id = stableId(context?.blockId, `activity-${stableId(payload?.stage, "status")}`);
      projection.activities.set(id, {
        id,
        ...projection.activities.get(id),
        ...mobileSafeFields(payload, ["stage", "label", "detail", "status", "duration_ms"])
      });
    } else if (["tool.started", "tool.completed"].includes(type)) {
      const id = stableId(context?.blockId || payload?.tool_name, `tool-${projection.tools.size + 1}`);
      projection.tools.set(id, {
        id,
        ...projection.tools.get(id),
        ...mobileSafeFields(payload, ["tool_name", "label", "status", "started_at", "duration_ms", "summary"])
      });
    } else if (["approval.requested", "approval.resolved"].includes(type)) {
      const id = stableId(payload?.approval_id, `approval-${projection.approvals.size + 1}`);
      const approval = {
        id,
        approval_id: id,
        ...projection.approvals.get(id),
        ...mobileSafeFields(payload, ["title", "selected", "status", "resolved_by"])
      };
      const options = mobileSafeOptions(payload?.options);
      if (options) approval.options = options;
      projection.approvals.set(id, approval);
    } else if (type === "artifact.available") {
      const id = stableId(payload?.artifact_id, `artifact-${projection.artifacts.size + 1}`);
      projection.artifacts.set(id, {
        id,
        artifact_id: id,
        ...projection.artifacts.get(id),
        ...mobileSafeFields(payload, ["kind", "label", "vault_path", "url", "size"])
      });
    }
  }

  projectionForTurn(context) {
    const projection = this.turnProjection(context);
    return {
      status: projection?.status || null,
      current_operation: {
        activities: projection ? [...projection.activities.values()].map((item) => ({ ...item })) : [],
        tools: projection ? [...projection.tools.values()].map((item) => ({ ...item })) : []
      },
      approvals: projection ? [...projection.approvals.values()].map((item) => ({
        ...item,
        ...(item.options ? { options: item.options.map((option) => ({ ...option })) } : {})
      })) : [],
      artifacts: projection ? [...projection.artifacts.values()].map((item) => ({ ...item })) : []
    };
  }

  finalizeTurnProjection(context, terminal) {
    const projection = this.turnProjection(context);
    if (!projection) return;
    const finalStatus = ["completed", "interrupted", "failed"].includes(terminal) ? terminal : "completed";
    projection.status = finalStatus;
    for (const collection of [projection.activities, projection.tools]) {
      for (const [id, item] of collection) {
        if (item.status === "running") collection.set(id, { ...item, status: finalStatus });
      }
    }
  }

  noteTerminalHint(conversationId, status, details = {}) {
    const key = stableId(conversationId, "conversation-pending");
    if (!this.terminalHints.has(key)) {
      this.terminalHints.set(key, {
        status: ["failed", "interrupted"].includes(status) ? status : "completed",
        ...(status === "interrupted" ? { queued_draft_returned: Boolean(details.queued_draft_returned) } : {})
      });
    }
    return this.terminalHints.get(key);
  }

  revisionFor(conversationId) {
    return this.revisions.get(conversationId) || 0;
  }

  async emit(type, context, payload) {
    const conversationId = stableId(context.conversationId, "conversation-pending");
    const revision = this.revisionFor(conversationId) + 1;
    this.revisions.set(conversationId, revision);
    const sequence = ++this.sourceSequence;
    const event = {
      protocol: PROTOCOL,
      kind: "event",
      event_type: type,
      source: { instance_id: this.sourceInstanceId, sequence },
      entity: { conversation_id: conversationId },
      occurred_at: new Date(this.clock()).toISOString(),
      revision,
      payload
    };
    for (const field of ["turnId", "messageId", "blockId"]) {
      if (context[field]) event.entity[field.replace(/[A-Z]/g, (letter) => `_${letter.toLowerCase()}`)] = stableId(context[field], field);
    }
    this.recordProjectionEvent(type, {
      conversationId,
      turnId: event.entity.turn_id,
      messageId: event.entity.message_id,
      blockId: event.entity.block_id
    }, payload);
    await this.emitSink(event);
    return event;
  }

  async observePostCommit(chunk, message, context) {
    const kind = String(chunk?.type || "");
    if (kind !== "text") await this.flushText();
    if (kind === "thinking") {
      return this.emit("activity.updated", context, { stage: "thinking", label: "正在思考", status: "running" });
    }
    if (kind === "text") return this.observeText(message, context);
    if (kind === "tool_use") {
      return this.emit("tool.started", context, {
        tool_name: stableId(chunk.name, "tool"), label: `正在使用 ${safeText(chunk.name || "工具")}`,
        status: "running", started_at: new Date(this.clock()).toISOString()
      });
    }
    if (kind === "tool_result" || kind === "tool_output") {
      return this.emit("tool.completed", context, {
        tool_name: "tool", label: "工具操作完成", status: "completed", summary: "操作已完成"
      });
    }
    if (kind === "error") {
      this.noteTerminalHint(context.conversationId, "failed");
      return this.emit("activity.updated", context, { stage: "provider_error", label: "模型输出失败", status: "failed" });
    }
    if (kind === "done") {
      return this.emit("activity.updated", context, { stage: "provider", label: "模型输出结束，正在保存", status: "running" });
    }
    return null;
  }

  consumeTerminalHint(conversationId) {
    const key = stableId(conversationId, "conversation-pending");
    const hint = this.terminalHints.get(key) || { status: "completed" };
    this.terminalHints.delete(key);
    return hint;
  }

  async observeText(message, context) {
    const key = `${context.conversationId}:${context.messageId}:${context.blockId || "text"}`;
    const current = safeText(latestText(message));
    const previous = this.lastText.get(key) || "";
    this.lastText.set(key, current);
    if (!current.startsWith(previous)) {
      await this.flushText(key);
      return this.emit("text.replace", context, { text: current });
    }
    const delta = current.slice(previous.length);
    if (!delta) return null;
    const pending = this.pendingText.get(key) || {
      text: "",
      offset: previous.length,
      baseRevision: this.revisionFor(context.conversationId),
      context,
      timer: null
    };
    pending.text += delta;
    this.pendingText.set(key, pending);
    if (new TextEncoder().encode(pending.text).length >= this.batchBytes) return this.flushText(key);
    if (!pending.timer) pending.timer = this.timers.setTimeout(() => void this.flushText(key), this.batchMs);
    return null;
  }

  async flushText(onlyKey = null) {
    const keys = onlyKey ? [onlyKey] : Array.from(this.pendingText.keys());
    for (const key of keys) {
      const pending = this.pendingText.get(key);
      if (!pending) continue;
      if (pending.timer) this.timers.clearTimeout(pending.timer);
      this.pendingText.delete(key);
      await this.emit("text.delta", pending.context, {
        text: pending.text,
        base_revision: pending.baseRevision,
        offset: pending.offset
      });
    }
  }
}

export function safeToolSummary(tool) {
  return {
    id: stableId(tool?.id, "tool"),
    name: stableId(tool?.name, "tool"),
    status: ["running", "completed", "failed"].includes(tool?.status) ? tool.status : "running",
    label: `${tool?.status === "completed" ? "已完成" : "正在使用"} ${safeText(tool?.name || "工具")}`
  };
}
