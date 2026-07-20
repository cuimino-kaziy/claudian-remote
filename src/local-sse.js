const encoder = new TextEncoder();

export function formatSse({ id, event = "semantic", data }) {
  const lines = [];
  if (id !== undefined && id !== null) lines.push(`id: ${String(id).replace(/[\r\n]/g, "")}`);
  if (event) lines.push(`event: ${String(event).replace(/[\r\n]/g, "")}`);
  const serialized = typeof data === "string" ? data : JSON.stringify(data);
  for (const line of serialized.split(/\r\n|\r|\n/)) lines.push(`data: ${line}`);
  return `${lines.join("\n")}\n\n`;
}

export class BoundedEventRing {
  constructor({ maxEvents = 2048, maxBytes = 8 * 1024 * 1024 } = {}) {
    this.maxEvents = maxEvents;
    this.maxBytes = maxBytes;
    this.items = [];
    this.bytes = 0;
  }

  append(event) {
    const id = event?.source?.sequence;
    if (!Number.isInteger(id) || id < 1) throw new TypeError("event source sequence is required");
    const size = encoder.encode(JSON.stringify(event)).length;
    if (size > this.maxBytes) throw new RangeError("event exceeds local ring byte budget");
    const item = { id, event, size };
    this.items.push(item);
    this.bytes += size;
    while (this.items.length > this.maxEvents || this.bytes > this.maxBytes) {
      this.bytes -= this.items.shift().size;
    }
    return item;
  }

  replayAfter(lastEventId) {
    const cursor = Number(lastEventId || 0);
    if (!Number.isInteger(cursor) || cursor < 0) return { resync: true, reason: "invalid_last_event_id", items: [] };
    if (this.items.length && cursor && cursor < this.items[0].id - 1) {
      return { resync: true, reason: "local_retained_gap", retainedFloor: this.items[0].id, items: [] };
    }
    return { resync: false, items: this.items.filter((item) => item.id > cursor) };
  }
}

export class LocalSseHub {
  constructor({ ring = new BoundedEventRing(), keepaliveMs = 15000, maxSubscribers = 4, timers = globalThis } = {}) {
    this.ring = ring;
    this.keepaliveMs = keepaliveMs;
    this.maxSubscribers = maxSubscribers;
    this.timers = timers;
    this.subscribers = new Set();
  }

  publish(event) {
    const item = this.ring.append(event);
    for (const subscriber of [...this.subscribers]) {
      try { subscriber.write(formatSse({ id: item.id, data: item.event })); }
      catch { this.close(subscriber); }
    }
  }

  open(response, lastEventId = 0) {
    if (this.subscribers.size >= this.maxSubscribers) throw new RangeError("too_many_sse_subscribers");
    response.status?.(200);
    response.setHeader?.("Content-Type", "text/event-stream; charset=utf-8");
    response.setHeader?.("Cache-Control", "no-cache, no-transform");
    response.setHeader?.("Connection", "keep-alive");
    response.flushHeaders?.();
    const replay = this.ring.replayAfter(lastEventId);
    if (replay.resync) {
      response.write(formatSse({ event: "resync", data: { reason: replay.reason, retained_floor: replay.retainedFloor || null } }));
    } else {
      for (const item of replay.items) response.write(formatSse({ id: item.id, data: item.event }));
    }
    const subscriber = {
      write: (data) => response.write(data),
      end: () => response.end?.(),
      timer: this.timers.setInterval(() => {
        try { response.write(": keepalive\n\n"); } catch { this.close(subscriber); }
      }, this.keepaliveMs)
    };
    this.subscribers.add(subscriber);
    response.on?.("close", () => this.close(subscriber));
    return () => this.close(subscriber);
  }

  close(subscriber) {
    if (!this.subscribers.delete(subscriber)) return;
    this.timers.clearInterval(subscriber.timer);
    subscriber.end();
  }

  closeAll() {
    for (const subscriber of [...this.subscribers]) this.close(subscriber);
  }
}
