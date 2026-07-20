const BACKOFF_MS = [0, 500, 1000, 2000, 5000, 10000, 15000];

export class MobileRecoveryController {
  constructor({ client, replica, persist = async () => {}, timers = globalThis, random = Math.random }) {
    this.client = client;
    this.replica = replica;
    this.persist = persist;
    this.timers = timers;
    this.random = random;
    this.visible = false;
    this.attempt = 0;
    this.timer = null;
    this.generation = 0;
    this.disposed = false;
    this.client.onClose = () => this.handleClose();
    this.unsubscribe = this.replica.subscribe((_state, reason) => {
      if (reason === "recovery" && this.visible) this.client.requestKeyframe?.(this.replica.state.recovery.reason);
      if (reason === "transport" && this.visible && this.replica.state.transport.status === "connected") {
        this.client.requestKeyframe?.("foreground_recalibrate");
      }
    });
  }

  async setVisible(visible) {
    this.visible = Boolean(visible);
    this.replica.setVisible(this.visible);
    if (!this.visible) {
      this.clearTimer();
      this.generation += 1;
      this.client.close("hidden");
      await this.replica.applyFrame({ type: "connection.changed", status: "disconnected" });
      await this.persist(this.replica.state);
      return;
    }
    this.attempt = 0;
    await this.replica.applyFrame({ type: "connection.changed", status: "connecting" });
    this.generation += 1;
    this.client.close("foreground_recalibrate");
    await this.connectNow(this.generation);
  }

  async connectNow(generation = this.generation) {
    if (!this.visible || this.disposed || generation !== this.generation) return;
    try {
      await this.client.connect({ epoch: this.replica.state.relay.epoch, cursor: this.replica.state.relay.appliedCursor });
      if (generation === this.generation) this.attempt = 0;
    } catch {
      if (generation === this.generation) this.scheduleReconnect();
    }
  }

  handleClose() {
    void this.replica.applyFrame({ type: "connection.changed", status: "disconnected" });
    if (this.visible && !this.disposed) this.scheduleReconnect();
  }

  scheduleReconnect() {
    if (this.timer || !this.visible || this.disposed) return;
    const index = Math.min(this.attempt, BACKOFF_MS.length - 1);
    const base = BACKOFF_MS[index];
    this.attempt += 1;
    const delay = Math.max(0, Math.round(base * (0.85 + this.random() * 0.3)));
    const generation = this.generation;
    this.timer = this.timers.setTimeout(() => {
      this.timer = null;
      void this.connectNow(generation);
    }, delay);
  }

  clearTimer() {
    if (this.timer) this.timers.clearTimeout(this.timer);
    this.timer = null;
  }

  async dispose() {
    this.disposed = true;
    this.visible = false;
    this.clearTimer();
    this.generation += 1;
    this.client.close("unload");
    this.unsubscribe?.();
    await this.persist(this.replica.state);
  }
}
