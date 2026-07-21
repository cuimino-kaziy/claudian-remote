export const BRIDGE_SUBPROTOCOL = "claudian.remote.bridge.v1";
export const DEFAULT_BRIDGE_ENDPOINT = "ws://127.0.0.1:27124/bridge";
const MAX_PENDING_MANAGEMENT = 16;

const encoder = new TextEncoder();

function base64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  const base64 = typeof btoa === "function"
    ? btoa(binary)
    : globalThis.Buffer?.from(bytes)?.toString("base64");
  if (!base64) throw new Error("bridge_crypto_unavailable");
  return base64.replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

export async function bridgeProof(secret, nonce, subtle = globalThis.crypto?.subtle) {
  if (!subtle || !secret || !nonce) throw new Error("bridge_crypto_unavailable");
  const key = await subtle.importKey(
    "raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const signature = await subtle.sign("HMAC", key, encoder.encode(`claudian-remote-bridge:${nonce}`));
  return base64Url(new Uint8Array(signature));
}

function currentConversationId(tab) {
  return tab?.conversationId || tab?.state?.currentConversationId || null;
}

export class DesktopBridgeRouter {
  constructor({ adapter, capture, getActiveTab, evaluateCompatibility, componentSet, importUpload }) {
    this.adapter = adapter;
    this.capture = capture;
    this.getActiveTab = getActiveTab;
    this.evaluateCompatibility = evaluateCompatibility;
    this.componentSet = componentSet;
    this.importUpload = importUpload;
    this.binding = null;
  }

  async keyframe() {
    const tab = this.getActiveTab();
    if (!tab) throw new Error("active_claudian_tab_required");
    return await this.capture.emitBootstrap(tab);
  }

  async bind(payload, { invalidatePrevious = false } = {}) {
    if (invalidatePrevious && this.binding) this.adapter.invalidateTransport(this.binding);
    const componentCompatibility = this.evaluateCompatibility(payload.compatibility);
    const binding = this.adapter.bindTransport(payload);
    this.binding = binding;
    const tab = this.getActiveTab();
    const claudianCompatibility = this.capture.compatibility?.(tab);
    const writable = componentCompatibility.writable && claudianCompatibility?.writable === true;
    const compatibility = writable
      ? componentCompatibility
      : { ...(componentCompatibility.writable ? claudianCompatibility : componentCompatibility), writable: false, mode: "read_only" };
    if (tab) await this.capture.emitBootstrap(tab);
    return { binding, compatibility, component_set: this.componentSet };
  }

  async handle(operation, payload = {}) {
    switch (operation) {
      case "transport.bind":
        return await this.bind(payload);
      case "transport.cutover":
      case "transport.rollback":
        return await this.bind(payload, { invalidatePrevious: true });
      case "transport.invalidate": {
        const invalidated = this.adapter.invalidateTransport(payload);
        if (invalidated) this.binding = null;
        return { invalidated };
      }
      case "command.execute":
        return await this.adapter.execute(payload);
      case "keyframe.request":
        return await this.keyframe();
      case "upload.import":
        return await this.importUpload(payload);
      case "capabilities.read": {
        const tab = this.getActiveTab();
        return {
          revision: this.capture.normalizer?.revisionFor?.(currentConversationId(tab) || "conversation-pending") || 0,
          capabilities: this.capture.capabilities?.(tab) || {},
          compatibility: this.capture.compatibility?.(tab) || { writable: false },
          component_set: this.componentSet
        };
      }
      default:
        throw new Error("bridge_operation_unknown");
    }
  }
}

export class CompanionChannel {
  constructor({
    endpoint = DEFAULT_BRIDGE_ENDPOINT,
    credentialProvider,
    router,
    webSocketFactory = (url, protocol) => new WebSocket(url, protocol),
    proof = bridgeProof,
    diagnostic = () => {},
    setTimeoutFn = (callback, delay) => globalThis.setTimeout(callback, delay),
    clearTimeoutFn = (timer) => globalThis.clearTimeout(timer),
    reconnectMinMs = 1000,
    reconnectMaxMs = 30000
  }) {
    const parsed = new URL(endpoint);
    if (parsed.protocol !== "ws:" || parsed.hostname !== "127.0.0.1" || parsed.pathname !== "/bridge" || parsed.username || parsed.password || parsed.search || parsed.hash) {
      throw new Error("bridge_endpoint_not_loopback");
    }
    this.endpoint = endpoint;
    this.credentialProvider = credentialProvider;
    this.router = router;
    this.webSocketFactory = webSocketFactory;
    this.proof = proof;
    this.diagnostic = diagnostic;
    this.setTimeoutFn = setTimeoutFn;
    this.clearTimeoutFn = clearTimeoutFn;
    this.reconnectMinMs = Math.max(250, Number(reconnectMinMs) || 1000);
    this.reconnectMaxMs = Math.max(this.reconnectMinMs, Number(reconnectMaxMs) || 30000);
    this.socket = null;
    this.authenticated = false;
    this.reconnectEnabled = false;
    this.reconnectAttempt = 0;
    this.reconnectTimer = null;
    this.managementSequence = 0;
    this.managementPending = new Map();
  }

  connect() {
    this.disconnect();
    this.reconnectEnabled = true;
    return this.openSocket();
  }

  openSocket() {
    if (!this.reconnectEnabled) return null;
    if (this.reconnectTimer !== null) {
      this.clearTimeoutFn(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    const socket = this.webSocketFactory(this.endpoint, BRIDGE_SUBPROTOCOL);
    this.socket = socket;
    socket.onmessage = (event) => { void this.handleFrame(event.data, socket); };
    socket.onclose = () => this.handleSocketClose(socket);
    socket.onerror = () => this.diagnostic({ type: "bridge_socket_error" });
    return socket;
  }

  disconnect() {
    this.reconnectEnabled = false;
    this.reconnectAttempt = 0;
    if (this.reconnectTimer !== null) {
      this.clearTimeoutFn(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    this.authenticated = false;
    const socket = this.socket;
    this.socket = null;
    this.rejectManagementPending("bridge_disconnected");
    try { socket?.close?.(); } catch {}
  }

  rejectManagementPending(code) {
    for (const pending of this.managementPending.values()) {
      globalThis.clearTimeout(pending.timer);
      pending.reject(new Error(code));
    }
    this.managementPending.clear();
  }

  handleSocketClose(socket) {
    if (this.socket !== socket) return;
    this.socket = null;
    this.authenticated = false;
    this.rejectManagementPending("bridge_disconnected");
    this.scheduleReconnect();
  }

  scheduleReconnect() {
    if (!this.reconnectEnabled || this.reconnectTimer !== null || this.socket) return;
    const delay = Math.min(
      this.reconnectMaxMs,
      this.reconnectMinMs * (2 ** Math.min(this.reconnectAttempt, 10))
    );
    this.reconnectAttempt += 1;
    this.diagnostic({ type: "bridge_reconnect_scheduled", delay_ms: delay });
    this.reconnectTimer = this.setTimeoutFn(() => {
      this.reconnectTimer = null;
      if (!this.reconnectEnabled || this.socket) return;
      try { this.openSocket(); }
      catch {
        this.scheduleReconnect();
      }
    }, delay);
  }

  send(frame, socket = this.socket) {
    if (!socket || this.socket !== socket || socket.readyState !== 1) return false;
    socket.send(JSON.stringify(frame));
    return true;
  }

  publish(event) {
    if (!this.authenticated) return false;
    return this.send({ type: "event.publish", event });
  }

  management(operation, payload = {}, { timeoutMs = 15000 } = {}) {
    if (!this.authenticated) return Promise.reject(new Error("bridge_not_ready"));
    if (this.managementPending.size >= MAX_PENDING_MANAGEMENT) {
      return Promise.reject(new Error("management_backpressure"));
    }
    const requestId = `management-${Date.now()}-${++this.managementSequence}`;
    return new Promise((resolve, reject) => {
      const timer = globalThis.setTimeout(() => {
        this.managementPending.delete(requestId);
        reject(new Error("management_request_timeout"));
      }, Math.max(1000, Math.min(Number(timeoutMs) || 15000, 30000)));
      this.managementPending.set(requestId, { resolve, reject, timer });
      if (!this.send({ type: "management.request", request_id: requestId, operation, payload })) {
        globalThis.clearTimeout(timer);
        this.managementPending.delete(requestId);
        reject(new Error("bridge_disconnected"));
      }
    });
  }

  async handleFrame(raw, socket = this.socket) {
    if (!socket || this.socket !== socket) return;
    let frame;
    try { frame = typeof raw === "string" ? JSON.parse(raw) : raw; }
    catch { return; }
    if (frame?.type === "auth.challenge") {
      try {
        const credential = await this.credentialProvider();
        if (this.socket !== socket) return;
        if (!credential?.credential_id || !credential?.secret) return;
        const value = await this.proof(credential.secret, frame.nonce);
        if (this.socket !== socket) return;
        this.send({
          type: "auth.response", credential_id: credential.credential_id,
          nonce: frame.nonce, proof: value
        }, socket);
      } catch {
        if (this.socket !== socket) return;
        this.diagnostic({ type: "bridge_auth_unavailable" });
        this.disconnect();
      }
      return;
    }
    if (frame?.type === "auth.accepted") {
      this.authenticated = true;
      this.reconnectAttempt = 0;
      return;
    }
    if (frame?.type === "auth.rejected") {
      this.disconnect();
      return;
    }
    if (this.authenticated && frame?.type === "management.response" && frame.request_id) {
      const pending = this.managementPending.get(String(frame.request_id));
      if (!pending) return;
      this.managementPending.delete(String(frame.request_id));
      globalThis.clearTimeout(pending.timer);
      if (frame.ok === true) pending.resolve(frame.result && typeof frame.result === "object" ? frame.result : {});
      else pending.reject(new Error(String(frame.error_code || "management_operation_failed")));
      return;
    }
    if (!this.authenticated || frame?.type !== "request" || !frame.request_id) return;
    try {
      const result = await this.router.handle(frame.operation, frame.payload || {});
      if (this.socket !== socket) return;
      this.send({ type: "response", request_id: frame.request_id, ok: true, result }, socket);
    } catch (error) {
      if (this.socket !== socket) return;
      this.send({
        type: "response", request_id: frame.request_id, ok: false,
        error_code: error?.message || "bridge_operation_failed"
      }, socket);
    }
  }
}
