export const BRIDGE_SUBPROTOCOL = "claudian.remote.bridge.v1";
export const DEFAULT_BRIDGE_ENDPOINT = "ws://127.0.0.1:27124/bridge";

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
    diagnostic = () => {}
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
    this.socket = null;
    this.authenticated = false;
  }

  connect() {
    this.disconnect();
    const socket = this.webSocketFactory(this.endpoint, BRIDGE_SUBPROTOCOL);
    this.socket = socket;
    socket.onmessage = (event) => { void this.handleFrame(event.data); };
    socket.onclose = () => { if (this.socket === socket) this.authenticated = false; };
    socket.onerror = () => this.diagnostic({ type: "bridge_socket_error" });
    return socket;
  }

  disconnect() {
    this.authenticated = false;
    const socket = this.socket;
    this.socket = null;
    try { socket?.close?.(); } catch {}
  }

  send(frame) {
    if (!this.socket || this.socket.readyState !== 1) return false;
    this.socket.send(JSON.stringify(frame));
    return true;
  }

  publish(event) {
    if (!this.authenticated) return false;
    return this.send({ type: "event.publish", event });
  }

  async handleFrame(raw) {
    let frame;
    try { frame = typeof raw === "string" ? JSON.parse(raw) : raw; }
    catch { return; }
    if (frame?.type === "auth.challenge") {
      try {
        const credential = await this.credentialProvider();
        if (!credential?.credential_id || !credential?.secret) return;
        const value = await this.proof(credential.secret, frame.nonce);
        this.send({
          type: "auth.response", credential_id: credential.credential_id,
          nonce: frame.nonce, proof: value
        });
      } catch {
        this.diagnostic({ type: "bridge_auth_unavailable" });
        this.disconnect();
      }
      return;
    }
    if (frame?.type === "auth.accepted") {
      this.authenticated = true;
      return;
    }
    if (frame?.type === "auth.rejected") {
      this.disconnect();
      return;
    }
    if (!this.authenticated || frame?.type !== "request" || !frame.request_id) return;
    try {
      const result = await this.router.handle(frame.operation, frame.payload || {});
      this.send({ type: "response", request_id: frame.request_id, ok: true, result });
    } catch (error) {
      this.send({
        type: "response", request_id: frame.request_id, ok: false,
        error_code: error?.message || "bridge_operation_failed"
      });
    }
  }
}
