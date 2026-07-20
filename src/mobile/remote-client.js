const PROTOCOL = "claudian.remote.v2";

function trimSlash(value) {
  return String(value || "").replace(/\/+$/, "");
}

export class RemoteClient {
  constructor({ baseUrl, tokenProvider, deviceId, clientInstanceId, fetchImpl = globalThis.fetch, WebSocketImpl = globalThis.WebSocket, onFrame = async () => {}, onClose = () => {} }) {
    this.baseUrl = trimSlash(baseUrl);
    this.tokenProvider = tokenProvider;
    this.deviceId = deviceId;
    this.clientInstanceId = clientInstanceId;
    this.fetchImpl = fetchImpl;
    this.WebSocketImpl = WebSocketImpl;
    this.onFrame = onFrame;
    this.onClose = onClose;
    this.socket = null;
    this.generation = 0;
  }

  token() {
    const value = this.tokenProvider?.();
    if (!value) throw new Error("mobile_token_missing");
    return value;
  }

  async issueTicket() {
    const response = await this.fetchImpl(`${this.baseUrl}/api/v2/ws-ticket`, {
      method: "POST",
      headers: { Authorization: `Bearer ${this.token()}`, "Content-Type": "application/json" },
      body: JSON.stringify({ device_id: this.deviceId, client_instance_id: this.clientInstanceId })
    });
    if (!response.ok) throw new Error(`ticket_failed_${response.status}`);
    return response.json();
  }

  websocketUrl() {
    const parsed = new URL(`${this.baseUrl}/api/v2/ws/mobile`);
    parsed.protocol = parsed.protocol === "https:" ? "wss:" : "ws:";
    parsed.search = "";
    parsed.username = "";
    parsed.password = "";
    return parsed.toString();
  }

  async connect({ epoch = "", cursor = 0 } = {}) {
    this.close("replaced");
    const generation = ++this.generation;
    const grant = await this.issueTicket();
    if (generation !== this.generation) return null;
    const socket = new this.WebSocketImpl(this.websocketUrl(), PROTOCOL);
    this.socket = socket;
    socket.addEventListener("open", () => {
      if (generation !== this.generation) return socket.close();
      socket.send(JSON.stringify({
        type: "authenticate",
        role: "mobile",
        ticket: grant.ticket,
        device_id: this.deviceId,
        client_instance_id: this.clientInstanceId,
        epoch,
        cursor
      }));
    }, { once: true });
    socket.addEventListener("message", (message) => {
      if (generation !== this.generation) return;
      try { void this.onFrame(JSON.parse(String(message.data))); }
      catch { void this.onFrame({ type: "protocol.error", error: "invalid_server_json" }); }
    });
    socket.addEventListener("close", (event) => {
      if (generation === this.generation) {
        this.socket = null;
        this.onClose({ code: event.code, reason: event.reason, generation });
      }
    }, { once: true });
    return socket;
  }

  async submit(command) {
    const response = await this.fetchImpl(`${this.baseUrl}/api/v2/commands`, {
      method: "POST",
      headers: { Authorization: `Bearer ${this.token()}`, "Content-Type": "application/json" },
      body: JSON.stringify({ command })
    });
    const body = await response.json();
    return { httpStatus: response.status, ...body };
  }

  requestKeyframe(reason = "mobile_reset") {
    if (this.socket?.readyState !== 1) return false;
    this.socket.send(JSON.stringify({ type: "keyframe.request", reason: String(reason).slice(0, 128) }));
    return true;
  }

  close(reason = "client_close") {
    this.generation += 1;
    const socket = this.socket;
    this.socket = null;
    if (socket && socket.readyState < 2) socket.close(1000, reason);
  }
}
