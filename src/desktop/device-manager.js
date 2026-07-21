function adminHeaders(credential) {
  const value = String(credential?.secret || credential?.token || credential || "");
  if (!value) throw new Error("pairing_admin_unavailable");
  return { Authorization: `Bearer ${value}`, "Content-Type": "application/json" };
}

async function decodeResponse(response) {
  const status = Number(response?.status || 0);
  let body;
  if (typeof response?.json === "function") body = await response.json();
  else if (response?.json !== undefined) body = response.json;
  else if (typeof response?.text === "string" && response.text) body = JSON.parse(response.text);
  else body = {};
  return { status, ok: response?.ok ?? (status >= 200 && status < 300), body: body || {} };
}

function assertCredentialBinding(credential, profile) {
  if (!credential || typeof credential !== "object") return;
  for (const field of ["installation_id", "vault_id", "endpoint_audience"]) {
    if (credential[field] && String(credential[field]) !== String(profile[field] || "")) {
      throw new Error("pairing_admin_profile_mismatch");
    }
  }
}

export class DesktopDeviceManager {
  constructor({ relayBaseUrl, profileProvider = null, credentialProvider, managementRequest = null, requestImpl = null, fetchImpl = globalThis.fetch, now = Date.now } = {}) {
    this.staticRelayBaseUrl = String(relayBaseUrl || "").replace(/\/+$/, "");
    this.profileProvider = profileProvider;
    this.credentialProvider = credentialProvider;
    this.managementRequest = managementRequest;
    this.requestImpl = requestImpl || (async (options) => fetchImpl(options.url, options));
    this.now = now;
    this.activeClaim = null;
  }

  management(operation, payload = {}) {
    if (typeof this.managementRequest !== "function") return null;
    return this.managementRequest(operation, payload);
  }

  profile() {
    const current = this.profileProvider?.() || {};
    const relayBaseUrl = String(current.relay_base_url || current.endpoint || this.staticRelayBaseUrl).replace(/\/+$/, "");
    if (!relayBaseUrl) throw new Error("pairing_endpoint_missing");
    return { ...current, relay_base_url: relayBaseUrl };
  }

  async request(path, options = {}) {
    const profile = this.profile();
    const credential = await this.credentialProvider?.();
    assertCredentialBinding(credential, profile);
    const response = await decodeResponse(await this.requestImpl({
      url: `${profile.relay_base_url}${path}`,
      ...options,
      headers: { ...adminHeaders(credential), ...(options.headers || {}) }
    }));
    if (!response.ok) throw new Error(response.body?.error || "device_manager_request_failed");
    return response.body;
  }

  clearExpired() {
    if (this.activeClaim && Number(this.activeClaim.expires_at || 0) <= this.now() / 1000) this.activeClaim = null;
  }

  async createClaim() {
    this.clearExpired();
    const body = await (this.management("pairing.claim.create")
      || this.request("/api/v2/pairing/claims", { method: "POST" }));
    this.activeClaim = {
      claim_id: String(body.claim_id),
      short_code: String(body.short_code),
      deep_link: String(body.deep_link),
      expires_at: Date.parse(body.expires_at) / 1000
    };
    return { ...this.activeClaim };
  }

  async pending() {
    this.clearExpired();
    const body = await (this.management("pairing.claims")
      || this.request("/api/v2/pairing/claims", { method: "GET" }));
    return Array.isArray(body.claims) ? body.claims : [];
  }

  async devices() {
    const body = await (this.management("pairing.devices")
      || this.request("/api/v2/pairing/devices", { method: "GET" }));
    return Array.isArray(body.devices) ? body.devices : [];
  }

  async inspect(deviceId) {
    const devices = await this.devices();
    return devices.filter((item) => String(item.device_id) === String(deviceId));
  }

  async approve(claimId, deviceId) {
    const body = await (this.management("pairing.claim.approve", { claim_id: claimId, device_id: deviceId })
      || this.request(`/api/v2/pairing/claims/${encodeURIComponent(claimId)}/approve`, {
        method: "POST",
        body: JSON.stringify({ device_id: deviceId })
      }));
    this.activeClaim = null;
    return body;
  }

  async reject(claimId) {
    const body = await (this.management("pairing.claim.reject", { claim_id: claimId })
      || this.request(`/api/v2/pairing/claims/${encodeURIComponent(claimId)}/reject`, {
        method: "POST",
        body: "{}"
      }));
    this.activeClaim = null;
    return body;
  }

  revoke(deviceId, reason = "revoked") {
    return this.management("pairing.device.revoke", { device_id: deviceId, reason })
      || this.request(`/api/v2/pairing/devices/${encodeURIComponent(deviceId)}/revoke`, {
        method: "POST",
        body: JSON.stringify({ reason })
      });
  }

  diagnosticSummary() {
    this.clearExpired();
    return { pairing: this.activeClaim ? "claim_ready" : "idle" };
  }
}
