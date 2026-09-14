function required(value, code) {
  const text = String(value || "").trim();
  if (!text) throw new Error(code);
  return text;
}

function optional(value) {
  return String(value || "").trim();
}

function relayEndpoint(value) {
  const text = required(value, "pairing_endpoint_missing").replace(/\/+$/, "");
  const parsed = new URL(text);
  if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw new Error("pairing_endpoint_invalid");
  }
  return text;
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

export function parsePairingDeepLink(value) {
  const url = value instanceof URL ? value : new URL(String(value));
  if (url.protocol !== "obsidian:" || url.hostname !== "claudian-remote") {
    throw new Error("pairing_deep_link_invalid");
  }
  return {
    claim_id: required(url.searchParams.get("claim_id"), "pairing_claim_id_missing"),
    claim_token: required(url.searchParams.get("claim_token"), "pairing_claim_missing"),
    relay_base_url: relayEndpoint(url.searchParams.get("relay_base_url")),
    installation_id: required(url.searchParams.get("installation_id"), "pairing_installation_missing"),
    vault_id: required(url.searchParams.get("vault_id"), "pairing_vault_missing"),
    endpoint_audience: required(url.searchParams.get("endpoint_audience"), "pairing_audience_missing")
  };
}

export class MobilePairingController {
  constructor({ requestImpl = null, fetchImpl = globalThis.fetch, profileProvider, deviceStore, deviceContext, onPaired = () => {} } = {}) {
    this.requestImpl = requestImpl || (async (options) => fetchImpl(options.url, options));
    this.profileProvider = profileProvider;
    this.deviceStore = deviceStore;
    this.deviceContext = deviceContext;
    this.onPaired = onPaired;
    this.pending = null;
    this.pollGeneration = 0;
    this.waiters = new Set();
  }

  profile(hint = {}) {
    const local = this.profileProvider?.() || {};
    const hintedVault = optional(hint.vault_id);
    const localVault = optional(local.vault_id);
    if (hintedVault && localVault && hintedVault !== localVault) throw new Error("pairing_wrong_vault");
    const hintedInstallation = optional(hint.installation_id);
    const localInstallation = optional(local.installation_id);
    if (hintedInstallation && localInstallation && hintedInstallation !== localInstallation) {
      throw new Error("pairing_wrong_installation");
    }
    const hintedAudience = optional(hint.endpoint_audience);
    const localAudience = optional(local.endpoint_audience);
    if (hintedAudience && localAudience && hintedAudience !== localAudience) throw new Error("pairing_wrong_audience");
    return {
      relay_base_url: relayEndpoint(hint.relay_base_url || local.relay_base_url || local.endpoint),
      installation_id: hintedInstallation || localInstallation,
      vault_id: required(hintedVault || localVault, "pairing_vault_missing"),
      endpoint_audience: hintedAudience || localAudience
    };
  }

  context() {
    const context = this.deviceContext?.() || {};
    return {
      device_id: required(context.device_id, "pairing_device_missing"),
      device_name: required(context.device_name, "pairing_device_name_missing")
    };
  }

  async request(url, options) {
    let timer;
    try {
      const timeout = new Promise((_, reject) => {
        timer = globalThis.setTimeout(() => reject(new Error("pairing_request_timeout")), 15000);
      });
      const response = await Promise.race([this.requestImpl({ url, ...options, throw: false }), timeout]);
      return await decodeResponse(response);
    } finally {
      globalThis.clearTimeout(timer);
    }
  }

  async redeem({ claim_id = null, claim_token = null, short_code = null, ...profileHint } = {}) {
    const profile = this.profile(profileHint);
    const context = this.context();
    const { ok, body } = await this.request(`${profile.relay_base_url}/api/v2/pairing/redeem`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        claim_id,
        claim_token,
        short_code,
        ...context,
        installation_id: profile.installation_id || undefined,
        vault_id: profile.vault_id,
        endpoint_audience: profile.endpoint_audience || undefined
      })
    });
    // The raw claim is intentionally never copied into controller state.
    claim_token = null;
    short_code = null;
    if (!ok) throw new Error(body?.error || "pairing_redeem_failed");
    const authoritative = this.profile({
      ...profile,
      installation_id: body.profile?.installation_id || profile.installation_id,
      vault_id: body.profile?.vault_id || profile.vault_id,
      endpoint_audience: body.profile?.endpoint_audience || profile.endpoint_audience
    });
    this.pending = {
      claim_id: String(body.claim_id),
      redemption_handle: String(body.redemption_handle),
      device_id: context.device_id,
      status: body.status === "approved" ? "approved" : "pending_approval",
      expires_at: Number(body.expires_at || 0),
      profile: authoritative
    };
    return { claim_id: this.pending.claim_id, status: this.pending.status, expires_at: this.pending.expires_at };
  }

  acceptDeepLink(value) {
    return this.redeem(parsePairingDeepLink(value));
  }

  acceptProtocolParams(params = {}) {
    return this.redeem({
      claim_id: params.claim_id,
      claim_token: params.claim_token,
      relay_base_url: params.relay_base_url,
      installation_id: params.installation_id,
      vault_id: params.vault_id,
      endpoint_audience: params.endpoint_audience
    });
  }

  acceptShortCode(shortCode) {
    return this.redeem({ short_code: required(shortCode, "pairing_short_code_missing").toUpperCase() });
  }

  async complete() {
    if (!this.pending) throw new Error("pairing_not_pending");
    const pending = this.pending;
    const profile = pending.profile;
    const { status, ok, body } = await this.request(
      `${profile.relay_base_url}/api/v2/pairing/claims/${encodeURIComponent(pending.claim_id)}/complete`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          redemption_handle: pending.redemption_handle,
          device_id: pending.device_id
        })
      }
    );
    if (status === 202 && body?.status === "pending_approval") {
      return { paired: false, status: "pending_approval" };
    }
    if (!ok) {
      if (["claim_expired", "claim_replayed", "credential_delivery_expired"].includes(body?.error)) this.cancel();
      throw new Error(body?.error || "pairing_complete_failed");
    }
    const identity = {
      credential_id: required(body.credential_id, "pairing_credential_id_missing"),
      mobile_token: required(body.credential, "pairing_credential_missing"),
      device_id: pending.device_id,
      client_instance_id: `mobile-view-${globalThis.crypto?.randomUUID?.() || Date.now()}`,
      generation: Number(body.generation || 1),
      installation_id: required(profile.installation_id, "pairing_installation_missing"),
      vault_id: required(profile.vault_id, "pairing_vault_missing"),
      endpoint_audience: required(profile.endpoint_audience, "pairing_audience_missing")
    };
    const connectionProfile = {
      endpoint: profile.relay_base_url,
      installation_id: identity.installation_id,
      vault_id: identity.vault_id,
      endpoint_audience: identity.endpoint_audience
    };
    this.deviceStore.clearRevokedDevice();
    if (!this.deviceStore.write("connection-profile", connectionProfile)) throw new Error("device_local_persistence_unavailable");
    if (!this.deviceStore.write("identity", identity)) {
      this.deviceStore.remove("connection-profile");
      throw new Error("device_local_persistence_unavailable");
    }
    this.pending = null;
    this.pollGeneration += 1;
    this.onPaired({ ...identity, mobile_token: undefined, profile: connectionProfile });
    return { paired: true, credential_id: identity.credential_id, device_id: identity.device_id };
  }

  async pollUntilComplete({ intervalMs = 1000, maxAttempts = 60 } = {}) {
    const generation = ++this.pollGeneration;
    for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
      if (generation !== this.pollGeneration || !this.pending) return { paired: false, status: "cancelled" };
      const result = await this.complete();
      if (result.paired) return result;
      await this.wait(intervalMs);
    }
    return { paired: false, status: "pending_approval" };
  }

  wait(milliseconds) {
    if (milliseconds <= 0) return Promise.resolve();
    return new Promise((resolve) => {
      const timer = globalThis.setTimeout(() => {
        this.waiters.delete(cancel);
        resolve();
      }, milliseconds);
      const cancel = () => { globalThis.clearTimeout(timer); resolve(); };
      this.waiters.add(cancel);
    });
  }

  cancel() {
    this.pollGeneration += 1;
    this.pending = null;
    for (const cancel of this.waiters) cancel();
    this.waiters.clear();
  }

  dispose() {
    this.cancel();
  }

  diagnosticSummary() {
    return { status: this.pending?.status || "idle" };
  }
}
