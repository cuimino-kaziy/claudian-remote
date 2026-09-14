import { sanitizeSyncPreferences } from "./sync-preferences.js";

const MIGRATION_KEY = "legacy_shared_token_v1";

export class DeviceStore {
  constructor({ storage = globalThis.localStorage, namespace = "claudian-remote" } = {}) {
    this.storage = storage;
    this.namespace = String(namespace || "claudian-remote");
  }

  key(name) {
    return `${this.namespace}:${String(name)}`;
  }

  read(name) {
    try {
      const raw = this.storage?.getItem?.(this.key(name));
      return raw ? JSON.parse(raw) : null;
    } catch {
      return null;
    }
  }

  write(name, value) {
    try {
      if (!this.storage?.setItem) return false;
      this.storage.setItem(this.key(name), JSON.stringify(value));
      return true;
    } catch {
      return false;
    }
  }

  remove(name) {
    try {
      if (!this.storage?.removeItem) return false;
      this.storage.removeItem(this.key(name));
      return true;
    } catch {
      return false;
    }
  }

  installBridgeProfile({ bridgeIdentity, connectionProfile, retireNames = [] } = {}) {
    const retired = [...new Set(retireNames.map(String))]
      .filter((name) => name && !["bridge-identity", "connection-profile"].includes(name));
    const names = ["bridge-identity", "connection-profile", ...retired];
    if (!this.storage?.getItem || !this.storage?.setItem || !this.storage?.removeItem) return false;
    const previous = new Map(names.map((name) => [name, this.storage.getItem(this.key(name))]));
    const values = new Map([
      ["bridge-identity", JSON.stringify(bridgeIdentity)],
      ["connection-profile", JSON.stringify(connectionProfile)]
    ]);
    const rollback = () => {
      for (const name of names) {
        const value = previous.get(name);
        if (value === null || value === undefined) this.storage.removeItem(this.key(name));
        else this.storage.setItem(this.key(name), value);
      }
    };
    try {
      for (const [name, value] of values) this.storage.setItem(this.key(name), value);
      for (const name of retired) this.storage.removeItem(this.key(name));
      const recordsMatch = [...values]
        .every(([name, value]) => this.storage.getItem(this.key(name)) === value);
      const retiredAbsent = retired.every((name) => this.storage.getItem(this.key(name)) === null);
      if (!recordsMatch || !retiredAbsent) {
        rollback();
        return false;
      }
      return true;
    } catch {
      try { rollback(); } catch {}
      return false;
    }
  }

  clearRemoteState({ includeMigration = false } = {}) {
    const names = ["identity", "bridge-identity", "pairing-admin-identity", "connection-profile", "local-preferences", "recovery", "offline-cache"];
    if (includeMigration) names.push("migration");
    return names.map((name) => this.remove(name)).every(Boolean);
  }

  clearRevokedDevice() {
    return ["identity", "recovery", "offline-cache"].map((name) => this.remove(name)).every(Boolean);
  }
}

function legacyCredential(value) {
  return String(value?.mobile_token || value?.relayToken || "");
}

export async function migrateLegacySynchronizedState({
  synchronized = {},
  deviceStore,
  revokeLegacyCredential = async () => false
} = {}) {
  if (!(deviceStore instanceof DeviceStore)) throw new TypeError("device store required");
  const migrations = deviceStore.read("migration") || {};
  if (migrations[MIGRATION_KEY]?.completed === true) {
    const preferences = sanitizeSyncPreferences(synchronized);
    const identity = deviceStore.read("identity");
    const profile = deviceStore.read("connection-profile");
    // The migration's re-pair flag describes the retired shared token, not a
    // scoped device credential successfully paired and saved since then.
    const paired = ["credential_id", "mobile_token", "device_id", "installation_id", "vault_id", "endpoint_audience"]
      .every((key) => typeof identity?.[key] === "string" && identity[key].trim())
      && ["installation_id", "vault_id", "endpoint_audience"].every((key) => identity[key] === profile?.[key])
      && identity.vault_id === preferences.vault_id;
    return {
      synchronized: preferences,
      rePairRequired: migrations[MIGRATION_KEY].re_pair_required === true && !paired,
      alreadyCompleted: true
    };
  }

  const credential = legacyCredential(synchronized);
  if (credential) {
    const outcome = await revokeLegacyCredential(credential);
    const verified = outcome === true || outcome?.verified === true;
    if (!verified) throw new Error("legacy_credential_revocation_unverified");
  }
  const marker = {
    completed: true,
    re_pair_required: Boolean(credential),
    completed_at: new Date().toISOString()
  };
  if (!deviceStore.write("migration", { ...migrations, [MIGRATION_KEY]: marker })) {
    throw new Error("device_local_migration_state_unavailable");
  }
  if (credential) deviceStore.clearRevokedDevice();
  return {
    synchronized: sanitizeSyncPreferences(synchronized),
    rePairRequired: Boolean(credential),
    alreadyCompleted: false
  };
}
