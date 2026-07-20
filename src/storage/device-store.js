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

  clearRemoteState({ includeMigration = false } = {}) {
    const names = ["identity", "local-preferences", "recovery", "offline-cache"];
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
  revokeLegacyCredential = async () => {}
} = {}) {
  if (!(deviceStore instanceof DeviceStore)) throw new TypeError("device store required");
  const migrations = deviceStore.read("migration") || {};
  if (migrations[MIGRATION_KEY]?.completed === true) {
    return {
      synchronized: sanitizeSyncPreferences(synchronized),
      rePairRequired: migrations[MIGRATION_KEY].re_pair_required === true,
      alreadyCompleted: true
    };
  }

  const credential = legacyCredential(synchronized);
  if (credential) await revokeLegacyCredential(credential);
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
