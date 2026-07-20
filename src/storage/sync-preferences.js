export const SYNC_PREFERENCES_VERSION = 2;

export const DEFAULT_SYNC_PREFERENCES = Object.freeze({
  schema_version: SYNC_PREFERENCES_VERSION,
  vault_id: "",
  connection_mode: "",
  notifications_enabled: true,
  haptics_enabled: true
});

const CONNECTION_MODES = new Set(["", "local_tailscale", "local_lan", "remote_vps"]);
const VAULT_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/;

function booleanPreference(value, fallback) {
  return typeof value === "boolean" ? value : fallback;
}

export function sanitizeSyncPreferences(value = {}) {
  const connectionMode = String(value?.connection_mode || "");
  const vaultId = String(value?.vault_id || "");
  return {
    schema_version: SYNC_PREFERENCES_VERSION,
    vault_id: VAULT_ID.test(vaultId) ? vaultId : "",
    connection_mode: CONNECTION_MODES.has(connectionMode) ? connectionMode : "",
    notifications_enabled: booleanPreference(value?.notifications_enabled, true),
    haptics_enabled: booleanPreference(value?.haptics_enabled, true)
  };
}
