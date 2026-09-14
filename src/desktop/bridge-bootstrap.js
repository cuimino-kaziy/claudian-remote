import { Platform } from "obsidian";

const BOOTSTRAP_SCHEMA = "claudian-remote.bridge-bootstrap/v1";
const MAX_BOOTSTRAP_BYTES = 16 * 1024;
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/;

function desktopRequire(name) {
  if (!Platform.isDesktopApp) throw new Error("desktop_runtime_unavailable");
  const loader = typeof require === "function" ? require : globalThis.require;
  if (typeof loader !== "function") throw new Error("desktop_runtime_unavailable");
  return loader(name);
}

export function defaultBridgeBootstrapPath(expectedVaultId = null) {
  const os = desktopRequire("node:os");
  const path = desktopRequire("node:path");
  let name = "bridge-bootstrap.json";
  if (expectedVaultId) {
    const crypto = desktopRequire("node:crypto");
    const digest = crypto.createHash("sha256").update(String(expectedVaultId), "utf8").digest("hex").slice(0, 24);
    name = `bridge-bootstrap.${digest}.json`;
  }
  return path.join(os.homedir(), "Library", "Application Support", "Claudian Remote", "state", name);
}

function safeEndpoint(value) {
  try {
    const parsed = new URL(String(value || ""));
    return parsed.protocol === "https:"
      && !parsed.username
      && !parsed.password
      && !parsed.search
      && !parsed.hash;
  } catch {
    return false;
  }
}

function eraseAndRemove(fs, path, size = 0) {
  try {
    if (size > 0 && size <= MAX_BOOTSTRAP_BYTES) {
      const descriptor = fs.openSync(path, "r+");
      try {
        fs.writeSync(descriptor, new Uint8Array(size), 0, size, 0);
        fs.fsyncSync(descriptor);
      } finally {
        fs.closeSync(descriptor);
      }
    }
  } catch {}
  try { fs.unlinkSync(path); } catch {}
}

export function consumeBridgeBootstrap({
  path = null,
  fs = null,
  now = () => Date.now(),
  expectedVaultId = null
} = {}) {
  const fileSystem = fs || desktopRequire("node:fs");
  const bootstrapPath = path || defaultBridgeBootstrapPath(expectedVaultId);
  let stat;
  try { stat = fileSystem.lstatSync(bootstrapPath); }
  catch (error) {
    if (error?.code === "ENOENT") return null;
    throw new Error("bridge_bootstrap_unavailable");
  }
  let size = Number(stat.size || 0);
  try {
    if (!stat.isFile() || stat.isSymbolicLink() || (Number(stat.mode) & 0o077) !== 0) {
      throw new Error("bridge_bootstrap_permissions_invalid");
    }
    const processUid = globalThis.process?.getuid?.();
    if (Number.isInteger(processUid) && Number(stat.uid) !== processUid) {
      throw new Error("bridge_bootstrap_owner_invalid");
    }
    if (size < 2 || size > MAX_BOOTSTRAP_BYTES) throw new Error("bridge_bootstrap_size_invalid");
    const value = JSON.parse(fileSystem.readFileSync(bootstrapPath, "utf8"));
    const installationId = String(value?.installation_id || "");
    const vaultId = String(value?.vault_id || "");
    const credentialId = String(value?.bridge_credential_id || "");
    const secret = String(value?.bridge_secret || "");
    const expiresAt = Number(value?.expires_at || 0) * 1000;
    if (value?.bootstrap_schema !== BOOTSTRAP_SCHEMA
      || !SAFE_ID.test(installationId)
      || !SAFE_ID.test(vaultId)
      || !SAFE_ID.test(credentialId)
      || secret.length < 32
      || !safeEndpoint(value?.endpoint)
      || String(value?.endpoint_audience || "") !== `claudian-remote:local_tailscale:${installationId}`
      || expiresAt <= now()
      || expiresAt - now() > 10 * 60 * 1000
      || (expectedVaultId && String(expectedVaultId) !== vaultId)) {
      throw new Error("bridge_bootstrap_invalid");
    }
    return {
      installation_id: installationId,
      vault_id: vaultId,
      endpoint: String(value.endpoint).replace(/\/+$/, ""),
      endpoint_audience: String(value.endpoint_audience),
      credential_id: credentialId,
      secret
    };
  } catch (error) {
    if (error?.message?.startsWith?.("bridge_bootstrap_")) throw error;
    throw new Error("bridge_bootstrap_invalid");
  } finally {
    eraseAndRemove(fileSystem, bootstrapPath, size);
  }
}
