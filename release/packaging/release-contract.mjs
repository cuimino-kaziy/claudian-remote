import { createHash, createPublicKey, verify } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import { resolve } from "node:path";

export const FINAL_PLUGIN_ID = "claudian-remote";
export const LEGACY_PLUGIN_ID = "whale-agent-bridge";
export const REQUIRED_CLAUDIAN_VERSION = "2.0.4";
const SHA256 = /^[a-f0-9]{64}$/;
const COMPONENTS = ["plugin", "companion", "relay", "installer"];

export class ReleaseContractError extends Error {
  constructor(errors) {
    super(`release contract rejected:\n- ${errors.join("\n- ")}`);
    this.name = "ReleaseContractError";
    this.errors = errors;
  }
}

export function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

export function unsignedManifest(manifest) {
  const { signature: _signature, ...payload } = manifest;
  return payload;
}

export function sha256Bytes(value) {
  return createHash("sha256").update(value).digest("hex");
}

export function sha256File(path) {
  return sha256Bytes(readFileSync(path));
}

export function publicKeyFingerprint(publicKeyPem) {
  return sha256Bytes(createPublicKey(publicKeyPem).export({ type: "spki", format: "der" }));
}

export function validateReleaseContract(manifest, context) {
  const errors = [];
  const compatibility = manifest?.compatibility_set ?? {};
  const plugin = compatibility.plugin ?? {};
  const matrix = context.supportMatrix;
  const pluginManifest = context.pluginManifest;
  const versions = context.versions;

  if (manifest?.schema_version !== 1) errors.push("schema_version must be 1");
  if (manifest?.release_tag !== `v${manifest?.release_version}`) errors.push("release tag and release version disagree");
  if (manifest?.source_ref !== `refs/tags/${manifest?.release_tag}`) errors.push("source_ref must be the exact release tag");
  if (context.expectedTag && manifest?.release_tag !== context.expectedTag) errors.push("workflow tag and manifest tag disagree");
  if (plugin.id !== FINAL_PLUGIN_ID || pluginManifest.id !== FINAL_PLUGIN_ID) errors.push("final plugin id is required");
  if (plugin.version !== manifest?.release_version || pluginManifest.version !== manifest?.release_version) errors.push("plugin and release versions disagree");
  if (versions[manifest?.release_version] !== pluginManifest.minAppVersion) errors.push("versions.json and plugin minimum app version disagree");
  if (matrix.release_version !== manifest?.release_version) errors.push("support matrix and release versions disagree");
  for (const component of COMPONENTS) {
    if (compatibility[component]?.version !== matrix.components?.[component]) errors.push(`${component} and support-matrix versions disagree`);
  }
  if (compatibility.configuration_schema !== matrix.components?.configuration_schema) errors.push("configuration schema versions disagree");
  if (compatibility.protocol?.current !== matrix.protocol?.current
    || canonicalJson(compatibility.protocol?.compatible) !== canonicalJson(matrix.protocol?.compatible)
    || canonicalJson(compatibility.protocol?.rollback) !== canonicalJson(matrix.protocol?.rollback)) errors.push("protocol compatibility ranges disagree");
  if (canonicalJson(compatibility.runtime) !== canonicalJson(matrix.runtime)) errors.push("runtime versions disagree");
  if (compatibility.claudian?.exact_version !== REQUIRED_CLAUDIAN_VERSION || matrix.claudian?.exact_version !== REQUIRED_CLAUDIAN_VERSION) errors.push("Claudian 2.0.4 is the only writable beta version");
  if (plugin.minimum_obsidian_version !== matrix.plugin?.minimum_obsidian_version) errors.push("minimum Obsidian versions disagree");

  const allowedOwner = manifest?.distribution_channel === "private_beta"
    ? "lifecycle_manager"
    : manifest?.distribution_channel === "community"
      ? "obsidian"
      : null;
  if (!allowedOwner || manifest.plugin_update_owner !== allowedOwner) errors.push("distribution channel and plugin update owner disagree");

  const migrationIds = matrix.plugin?.migration_source_ids ?? [];
  if (!migrationIds.includes(LEGACY_PLUGIN_ID) || matrix.plugin?.legacy_id_may_coexist !== false) errors.push("legacy plugin id must be migration-only and non-coexisting");

  const assets = Array.isArray(manifest?.assets) ? manifest.assets : [];
  for (const component of COMPONENTS) {
    if (assets.filter((asset) => asset.component === component).length !== 1) errors.push(`exactly one ${component} asset is required`);
  }
  const names = new Set();
  for (const asset of assets) {
    if (names.has(asset.name)) errors.push(`duplicate asset name: ${asset.name}`);
    names.add(asset.name);
    if (!SHA256.test(asset.sha256 ?? "")) errors.push(`missing or invalid asset digest: ${asset.name ?? "unknown"}`);
    if (!Number.isSafeInteger(asset.size) || asset.size < 1) errors.push(`invalid asset size: ${asset.name ?? "unknown"}`);
    const expectedLicense = asset.component === "relay" ? "AGPL-3.0-only" : "MIT";
    if (asset.license !== expectedLicense) errors.push(`wrong license for ${asset.component}`);
    if (!Array.isArray(asset.dependency_locks) || asset.dependency_locks.length === 0) errors.push(`dependency lock missing for ${asset.name ?? "unknown"}`);
    for (const lock of asset.dependency_locks ?? []) {
      if (!SHA256.test(lock.sha256 ?? "")) errors.push(`missing or invalid lock digest: ${lock.path ?? "unknown"}`);
      if (context.rootDir) {
        try {
          if (sha256File(resolve(context.rootDir, lock.path)) !== lock.sha256) errors.push(`dependency lock drift: ${lock.path}`);
        } catch {
          errors.push(`dependency lock missing: ${lock.path}`);
        }
      }
    }
    if (context.assetDir) {
      try {
        const path = resolve(context.assetDir, asset.name);
        if (statSync(path).size !== asset.size || sha256File(path) !== asset.sha256) errors.push(`asset tampering detected: ${asset.name}`);
      } catch {
        errors.push(`asset missing: ${asset.name}`);
      }
    }
  }

  const signature = manifest?.signature ?? {};
  const trusted = (context.trustStore?.keys ?? []).find((key) => key.fingerprint === signature.key_fingerprint);
  if (!trusted) errors.push("unknown signing key");
  else if (trusted.status !== "trusted") errors.push("revoked signing key");
  else if (signature.algorithm !== "ed25519") errors.push("signature algorithm must be ed25519");
  else {
    try {
      const valid = verify(null, Buffer.from(canonicalJson(unsignedManifest(manifest))), trusted.public_key_pem, Buffer.from(signature.value ?? "", "base64"));
      if (!valid) errors.push("manifest signature is invalid");
    } catch {
      errors.push("manifest signature is invalid");
    }
  }

  if (errors.length) throw new ReleaseContractError(errors);
  return true;
}
