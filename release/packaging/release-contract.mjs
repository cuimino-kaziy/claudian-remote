import { createHash, createPublicKey, verify } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import { resolve } from "node:path";

export const FINAL_PLUGIN_ID = "claudian-remote";
export const LEGACY_PLUGIN_ID = "whale-agent-bridge";
export const REQUIRED_CLAUDIAN_VERSION = "2.0.4";
const SHA256 = /^[a-f0-9]{64}$/;
const COMPONENTS = ["plugin", "companion", "relay", "installer"];
const RUNTIME_TARGETS = ["darwin/arm64", "darwin/x86_64"];

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

function validHttpsAssetUrl(value) {
  try {
    const parsed = new URL(value);
    return parsed.protocol === "https:"
      && parsed.username === ""
      && parsed.password === ""
      && parsed.search === ""
      && parsed.hash === "";
  } catch {
    return false;
  }
}

export function resolveRuntimeAssets(runtime, environment = process.env) {
  const errors = [];
  const assets = [];
  const required = Array.isArray(runtime?.required_assets) ? runtime.required_assets : [];
  const targets = new Set();

  for (const target of required) {
    const key = `${target?.platform}/${target?.arch}`;
    if (!RUNTIME_TARGETS.includes(key) || targets.has(key)) {
      errors.push(`invalid or duplicate runtime target: ${key}`);
      continue;
    }
    targets.add(key);
    const resolved = { platform: target.platform, arch: target.arch };
    for (const component of ["python", "uv"]) {
      const descriptor = target?.[component] ?? {};
      const url = descriptor.url ?? environment[descriptor.url_env ?? ""];
      const sha256 = descriptor.sha256 ?? environment[descriptor.sha256_env ?? ""];
      if (descriptor.version !== runtime?.[component]) errors.push(`${key} ${component} version does not match the support matrix`);
      if (!validHttpsAssetUrl(url)) errors.push(`${key} ${component} runtime asset URL is missing or unsafe`);
      if (!SHA256.test(sha256 ?? "")) errors.push(`${key} ${component} runtime asset digest is missing or invalid`);
      resolved[component] = { version: descriptor.version, url, sha256 };
    }
    assets.push(resolved);
  }
  for (const target of RUNTIME_TARGETS) {
    if (!targets.has(target)) errors.push(`required runtime target is missing: ${target}`);
  }
  if (runtime?.delivery !== "private_release_asset") errors.push("runtime delivery must be private_release_asset");
  if (errors.length) throw new ReleaseContractError(errors);
  return assets;
}

function validateRuntimeDistribution(runtime, matrixRuntime, errors) {
  if (runtime?.python !== matrixRuntime?.python || runtime?.uv !== matrixRuntime?.uv) {
    errors.push("runtime versions disagree");
  }
  if (runtime?.delivery !== "private_release_asset" || matrixRuntime?.delivery !== "private_release_asset") {
    errors.push("runtime delivery must be private_release_asset");
  }
  const manifestAssets = Array.isArray(runtime?.assets) ? runtime.assets : [];
  const matrixAssets = Array.isArray(matrixRuntime?.required_assets) ? matrixRuntime.required_assets : [];
  const manifestByTarget = new Map();
  const matrixByTarget = new Map();
  for (const asset of manifestAssets) {
    const key = `${asset?.platform}/${asset?.arch}`;
    if (manifestByTarget.has(key)) errors.push(`duplicate runtime target: ${key}`);
    manifestByTarget.set(key, asset);
  }
  for (const descriptor of matrixAssets) {
    const key = `${descriptor?.platform}/${descriptor?.arch}`;
    if (matrixByTarget.has(key)) errors.push(`duplicate support-matrix runtime target: ${key}`);
    matrixByTarget.set(key, descriptor);
  }
  for (const key of RUNTIME_TARGETS) {
    const asset = manifestByTarget.get(key);
    const descriptor = matrixByTarget.get(key);
    if (!asset) {
      errors.push(`required runtime asset is missing: ${key}`);
      continue;
    }
    if (!descriptor) {
      errors.push(`support-matrix runtime target is missing: ${key}`);
      continue;
    }
    for (const component of ["python", "uv"]) {
      const value = asset?.[component] ?? {};
      const expected = descriptor?.[component] ?? {};
      if (value.version !== matrixRuntime?.[component] || expected.version !== matrixRuntime?.[component]) {
        errors.push(`${key} ${component} version does not match the support matrix`);
      }
      if (!validHttpsAssetUrl(value.url)) errors.push(`${key} ${component} runtime asset URL is missing or unsafe`);
      if (!SHA256.test(value.sha256 ?? "")) errors.push(`${key} ${component} runtime asset digest is missing or invalid`);
      if (expected.url && value.url !== expected.url) errors.push(`${key} ${component} runtime asset URL disagrees with the support matrix`);
      if (expected.sha256 && value.sha256 !== expected.sha256) errors.push(`${key} ${component} runtime asset digest disagrees with the support matrix`);
    }
  }
  for (const key of manifestByTarget.keys()) {
    if (!RUNTIME_TARGETS.includes(key)) errors.push(`unsupported runtime target: ${key}`);
  }
  for (const key of matrixByTarget.keys()) {
    if (!RUNTIME_TARGETS.includes(key)) errors.push(`unsupported support-matrix runtime target: ${key}`);
  }
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
  validateRuntimeDistribution(compatibility.runtime, matrix.runtime, errors);
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
