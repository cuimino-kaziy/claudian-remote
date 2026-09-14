import { createHash, createPublicKey, verify } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import { basename, resolve } from "node:path";

export const FINAL_PLUGIN_ID = "claudian-remote";
export const LEGACY_PLUGIN_ID = "whale-agent-bridge";
export const REQUIRED_CLAUDIAN_VERSION = "2.2.6";
export const SUPPORTED_CLAUDIAN_VERSIONS = Object.freeze(["2.0.4", "2.2.6", "2.2.7"]);
export const REQUIRED_RELEASE_VERSION = "0.2.0";
const SHA256 = /^[a-f0-9]{64}$/;
const COMPONENTS = ["plugin", "companion", "relay", "installer"];
const ASSET_COMPONENTS = [...COMPONENTS, "legacy_retirement_helper"];
const RUNTIME_TARGETS = ["darwin/arm64", "darwin/x86_64"];

export function releaseTagForVersion(version, channel) {
  if (channel === "community" && /^[0-9]+\.[0-9]+\.[0-9]+$/.test(version)) return version;
  if (channel === "private_beta" && /^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/.test(version)) return `v${version}`;
  throw new Error("release version is invalid for distribution channel");
}

function expectedAssetName(component, version) {
  if (component === "installer") return `claudian-remote-lifecycle-${version}.tar.gz`;
  if (component === "legacy_retirement_helper") {
    return `claudian-remote-legacy-retirement-helper-${version}.py`;
  }
  return `claudian-remote-${component}-${version}.tar.gz`;
}

function expectedUpgradeContract(version, helperDigest) {
  return {
    contract_schema: "claudian-remote.upgrade-capabilities/v1",
    journey_capabilities: ["fresh_install", "current_update", "legacy_upgrade"],
    result_schema_versions: ["claudian-remote.lifecycle-result/v2"],
    proof_schema_versions: ["claudian-remote.legacy-retirement-proof/v1"],
    supported_legacy_lineages: [
      { plugin_id: FINAL_PLUGIN_ID, version: "0.2.0-beta.4", journey: "current_update" },
      { plugin_id: FINAL_PLUGIN_ID, version: "0.2.0-beta.5", journey: "current_update" },
      { plugin_id: FINAL_PLUGIN_ID, version: "0.2.0-beta.6", journey: "current_update" },
      { plugin_id: FINAL_PLUGIN_ID, version: "0.2.0-beta.6.1", journey: "current_update" },
      { plugin_id: FINAL_PLUGIN_ID, version: "0.2.0-beta.6.2", journey: "current_update" },
      { plugin_id: FINAL_PLUGIN_ID, version: "0.2.0-beta.6.3", journey: "current_update" },
      { plugin_id: FINAL_PLUGIN_ID, version: "0.2.0-beta.6.4", journey: "current_update" },
      { plugin_id: FINAL_PLUGIN_ID, version: "0.2.0-beta.6.5", journey: "current_update" },
      { plugin_id: FINAL_PLUGIN_ID, version: "0.2.0-beta.6.6", journey: "current_update" },
      { plugin_id: FINAL_PLUGIN_ID, version: "0.2.0-beta.6.7", journey: "current_update" },
      { plugin_id: LEGACY_PLUGIN_ID, version: "recognized-dogfood-lineage", journey: "legacy_upgrade" }
    ],
    supported_profiles: ["local_tailscale"],
    final_topology_boundary: {
      mode: "local_tailscale",
      relay_location: "mac_loopback",
      exposure: "tailscale_serve",
      silent_fallback: false
    },
    current_update_pairing_rows: ["preserve", "rotate"].map((pairing_identity_policy) => ({
      pairing_identity_policy,
      plugin: version,
      companion: version,
      installer: version
    })),
    adapter_rows: [
      { profile_id: "dogfood-local-v1", adapter: "local_managed_relay" },
      { profile_id: "dogfood-vps-v1", adapter: "legacy_vps_relay" }
    ],
    helper_rows: [{
      component: "legacy_retirement_helper",
      name: expectedAssetName("legacy_retirement_helper", version),
      source_path: "gateway/relay/legacy_retirement.py",
      delivery: "signed_kit_asset",
      sha256: helperDigest
    }],
    execution_constraints: {
      runtime_paths_must_be_absolute: true,
      runtime_exact_paths: ["/usr/bin/python3", "/usr/local/bin/python3"],
      runtime_prefixes: ["/opt/claudian-remote/runtime"],
      import_paths_must_be_absolute: true,
      import_prefixes: ["/opt/claudian-remote", "/var/lib/claudian-remote/operations"],
      developer_checkout_dependency: "forbidden",
      unbound_network_dependency: "forbidden",
      runtime_proof_secret_material: "excluded"
    },
    packaged_acceptance_rows: [
      { journey: "fresh_install", components: ["plugin", "companion", "relay", "installer"] },
      { journey: "current_update", components: ["plugin", "companion", "relay", "installer"] },
      { journey: "legacy_upgrade", components: ASSET_COMPONENTS }
    ]
  };
}

function containsPrivateKeyMaterial(value) {
  if (Array.isArray(value)) return value.some(containsPrivateKeyMaterial);
  if (value && typeof value === "object") {
    return Object.entries(value).some(([key, item]) => {
      const normalizedKey = key.toLowerCase().replaceAll(/[^a-z0-9]/g, "");
      return normalizedKey.includes("privatekey") || containsPrivateKeyMaterial(item);
    });
  }
  return typeof value === "string"
    && /-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----/.test(value);
}

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
  if (runtime?.delivery !== "immutable_upstream_asset") errors.push("runtime delivery must be immutable_upstream_asset");
  if (errors.length) throw new ReleaseContractError(errors);
  return assets;
}

function validateRuntimeDistribution(runtime, matrixRuntime, errors) {
  if (runtime?.python !== matrixRuntime?.python || runtime?.uv !== matrixRuntime?.uv) {
    errors.push("runtime versions disagree");
  }
  if (runtime?.delivery !== "immutable_upstream_asset" || matrixRuntime?.delivery !== "immutable_upstream_asset") {
    errors.push("runtime delivery must be immutable_upstream_asset");
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

function validateUpgradeContract(contract, matrixContract, releaseVersion, context, errors) {
  const matrixHelper = Array.isArray(matrixContract?.helper_rows)
    ? matrixContract.helper_rows[0]
    : null;
  const helperDigest = matrixHelper?.sha256;
  if (!SHA256.test(helperDigest ?? "")) {
    errors.push("upgrade helper digest is missing or invalid");
    return;
  }
  const expected = expectedUpgradeContract(releaseVersion, helperDigest);
  if (canonicalJson(matrixContract) !== canonicalJson(expected)) {
    errors.push("support-matrix upgrade capability rows are unsupported");
  }
  if (canonicalJson(contract) !== canonicalJson(expected)) {
    errors.push("signed upgrade capability rows disagree");
  }
  if (context.rootDir) {
    try {
      if (sha256File(resolve(context.rootDir, expected.helper_rows[0].source_path)) !== helperDigest) {
        errors.push("upgrade helper source digest disagrees with the signed contract");
      }
    } catch {
      errors.push("upgrade helper source is missing");
    }
  }
}

export function validateReleaseContract(manifest, context) {
  const errors = [];
  const compatibility = manifest?.compatibility_set ?? {};
  const plugin = compatibility.plugin ?? {};
  const matrix = context.supportMatrix;
  const pluginManifest = context.pluginManifest;
  const versions = context.versions;

  if (containsPrivateKeyMaterial(manifest)) errors.push("private key material must not be included in a release manifest");
  if (manifest?.schema_version !== 1) errors.push("schema_version must be 1");
  if (manifest?.release_version !== REQUIRED_RELEASE_VERSION) errors.push(`release version must be ${REQUIRED_RELEASE_VERSION}`);
  try {
    if (manifest?.release_tag !== releaseTagForVersion(manifest?.release_version, manifest?.distribution_channel)) {
      errors.push("release tag and release version disagree");
    }
  } catch (error) {
    errors.push(error.message);
  }
  if (manifest?.source_ref !== `refs/tags/${manifest?.release_tag}`) errors.push("source_ref must be the exact release tag");
  if (context.expectedTag && manifest?.release_tag !== context.expectedTag) errors.push("workflow tag and manifest tag disagree");
  if (plugin.id !== FINAL_PLUGIN_ID || pluginManifest.id !== FINAL_PLUGIN_ID) errors.push("final plugin id is required");
  if (plugin.version !== manifest?.release_version || pluginManifest.version !== manifest?.release_version) errors.push("plugin and release versions disagree");
  if (versions[manifest?.release_version] !== pluginManifest.minAppVersion) errors.push("versions.json and plugin minimum app version disagree");
  if (matrix.release_version !== manifest?.release_version) errors.push("support matrix and release versions disagree");
  if (compatibility.id !== matrix.components?.compatibility_set_id
    || compatibility.id !== `claudian-remote-${manifest?.release_version}`) errors.push("compatibility set id and release version disagree");
  for (const component of COMPONENTS) {
    if (compatibility[component]?.version !== matrix.components?.[component]) errors.push(`${component} and support-matrix versions disagree`);
  }
  if (compatibility.configuration_schema !== matrix.components?.configuration_schema) errors.push("configuration schema versions disagree");
  if (compatibility.protocol?.current !== matrix.protocol?.current
    || canonicalJson(compatibility.protocol?.compatible) !== canonicalJson(matrix.protocol?.compatible)
    || canonicalJson(compatibility.protocol?.rollback) !== canonicalJson(matrix.protocol?.rollback)) errors.push("protocol compatibility ranges disagree");
  validateRuntimeDistribution(compatibility.runtime, matrix.runtime, errors);
  validateUpgradeContract(compatibility.upgrade_contract, matrix.upgrade_contract, manifest?.release_version, context, errors);
  for (const claudian of [compatibility.claudian, matrix.claudian]) {
    if (claudian?.exact_version !== REQUIRED_CLAUDIAN_VERSION
      || canonicalJson(claudian?.supported_versions) !== canonicalJson(SUPPORTED_CLAUDIAN_VERSIONS)) {
      errors.push("Claudian supported versions must be exactly 2.0.4, 2.2.6, and 2.2.7");
    }
  }
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
  if (assets.length !== ASSET_COMPONENTS.length) errors.push("release asset set must be exact");
  for (const component of ASSET_COMPONENTS) {
    if (assets.filter((asset) => asset.component === component).length !== 1) errors.push(`exactly one ${component} asset is required`);
  }
  const names = new Set();
  for (const asset of assets) {
    if (names.has(asset.name)) errors.push(`duplicate asset name: ${asset.name}`);
    names.add(asset.name);
    if (basename(String(asset.name ?? "")) !== asset.name) errors.push(`unsafe asset name: ${asset.name ?? "unknown"}`);
    if (!ASSET_COMPONENTS.includes(asset.component)) errors.push(`unsupported asset component: ${asset.component ?? "unknown"}`);
    if (ASSET_COMPONENTS.includes(asset.component)
      && asset.name !== expectedAssetName(asset.component, manifest?.release_version)) {
      errors.push(`asset version or name mismatch: ${asset.name ?? "unknown"}`);
    }
    if (!SHA256.test(asset.sha256 ?? "")) errors.push(`missing or invalid asset digest: ${asset.name ?? "unknown"}`);
    if (!Number.isSafeInteger(asset.size) || asset.size < 1) errors.push(`invalid asset size: ${asset.name ?? "unknown"}`);
    const expectedLicense = ["relay", "legacy_retirement_helper"].includes(asset.component) ? "AGPL-3.0-only" : "MIT";
    if (asset.license !== expectedLicense) errors.push(`wrong license for ${asset.component}`);
    const expectedLock = asset.component === "plugin"
      ? "package-lock.json"
      : asset.component === "installer"
        ? "release/lifecycle-dependencies.lock.json"
        : "gateway/requirements.lock";
    if (!Array.isArray(asset.dependency_locks)
      || asset.dependency_locks.length !== 1
      || asset.dependency_locks[0]?.path !== expectedLock) {
      errors.push(`dependency lock mismatch for ${asset.name ?? "unknown"}`);
    }
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
  const helperRow = compatibility.upgrade_contract?.helper_rows?.[0];
  const helperAsset = assets.find((asset) => asset.component === "legacy_retirement_helper");
  if (!helperAsset || helperAsset.name !== helperRow?.name || helperAsset.sha256 !== helperRow?.sha256) {
    errors.push("upgrade helper asset binding mismatch");
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
