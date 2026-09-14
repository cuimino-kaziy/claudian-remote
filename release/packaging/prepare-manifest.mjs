import { readFileSync, statSync, writeFileSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import { releaseTagForVersion, resolveRuntimeAssets, sha256File } from "./release-contract.mjs";

const root = resolve(import.meta.dirname, "../..");
const tag = process.argv[2];
const dist = resolve(process.argv[3] ?? join(root, "dist"));
const plugin = JSON.parse(readFileSync(join(root, "manifest.json"), "utf8"));
const matrix = JSON.parse(readFileSync(join(root, "release/support-matrix.json"), "utf8"));
const channel = process.env.CLAUDIAN_RELEASE_CHANNEL ?? "community";
if (tag !== releaseTagForVersion(plugin.version, channel)) throw new Error("release tag must match the plugin version and distribution channel");

const lock = (path) => ({ path, sha256: sha256File(join(root, path)) });
const descriptions = [
  ["plugin", `claudian-remote-plugin-${plugin.version}.tar.gz`, "MIT", [lock("package-lock.json")]],
  ["companion", `claudian-remote-companion-${plugin.version}.tar.gz`, "MIT", [lock("gateway/requirements.lock")]],
  ["relay", `claudian-remote-relay-${plugin.version}.tar.gz`, "AGPL-3.0-only", [lock("gateway/requirements.lock")]],
  ["installer", `claudian-remote-lifecycle-${plugin.version}.tar.gz`, "MIT", [lock("release/lifecycle-dependencies.lock.json")]],
  ["legacy_retirement_helper", `claudian-remote-legacy-retirement-helper-${plugin.version}.py`, "AGPL-3.0-only", [lock("gateway/requirements.lock")]]
];
const assets = descriptions.map(([component, name, license, dependency_locks]) => {
  const path = join(dist, name);
  return { name: basename(path), component, sha256: sha256File(path), size: statSync(path).size, license, dependency_locks };
});
const helper = matrix.upgrade_contract?.helper_rows?.[0];
const helperAsset = assets.find((asset) => asset.component === "legacy_retirement_helper");
if (!helper || helper.delivery !== "signed_kit_asset"
  || helper.name !== helperAsset?.name
  || helper.sha256 !== helperAsset?.sha256
  || helper.sha256 !== sha256File(join(root, helper.source_path ?? ""))) {
  throw new Error("legacy retirement helper does not match the signed supply-chain row");
}
const manifest = {
  schema_version: 1,
  release_tag: tag,
  release_version: plugin.version,
  source_ref: `refs/tags/${tag}`,
  distribution_channel: channel,
  plugin_update_owner: channel === "community" ? "obsidian" : "lifecycle_manager",
  compatibility_set: {
    id: matrix.components.compatibility_set_id,
    plugin: { id: plugin.id, version: plugin.version, minimum_obsidian_version: plugin.minAppVersion },
    companion: { version: matrix.components.companion },
    relay: { version: matrix.components.relay },
    installer: { version: matrix.components.installer },
    protocol: matrix.protocol,
    configuration_schema: matrix.components.configuration_schema,
    claudian: { exact_version: matrix.claudian.exact_version, supported_versions: matrix.claudian.supported_versions },
    runtime: {
      python: matrix.runtime.python,
      uv: matrix.runtime.uv,
      delivery: matrix.runtime.delivery,
      assets: resolveRuntimeAssets(matrix.runtime)
    },
    upgrade_contract: matrix.upgrade_contract
  },
  assets,
  signature: { algorithm: "ed25519", key_fingerprint: "", value: "" }
};
writeFileSync(join(dist, "release-manifest.unsigned.json"), `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o600 });
