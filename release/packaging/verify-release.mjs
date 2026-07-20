import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { validateReleaseContract } from "./release-contract.mjs";

const root = resolve(import.meta.dirname, "../..");
const dist = resolve(process.argv[2] ?? join(root, "dist"));
const manifest = JSON.parse(readFileSync(join(dist, "release-manifest.json"), "utf8"));
validateReleaseContract(manifest, {
  expectedTag: process.env.CLAUDIAN_RELEASE_TAG ?? manifest.release_tag,
  pluginManifest: JSON.parse(readFileSync(join(root, "manifest.json"), "utf8")),
  versions: JSON.parse(readFileSync(join(root, "versions.json"), "utf8")),
  supportMatrix: JSON.parse(readFileSync(join(root, "release/support-matrix.json"), "utf8")),
  trustStore: JSON.parse(readFileSync(join(root, "release/trust-root.json"), "utf8")),
  rootDir: root,
  assetDir: dist
});
console.log("signed release contract: ok");
