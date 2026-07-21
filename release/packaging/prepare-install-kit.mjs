import { execFileSync } from "node:child_process";
import {
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";

function safeAssetName(value) {
  const name = String(value ?? "");
  return name && basename(name) === name && name !== "." && name !== "..";
}

export function prepareInstallKit(distDirectory) {
  const dist = resolve(distDirectory);
  const manifestPath = join(dist, "release-manifest.json");
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  const signature = manifest?.signature ?? {};
  if (signature.algorithm !== "ed25519" || !signature.key_fingerprint || !signature.value) {
    throw new Error("a signed and verified release manifest is required");
  }
  const assets = Array.isArray(manifest.assets) ? manifest.assets : [];
  if (assets.length === 0 || assets.some((asset) => !safeAssetName(asset?.name))) {
    throw new Error("release manifest asset list is invalid");
  }
  const installer = assets.find((asset) => asset.component === "installer");
  if (!installer || assets.filter((asset) => asset.component === "installer").length !== 1) {
    throw new Error("exactly one lifecycle installer asset is required");
  }
  for (const asset of assets) {
    const path = join(dist, asset.name);
    if (!statSync(path).isFile()) throw new Error(`release asset missing: ${asset.name}`);
  }

  const temporary = mkdtempSync(join(tmpdir(), "claudian-remote-install-kit-"));
  const root = join(temporary, "kit");
  const assetRoot = join(root, "assets");
  mkdirSync(assetRoot, { recursive: true, mode: 0o700 });
  try {
    execFileSync("tar", ["-xzf", join(dist, installer.name), "-C", root], { stdio: "pipe" });
    copyFileSync(manifestPath, join(root, "release-manifest.json"));
    for (const asset of assets) copyFileSync(join(dist, asset.name), join(assetRoot, asset.name));
    const output = join(dist, `claudian-remote-beta-kit-${manifest.release_version}.tar.gz`);
    execFileSync("sh", [join(import.meta.dirname, "deterministic-tar.sh"), root, output], {
      stdio: "pipe"
    });
    return output;
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(import.meta.filename)) {
  const root = resolve(import.meta.dirname, "../..");
  const output = prepareInstallKit(process.argv[2] ?? join(root, "dist"));
  process.stdout.write(`${output}\n`);
}
