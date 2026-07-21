import { readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { sha256File } from "./release-contract.mjs";

const bundleRoot = resolve(process.argv[2] ?? "");
if (!process.argv[2] || !statSync(bundleRoot).isDirectory()) {
  throw new Error("lifecycle bundle directory is required");
}

const matrix = JSON.parse(readFileSync(join(bundleRoot, "release/support-matrix.json"), "utf8"));
const dependencyLockPath = join(bundleRoot, "release/lifecycle-dependencies.lock.json");

function collectFiles(directory) {
  const files = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) files.push(...collectFiles(path));
    else if (entry.isFile()) files.push(path);
  }
  return files;
}

const includedRoots = [
  join(bundleRoot, "CLAUDIAN_REMOTE_INSTALL.md"),
  join(bundleRoot, "bin/claudian-remote-lifecycle"),
  join(bundleRoot, "installer")
];
const files = includedRoots.flatMap((path) => statSync(path).isDirectory() ? collectFiles(path) : [path]);
const source_files = Object.fromEntries(files
  .map((path) => [relative(bundleRoot, path).replaceAll("\\", "/"), sha256File(path)])
  .sort(([left], [right]) => left.localeCompare(right)));

const lock = {
  schema_version: 1,
  package: "installer.claudian_remote_lifecycle",
  entrypoint: "bin/claudian-remote-lifecycle",
  guide: "CLAUDIAN_REMOTE_INSTALL.md",
  runtime: {
    python: matrix.runtime.python,
    uv: matrix.runtime.uv,
    required_targets: matrix.runtime.required_assets.map(({ platform, arch }) => ({ platform, arch }))
  },
  dependency_lock: {
    path: "release/lifecycle-dependencies.lock.json",
    sha256: sha256File(dependencyLockPath)
  },
  source_files
};

writeFileSync(
  join(bundleRoot, "release/lifecycle-runtime.lock.json"),
  `${JSON.stringify(lock, null, 2)}\n`,
  { mode: 0o600 }
);
