import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { copyFileSync, mkdtempSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { execFileSync } from "node:child_process";
import test from "node:test";
import {
  canonicalJson,
  publicKeyFingerprint,
  resolveRuntimeAssets,
  sha256Bytes,
  sha256File,
  unsignedManifest,
  validateReleaseContract
} from "../release/packaging/release-contract.mjs";
import { scanSourceBoundary } from "../release/packaging/check-source-boundary.mjs";
import { prepareInstallKit } from "../release/packaging/prepare-install-kit.mjs";

const root = resolve(import.meta.dirname, "..");
const pluginManifest = JSON.parse(readFileSync(join(root, "manifest.json"), "utf8"));
const versions = JSON.parse(readFileSync(join(root, "versions.json"), "utf8"));
const supportMatrix = JSON.parse(readFileSync(join(root, "release/support-matrix.json"), "utf8"));

function runtimeFixture() {
  return {
    python: supportMatrix.runtime.python,
    uv: supportMatrix.runtime.uv,
    delivery: "immutable_upstream_asset",
    assets: resolveRuntimeAssets(supportMatrix.runtime, {})
  };
}

function fixture() {
  const directory = mkdtempSync(join(tmpdir(), "claudian-release-contract-"));
  const assetDir = join(directory, "assets");
  mkdirSync(assetDir);
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" });
  const fingerprint = publicKeyFingerprint(publicKeyPem);
  const lockPath = "package-lock.json";
  const lockDigest = sha256File(join(root, lockPath));
  const assets = ["plugin", "companion", "relay", "installer"].map((component) => {
    const name = `${component}.tgz`;
    const bytes = Buffer.from(`immutable-${component}-asset`);
    writeFileSync(join(assetDir, name), bytes);
    return {
      name,
      component,
      sha256: sha256Bytes(bytes),
      size: bytes.length,
      license: component === "relay" ? "AGPL-3.0-only" : "MIT",
      dependency_locks: [{ path: lockPath, sha256: lockDigest }]
    };
  });
  const manifest = {
    schema_version: 1,
    release_tag: `v${pluginManifest.version}`,
    release_version: pluginManifest.version,
    source_ref: `refs/tags/v${pluginManifest.version}`,
    distribution_channel: "private_beta",
    plugin_update_owner: "lifecycle_manager",
    compatibility_set: {
      plugin: { id: "claudian-remote", version: pluginManifest.version, minimum_obsidian_version: pluginManifest.minAppVersion },
      companion: { version: pluginManifest.version },
      relay: { version: pluginManifest.version },
      installer: { version: pluginManifest.version },
      protocol: supportMatrix.protocol,
      configuration_schema: supportMatrix.components.configuration_schema,
      claudian: { exact_version: "2.0.4" },
      runtime: runtimeFixture()
    },
    assets,
    signature: { algorithm: "ed25519", key_fingerprint: fingerprint, value: "" }
  };
  manifest.signature.value = sign(null, Buffer.from(canonicalJson(unsignedManifest(manifest))), privateKey).toString("base64");
  const context = {
    expectedTag: manifest.release_tag,
    pluginManifest,
    versions,
    supportMatrix,
    trustStore: { keys: [{ fingerprint, status: "trusted", public_key_pem: publicKeyPem }] },
    rootDir: root,
    assetDir
  };
  return { manifest, context };
}

test("an exact signed compatibility set is accepted", () => {
  const { manifest, context } = fixture();
  assert.equal(validateReleaseContract(manifest, context), true);
});

test("tag, plugin, versions, and lock drift are rejected", () => {
  for (const mutate of [
    ({ manifest }) => { manifest.release_tag = "v9.9.9"; },
    ({ manifest }) => { manifest.compatibility_set.plugin.version = "9.9.9"; },
    ({ context, manifest }) => { context.versions = { [manifest.release_version]: "0.0.1" }; },
    ({ manifest }) => { manifest.assets[0].dependency_locks[0].sha256 = "0".repeat(64); }
  ]) {
    const subject = fixture();
    mutate(subject);
    assert.throws(() => validateReleaseContract(subject.manifest, subject.context));
  }
});

test("manifest or asset tampering and unknown or revoked keys are rejected", () => {
  const manifestTamper = fixture();
  manifestTamper.manifest.plugin_update_owner = "obsidian";
  assert.throws(() => validateReleaseContract(manifestTamper.manifest, manifestTamper.context));

  const assetTamper = fixture();
  writeFileSync(join(assetTamper.context.assetDir, assetTamper.manifest.assets[0].name), "changed");
  assert.throws(() => validateReleaseContract(assetTamper.manifest, assetTamper.context));

  const unknown = fixture();
  unknown.context.trustStore.keys = [];
  assert.throws(() => validateReleaseContract(unknown.manifest, unknown.context), /unknown signing key/);

  const revoked = fixture();
  revoked.context.trustStore.keys[0].status = "revoked";
  assert.throws(() => validateReleaseContract(revoked.manifest, revoked.context), /revoked signing key/);
});

test("unsupported Claudian and missing asset digests fail closed", () => {
  const unsupported = fixture();
  unsupported.manifest.compatibility_set.claudian.exact_version = "2.0.3";
  assert.throws(() => validateReleaseContract(unsupported.manifest, unsupported.context), /Claudian 2\.0\.4/);

  const missingDigest = fixture();
  delete missingDigest.manifest.assets[0].sha256;
  assert.throws(() => validateReleaseContract(missingDigest.manifest, missingDigest.context), /asset digest/);
});

test("both macOS runtime architectures require pinned HTTPS URLs, digests, and exact versions", () => {
  const valid = fixture();
  assert.equal(validateReleaseContract(valid.manifest, valid.context), true);

  for (const mutate of [
    ({ manifest }) => { manifest.compatibility_set.runtime.assets.pop(); },
    ({ manifest }) => { manifest.compatibility_set.runtime.assets[0].python.url = "http://downloads.example.test/python.tar.gz"; },
    ({ manifest }) => { manifest.compatibility_set.runtime.assets[0].python.url = "https://token@downloads.example.test/python.tar.gz"; },
    ({ manifest }) => { manifest.compatibility_set.runtime.assets[0].uv.sha256 = ""; },
    ({ manifest }) => { manifest.compatibility_set.runtime.assets[1].python.version = "3.13.0"; }
  ]) {
    const subject = fixture();
    mutate(subject);
    assert.throws(() => validateReleaseContract(subject.manifest, subject.context), /runtime|support matrix/);
  }
});

test("runtime asset preparation is reproducible without external release variables", () => {
  const assets = resolveRuntimeAssets(supportMatrix.runtime, {});
  assert.deepEqual(assets.map(({ platform, arch }) => `${platform}/${arch}`).sort(), ["darwin/arm64", "darwin/x86_64"]);
  for (const target of assets) {
    assert.match(target.python.url, /python-build-standalone\/releases\/download\/20250612\/cpython-3\.12\.11/);
    assert.match(target.uv.url, /astral-sh\/uv\/releases\/download\/0\.10\.12\/uv-/);
    assert.match(target.python.sha256, /^[a-f0-9]{64}$/);
    assert.match(target.uv.sha256, /^[a-f0-9]{64}$/);
  }
});

test("old plugin id is migration-only and beta update ownership is fixed", () => {
  assert.deepEqual(supportMatrix.plugin.migration_source_ids, ["whale-agent-bridge"]);
  assert.equal(supportMatrix.plugin.legacy_id_may_coexist, false);

  const invalidBeta = fixture();
  invalidBeta.manifest.plugin_update_owner = "obsidian";
  assert.throws(() => validateReleaseContract(invalidBeta.manifest, invalidBeta.context), /update owner/);

  const invalidCommunity = fixture();
  invalidCommunity.manifest.distribution_channel = "community";
  assert.throws(() => validateReleaseContract(invalidCommunity.manifest, invalidCommunity.context), /update owner/);
});

test("source boundary rejects local state, credentials, personal paths, and private deployment identifiers", () => {
  const directory = mkdtempSync(join(tmpdir(), "claudian-source-boundary-"));
  writeFileSync(join(directory, "config.local.json"), "{}");
  writeFileSync(join(directory, "source.txt"), [
    ["/Users", "seed-owner", "private"].join("/"),
    ["ghp", "seededcredential123456"].join("_"),
    ["relay", "quelplan", "com"].join(".")
  ].join("\n"));
  const findings = scanSourceBoundary(directory);
  assert.ok(findings.some((finding) => finding.includes("local-state filename")));
  assert.ok(findings.some((finding) => finding.includes("personal absolute path")));
  assert.ok(findings.some((finding) => finding.includes("credential-like value")));
  assert.ok(findings.some((finding) => finding.includes("private deployment identifier")));
});

test("source boundary excludes release virtual environments from publishable source", () => {
  const directory = mkdtempSync(join(tmpdir(), "claudian-source-venv-boundary-"));
  mkdirSync(join(directory, ".release-venv"));
  const privatePath = ["", "Users", "private-owner", "runtime"].join("/");
  writeFileSync(join(directory, ".release-venv", "pyvenv.cfg"), `${privatePath}\n`);
  assert.deepEqual(scanSourceBoundary(directory), []);
});

test("release schema and support matrix pin the public contract", () => {
  const schema = JSON.parse(readFileSync(join(root, "release/release-manifest.schema.json"), "utf8"));
  assert.equal(schema.$defs.compatibilitySet.properties.claudian.properties.exact_version.const, "2.0.4");
  assert.equal(pluginManifest.id, "claudian-remote");
  assert.equal(versions[pluginManifest.version], pluginManifest.minAppVersion);
  assert.equal(supportMatrix.distribution.allowed_combinations.length, 2);
  assert.equal(schema.$defs.runtimeDistribution.properties.delivery.const, "immutable_upstream_asset");
  assert.deepEqual(
    supportMatrix.runtime.required_assets.map(({ platform, arch }) => `${platform}/${arch}`).sort(),
    ["darwin/arm64", "darwin/x86_64"]
  );
  for (const target of supportMatrix.runtime.required_assets) {
    for (const component of ["python", "uv"]) {
      assert.match(target[component].url, /^https:\/\/github\.com\/astral-sh\//);
      assert.match(target[component].sha256, /^[a-f0-9]{64}$/);
      assert.equal(Object.hasOwn(target[component], "url_env"), false);
      assert.equal(Object.hasOwn(target[component], "sha256_env"), false);
    }
  }
  assert.match(readFileSync(join(root, "gateway/relay/relay_server.py"), "utf8"), /VERSION = "0\.2\.0-beta\.1"/);
  assert.match(readFileSync(join(root, "gateway/mac_companion/__init__.py"), "utf8"), /__version__ = "0\.2\.0-beta\.1"/);
});

test("built mobile bundle has no top-level Node or Electron import", () => {
  execFileSync(process.execPath, ["esbuild.config.mjs", "production"], { cwd: root, stdio: "pipe" });
  const bundle = readFileSync(join(root, "main.js"), "utf8");
  assert.equal(bundle.includes('require("electron")'), false);
  assert.equal(bundle.includes('require("node:'), false);
  assert.equal(/(?:^|;)var [A-Za-z_$][\w$]*=require\("(?:fs|path|crypto|child_process|net|tls|http|https|os)"\)/.test(bundle), false);
});

test("beta plugin and companion assets have no Local REST transport dependency", () => {
  execFileSync(process.execPath, ["esbuild.config.mjs", "production"], { cwd: root, stdio: "pipe" });
  const bundle = readFileSync(join(root, "main.js"), "utf8");
  assert.equal(bundle.includes("obsidian-local-rest-api"), false);
  assert.equal(bundle.includes("/claudian-remote/v2/events"), false);
  assert.equal(bundle.includes("LocalSseHub"), false);
  const config = readFileSync(join(root, "gateway/mac_companion/config.example.json"), "utf8");
  assert.equal(config.includes("adapter_base_url"), false);
  assert.equal(config.includes("adapter_token"), false);
  assert.equal(config.includes("bridge_sse_path"), false);
});

test("packaged Companion contains only the loopback Bridge production runtime", () => {
  execFileSync("sh", ["release/packaging/build-assets.sh", "--assets-only"], { cwd: root, stdio: "pipe" });
  const asset = join(root, "dist", `claudian-remote-companion-${pluginManifest.version}.tar.gz`);
  const listing = execFileSync("tar", ["-tzf", asset], { encoding: "utf8" });
  assert.equal(listing.includes("__pycache__"), false);
  assert.equal(listing.includes("companion.py"), false);
  assert.equal(listing.includes("sse_client.py"), false);
  const paths = [
    "./gateway/mac_companion/config.example.json",
    "./gateway/mac_companion/runner.py",
    "./gateway/mac_companion/stream_pump.py"
  ];
  const contents = paths.map((entry) => execFileSync("tar", ["-xOzf", asset, entry], { encoding: "utf8" })).join("\n");
  for (const forbidden of [
    "obsidian-local-rest-api", "adapter_base_url", "adapter_token",
    "bridge_sse_path", "/claudian-remote/v2/events", "LocalBridgeV2Client"
  ]) assert.equal(contents.includes(forbidden), false, `forbidden packaged dependency: ${forbidden}`);
});

test("packaged lifecycle asset contains the guide, Python package, entrypoint, and a content lock", () => {
  execFileSync("sh", ["release/packaging/build-assets.sh", "--assets-only"], { cwd: root, stdio: "pipe" });
  const asset = join(root, "dist", `claudian-remote-lifecycle-${pluginManifest.version}.tar.gz`);
  const listing = execFileSync("tar", ["-tzf", asset], { encoding: "utf8" });
  for (const path of [
    "./CLAUDIAN_REMOTE_INSTALL.md",
    "./bin/claudian-remote-lifecycle",
    "./installer/__init__.py",
    "./installer/claudian_remote_lifecycle/__init__.py",
    "./installer/claudian_remote_lifecycle/cli.py",
    "./installer/claudian_remote_lifecycle/model.py",
    "./release/lifecycle-runtime.lock.json",
    "./release/lifecycle-dependencies.lock.json",
    "./release/support-matrix.json",
    "./release/trust-root.json"
  ]) assert.equal(listing.includes(path), true, `missing lifecycle bundle path: ${path}`);
  assert.equal(listing.includes("__pycache__"), false);
  assert.equal(listing.includes(".pyc"), false);

  const lock = JSON.parse(execFileSync("tar", ["-xOzf", asset, "./release/lifecycle-runtime.lock.json"], { encoding: "utf8" }));
  assert.equal(lock.entrypoint, "bin/claudian-remote-lifecycle");
  assert.equal(lock.guide, "CLAUDIAN_REMOTE_INSTALL.md");
  assert.equal(lock.dependency_lock.path, "release/lifecycle-dependencies.lock.json");
  assert.equal(
    lock.dependency_lock.sha256,
    sha256Bytes(execFileSync("tar", ["-xOzf", asset, "./release/lifecycle-dependencies.lock.json"]))
  );
  assert.deepEqual(lock.runtime.required_targets, [
    { platform: "darwin", arch: "arm64" },
    { platform: "darwin", arch: "x86_64" }
  ]);
  for (const [path, digest] of Object.entries(lock.source_files)) {
    const bytes = execFileSync("tar", ["-xOzf", asset, `./${path}`]);
    assert.equal(sha256Bytes(bytes), digest, `lifecycle content lock drift: ${path}`);
  }
});

test("component archives are byte-for-byte reproducible", () => {
  const assetNames = ["plugin", "companion", "relay", "lifecycle"]
    .map((component) => `claudian-remote-${component}-${pluginManifest.version}.tar.gz`);
  execFileSync("sh", ["release/packaging/build-assets.sh", "--assets-only"], { cwd: root, stdio: "pipe" });
  const first = Object.fromEntries(assetNames.map((name) => [name, sha256File(join(root, "dist", name))]));
  execFileSync("sh", ["release/packaging/build-assets.sh", "--assets-only"], { cwd: root, stdio: "pipe" });
  const second = Object.fromEntries(assetNames.map((name) => [name, sha256File(join(root, "dist", name))]));
  assert.deepEqual(second, first);
});

test("tester-facing beta kit is self-contained and its launcher binds the extracted release directory", () => {
  execFileSync("sh", ["release/packaging/build-assets.sh", "--assets-only"], { cwd: root, stdio: "pipe" });
  const directory = mkdtempSync(join(tmpdir(), "claudian-beta-kit-test-"));
  const components = ["plugin", "companion", "relay", "lifecycle"];
  const assets = components.map((name) => {
    const sourceName = `claudian-remote-${name}-${pluginManifest.version}.tar.gz`;
    copyFileSync(join(root, "dist", sourceName), join(directory, sourceName));
    return {
      name: sourceName,
      component: name === "lifecycle" ? "installer" : name,
      sha256: sha256File(join(directory, sourceName)),
      size: statSync(join(directory, sourceName)).size
    };
  });
  writeFileSync(join(directory, "release-manifest.json"), JSON.stringify({
    release_version: pluginManifest.version,
    assets,
    signature: {
      algorithm: "ed25519",
      key_fingerprint: "fixture-fingerprint",
      value: "fixture-signature"
    }
  }));

  const kit = prepareInstallKit(directory);
  const firstDigest = sha256File(kit);
  const rebuiltKit = prepareInstallKit(directory);
  assert.equal(sha256File(rebuiltKit), firstDigest);
  const listing = execFileSync("tar", ["-tzf", kit], { encoding: "utf8" });
  assert.equal(listing.includes("./CLAUDIAN_REMOTE_INSTALL.md"), true);
  assert.equal(listing.includes("./release-manifest.json"), true);
  for (const asset of assets) {
    assert.equal(listing.includes(`./assets/${asset.name}`), true, `missing kit asset: ${asset.name}`);
  }
  const launcher = execFileSync("tar", ["-xOzf", kit, "./bin/claudian-remote-lifecycle"], { encoding: "utf8" });
  assert.match(launcher, /--release-dir "\$\{release_root\}"/);
  assert.match(launcher, /CLAUDIAN_REMOTE_RELEASE_DIR:-\$\{bundle_root\}/);
});

test("all workflow Actions are immutable and permissions remain least-privilege", () => {
  for (const workflowName of ["ci.yml", "release.yml"]) {
    const workflow = readFileSync(join(root, ".github/workflows", workflowName), "utf8");
    const actionRefs = [...workflow.matchAll(/^\s*uses:\s*[^@\s]+@([^\s#]+)/gm)].map((match) => match[1]);
    assert.ok(actionRefs.length > 0, `${workflowName} must declare at least one Action`);
    for (const ref of actionRefs) assert.match(ref, /^[a-f0-9]{40}$/, `${workflowName} contains a mutable Action ref`);
    assert.equal(/permissions:\s*write-all/.test(workflow), false);
    assert.equal(/pull-requests:\s*write/.test(workflow), false);
    assert.equal(/actions:\s*write/.test(workflow), false);
  }
  const ci = readFileSync(join(root, ".github/workflows/ci.yml"), "utf8");
  assert.match(ci, /^permissions:\n\s+contents:\s+read/m);
  const release = readFileSync(join(root, ".github/workflows/release.yml"), "utf8");
  assert.match(release, /^permissions:\n\s+contents:\s+read/m);
  assert.match(release, /^\s{6}contents:\s+write/m);
});
