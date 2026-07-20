import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { execFileSync } from "node:child_process";
import test from "node:test";
import {
  canonicalJson,
  publicKeyFingerprint,
  sha256Bytes,
  sha256File,
  unsignedManifest,
  validateReleaseContract
} from "../release/packaging/release-contract.mjs";
import { scanSourceBoundary } from "../release/packaging/check-source-boundary.mjs";

const root = resolve(import.meta.dirname, "..");
const pluginManifest = JSON.parse(readFileSync(join(root, "manifest.json"), "utf8"));
const versions = JSON.parse(readFileSync(join(root, "versions.json"), "utf8"));
const supportMatrix = JSON.parse(readFileSync(join(root, "release/support-matrix.json"), "utf8"));

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
      runtime: supportMatrix.runtime
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

test("release schema and support matrix pin the public contract", () => {
  const schema = JSON.parse(readFileSync(join(root, "release/release-manifest.schema.json"), "utf8"));
  assert.equal(schema.$defs.compatibilitySet.properties.claudian.properties.exact_version.const, "2.0.4");
  assert.equal(pluginManifest.id, "claudian-remote");
  assert.equal(versions[pluginManifest.version], pluginManifest.minAppVersion);
  assert.equal(supportMatrix.distribution.allowed_combinations.length, 2);
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
