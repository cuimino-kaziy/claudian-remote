import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { chmodSync, copyFileSync, mkdtempSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { execFileSync } from "node:child_process";
import test from "node:test";
import {
  canonicalJson,
  publicKeyFingerprint,
  releaseTagForVersion,
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
const require = createRequire(import.meta.url);
let buildDependenciesAvailable = true;
try {
  require.resolve("esbuild");
} catch {
  buildDependenciesAvailable = false;
}
const buildTest = buildDependenciesAvailable ? test : test.skip;

function buildAssets(directory = mkdtempSync(join(tmpdir(), "claudian-release-assets-"))) {
  execFileSync("sh", ["release/packaging/build-assets.sh", "--assets-only"], {
    cwd: root,
    env: { ...process.env, CLAUDIAN_RELEASE_DIST: directory },
    stdio: "pipe"
  });
  return directory;
}

function runtimeFixture() {
  return {
    python: supportMatrix.runtime.python,
    uv: supportMatrix.runtime.uv,
    delivery: "immutable_upstream_asset",
    assets: resolveRuntimeAssets(supportMatrix.runtime, {})
  };
}

function fixture(distributionChannel = "community") {
  const directory = mkdtempSync(join(tmpdir(), "claudian-release-contract-"));
  const assetDir = join(directory, "assets");
  mkdirSync(assetDir);
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" });
  const fingerprint = publicKeyFingerprint(publicKeyPem);
  const assetRows = [
    ["plugin", `claudian-remote-plugin-${pluginManifest.version}.tar.gz`, "package-lock.json"],
    ["companion", `claudian-remote-companion-${pluginManifest.version}.tar.gz`, "gateway/requirements.lock"],
    ["relay", `claudian-remote-relay-${pluginManifest.version}.tar.gz`, "gateway/requirements.lock"],
    ["installer", `claudian-remote-lifecycle-${pluginManifest.version}.tar.gz`, "release/lifecycle-dependencies.lock.json"],
    ["legacy_retirement_helper", `claudian-remote-legacy-retirement-helper-${pluginManifest.version}.py`, "gateway/requirements.lock"]
  ];
  const assets = assetRows.map(([component, name, lockPath]) => {
    const bytes = component === "legacy_retirement_helper"
      ? readFileSync(join(root, "gateway/relay/legacy_retirement.py"))
      : Buffer.from(`immutable-${component}-asset`);
    writeFileSync(join(assetDir, name), bytes);
    return {
      name,
      component,
      sha256: sha256Bytes(bytes),
      size: bytes.length,
      license: ["relay", "legacy_retirement_helper"].includes(component) ? "AGPL-3.0-only" : "MIT",
      dependency_locks: [{ path: lockPath, sha256: sha256File(join(root, lockPath)) }]
    };
  });
  const manifest = {
    schema_version: 1,
    release_tag: distributionChannel === "community" ? pluginManifest.version : `v${pluginManifest.version}`,
    release_version: pluginManifest.version,
    source_ref: `refs/tags/${distributionChannel === "community" ? pluginManifest.version : `v${pluginManifest.version}`}`,
    distribution_channel: distributionChannel,
    plugin_update_owner: distributionChannel === "community" ? "obsidian" : "lifecycle_manager",
    compatibility_set: {
      id: supportMatrix.components.compatibility_set_id,
      plugin: { id: "claudian-remote", version: pluginManifest.version, minimum_obsidian_version: pluginManifest.minAppVersion },
      companion: { version: pluginManifest.version },
      relay: { version: pluginManifest.version },
      installer: { version: pluginManifest.version },
      protocol: supportMatrix.protocol,
      configuration_schema: supportMatrix.components.configuration_schema,
      claudian: { exact_version: "2.2.6", supported_versions: ["2.0.4", "2.2.6", "2.2.7"] },
      runtime: runtimeFixture(),
      upgrade_contract: structuredClone(supportMatrix.upgrade_contract)
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

test("community signed upgrade capabilities preserve every supported beta journey", () => {
  assert.equal(pluginManifest.version, "0.2.0");
  assert.equal(supportMatrix.components.compatibility_set_id, "claudian-remote-0.2.0");
  assert.equal(versions["0.2.0-beta.5"], "1.12.3");
  assert.equal(versions["0.2.0-beta.6.7"], "1.12.3");
  assert.equal(versions["0.2.0"], "1.12.3");
  assert.deepEqual(
    supportMatrix.upgrade_contract.supported_legacy_lineages.filter((row) => row.journey === "current_update").map((row) => row.version),
    ["0.2.0-beta.4", "0.2.0-beta.5", "0.2.0-beta.6", "0.2.0-beta.6.1", "0.2.0-beta.6.2", "0.2.0-beta.6.3", "0.2.0-beta.6.4", "0.2.0-beta.6.5", "0.2.0-beta.6.6", "0.2.0-beta.6.7"]
  );
  assert.deepEqual(supportMatrix.upgrade_contract.journey_capabilities, [
    "fresh_install", "current_update", "legacy_upgrade"
  ]);
  assert.deepEqual(supportMatrix.upgrade_contract.result_schema_versions, [
    "claudian-remote.lifecycle-result/v2"
  ]);
  assert.deepEqual(supportMatrix.upgrade_contract.proof_schema_versions, [
    "claudian-remote.legacy-retirement-proof/v1"
  ]);
  assert.deepEqual(
    supportMatrix.upgrade_contract.current_update_pairing_rows.map((row) => row.pairing_identity_policy),
    ["preserve", "rotate"]
  );
  assert.deepEqual(supportMatrix.upgrade_contract.supported_profiles, ["local_tailscale"]);
  assert.equal(supportMatrix.upgrade_contract.final_topology_boundary.silent_fallback, false);

  for (const mutate of [
    (contract) => { contract.journey_capabilities.pop(); },
    (contract) => { contract.result_schema_versions[0] = "claudian-remote.lifecycle-result/v1"; },
    (contract) => { contract.proof_schema_versions[0] = "attacker/proof/v9"; },
    (contract) => { contract.supported_legacy_lineages[2].version = "unknown-lineage"; },
    (contract) => { contract.supported_profiles.push("local_lan"); },
    (contract) => { contract.final_topology_boundary.mode = "remote_vps"; },
    (contract) => { contract.current_update_pairing_rows[0].plugin = "0.2.0-beta.4"; },
    (contract) => { contract.adapter_rows[0].profile_id = "unsupported-profile"; },
    (contract) => { contract.helper_rows[0].sha256 = "0".repeat(64); },
    (contract) => { contract.execution_constraints.runtime_exact_paths[0] = "python3"; },
    (contract) => { contract.execution_constraints.import_prefixes[0] = "relative/imports"; },
    (contract) => { contract.execution_constraints.unbound_network_dependency = "allowed"; },
    (contract) => { contract.runtime_proof_private_key = "must-never-be-packaged"; },
    (contract) => { contract.packaged_acceptance_rows[2].components.pop(); }
  ]) {
    const subject = fixture();
    mutate(subject.manifest.compatibility_set.upgrade_contract);
    assert.throws(
      () => validateReleaseContract(subject.manifest, subject.context),
      /upgrade capability|helper|private key|signature/
    );
  }
});

test("beta 4, missing, replaced, or helper-substituted assets fail closed", () => {
  const missing = fixture();
  missing.manifest.assets.pop();
  assert.throws(() => validateReleaseContract(missing.manifest, missing.context), /asset|helper/);

  const mixed = fixture();
  mixed.manifest.assets[0].name = "claudian-remote-plugin-0.2.0-beta.4.tar.gz";
  assert.throws(() => validateReleaseContract(mixed.manifest, mixed.context), /asset version|signature/);

  const replaced = fixture();
  replaced.manifest.assets[0].component = "companion";
  assert.throws(() => validateReleaseContract(replaced.manifest, replaced.context), /asset|companion/);

  const helper = fixture();
  const helperAsset = helper.manifest.assets.find((asset) => asset.component === "legacy_retirement_helper");
  writeFileSync(join(helper.context.assetDir, helperAsset.name), "substituted helper");
  assert.throws(() => validateReleaseContract(helper.manifest, helper.context), /tampering|helper/);
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

test("community tags are plain versions while private beta tags retain their prefix", () => {
  assert.equal(releaseTagForVersion("0.2.0", "community"), "0.2.0");
  assert.equal(releaseTagForVersion("0.2.0-beta.6.7", "private_beta"), "v0.2.0-beta.6.7");
  assert.throws(() => releaseTagForVersion("0.2.0-beta.6.7", "community"), /version|channel/);
  assert.throws(() => releaseTagForVersion("0.2.0", "unknown"), /version|channel/);
  for (const channel of ["community", "private_beta"]) {
    const valid = fixture(channel);
    assert.equal(validateReleaseContract(valid.manifest, valid.context), true);
    const wrongTag = fixture(channel);
    wrongTag.manifest.release_tag = channel === "community" ? `v${pluginManifest.version}` : pluginManifest.version;
    wrongTag.manifest.source_ref = `refs/tags/${wrongTag.manifest.release_tag}`;
    wrongTag.context.expectedTag = wrongTag.manifest.release_tag;
    assert.throws(() => validateReleaseContract(wrongTag.manifest, wrongTag.context), /release tag/);
    const wrongRef = fixture(channel);
    wrongRef.manifest.source_ref = "refs/heads/main";
    assert.throws(() => validateReleaseContract(wrongRef.manifest, wrongRef.context), /source_ref/);
  }
});

test("manifest preparation selects the channel owner and rejects mismatched tags", () => {
  for (const channel of ["community", "private_beta"]) {
    const subject = fixture(channel);
    const prepare = (tag) => execFileSync(process.execPath, [
      "release/packaging/prepare-manifest.mjs", tag, subject.context.assetDir
    ], {
      cwd: root,
      env: { ...process.env, CLAUDIAN_RELEASE_CHANNEL: channel },
      stdio: "pipe"
    });
    const wrongTag = channel === "community" ? `v${pluginManifest.version}` : pluginManifest.version;
    assert.throws(() => prepare(wrongTag), /release tag/);
    prepare(subject.manifest.release_tag);
    const prepared = JSON.parse(readFileSync(join(subject.context.assetDir, "release-manifest.unsigned.json"), "utf8"));
    assert.equal(prepared.release_tag, subject.manifest.release_tag);
    assert.equal(prepared.source_ref, subject.manifest.source_ref);
    assert.equal(prepared.distribution_channel, channel);
    assert.equal(prepared.plugin_update_owner, subject.manifest.plugin_update_owner);
  }
});

test("manifest or asset tampering and unknown or revoked keys are rejected", () => {
  const manifestTamper = fixture();
  manifestTamper.manifest.plugin_update_owner = "lifecycle_manager";
  assert.throws(() => validateReleaseContract(manifestTamper.manifest, manifestTamper.context));

  const assetTamper = fixture();
  writeFileSync(join(assetTamper.context.assetDir, assetTamper.manifest.assets[0].name), "changed");
  assert.throws(() => validateReleaseContract(assetTamper.manifest, assetTamper.context));

  const privateKey = fixture();
  privateKey.manifest.runtime_proof_private_key = "must-never-be-packaged";
  assert.throws(
    () => validateReleaseContract(privateKey.manifest, privateKey.context),
    /private key material/
  );

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
  assert.throws(() => validateReleaseContract(unsupported.manifest, unsupported.context), /Claudian supported versions/);

  for (const versions of [undefined, ["2.2.6"], ["2.0.4", "2.2.6", "2.2.7", "2.2.8"]]) {
    const changed = fixture();
    changed.manifest.compatibility_set.claudian.supported_versions = versions;
    assert.throws(() => validateReleaseContract(changed.manifest, changed.context), /Claudian supported versions/);
  }

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

test("old plugin id is migration-only and each channel has one update owner", () => {
  assert.deepEqual(supportMatrix.plugin.migration_source_ids, ["whale-agent-bridge"]);
  assert.equal(supportMatrix.plugin.legacy_id_may_coexist, false);

  const invalidBeta = fixture("private_beta");
  invalidBeta.manifest.plugin_update_owner = "obsidian";
  assert.throws(() => validateReleaseContract(invalidBeta.manifest, invalidBeta.context), /update owner/);

  const invalidCommunity = fixture();
  invalidCommunity.manifest.plugin_update_owner = "lifecycle_manager";
  assert.throws(() => validateReleaseContract(invalidCommunity.manifest, invalidCommunity.context), /update owner/);
});

test("source boundary rejects local state, credentials, personal paths, and private deployment identifiers", () => {
  const directory = mkdtempSync(join(tmpdir(), "claudian-source-boundary-"));
  writeFileSync(join(directory, "config.local.json"), "{}");
  writeFileSync(join(directory, "source.txt"), [
    ["/Users", "seed-owner", "private"].join("/"),
    ["ghp", "seededcredential123456"].join("_"),
    "https://RELAY.example.test/health"
  ].join("\n"));
  const findings = scanSourceBoundary(directory, ["", " relay.example.test "]);
  assert.ok(findings.some((finding) => finding.includes("local-state filename")));
  assert.ok(findings.some((finding) => finding.includes("personal absolute path")));
  assert.ok(findings.some((finding) => finding.includes("credential-like value")));
  assert.ok(findings.some((finding) => finding.includes("private deployment identifier")));
  assert.throws(() => execFileSync(process.execPath, [join(root, "release/packaging/check-source-boundary.mjs"), directory], {
    env: { ...process.env, CLAUDIAN_PRIVATE_SOURCE_IDENTIFIERS: "\r\n relay.example.test \r\n" },
    stdio: "pipe"
  }), (error) => error.status === 1 && /private deployment identifier/.test(error.stderr.toString()));
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
  assert.equal(schema.$defs.compatibilitySet.properties.id.const, "claudian-remote-0.2.0");
  assert.equal(schema.$defs.compatibilitySet.properties.claudian.properties.exact_version.const, "2.2.6");
  assert.deepEqual(schema.$defs.compatibilitySet.properties.claudian.properties.supported_versions.const, ["2.0.4", "2.2.6", "2.2.7"]);
  assert.equal(pluginManifest.id, "claudian-remote");
  assert.equal(versions[pluginManifest.version], pluginManifest.minAppVersion);
  assert.equal(supportMatrix.distribution.allowed_combinations.length, 2);
  assert.equal(schema.$defs.runtimeDistribution.properties.delivery.const, "immutable_upstream_asset");
  assert.equal(schema.$defs.helperRow.properties.delivery.const, "signed_kit_asset");
  const lineages = fixture().manifest.compatibility_set.upgrade_contract.supported_legacy_lineages;
  const lineageList = schema.$defs.upgradeContract.properties.supported_legacy_lineages;
  assert.ok(lineages.length >= lineageList.minItems && lineages.length <= lineageList.maxItems);
  for (const lineage of lineages) {
    for (const [field, rule] of Object.entries(schema.$defs.legacyLineage.properties)) {
      assert.ok(rule.enum.includes(lineage[field]), `lineage ${field} must match the release schema: ${lineage[field]}`);
    }
  }
  assert.equal(schema.$defs.executionConstraints.properties.runtime_paths_must_be_absolute.const, true);
  assert.equal(schema.$defs.executionConstraints.properties.import_paths_must_be_absolute.const, true);
  assert.equal(schema.$defs.executionConstraints.properties.runtime_proof_secret_material.const, "excluded");
  assert.equal(
    supportMatrix.upgrade_contract.helper_rows[0].sha256,
    sha256File(join(root, supportMatrix.upgrade_contract.helper_rows[0].source_path))
  );
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
  assert.ok(
    readFileSync(join(root, "gateway/relay/relay_server.py"), "utf8")
      .includes(`VERSION = "${pluginManifest.version}"`)
  );
  assert.ok(
    readFileSync(join(root, "gateway/mac_companion/__init__.py"), "utf8")
      .includes(`__version__ = "${pluginManifest.version}"`)
  );
});

buildTest("built mobile bundle has no top-level Node or Electron import", () => {
  execFileSync(process.execPath, ["esbuild.config.mjs", "production"], { cwd: root, stdio: "pipe" });
  const bundle = readFileSync(join(root, "main.js"), "utf8");
  assert.equal(bundle.includes('require("electron")'), false);
  assert.equal(bundle.includes('require("node:'), false);
  assert.equal(/(?:^|;)var [A-Za-z_$][\w$]*=require\("(?:fs|path|crypto|child_process|net|tls|http|https|os)"\)/.test(bundle), false);
});

buildTest("beta plugin and companion assets have no Local REST transport dependency", () => {
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

buildTest("packaged Companion contains only the loopback Bridge production runtime", () => {
  const directory = buildAssets();
  const asset = join(directory, `claudian-remote-companion-${pluginManifest.version}.tar.gz`);
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

buildTest("packaged lifecycle asset contains the guide, Python package, entrypoint, and a content lock", () => {
  const directory = buildAssets();
  const relayAsset = join(directory, `claudian-remote-relay-${pluginManifest.version}.tar.gz`);
  assert.deepEqual(
    execFileSync("tar", ["-xOzf", relayAsset, "./release/support-matrix.json"]),
    readFileSync(join(root, "release/support-matrix.json")),
    "Relay must carry its runtime policy at the path used by gateway.relay.config"
  );
  const asset = join(directory, `claudian-remote-lifecycle-${pluginManifest.version}.tar.gz`);
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

buildTest("downloadable plugin ZIP and standalone assets match the built plugin exactly", () => {
  const directory = buildAssets();
  const archive = join(directory, `claudian-remote-plugin-${pluginManifest.version}.zip`);
  const contents = JSON.parse(execFileSync("python3.12", ["-c", `
import hashlib, json, sys, zipfile
with zipfile.ZipFile(sys.argv[1]) as archive:
    print(json.dumps({name: hashlib.sha256(archive.read(name)).hexdigest() for name in archive.namelist()}))
`, archive], { encoding: "utf8" }));
  const files = ["LICENSE", "main.js", "manifest.json", "styles.css"];
  assert.deepEqual(Object.keys(contents), files.map((name) => `claudian-remote/${name}`));
  for (const name of files) {
    assert.equal(contents[`claudian-remote/${name}`], sha256File(join(root, name)));
    if (name !== "LICENSE") assert.equal(sha256File(join(directory, name)), contents[`claudian-remote/${name}`]);
    const signedArchiveBytes = execFileSync("tar", ["-xOzf", join(directory, `claudian-remote-plugin-${pluginManifest.version}.tar.gz`), `./${name}`]);
    assert.equal(sha256Bytes(signedArchiveBytes), contents[`claudian-remote/${name}`]);
  }
});

buildTest("component archives and convenience downloads are byte-for-byte reproducible", () => {
  const assetNames = ["plugin", "companion", "relay", "lifecycle"]
    .map((component) => `claudian-remote-${component}-${pluginManifest.version}.tar.gz`);
  assetNames.push(`claudian-remote-legacy-retirement-helper-${pluginManifest.version}.py`);
  assetNames.push(`claudian-remote-plugin-${pluginManifest.version}.zip`, "main.js", "manifest.json", "styles.css");
  const directory = buildAssets();
  const first = Object.fromEntries(assetNames.map((name) => [name, sha256File(join(directory, name))]));
  buildAssets(directory);
  const second = Object.fromEntries(assetNames.map((name) => [name, sha256File(join(directory, name))]));
  assert.deepEqual(second, first);
});

test("tester-facing beta kit is self-contained and its launcher binds the extracted release directory", () => {
  const directory = mkdtempSync(join(tmpdir(), "claudian-beta-kit-test-"));
  const installerRoot = join(directory, "installer-root");
  mkdirSync(join(installerRoot, "bin"), { recursive: true });
  copyFileSync(join(root, "CLAUDIAN_REMOTE_INSTALL.md"), join(installerRoot, "CLAUDIAN_REMOTE_INSTALL.md"));
  const launcherPath = join(installerRoot, "bin/claudian-remote-lifecycle");
  writeFileSync(launcherPath, `#!/bin/sh
release_root=/absolute/release
bundle_root=/absolute/bundle
: "\${CLAUDIAN_REMOTE_RELEASE_DIR:-\${bundle_root}}"
exec python3 -m installer --release-dir "\${release_root}"
`);
  chmodSync(launcherPath, 0o755);
  const installerName = `claudian-remote-lifecycle-${pluginManifest.version}.tar.gz`;
  execFileSync("sh", [
    join(root, "release/packaging/deterministic-tar.sh"),
    installerRoot,
    join(directory, installerName)
  ], { stdio: "pipe" });
  for (const component of ["plugin", "companion", "relay"]) {
    writeFileSync(
      join(directory, `claudian-remote-${component}-${pluginManifest.version}.tar.gz`),
      `deterministic-${component}-fixture\n`
    );
  }
  copyFileSync(
    join(root, supportMatrix.upgrade_contract.helper_rows[0].source_path),
    join(directory, supportMatrix.upgrade_contract.helper_rows[0].name)
  );
  execFileSync(process.execPath, [
    "release/packaging/prepare-manifest.mjs",
    `v${pluginManifest.version}`,
    directory
  ], { cwd: root, env: { ...process.env, CLAUDIAN_RELEASE_CHANNEL: "private_beta" }, stdio: "pipe" });
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" });
  const fingerprint = publicKeyFingerprint(publicKeyPem);
  const manifest = JSON.parse(readFileSync(join(directory, "release-manifest.unsigned.json"), "utf8"));
  manifest.signature.key_fingerprint = fingerprint;
  manifest.signature.value = sign(
    null,
    Buffer.from(canonicalJson(unsignedManifest(manifest))),
    privateKey
  ).toString("base64");
  writeFileSync(join(directory, "release-manifest.json"), JSON.stringify(manifest));
  const assets = manifest.assets;

  const validationOverrides = {
    trustStore: { keys: [{ fingerprint, status: "trusted", public_key_pem: publicKeyPem }] }
  };
  const kit = prepareInstallKit(directory, validationOverrides);
  const firstDigest = sha256File(kit);
  const bootstrapPath = join(directory, `CLAUDIAN_REMOTE_TRUSTED_BOOTSTRAP-${pluginManifest.version}.md`);
  const bootstrap = readFileSync(bootstrapPath, "utf8");
  assert.match(bootstrap, new RegExp(firstDigest));
  assert.match(bootstrap, new RegExp(fingerprint));
  assert.match(bootstrap, /可信通道单独发送/);
  assert.match(bootstrap, /校验成功前，不得解压/);
  const rebuiltKit = prepareInstallKit(directory, validationOverrides);
  assert.equal(sha256File(rebuiltKit), firstDigest);
  const listing = execFileSync("tar", ["-tzf", kit], { encoding: "utf8" });
  assert.equal(listing.includes("./CLAUDIAN_REMOTE_INSTALL.md"), true);
  assert.equal(listing.includes("TRUSTED_BOOTSTRAP"), false);
  assert.equal(listing.includes("./release-manifest.json"), true);
  for (const asset of assets) {
    assert.equal(listing.includes(`./assets/${asset.name}`), true, `missing kit asset: ${asset.name}`);
  }
  assert.equal(listing.includes("private-key"), false);
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
