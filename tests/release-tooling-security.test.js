import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { generateKeyPairSync, sign } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";
import test from "node:test";
import { prepareInstallKit } from "../release/packaging/prepare-install-kit.mjs";
import { canonicalJson, publicKeyFingerprint, sha256File, unsignedManifest } from "../release/packaging/release-contract.mjs";
import { storeSigningKeyInKeychain } from "../release/packaging/signing-key-source.mjs";
import { verifyRuntimeAsset } from "../release/packaging/verify-runtime-assets.mjs";

function communityReleaseFixture() {
  const root = resolve(import.meta.dirname, "..");
  const directory = mkdtempSync(join(tmpdir(), "claudian-community-kit-"));
  execFileSync("sh", ["release/packaging/build-assets.sh"], {
    cwd: root,
    env: {
      ...process.env,
      CLAUDIAN_RELEASE_DIST: directory,
      CLAUDIAN_RELEASE_CHANNEL: "community",
      CLAUDIAN_RELEASE_TAG: "0.2.0"
    },
    stdio: "pipe"
  });
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" });
  const fingerprint = publicKeyFingerprint(publicKeyPem);
  const manifest = JSON.parse(readFileSync(join(directory, "release-manifest.unsigned.json"), "utf8"));
  manifest.signature.key_fingerprint = fingerprint;
  manifest.signature.value = sign(null, Buffer.from(canonicalJson(unsignedManifest(manifest))), privateKey).toString("base64");
  writeFileSync(join(directory, "release-manifest.json"), JSON.stringify(manifest));
  return {
    directory,
    manifest,
    options: { trustStore: { keys: [{ fingerprint, status: "trusted", public_key_pem: publicKeyPem }] } }
  };
}

test("community kit publishes an external guide whose shell checks the complete archive before extraction", () => {
  const { directory, manifest, options } = communityReleaseFixture();
  try {
    const kit = prepareInstallKit(directory, options);
    assert.equal(basename(kit), "claudian-remote-kit-0.2.0.tar.gz");
    const guideName = "CLAUDIAN_REMOTE_INSTALL_VERIFICATION-0.2.0.md";
    const guide = readFileSync(join(directory, guideName), "utf8");
    assert.ok(guide.includes("https://github.com/cuimino-kaziy/claudian-remote/releases/tag/0.2.0"));
    assert.ok(guide.includes(sha256File(kit)));
    assert.ok(guide.includes(manifest.signature.key_fingerprint));
    assert.match(guide, /同一信任来源/);
    assert.match(guide, /Ed25519/);
    assert.equal(existsSync(join(directory, "CLAUDIAN_REMOTE_TRUSTED_BOOTSTRAP-0.2.0.md")), false);
    const listing = execFileSync("tar", ["-tzf", kit], { encoding: "utf8" });
    assert.equal(listing.includes(guideName), false);
    assert.equal(listing.includes("TRUSTED_BOOTSTRAP"), false);
    const script = guide.match(/```bash\n([\s\S]*?)\n```/)?.[1];
    assert.ok(script, "guide must contain a runnable pre-extraction verification block");
    for (const scenario of ["valid", "tampered", "missing"]) {
      const download = join(directory, `download with spaces ${scenario}`);
      mkdirSync(download);
      const downloadedKit = join(download, basename(kit));
      if (scenario !== "missing") copyFileSync(kit, downloadedKit);
      if (scenario === "tampered") writeFileSync(downloadedKit, "tampered archive");
      const run = () => execFileSync("/bin/bash", [], { input: script, cwd: download, stdio: ["pipe", "pipe", "pipe"] });
      if (scenario === "valid") {
        run();
        const extracted = readdirSync(download).filter((name) => name.startsWith("claudian-remote-0.2.0."));
        assert.equal(extracted.length, 1);
        assert.deepEqual(
          JSON.parse(readFileSync(join(download, extracted[0], "release-manifest.json"), "utf8")),
          manifest
        );
      } else {
        assert.throws(run, (error) => error.status === 1);
        assert.equal(readdirSync(download).filter((name) => name.startsWith("claudian-remote-0.2.0.")).length, 0);
      }
    }
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("community kit preparation retains pinned Ed25519 and signed asset checks", () => {
  const { directory, manifest, options } = communityReleaseFixture();
  try {
    assert.throws(() => prepareInstallKit(directory, { trustStore: { keys: [] } }), /unknown signing key/);
    const changed = structuredClone(manifest);
    changed.signature.value = Buffer.alloc(64).toString("base64");
    writeFileSync(join(directory, "release-manifest.json"), JSON.stringify(changed));
    assert.throws(() => prepareInstallKit(directory, options), /signature/);
    writeFileSync(join(directory, "release-manifest.json"), JSON.stringify(manifest));
    writeFileSync(join(directory, manifest.assets[0].name), "tampered signed component");
    assert.throws(() => prepareInstallKit(directory, options), /tampering/);
    assert.equal(existsSync(join(directory, "claudian-remote-kit-0.2.0.tar.gz")), false);
    assert.equal(existsSync(join(directory, "CLAUDIAN_REMOTE_INSTALL_VERIFICATION-0.2.0.md")), false);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("release signing key is supplied over stdin and an existing key is not overwritten", () => {
  const secret = "private-key-material";
  let invocation;
  storeSigningKeyInKeychain(secret, "f".repeat(64), {
    platform: "darwin",
    spawn(command, commandArguments, options) {
      invocation = { command, commandArguments, options };
      return { status: 0 };
    }
  });

  assert.equal(invocation.command, "security");
  assert.equal(invocation.commandArguments.at(-1), "-w");
  assert.equal(invocation.commandArguments.includes("-U"), false);
  assert.equal(invocation.commandArguments.includes(secret), false);
  assert.equal(invocation.options.input, `${secret}\n${secret}\n`);
});

test("release signing key initialization fails closed when Keychain refuses the insert", () => {
  assert.throws(
    () => storeSigningKeyInKeychain("secret", "f".repeat(64), {
      platform: "darwin",
      spawn: () => ({ status: 45 })
    }),
    /existing key was not replaced/
  );
});

test("runtime asset verification has a per-asset timeout with target context", async () => {
  const target = {
    platform: "darwin",
    arch: "arm64",
    python: {
      url: "https://downloads.example/python.tar.gz",
      sha256: "a".repeat(64)
    }
  };
  // AbortSignal.timeout's timer is unref'd, so it does not keep the Node event
  // loop alive on its own; in a busy CI loop the abort could be starved before
  // the fake fetch settles. Keep the loop alive from the fetch side so the
  // production default per-asset timeout deterministically fires the abort.
  const fetchImpl = (_url, { signal }) => new Promise((_resolve, reject) => {
    const keepAlive = setInterval(() => {}, 60_000);
    signal.addEventListener("abort", () => {
      clearInterval(keepAlive);
      reject(signal.reason);
    }, { once: true });
  });

  await assert.rejects(
    verifyRuntimeAsset(target, "python", { fetchImpl, timeoutMs: 10 }),
    /darwin\/arm64 python verification failed/
  );
});
