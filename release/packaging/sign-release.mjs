import { createPrivateKey, sign } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { canonicalJson, publicKeyFingerprint, unsignedManifest } from "./release-contract.mjs";
import { readSigningKeyFromKeychain } from "./signing-key-source.mjs";

const root = resolve(import.meta.dirname, "../..");
const dist = resolve(process.argv[2] ?? join(root, "dist"));
const trustStore = JSON.parse(readFileSync(join(root, "release/trust-root.json"), "utf8"));
const trustedKeys = (trustStore.keys ?? []).filter((key) => key.status === "trusted");
const encodedKey = process.env.CLAUDIAN_RELEASE_SIGNING_KEY_B64 || readSigningKeyFromKeychain();
const expectedFingerprint = process.env.CLAUDIAN_RELEASE_KEY_FINGERPRINT
  || (trustedKeys.length === 1 ? trustedKeys[0].fingerprint : "");
if (!encodedKey || !expectedFingerprint) {
  throw new Error("release signing key and one pinned trusted fingerprint are required");
}

const privateKey = createPrivateKey(Buffer.from(encodedKey, "base64"));
const actualFingerprint = publicKeyFingerprint(privateKey);
if (actualFingerprint !== expectedFingerprint) throw new Error("signing key does not match the pinned fingerprint");
if (!(trustStore.keys ?? []).some((key) => key.fingerprint === actualFingerprint && key.status === "trusted")) {
  throw new Error("signing key is not pinned as trusted in the bootstrap trust root");
}

const path = join(dist, "release-manifest.unsigned.json");
const manifest = JSON.parse(readFileSync(path, "utf8"));
manifest.signature.key_fingerprint = actualFingerprint;
manifest.signature.value = sign(null, Buffer.from(canonicalJson(unsignedManifest(manifest))), privateKey).toString("base64");
writeFileSync(join(dist, "release-manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o600 });
