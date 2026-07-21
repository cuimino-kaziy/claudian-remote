import { generateKeyPairSync } from "node:crypto";
import { spawnSync } from "node:child_process";
import { publicKeyFingerprint } from "./release-contract.mjs";
import {
  SIGNING_KEYCHAIN_ACCOUNT,
  SIGNING_KEYCHAIN_SERVICE
} from "./signing-key-source.mjs";

if (process.platform !== "darwin") {
  throw new Error("local release-key bootstrap currently requires macOS Keychain");
}

const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const publicKeyPem = publicKey.export({ type: "spki", format: "pem" });
const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" });
const fingerprint = publicKeyFingerprint(publicKeyPem);
const encodedPrivateKey = Buffer.from(privateKeyPem).toString("base64");

const stored = spawnSync(
  "security",
  [
    "add-generic-password",
    "-U",
    "-a", SIGNING_KEYCHAIN_ACCOUNT,
    "-s", SIGNING_KEYCHAIN_SERVICE,
    "-D", "Claudian Remote release signing key",
    "-j", fingerprint,
    "-w", encodedPrivateKey
  ],
  {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"]
  }
);
if (stored.status !== 0) {
  throw new Error("failed to store the release signing key in macOS Keychain");
}

const verified = spawnSync(
  "security",
  [
    "find-generic-password",
    "-a", SIGNING_KEYCHAIN_ACCOUNT,
    "-s", SIGNING_KEYCHAIN_SERVICE,
    "-w"
  ],
  { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }
);
if (verified.status !== 0 || verified.stdout.trim() !== encodedPrivateKey) {
  throw new Error("release signing key could not be read back from macOS Keychain");
}

process.stdout.write(`${JSON.stringify({
  fingerprint,
  status: "trusted",
  public_key_pem: publicKeyPem
}, null, 2)}\n`);
