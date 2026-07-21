import { generateKeyPairSync } from "node:crypto";
import { publicKeyFingerprint } from "./release-contract.mjs";
import {
  readSigningKeyFromKeychain,
  storeSigningKeyInKeychain
} from "./signing-key-source.mjs";

if (process.platform !== "darwin") {
  throw new Error("local release-key bootstrap currently requires macOS Keychain");
}

const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const publicKeyPem = publicKey.export({ type: "spki", format: "pem" });
const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" });
const fingerprint = publicKeyFingerprint(publicKeyPem);
const encodedPrivateKey = Buffer.from(privateKeyPem).toString("base64");

storeSigningKeyInKeychain(encodedPrivateKey, fingerprint);

if (readSigningKeyFromKeychain() !== encodedPrivateKey) {
  throw new Error("release signing key could not be read back from macOS Keychain");
}

process.stdout.write(`${JSON.stringify({
  fingerprint,
  status: "trusted",
  public_key_pem: publicKeyPem
}, null, 2)}\n`);
