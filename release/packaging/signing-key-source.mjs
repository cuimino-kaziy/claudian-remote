import { execFileSync, spawnSync } from "node:child_process";

export const SIGNING_KEYCHAIN_ACCOUNT = "maintainer";
export const SIGNING_KEYCHAIN_SERVICE = "com.claudian.remote.release-signing";

export function storeSigningKeyInKeychain(
  encodedPrivateKey,
  fingerprint,
  { platform = process.platform, spawn = spawnSync } = {}
) {
  if (platform !== "darwin") {
    throw new Error("local release-key bootstrap currently requires macOS Keychain");
  }
  const stored = spawn(
    "security",
    [
      "add-generic-password",
      "-a", SIGNING_KEYCHAIN_ACCOUNT,
      "-s", SIGNING_KEYCHAIN_SERVICE,
      "-D", "Claudian Remote release signing key",
      "-j", fingerprint,
      "-w"
    ],
    {
      encoding: "utf8",
      input: `${encodedPrivateKey}\n${encodedPrivateKey}\n`,
      stdio: ["pipe", "pipe", "pipe"]
    }
  );
  if (stored.status !== 0) {
    throw new Error("failed to store the release signing key in macOS Keychain; an existing key was not replaced");
  }
}

export function readSigningKeyFromKeychain() {
  if (process.platform !== "darwin") return "";
  try {
    return execFileSync(
      "security",
      [
        "find-generic-password",
        "-a", SIGNING_KEYCHAIN_ACCOUNT,
        "-s", SIGNING_KEYCHAIN_SERVICE,
        "-w"
      ],
      { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }
    ).trim();
  } catch {
    return "";
  }
}
