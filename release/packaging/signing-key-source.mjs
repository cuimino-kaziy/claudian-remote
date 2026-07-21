import { execFileSync } from "node:child_process";

export const SIGNING_KEYCHAIN_ACCOUNT = "maintainer";
export const SIGNING_KEYCHAIN_SERVICE = "com.claudian.remote.release-signing";

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
