import { readdirSync, readFileSync } from "node:fs";
import { basename, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const FORBIDDEN_NAMES = [
  /^\.env(?:\.|$)/,
  /^\.token$/,
  /^config\.local\.json$/,
  /^companion_state.*\.json$/,
  /\.(?:db|sqlite3?|log|wal|shm)$/
];
const FORBIDDEN_DIRS = new Set([".git", ".venv", ".release-venv", "venv", "node_modules", "dist", "data", "logs", "__pycache__", ".pytest_cache"]);
const SECRET_PATTERNS = [
  /\b(?:ghp|github_pat|xox[baprs])[-_][A-Za-z0-9_-]{12,}\b/g,
  /\bsk-[A-Za-z0-9_-]{20,}\b/g,
  /Authorization:\s*Bearer\s+(?![<[]|token-example|abcde)[A-Za-z0-9._~+/=-]{20,}/gi
];
const PRIVATE_SOURCE_PATTERNS = [
  new RegExp(["relay", "quelplan", "com"].join("\\."), "gi"),
  new RegExp(`\\b${["com", "lantian"].join("\\.")}\\.`, "g"),
  new RegExp(["周", "环", "系", "统"].join(""), "g")
];
const PERSONAL_PATH = /\/Users\/(?!example(?:\/|$)|tester(?:\/|$)|beta-user(?:\/|$))[A-Za-z0-9._-]+\/[A-Za-z0-9._~ -]+/g;

export function scanSourceBoundary(root) {
  const findings = [];
  const walk = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      if (entry.isDirectory() && FORBIDDEN_DIRS.has(entry.name)) continue;
      const path = resolve(directory, entry.name);
      const display = relative(root, path);
      if (entry.isDirectory()) {
        walk(path);
        continue;
      }
      if (!entry.isFile()) continue;
      if (FORBIDDEN_NAMES.some((pattern) => pattern.test(basename(path)))) findings.push(`${display}: forbidden local-state filename`);
      let text;
      try { text = readFileSync(path, "utf8"); } catch { continue; }
      if (PERSONAL_PATH.test(text)) findings.push(`${display}: personal absolute path`);
      PERSONAL_PATH.lastIndex = 0;
      for (const pattern of SECRET_PATTERNS) {
        if (pattern.test(text)) findings.push(`${display}: credential-like value`);
        pattern.lastIndex = 0;
      }
      for (const pattern of PRIVATE_SOURCE_PATTERNS) {
        if (pattern.test(text)) findings.push(`${display}: private deployment identifier`);
        pattern.lastIndex = 0;
      }
    }
  };
  walk(resolve(root));
  return findings;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const root = resolve(process.argv[2] ?? ".");
  const findings = scanSourceBoundary(root);
  if (findings.length) {
    console.error(findings.join("\n"));
    process.exitCode = 1;
  } else {
    console.log("publish-safe source boundary: ok");
  }
}
