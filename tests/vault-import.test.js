import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { deterministicVaultPath, importFileIntoVault, safeDisplayName, safeVaultDirectory } from "../src/desktop/vault-import.js";

test("display names and Vault directories cannot traverse", () => {
  assert.equal(safeDisplayName("../../Report.md"), "Report.md");
  assert.equal(safeDisplayName(".."), "attachment.bin");
  assert.equal(safeVaultDirectory("Claudian Remote/Uploads"), "Claudian Remote/Uploads");
  assert.throws(() => safeVaultDirectory("../Outside"), /invalid_vault_directory/);
});

test("upload identity always produces one deterministic conflict-safe Vault path", async () => {
  const adapter = { async exists() { return false; } };
  const selected = await deterministicVaultPath(adapter, "Uploads", "Report.md", "upload-12345678");
  assert.deepEqual(selected, { path: "Uploads/Report-upload-1.md", existed: false });
});

test("desktop import verifies hash and repeated delivery does not duplicate Vault file", async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "claudian-vault-import-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const sourceDir = path.join(root, "source");
  const vaultRoot = path.join(root, "vault");
  await mkdir(sourceDir, { recursive: true });
  await mkdir(vaultRoot, { recursive: true });
  const uploadId = "upload-12345678";
  const source = path.join(sourceDir, `${uploadId}.blob`);
  const content = Buffer.from("# imported\n");
  await writeFile(source, content);
  globalThis.require = createRequire(import.meta.url);
  const adapter = {
    async exists(vaultPath) { try { await readFile(path.join(vaultRoot, vaultPath)); return true; } catch { return false; } },
    async mkdir(vaultPath) { await mkdir(path.join(vaultRoot, vaultPath), { recursive: true }); },
    getFullPath(vaultPath) { return path.join(vaultRoot, vaultPath); }
  };
  const body = {
    upload_id: uploadId,
    temp_path: source,
    display_name: "Report.md",
    total_bytes: content.length,
    total_sha256: createHash("sha256").update(content).digest("hex")
  };
  const first = await importFileIntoVault({ app: { vault: { adapter } }, body, directory: "Remote/Uploads" });
  const second = await importFileIntoVault({ app: { vault: { adapter } }, body, directory: "Remote/Uploads" });
  assert.equal(first.vault_path, "Remote/Uploads/Report-upload-1.md");
  assert.deepEqual(second, first);
  assert.equal((await readFile(path.join(vaultRoot, first.vault_path), "utf8")), "# imported\n");
});
