import { Platform } from "obsidian";

const SAFE_UPLOAD_ID = /^[A-Za-z0-9-]{8,80}$/;

export function safeDisplayName(value) {
  const leaf = String(value || "attachment.bin").split(/[\\/]/).at(-1).replace(/[\u0000-\u001f\u007f]/g, "").trim();
  return leaf && leaf !== "." && leaf !== ".." ? leaf.slice(0, 180) : "attachment.bin";
}

export function safeVaultDirectory(value) {
  const parts = String(value || "Claudian Remote/Uploads").replace(/\\/g, "/").split("/").filter(Boolean);
  if (!parts.length || parts.some((part) => part === "." || part === "..")) throw new Error("invalid_vault_directory");
  return parts.join("/");
}

export async function deterministicVaultPath(adapter, directory, displayName, uploadId) {
  if (!SAFE_UPLOAD_ID.test(String(uploadId || ""))) throw new Error("invalid_upload_id");
  const name = safeDisplayName(displayName);
  const dot = name.lastIndexOf(".");
  const stem = dot > 0 ? name.slice(0, dot) : name;
  const extension = dot > 0 ? name.slice(dot) : "";
  const desired = `${directory}/${name}`;
  const deterministic = `${directory}/${stem}-${uploadId.slice(0, 8)}${extension}`;
  if (await adapter.exists(deterministic)) return { path: deterministic, existed: true };
  if (await adapter.exists(desired)) return { path: deterministic, existed: false };
  // Upload identity stays in the physical filename even without a conflict so
  // a repeated delivery after a local crash resolves to the same Vault path.
  return { path: deterministic, existed: false };
}

function nodeModules() {
  if (!Platform.isDesktopApp) throw new Error("desktop_runtime_unavailable");
  const loader = typeof require === "function" ? require : globalThis.require;
  if (typeof loader !== "function") throw new Error("desktop_runtime_unavailable");
  return { fs: loader("fs"), path: loader("path"), crypto: loader("crypto") };
}

async function fileDigest(fs, crypto, path) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash("sha256");
    const stream = fs.createReadStream(path, { highWaterMark: 64 * 1024 });
    stream.on("data", (chunk) => hash.update(chunk));
    stream.on("error", reject);
    stream.on("end", () => resolve(hash.digest("hex")));
  });
}

export async function importFileIntoVault({ app, body, directory = "Claudian Remote/Uploads" }) {
  const uploadId = String(body?.upload_id || "");
  if (!SAFE_UPLOAD_ID.test(uploadId)) throw new Error("invalid_upload_id");
  const { fs, path, crypto } = nodeModules();
  const source = String(body?.temp_path || body?.path || "");
  if (path.basename(source) !== `${uploadId}.blob`) throw new Error("invalid_upload_source");
  const stat = await fs.promises.stat(source);
  if (!stat.isFile() || stat.size !== Number(body.total_bytes)) throw new Error("upload_size_mismatch");
  if (await fileDigest(fs, crypto, source) !== String(body.total_sha256 || body.sha256 || "").toLowerCase()) throw new Error("upload_hash_mismatch");
  const vaultDirectory = safeVaultDirectory(directory);
  if (!(await app.vault.adapter.exists(vaultDirectory))) await app.vault.adapter.mkdir(vaultDirectory);
  const selected = await deterministicVaultPath(app.vault.adapter, vaultDirectory, body.display_name || body.filename, uploadId);
  if (!selected.existed) {
    const finalPath = app.vault.adapter.getFullPath(selected.path);
    const temporaryPath = app.vault.adapter.getFullPath(`${vaultDirectory}/.${uploadId}.part`);
    await fs.promises.copyFile(source, temporaryPath);
    const handle = await fs.promises.open(temporaryPath, "r");
    try { await handle.sync(); } finally { await handle.close(); }
    await fs.promises.rename(temporaryPath, finalPath);
  }
  return {
    artifact_id: uploadId,
    vault_path: selected.path,
    kind: selected.path.toLowerCase().endsWith(".md") ? "markdown" : "file",
    label: safeDisplayName(body.display_name || body.filename),
    size: stat.size
  };
}
