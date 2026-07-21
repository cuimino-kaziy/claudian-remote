import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";

function safeAssetName(value) {
  const name = String(value ?? "");
  return name && basename(name) === name && name !== "." && name !== "..";
}

function sha256File(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function writeTrustedBootstrap(dist, manifest, kit) {
  const version = String(manifest.release_version ?? "");
  if (!/^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/.test(version)) {
    throw new Error("release version is invalid");
  }
  const kitName = basename(kit);
  const kitDigest = sha256File(kit);
  const fingerprint = String(manifest.signature.key_fingerprint);
  const path = join(dist, `CLAUDIAN_REMOTE_TRUSTED_BOOTSTRAP-${version}.md`);
  writeFileSync(path, `# Claudian Remote 内测可信 Bootstrap

> 这份文件必须由维护者通过既有的可信通道单独发送。它不在 Beta Kit 内，
> 也不与 Kit 一起发布到 GitHub Release。如果本文件与 Kit 来自同一个未验证下载源，请停止。

- 发行版本：\`${version}\`
- Kit 文件：\`${kitName}\`
- Kit SHA-256：\`${kitDigest}\`
- 维护者签名钥指纹：\`${fingerprint}\`

## Agent 必须执行的预验证

1. 先确认用户是否从维护者的既有可信聊天或文件通道单独收到本 MD。
2. 在校验成功前，不得解压 Kit，不得执行 Kit 中任何命令。
3. 在 Kit 所在目录执行：

\`\`\`bash
test "$(shasum -a 256 '${kitName}' | awk '{print $1}')" = '${kitDigest}'
\`\`\`

4. 只有命令以状态 0 退出时，才能解压到一个新目录，并把其中的
   \`CLAUDIAN_REMOTE_INSTALL.md\` 作为 Agent 的后续安装入口。
5. 任何文件名、SHA-256 或指纹不一致都必须失败关闭：不得安装，联系维护者重新获取。
`, { encoding: "utf8", mode: 0o600 });
  return path;
}

export function prepareInstallKit(distDirectory) {
  const dist = resolve(distDirectory);
  const manifestPath = join(dist, "release-manifest.json");
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  const signature = manifest?.signature ?? {};
  if (signature.algorithm !== "ed25519" || !signature.key_fingerprint || !signature.value) {
    throw new Error("a signed and verified release manifest is required");
  }
  const assets = Array.isArray(manifest.assets) ? manifest.assets : [];
  if (assets.length === 0 || assets.some((asset) => !safeAssetName(asset?.name))) {
    throw new Error("release manifest asset list is invalid");
  }
  const installer = assets.find((asset) => asset.component === "installer");
  if (!installer || assets.filter((asset) => asset.component === "installer").length !== 1) {
    throw new Error("exactly one lifecycle installer asset is required");
  }
  for (const asset of assets) {
    const path = join(dist, asset.name);
    if (!statSync(path).isFile()) throw new Error(`release asset missing: ${asset.name}`);
  }

  const temporary = mkdtempSync(join(tmpdir(), "claudian-remote-install-kit-"));
  const root = join(temporary, "kit");
  const assetRoot = join(root, "assets");
  mkdirSync(assetRoot, { recursive: true, mode: 0o700 });
  try {
    execFileSync("tar", ["-xzf", join(dist, installer.name), "-C", root], { stdio: "pipe" });
    copyFileSync(manifestPath, join(root, "release-manifest.json"));
    for (const asset of assets) copyFileSync(join(dist, asset.name), join(assetRoot, asset.name));
    const output = join(dist, `claudian-remote-beta-kit-${manifest.release_version}.tar.gz`);
    execFileSync("sh", [join(import.meta.dirname, "deterministic-tar.sh"), root, output], {
      stdio: "pipe"
    });
    writeTrustedBootstrap(dist, manifest, output);
    return output;
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(import.meta.filename)) {
  const root = resolve(import.meta.dirname, "../..");
  const output = prepareInstallKit(process.argv[2] ?? join(root, "dist"));
  process.stdout.write(`${output}\n`);
}
