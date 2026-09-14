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
import { validateReleaseContract } from "./release-contract.mjs";

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

function writePublicVerification(dist, manifest, kit) {
  const version = manifest.release_version;
  const kitName = basename(kit);
  const kitDigest = sha256File(kit);
  const fingerprint = manifest.signature.key_fingerprint;
  const releaseUrl = `https://github.com/cuimino-kaziy/claudian-remote/releases/tag/${manifest.release_tag}`;
  const path = join(dist, `CLAUDIAN_REMOTE_INSTALL_VERIFICATION-${version}.md`);
  writeFileSync(path, `# Claudian Remote ${version} 下载与安装包校验

## 确认官方来源

从 [cuimino-kaziy/claudian-remote 的 ${manifest.release_tag} 发布页](${releaseUrl}) 下载本页和安装包。
核对地址中的 github.com、账号 cuimino-kaziy、仓库 claudian-remote 和精确版本 ${manifest.release_tag}。
同名项目、第三方网盘和 fork 不自动视为官方来源；不要用 Source code 或单独的插件 ZIP 代替完整 Kit。

本页与安装包属于同一信任来源，首次安装以你确认的官方 GitHub 发布者身份为信任起点。
这不是独立渠道验证，无法防御官方 GitHub 账号本身被攻破。无需私聊领取另一份校验文件。
已有用户可与此前保存的签名指纹核对；发现变化时停止安装。

- 安装包：\`${kitName}\`
- 完整 Kit SHA-256：\`${kitDigest}\`
- Ed25519 签名公钥指纹：\`${fingerprint}\`

## 先校验，再解压

在安装包所在目录执行下面整段命令。它只使用 macOS 系统工具，校验失败或文件缺失时退出，
不会解压或运行包内脚本。校验通过后才创建一个新目录并解压。

\`\`\`bash
(
  set -euo pipefail
  kit='${kitName}'
  expected='${kitDigest}'
  if [ ! -f "$kit" ]; then
    printf '%s\\n' '安装包不存在，请从官方发布页下载完整 Kit。' >&2
    exit 1
  fi
  actual=$(/usr/bin/shasum -a 256 "$kit" | /usr/bin/awk '{print $1}')
  if [ "$actual" != "$expected" ]; then
    printf '%s\\n' '校验失败，请停止安装并从官方发布页重新下载。' >&2
    exit 1
  fi
  extract_dir=$(/usr/bin/mktemp -d './claudian-remote-${version}.XXXXXX')
  /usr/bin/tar -xzf "$kit" -C "$extract_dir"
  printf '校验通过，已解压到 %s\\n' "$extract_dir"
)
\`\`\`

## 继续安装

让本地安装助手按新目录中的 \`CLAUDIAN_REMOTE_INSTALL.md\` 操作。
完整 Kit 校验不替代后续验证：安装入口仍必须核对固定公钥指纹、Ed25519 清单签名、
精确版本和各组件的 SHA-256。\`release/trust-root.json\` 中的可信指纹应与本页一致；
任何不匹配都应停止，不要修改清单、替换信任根或跳过验签。
`, { encoding: "utf8", mode: 0o644 });
  return path;
}

export function prepareInstallKit(distDirectory, { trustStore = null } = {}) {
  const dist = resolve(distDirectory);
  const repositoryRoot = resolve(import.meta.dirname, "../..");
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
  validateReleaseContract(manifest, {
    expectedTag: manifest.release_tag,
    pluginManifest: JSON.parse(readFileSync(join(repositoryRoot, "manifest.json"), "utf8")),
    versions: JSON.parse(readFileSync(join(repositoryRoot, "versions.json"), "utf8")),
    supportMatrix: JSON.parse(readFileSync(join(repositoryRoot, "release/support-matrix.json"), "utf8")),
    trustStore: trustStore
      ?? JSON.parse(readFileSync(join(repositoryRoot, "release/trust-root.json"), "utf8")),
    rootDir: repositoryRoot,
    assetDir: dist
  });
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
    const community = manifest.distribution_channel === "community";
    const output = join(dist, `claudian-remote-${community ? "kit" : "beta-kit"}-${manifest.release_version}.tar.gz`);
    execFileSync("sh", [join(import.meta.dirname, "deterministic-tar.sh"), root, output], {
      stdio: "pipe"
    });
    if (community) writePublicVerification(dist, manifest, output);
    else writeTrustedBootstrap(dist, manifest, output);
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
