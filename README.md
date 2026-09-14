# Claudian Remote

Claudian Remote is an internal beta for using one supported Mac Claudian
installation from one iPhone or iPad through an Obsidian plugin, Mac Companion,
and a user-controlled Relay.

## 下载和首次连接

Claudian Remote 把 Mac 上的 Claudian 延伸到手机：手机负责输入和阅读，Mac 负责运行模型、工具和仓库。Mac 需要保持开机、登录和唤醒。

1. 从 [GitHub Releases](https://github.com/cuimino-kaziy/claudian-remote/releases) 打开维护者指定的版本，下载 `claudian-remote-beta-kit-<version>.tar.gz`。首次安装需要完整 Kit；GitHub 自动生成的 “Source code” 不是安装包。内测版本可能需要受邀 GitHub 账号。
2. 在 Mac 先按维护者通过独立可信渠道提供的校验说明验证 Kit，成功后解压到新目录，再按包内 [安装手册](CLAUDIAN_REMOTE_INSTALL.md) 完成环境检查和后台服务安装。Mac 需要 Obsidian 1.12.3 或更新版本，以及受支持的 Claudian 2.0.4 / 2.2.6 / 2.2.7。单独下载插件不能代替 Mac 后台服务。
3. 在 iPhone / iPad 的同一个已同步仓库中启用 `Claudian Remote`，打开远程页面 → 历史栏底部的“设置”。首次使用先看“连接引导”。插件文件包含 `main.js`、`manifest.json` 和 `styles.css`，由内测安装流程交付到仓库的 `.obsidian/plugins/claudian-remote/`；手机需要重新加载并启用插件，配对凭据不会随仓库同步。
4. 新用户选择 **Tailscale**：两台设备安装 Tailscale 并登录同一账号。已有服务器的用户查看 [VPS 环境与连接说明](docs/self-host-vps.md)。当前安装器仅开放 Tailscale 自动部署；VPS 指已经完成部署和 Mac 配置的服务器。
5. 在 Mac 点击“添加移动设备”，在手机打开配对链接；或复制 Mac 的连接地址，保存后填写 8 位配对码。验证通过后会自动配对并连接，手机显示“已就绪”后即可使用。

**当前候选 `0.2.0-beta.6.7` 使用 `claudian-remote-recovery-kit-0.2.0-beta.6.7.tar.gz` 作为完整安装包。** 它包含修正后的安装器；此前仅在本机交付的同版本旧 Kit 不再用于分发。下载时以 [本版发布说明](docs/release-notes-0.2.0-beta.6.7.md) 和维护者独立提供的可信摘要为准。草稿不是已发布版本，实际下载以发布后的 Release 附件为准。

| 文件 | 用途 |
|---|---|
| `claudian-remote-beta-kit-<version>.tar.gz` | 首次安装和内测更新使用的完整签名 Kit，包含 Mac 后台服务和安装流程 |
| `claudian-remote-plugin-<version>.zip` | 插件便捷副本，解压后是 `claudian-remote/` 文件夹，包含三个插件文件和许可证；不包含 Mac 后台服务 |
| `main.js`、`manifest.json`、`styles.css` | 同一版本的独立插件文件，供插件分发与后续 Obsidian 市场使用 |
| `claudian-remote-plugin-<version>.tar.gz`、`release-manifest.json` | 签名发行合同中的插件归档及验证清单 |

ZIP 和独立文件与签名插件归档中的内容一致，但不是独立签名的安装 Kit。当前内测仍由安装流程负责安装和更新，便捷副本不能绕过签名验证或 Mac 服务配置。

**连接服务器地址（Relay）是什么？** 它是手机找到 Mac 的入口，不是模型 API 地址或服务器登录地址。Tailscale 通常是 `https://你的Mac名称.你的网络.ts.net`；VPS 是部署者提供的 `https://relay.你的域名.com`。直接复制 Mac 上显示的完整地址即可，不需要手工填写令牌。

Claudian 2.2.7 自身要求 Obsidian 1.13.0 或更新版本。

## Obsidian 插件市场

当前是 GitHub 内测分发，尚未宣称已经上架。公开版本准备好后，维护者应发布稳定的 `x.y.z` 版本，把 `main.js`、`manifest.json`、`styles.css` 放到对应 GitHub Release，并通过 [Obsidian 社区目录提交入口](https://community.obsidian.md/) 提交。具体要求见 [官方插件发布说明](https://docs.obsidian.md/plugins/releasing/submit-plugin)。

市场版通过 Obsidian“第三方插件 → 浏览”安装和更新插件；Mac 后台服务仍需单独安装。插件内只提供下载、引导和状态入口，不在 Obsidian 内自行下载覆盖插件或安装外部程序，遵循 [开发者政策](https://docs.obsidian.md/community-directory/developer-policies)。

## Beta contract

- Supported Claudian versions: **2.0.4, 2.2.6, and 2.2.7** (preferred: **2.2.6**). Other versions must remain
  read-only; inspection, diagnostics, rollback, and removal stay available.
- On Claudian 2.2.6 and 2.2.7, immediate steer is enabled only when the active provider
  supports it. Claude can still send and queue messages without steer.
- Plugin ID: `claudian-remote`. The old private ID `whale-agent-bridge` is only
  a migration source and must not coexist with this plugin.
- Distribution: exact invited GitHub Release assets only. Mutable branches,
  development checkouts, `curl | shell`, and server-returned commands are not
  installation sources.
- Update owner: the external lifecycle manager for `private_beta`; the plugin
  never overwrites its own assets. A future `community` release delegates
  plugin updates to Obsidian.
- Integrity: a release is accepted only after its Ed25519 manifest signature,
  pinned-key fingerprint, asset SHA-256 values, and dependency-lock SHA-256
  values all verify.

This repository contains no production credentials, local configuration,
device state, logs, databases, Vault paths, or recovery data. Example values
are intentionally non-working.

## Device-local state boundary

Obsidian-synchronized plugin data is an allowlisted preference document: a
non-secret Vault identity, explicit connection mode, and notification/haptic
choices. Relay endpoints, credentials, device identity, cursors, recent-history
cache, pairing state, and local paths stay in device-local storage. Companion
credentials are referenced from public configuration and resolved from the
macOS login Keychain only in memory.

The iPhone/iPad cache is a bounded, text-only convenience copy. Offline mode is
read-only, keeps no send queue, and never stores attachment binaries. Purge and
device revocation remove it. This separation prevents Obsidian Sync and iCloud
from copying authority between devices, but it is not a hardware security
boundary: another malicious Obsidian plugin in the same mobile sandbox, or a
compromised phone, may still access web storage. The beta limits that residual
risk to one revocable mobile device and requires immediate revocation after
loss or compromise.

## Licenses and external services

The plugin, Mac Companion, and lifecycle/packaging code are MIT licensed. The
self-hosted Relay under `gateway/relay/` is AGPL-3.0-only; see its own license.
GitHub Releases is used only to authenticate invited downloads and is not the
integrity root. Depending on the selected mode, users operate Tailscale or a
user-owned VPS. A VPS terminates TLS and can read Relay plaintext; this beta
does not claim end-to-end encryption.

Connection-mode security and exact recovery limits are documented in
[`docs/security.md`](docs/security.md). The narrow user-owned VPS profile is in
[`docs/self-host-vps.md`](docs/self-host-vps.md).

## Development gates

The source-boundary check rejects local state, credential patterns, and personal
Mac paths. To also reject your deployment identifiers, set
`CLAUDIAN_PRIVATE_SOURCE_IDENTIFIERS` to a newline-separated list before running
the checks. Keep that list outside the repository; do not put real deployment
names in scanner code or test fixtures. Scan Git history and final release
archives with a dedicated secret scanner before publication.

```sh
npm ci --ignore-scripts
npm run verify
python3.12 -m pytest gateway/tests -q
```

Release metadata lives in `release/`. Publication remains fail-closed until a
maintainer configures a real signing key and pins its public fingerprint in the
trusted lifecycle bootstrap; no signing secret is stored here.

Maintainers may sign locally using the existing macOS Keychain entry, then
verify and upload the exact signed assets. GitHub Actions always verifies and
builds tagged releases; its signing and publishing steps run only when
`CLAUDIAN_RELEASE_KEY_FINGERPRINT` is configured for CI signing.

The lifecycle release asset includes the Agent guide, executable entrypoint,
Python package, and a per-file content lock. macOS arm64 and x86_64 CPython/uv
assets are pinned to immutable upstream release URLs and GitHub-published
SHA-256 digests in the signed release contract. See
[`docs/beta-checklist.md`](docs/beta-checklist.md) for the remaining maintainer
and real-device release gates.
