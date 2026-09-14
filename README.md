# Claudian Remote

**在手机的 Obsidian 里，继续 Mac 上的 Claudian 对话。**

离开电脑后，你可以在手机上发送任务、查看逐步生成的回复和执行记录，或者把照片与文件带进当前对话。模型调用、仓库读写和工具操作仍由 Mac 上的 Claudian 完成，沿用电脑端的权限设置。

[从零开始安装与连接](docs/getting-started.md) · [常见问题](docs/troubleshooting.md) · [本版更新](docs/release-notes-0.2.0-beta.6.7.md)

> 当前版本：**0.2.0-beta.6.7 · 公开测试版**。从 [官方 GitHub Releases](https://github.com/cuimino-kaziy/claudian-remote/releases/tag/v0.2.0-beta.6.7) 免费下载；尚未上架 Obsidian 插件市场。

## 可以用它做什么

| 你想做的事 | 在手机上如何使用 |
|---|---|
| 继续电脑上的任务 | 打开同一仓库的远程页面，在当前对话中继续输入 |
| 查看任务进度 | 阅读实时回复、Markdown 内容和执行记录，处理当前任务的权限请求 |
| 发送手机上的材料 | 点输入栏旁的 `+` 选择照片或文件，等待附件就绪后发送 |
| 找回之前的对话 | 打开历史栏，按标题搜索、切换对话，或归档暂时不用的对话 |
| 管理连接 | 点历史栏底部“设置”，或点顶部连接状态查看详情 |

Claudian 是电脑上实际执行任务的插件；**Claudian Remote 是它的远程入口**。Remote 不附带模型服务，也不提供仓库文件同步。开始前，你的 Mac 上需要有能够正常对话的受支持 Claudian，两端也需要打开同一个已同步的 Obsidian 仓库。

## 它如何连接

```mermaid
flowchart LR
  Phone[手机 Obsidian / Claudian Remote] <-->|Tailscale 私有连接| Service[Mac 上的连接服务]
  Service <--> Claudian[Mac 上的 Claudian]
  Claudian <--> Vault[同一个 Obsidian 仓库]
```

你会在设置里看到“服务器地址”，有时也叫 **Relay 地址**。它表示手机该连接哪个服务。安装完成后直接复制 Mac 显示的完整 `https://` 地址即可，不需要自己推算 IP、端口或填写模型密钥。

**Mac 需要保持开机、登录和唤醒。** 屏幕熄灭可以继续使用；Mac 真正睡眠、关机或退出 Obsidian 后，手机无法让它继续执行任务。

## 开始前准备什么

| 位置 | 需要准备 |
|---|---|
| Mac | Obsidian、可正常使用的 Claudian，以及本版配套的 Remote 后台服务 |
| 手机 | Obsidian、与 Mac 相同且已同步的仓库、Claudian Remote 插件 |
| 连接网络 | 默认在 Mac 和手机安装 Tailscale，登录同一账号并打开连接 |
| 安装材料 | 官方 GitHub Releases 发布的完整 Kit，以及公开的 [下载与校验说明](docs/install-verification-0.2.0-beta.6.7.md) |

插件要求 Obsidian **1.12.3 或更新版本**，支持指定的 Claudian **2.0.4 / 2.2.6 / 2.2.7**；其中 Claudian **2.2.7 要求 Obsidian 1.13.0 或更新版本**。Claudian 本体可从 [官方 2.2.7 发布页](https://github.com/YishenTu/claudian/releases/tag/2.2.7) 获取，Remote 安装包不包含它。静态检查已确认该公开原版具备所需接口，尚未完成与 Remote 的端到端验收；不据此推定其他新版本兼容。已有可用且兼容的 Claudian 无需为本次测试更换。

现有 Mac / iPhone 环境已通过用户验收；iPad、Intel Mac 等其他组合仍需完成对应实机验证。每套安装目前绑定一个 Mac、一个仓库和一台移动设备。

## 选择连接方式

| 你的情况 | 选择 | 下一步 |
|---|---|---|
| 第一次使用，没有服务器 | **Tailscale（推荐）** | 按 [新手指南](docs/getting-started.md) 在 Mac 安装服务，再为手机配对 |
| 已有维护者部署好的 VPS | 已有 VPS 连接 | 向部署者取得 HTTPS 地址，确认 Mac 已绑定同一服务，按 [VPS 指南](docs/self-host-vps.md) 连接 |
| 有一台空服务器，想从头部署 | 维护者手动部署 | 先阅读 [环境与部署步骤](docs/self-host-vps.md)；本版不提供 VPS 自动安装 |

**Claudian Remote 公开测试本身免费。** Tailscale 的安装入口见 [官方网站](https://tailscale.com/download)。个人非商业用途可按其 Personal 计划使用，适用范围与费用以 [Tailscale 当前说明](https://tailscale.com/pricing) 为准。模型服务、可选同步服务及自建 VPS 的费用由各服务决定，Remote 不代付这些费用。

## 第一次使用的顺序

1. **先在 Mac 检查 Claudian。** 在目标仓库发送一句话，确认能够收到完整回复。
2. **配置 Mac 服务。** 让本地安装助手核验完整 Kit，再按包内手册配置后台服务。首次安装会等待手机配对，继续下面的步骤即可。
3. **让手机收到插件。** 等待同一仓库的插件文件同步，在手机启用或重新加载 Claudian Remote。
4. **配对一次。** Mac 设置中点击“添加移动设备”；手机保存连接地址，再填写 8 位配对码。也可以在手机打开 Mac 生成的配对链接。
5. **完成安装核验与首次对话。** 手机配对后，让助手恢复原安装操作并完成核验；手机显示“已就绪”后发送测试消息，确认收到完整回复。

每一步的按钮位置、成功状态和异常分流都在 [安装与连接指南](docs/getting-started.md)。配对后会在手机本机记住设备身份，普通断线、重启和配套升级不需要重新配对。

## 应该下载哪个文件

本版的完整包只有 **`claudian-remote-recovery-kit-0.2.0-beta.6.7.tar.gz`**。它包含修正后的安装器、插件和 Mac 服务；名称中的 `recovery` 不表示只供修复使用，新安装同样使用它。

| 下载文件 | 用途 |
|---|---|
| `claudian-remote-recovery-kit-0.2.0-beta.6.7.tar.gz` | **首次安装与测试版升级使用这个完整包** |
| `claudian-remote-plugin-0.2.0-beta.6.7.zip` | 插件便捷副本，不含 Mac 后台服务 |
| `main.js`、`manifest.json`、`styles.css` | 同版插件的独立文件，供维护者分发 |
| 其余组件归档、`release-manifest.json`、`SHA256SUMS` | 安装助手与维护者使用的配套组件和校验材料 |

从 [官方 GitHub Releases](https://github.com/cuimino-kaziy/claudian-remote/releases/tag/v0.2.0-beta.6.7) 下载完整包，按 [下载与校验说明](docs/install-verification-0.2.0-beta.6.7.md) 先验证再解压，无需私聊领取材料。不要用 GitHub 自动提供的“Source code”安装，也不要混用旧的同版本完整包。

## 用起来之后

- **再次打开：** 保持 Mac 与连接服务在线，手机进入原仓库和远程页面，等待恢复连接。
- **升级：** 通过下一版完整 Kit 配套更新，等待手机同步后重新加载插件；原配对默认保留。
- **连接异常：** 点顶部状态进入“连接详情”，先看原因，再参考 [常见问题与排查](docs/troubleshooting.md)。普通离线不用删配置或重新配对。
- **丢失手机或更换设备：** 从 Mac 的“设备”页撤销旧设备，再为新设备配对。

## 数据会经过哪里

Tailscale 路线连接到你自己的 Mac；已有 VPS 路线经过你管理的服务器。VPS 管理者可以接触转发的内容，本版不宣称该路线端到端加密。模型请求仍按电脑端 Claudian 的配置发送给相应提供方。

配对凭据保存在手机本机，不随仓库同步。插件不主动向维护者发送聊天、附件或诊断信息；需要帮助时可手动复制不含聊天正文和密钥的诊断报告。完整边界见 [安全与隐私说明](docs/security.md)。

## 文档入口

- [安装与连接指南](docs/getting-started.md)：从准备环境到首次对话、日常使用和升级。
- [下载与校验说明](docs/install-verification-0.2.0-beta.6.7.md)：确认官方来源、核对完整包，再解压安装。
- [常见问题与故障排查](docs/troubleshooting.md)：费用、配对、同步、只读与连接异常。
- [VPS 部署说明](docs/self-host-vps.md)：服务器环境、操作与配置字段。
- [本版发布说明](docs/release-notes-0.2.0-beta.6.7.md)：改动、验收范围和下载包。
- [安装助手手册](CLAUDIAN_REMOTE_INSTALL.md)：经过可信校验后执行的详细安装契约。

<details>
<summary>维护者与开发者：兼容、许可、构建及发布约束</summary>

## 公开测试的既有安装通道

已签名安装包与包内手册中的 `private_beta`／“内测”沿用既有安装器通道名称，不表示需要邀请。旧手册中私发或独立渠道校验说明的要求，以本次 [公测下载与校验补充说明](docs/install-verification-0.2.0-beta.6.7.md) 为准；其余安装与核验步骤不变，原 Ed25519 签名、固定指纹及更新器均保持不变。

## Beta contract

- Supported Claudian versions: **2.0.4, 2.2.6, and 2.2.7** (preferred: **2.2.6**). Other versions must remain
  read-only; inspection, diagnostics, rollback, and removal stay available.
- On Claudian 2.2.6 and 2.2.7, immediate steer is enabled only when the active provider
  supports it. Claude can still send and queue messages without steer.
- Plugin ID: `claudian-remote`. The old private ID `whale-agent-bridge` is only
  a migration source and must not coexist with this plugin.
- Distribution: exact official GitHub Release assets for the public beta only. Mutable branches,
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
The official GitHub repository is the initial download-trust source for this
public beta. Verify the exact Kit with the system checksum tool before
extracting it, then retain the existing Ed25519 and pinned-fingerprint checks.
This is not independent-channel verification. Depending on the selected mode, users operate Tailscale or a
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
maintainer configures a real signing key and pins its public fingerprint for
lifecycle verification; no signing secret is stored here.

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

</details>
