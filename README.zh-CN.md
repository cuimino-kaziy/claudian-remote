# Claudian Remote

**中文** | [English](README.md)

**在手机的 Obsidian 里，继续 Mac 上的 Claudian 对话。**

离开电脑后，你可以在手机上发送任务、查看逐步生成的回复和执行记录，或者把照片与文件带进当前对话。模型调用、仓库读写和工具操作仍由 Mac 上的 Claudian 完成，沿用电脑端的权限设置。

[从零开始安装与连接](docs/getting-started.md) · [常见问题](docs/troubleshooting.md) · [本版更新](docs/release-notes-0.2.0.md)

> 当前版本：**0.2.0**。已在 [Obsidian 社区插件目录](https://community.obsidian.md/plugins/claudian-remote) 发布，点击 **Add to Obsidian** 安装。后台服务包见 [GitHub Releases](https://github.com/cuimino-kaziy/claudian-remote/releases/tag/0.2.0)。

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
| 安装材料 | 官方 GitHub Releases 发布的完整 Kit，以及公开的 [下载与校验说明](docs/install-verification-0.2.0.md) |

插件要求 Obsidian **1.12.3 或更新版本**，支持指定的 Claudian **2.0.4 / 2.2.6 / 2.2.7**；其中 Claudian **2.2.7 要求 Obsidian 1.13.0 或更新版本**。Claudian 本体可从 [官方 2.2.7 发布页](https://github.com/YishenTu/claudian/releases/tag/2.2.7) 获取，Remote 安装包不包含它。静态检查已确认该公开原版具备所需接口，尚未完成与 Remote 的端到端验收；不据此推定其他新版本兼容。已有可用且兼容的 Claudian 无需为本次测试更换。

上一版已在用户的 Mac / iPhone 环境验收；本版社区安装变更通过自动化验证，尚未完成新版本真机验收。iPad、Intel Mac 等其他组合仍需实机验证。每套安装目前绑定一个 Mac、一个仓库和一台移动设备。

## 选择连接方式

| 你的情况 | 选择 | 下一步 |
|---|---|---|
| 第一次使用，没有服务器 | **Tailscale（推荐）** | 按 [新手指南](docs/getting-started.md) 在 Mac 安装服务，再为手机配对 |
| 已有维护者部署好的服务器 | 已有服务器连接 | 向部署者取得 HTTPS 地址，确认 Mac 已绑定同一服务，按 [服务器指南](docs/self-host-vps.md) 连接 |
| 有一台空服务器，想从头部署 | 维护者手动部署 | 先阅读 [环境与部署步骤](docs/self-host-vps.md)；本版不提供服务器自动安装 |

Tailscale 的安装入口见 [官方网站](https://tailscale.com/download)。个人非商业用途可按其 Personal 计划使用，适用范围与费用以 [Tailscale 当前说明](https://tailscale.com/pricing) 为准。模型服务、可选同步服务及自建服务器的费用由各服务决定，Remote 不代付这些费用。

## 第一次使用的顺序

1. **先在 Mac 检查 Claudian。** 在目标仓库发送一句话，确认能够收到完整回复。
2. **安装并启用插件。** 从 [社区目录](https://community.obsidian.md/plugins/claudian-remote) 点击 **Add to Obsidian**，或在 Obsidian 社区插件中搜索 Claudian Remote。在 Mac 和手机的同一同步仓库中启用 0.2.0，先打开一次设置。
3. **配置 Mac 服务。** 让本地安装助手核验完整 Kit，再按包内手册配置后台服务。安装器只核验已启用的插件，不写入插件目录。首次安装等待手机配对时继续下一步。
4. **配对一次。** Mac 设置中点击“添加移动设备”；手机保存连接地址，再填写 8 位配对码。也可以在手机打开 Mac 生成的配对链接。
5. **完成安装核验与首次对话。** 手机配对后，让助手恢复原安装操作并完成核验；手机显示“已就绪”后发送测试消息，确认收到完整回复。

每一步的按钮位置、成功状态和异常分流都在 [安装与连接指南](docs/getting-started.md)。配对后会在手机本机记住设备身份，普通断线、重启和配套升级不需要重新配对。

## 应该下载哪个文件

插件和后台服务分开安装，版本需要匹配。

| 下载文件 | 用途 |
|---|---|
| `claudian-remote-kit-0.2.0.tar.gz` | Mac 后台服务的首次安装或升级；先安装并启用同版本插件 |
| `main.js`、`manifest.json`、`styles.css` | Obsidian 社区插件自动下载的三份资产；手动安装时放入仓库的 `.obsidian/plugins/claudian-remote/`，保留原 `data.json` |
| `claudian-remote-plugin-0.2.0.zip` | 同版插件便捷副本，不包含后台服务 |
| 其余组件归档、`release-manifest.json`、`SHA256SUMS` | 安装助手与维护者使用的配套组件和校验材料 |

从 [官方 GitHub Releases](https://github.com/cuimino-kaziy/claudian-remote/releases/tag/0.2.0) 下载，按 [下载与校验说明](docs/install-verification-0.2.0.md) 先验证再解压。不要用 GitHub 自动提供的“Source code”安装。

## 用起来之后

- **再次打开：** 保持 Mac 与连接服务在线，手机进入原仓库和远程页面，等待恢复连接。
- **升级：** 通过 Obsidian 更新两端插件，再用同版本 Kit 更新 Mac 后台服务；原配对默认保留。升级过程中版本暂不一致会进入只读，配套更新完成后恢复。
- **连接异常：** 点顶部状态进入“连接详情”，先看原因，再参考 [常见问题与排查](docs/troubleshooting.md)。普通离线不用删配置或重新配对。
- **丢失手机或更换设备：** 从 Mac 的“设备”页撤销旧设备，再为新设备配对。

## 数据会经过哪里

Tailscale 路线连接到你自己的 Mac；已有服务器路线经过你管理的服务器。服务器管理员可以接触转发的内容，本版不宣称该路线端到端加密。模型请求仍按电脑端 Claudian 的配置发送给相应提供方。

配对凭据保存在手机本机，不随仓库同步。插件不主动向维护者发送聊天、附件或诊断信息；需要帮助时可手动复制不含聊天正文和密钥的诊断报告。完整边界见 [安全与隐私说明（英文）](docs/security.md)。

**仓库外文件访问：** Mac 插件会从用户的 `Library/Application Support/Claudian Remote/state/` 读取一次性连接交接文件，核验仓库与身份后覆盖并删除该文件；接收附件时读取 Companion 提供的临时文件、核验大小和摘要，再导入设置指定的仓库目录。配套服务安装器另行管理应用支持目录、启动项和 macOS 钥匙串。手机端不使用这些桌面文件接口，插件不会自行下载或安装后台服务。

## 文档入口

- [安装与连接指南](docs/getting-started.md)：从准备环境到首次对话、日常使用和升级。
- [下载与校验说明](docs/install-verification-0.2.0.md)：确认官方来源、核对完整包，再解压安装。
- [常见问题与故障排查](docs/troubleshooting.md)：费用、配对、同步、只读与连接异常。
- [服务器部署说明](docs/self-host-vps.md)：服务器环境、操作与配置字段。
- [本版发布说明](docs/release-notes-0.2.0.md)：改动、验收范围和下载包。
- [安装助手手册](CLAUDIAN_REMOTE_INSTALL.md)：经过可信校验后执行的详细安装契约。

<details>
<summary>维护者与开发者：兼容、许可、构建及发布约束</summary>

## 社区插件安装分工

`community` 发行由 Obsidian 管理插件资产。外部 Kit 只核验已安装、已启用且版本与摘要一致的插件，然后安装或升级后台服务。后台回退和卸载不替换、删除社区插件；需要移除插件时在 Obsidian 操作。旧 beta 安装仍可升级，但不能混用新旧组件。

## 兼容性与发布约束

- 支持的 Claudian 版本：**2.0.4、2.2.6 和 2.2.7**（优先使用 **2.2.6**）。其他版本必须保持只读，但仍可检查、诊断、回退和卸载。
- Claudian 2.2.6 和 2.2.7 仅在当前模型提供方支持时启用即时引导（steer）。不支持 steer 时，Claude 仍可发送和排队消息。
- 插件 ID：`claudian-remote`。旧私有 ID `whale-agent-bridge` 仅作为迁移来源，不得与本插件共存。
- 发行来源：本版本官方 GitHub Release 的精确发行件。可变分支、开发目录、`curl | shell` 和服务器返回的命令均不可作为安装来源。
- 更新归属：`private_beta` 由外部生命周期管理器更新；插件从不覆盖自己的资产。`community` 发行的插件更新由 Obsidian 管理。
- 完整性：只有 Ed25519 清单签名、固定公钥指纹、资产 SHA-256 和依赖锁 SHA-256 全部通过验证，发行件才可被接受。

本仓库不包含生产凭据、本地配置、设备状态、日志、数据库、真实仓库路径或恢复数据。示例值刻意设置为不可直接使用。

## 设备本机状态边界

由 Obsidian 同步的插件数据只包含白名单中的偏好设置：非秘密仓库身份、明确选择的连接方式，以及通知和触感选项。Relay 地址、凭据、设备身份、游标、近期历史缓存、配对状态和本地路径均保存在设备本机。公开配置只保存 Companion 凭据的引用；实际凭据从 macOS 登录钥匙串读取，仅在内存中解析使用。

iPhone / iPad 缓存是有容量限制的纯文本副本，方便查看近期内容。离线模式只读，不保留发送队列，也不保存附件二进制内容；清理缓存或撤销设备时会移除该副本。这种分离避免 Obsidian Sync 和 iCloud 在设备之间复制访问权限，但不构成硬件安全边界：同一移动端沙盒中的恶意 Obsidian 插件，或已被入侵的手机，仍可能访问网页存储。本版将这部分剩余风险限制在一台可撤销的移动设备内；设备丢失或被入侵后必须立即撤销。

## 许可证与外部服务

插件、Mac Companion 和生命周期管理／打包代码采用 MIT 许可证。`gateway/relay/` 下的自托管 Relay 采用 AGPL-3.0-only，详见该目录的许可证。

本版首次下载以官方 GitHub 仓库为信任来源。解压前先用系统校验工具核对精确 Kit，之后仍须执行原有 Ed25519 签名和固定指纹检查。这不属于独立渠道验证。用户按所选模式使用 Tailscale 或自有服务器。服务器终止 TLS 连接，可以读取 Relay 明文；本版不宣称端到端加密。

连接方式的安全边界与具体恢复限制见 [安全说明（英文）](docs/security.md)；自有服务器的受支持部署范围见 [服务器部署说明](docs/self-host-vps.md)。

## 开发与发布检查

源码边界检查会拒绝本地状态、疑似凭据和个人 Mac 路径。如需同时排除自己的部署标识，请在运行检查前将 `CLAUDIAN_PRIVATE_SOURCE_IDENTIFIERS` 设置为按行分隔的列表。将该列表保存在仓库外，不要把真实部署名称写入扫描器代码或测试样例。发布前还应使用专门的秘密扫描工具，检查 Git 历史和最终发行归档。

```sh
npm ci --ignore-scripts
npm run verify
python3.12 -m pytest gateway/tests -q
```

发布元数据位于 `release/`。维护者配置有效签名密钥，并固定其公钥指纹用于生命周期核验之前，发布流程保持关闭；仓库不保存签名私钥。

维护者可以使用现有 macOS 钥匙串条目在本机签名，再核验并上传这些精确的签名发行件。GitHub Actions 始终验证并构建带标签的发行版；只有为 CI 签名配置了 `CLAUDIAN_RELEASE_KEY_FINGERPRINT`，才执行签名和发布步骤。

生命周期管理发行件包含 Agent 手册、可执行入口、Python 包和逐文件内容锁。macOS arm64 与 x86_64 的 CPython / uv 资产在签名发布契约中固定到不可变的上游发行 URL，以及 GitHub 发布的 SHA-256 摘要。其余维护者检查和真机发布验收要求见 [Beta 检查清单](docs/beta-checklist.md)。

</details>
