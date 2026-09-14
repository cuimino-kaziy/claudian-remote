# Claudian Remote 0.2.0-beta.6.7

GitHub 公开测试版。Remote 公测本身免费，模型、VPS 及可选同步服务等外部费用另计。现有 Mac / iPhone 使用环境已由用户验收；尚未上架 Obsidian 插件市场。

Claudian Remote 让你在手机 Obsidian 中继续 Mac 上的 Claudian 对话，查看实时回复与执行记录，并发送照片或文件。模型、工具与仓库操作仍由 Mac 执行，Mac 需要保持开机、登录和唤醒。

**第一次使用：** 先读 [项目介绍](../README.md)，再按 [安装与连接指南](getting-started.md) 准备环境、安装后台服务并配对手机。已经安装的用户可直接查看 [常见问题与升级排查](troubleshooting.md)。

## 本版变化

- 手机输入栏随 Obsidian 页面布局调整，保留 Claudian 配色、正文排版和 Obsidian 底部导航。
- 历史对话提供搜索、归档与设置快捷入口；连接帮助采用分组和折叠说明，补充 Tailscale 与 VPS 的环境、步骤和字段来源。
- 首次配对输入短码后自动连接，无需再次到 Mac 批准；已配对设备在断网、重启和普通配套升级后保留身份。
- 修复 Claudian 能力变化后连接状态未及时刷新，以及 iCloud 目录备份卡住和中断更新无法继续的问题。

## 下载与升级

发布完成后，从 [官方 GitHub Releases](https://github.com/cuimino-kaziy/claudian-remote/releases) 获取文件。首次安装和测试版升级使用 **`claudian-remote-recovery-kit-0.2.0-beta.6.7.tar.gz`**，这是本次发行唯一的完整安装包，包含修正版安装器和配套 Mac 服务。

Kit SHA-256：`14eb15669db2ccbd01023702ab6ea6a6ec140c7c168049257bcfc2859b933cd4`

按公开的 [下载与校验说明](install-verification-0.2.0-beta.6.7.md)，先确认官方 GitHub 仓库 `cuimino-kaziy/claudian-remote` 与精确版本，用系统 `shasum` 核对完整 Kit 的官方 SHA-256，再解压并按安装手册操作。官方 GitHub 是下载信任起点，无需私聊领取材料，不把这一步称为独立渠道验证。Kit 内手册中的通用 `beta-kit` 名称在本次发行对应上述 `recovery-kit`；不使用此前单独交付的同版本旧 Kit，也不使用 GitHub 自动生成的 Source code 安装。

插件 ZIP 和 `main.js`、`manifest.json`、`styles.css` 是同一签名插件归档的便捷副本，不包含 Mac 后台服务。测试版更新仍通过完整 Kit 配套进行，默认保留已有配对；手机需等待仓库同步并重新加载插件。

已签名包与手册中的 `private_beta`／“内测”是既有安装器通道名称，不表示需要邀请。旧手册中私发或独立渠道校验说明的要求，以本次 [公测补充说明](install-verification-0.2.0-beta.6.7.md) 为准；其余安装与核验步骤、原 Ed25519 签名、固定指纹、通道值及更新器保持不变。

## 运行范围

- Mac 需要保持开机、登录和唤醒，安装 Obsidian 与受支持的 Claudian 2.0.4、2.2.6 或 2.2.7；Claudian 2.2.7 要求 Obsidian 1.13.0 或更新版本。
- Claudian 本体可从 [官方 2.2.7 发布页](https://github.com/YishenTu/claudian/releases/tag/2.2.7) 获取。静态检查已确认该公开原版具备所需接口，尚未完成与 Remote 的端到端验收；不推定任意新版本兼容，已有可用的兼容版本无需更换。
- 自动安装使用私有 Tailscale 连接。现有自建 VPS 可按 [部署说明](self-host-vps.md) 管理，本版不提供 VPS 自动部署。
- 每套安装绑定一个 Mac、一个仓库和一台移动设备。立即插话取决于当前模型提供方支持。

## 验证与发布范围

自动化验证：286 项 JavaScript、718 项 Python 测试通过；其中发布契约检查 20 项通过。安装恢复、已安装文件摘要、Mac 连接与配对保留已实测，用户于 2026-09-14 确认本版使用正常。

这一结论仅覆盖现有测试环境。Intel Mac、iPad、其他同步方式、干净安装及独立试用者矩阵仍按 [测试清单](beta-checklist.md) 记录，不宣称全部完成。公开测试的发行状态及文件以 [官方发布页](https://github.com/cuimino-kaziy/claudian-remote/releases/tag/v0.2.0-beta.6.7) 为准。

## 后续版本规则

沿用 `0.2.0` 版本线：本次保留已验收的 `0.2.0-beta.6.7`，下一次测试版简化为 `0.2.0-beta.7`，完成正式版验收后使用 `0.2.0`。随后兼容性问题修复使用 `0.2.1`，增加功能使用 `0.3.0`。插件版本、配套服务、签名清单与 Git tag 必须一致，不为同一安装包另起一套展示版本。
