---
artifact_contract: "ce-handoff/v1"
created_at: "2026-08-29T17:40:22Z"
title: "Claudian Remote private-repository bootstrap and Phase 1 adaptation handoff"
summary: "Private-repository bootstrap handoff for the preserved Beta 4 candidate baseline, Beta 5 U1-U6 engineering checkpoint, unresolved P1 security work, and the recommended first adaptation slice."
keywords: ["claudian-remote", "beta5", "phase1", "security", "tailscale", "ao-handoff"]
cwd: "."
resume_focus: "Verify the pushed main identity, then implement and independently verify the five-P1 bounded remediation slice before completing the full Beta 5 U6 contract; do not advance to U7-U9 or UI polish early."
repository: "cuimino-kaziy/claudian-remote"
repo_root_sha: "6acedc69af398fd80265791064e03169ff989f83"
branch: "main"
captured_code_head: "f80101be196c76ce5dc635edc854c447e295c54c"
---

# Claudian Remote 项目交接

## 交接目的

用户已授权将当前项目首次推送到私有 GitHub 空仓库
`cuimino-kaziy/claudian-remote`，并准备进入第一阶段适配开发。本文件用来让新的 AO 架构或开发
Agent 在不依赖聊天历史的情况下，识别真实版本、当前成熟度、安全边界和下一个有限开发切片。

本交接是上下文入口，不替代代码、测试、发行检查表或用户当前授权。接手 Agent 必须先读、再现场
验证，不得仅根据本文件执行不可逆操作。

## 接手时的阅读顺序

1. `README.md`：产品边界、私有内测约束、本地状态与同步状态的分离。
2. `docs/security.md:1-84`：网络、凭据、配对、恢复数据和隐私模型；其中 `31-44` 是 U6 设备
   凭据、旋转和撤销语义。
3. `CLAUDIAN_REMOTE_INSTALL.md:1-190`：安装 Agent 的当前操作入口与 `local_tailscale` 边界。
4. `docs/beta-checklist.md:1-72`：发行权威；人工阻断项和真机矩阵没有全部通过时，不得宣称已发布。
5. `docs/beta-acceptance-record-beta.4.md`：只是 Beta 4 候选基线与历史证据，不是 Beta 5 验收结论。
6. 同一机器工作区中的外部计划
   `../docs/plans/2026-07-22-001-feat-claudian-remote-beta5-fresh-install-legacy-upgrade-plan.md`：
   Beta 5 U1-U9 权威计划。该文件不在当前 Git 仓库内；跨机交接时必须另行传递或迁入仓库。

## 用户已确认的产品决策

- 当前只支持 macOS + iPhone/iPad，一台 Mac、一台移动设备、一个 Vault。
- 默认方案是免费 `local_tailscale`。用户自有 VPS 可作为后续高级方案，但不得在当前版本宣称
  `remote_vps` 自动部署已发布。
- Mac 必须开机、已登录并保持唤醒；屏幕可以熄灭。远程唤醒、关机后启动与自主拉起深度睡眠的 Mac
  仍属延后范围。
- 手机端与 Mac 端使用同一 Vault 与 Claudian 环境；移动端不建立另一套 Agent。
- 离线时禁止发送，不保留待上线自动执行的消息队列。
- 保留电脑端 Claudian 默认权限边界；手机不获得更高权限。
- 功能闭环优先于 UI 精修。第一轮先做功能、安全和安装验证；手机 UI 修补可在后续聚焦进行。
- 仓库先保持私有。公开发布、托管订阅服务、付费模式与大规模用户容量不在当前切片内。

## 截图时的 Git 与版本状态

- 交接捕获分支：`main`（从 `handoff/beta5-u6-checkpoint-20260830` 检查点新建）。
- 捕获基线 HEAD：`f80101be196c76ce5dc635edc854c447e295c54c`。
- 根提交：`6acedc69af398fd80265791064e03169ff989f83`。
- 当前版本元数据仍是 `0.2.0-beta.4`：`package.json`、`manifest.json` 和
  `release/support-matrix.json` 一致。
- `f80101b` 的提交说明是：保存 Beta 4 基线与 Beta 5 U1-U6 工作；U6 仍为 `Not Ready`；
  U7-U9 有意未正式开始。
- 在创建本文件之前，工作树干净：238 个跟踪文件，无 staged、unstaged 或非忽略 untracked 文件。
- 上述 `captured_code_head` 是交接文档之前的代码快照，不包含本文件。包含本文件的交接提交应在接手时用
  `git log -1 --format=%H -- docs/handoffs/2026-08-30-claudian-remote-phase1-adaptation.md` 独立解析，并与远端 `main` 现场核对。
- `dist/`、`main.js`、`.venv/`、`node_modules/`、测试缓存和本地状态均被忽略，不是首次推送内容。
- 远程仓库：`https://github.com/cuimino-kaziy/claudian-remote.git`，私有且在首推前无远程分支。

## 当前成熟度

| 部分 | 当前结论 | 权威证据 |
|---|---|---|
| Beta 4 候选基线 | 已保存自动化与打包证据；真机和 canary 验收仍未被当前跟踪证据证明 | `docs/beta-acceptance-record-beta.4.md` 与 `docs/beta-checklist.md` |
| Beta 5 U1-U5 | 工程实现已进入检查点，不等于独立验收 | `f80101b` 及外部 Beta 5 计划 |
| Beta 5 U6 | `Not Ready`；配对、撤销和共享收尾存在已知 P1 | `docs/security.md:31-44` 与本文下方安全审计 |
| Beta 5 U7 | 未作为 Beta 5 单元完成和验收；当前手册可作历史输入 | `CLAUDIAN_REMOTE_INSTALL.md` 与 Beta 5 计划 U7 |
| Beta 5 U8 | 未开始发行绑定；版本仍是 beta.4 | 版本元数据与 Beta 5 计划 U8 |
| Beta 5 U9 | 未完成打包 Kit 真机矩阵 | `docs/beta-checklist.md:23-65` 与 Beta 5 计划 U9 |

## 已完成的推送前安全审计

已检查当前跟踪树、全部可达 Git 历史和当时的本地发行包。没有发现可识别的真实 API Key、私钥或生产
Token。当时的验证包括：

- `npm run check:source` 通过。
- Node release contract/tooling 测试 20 项通过。
- 安全相关 Python 测试 33 项通过。
- 没有安装 `gitleaks`、`trufflehog` 或 `detect-secrets`；因此上述结论是项目自带边界检查加高置信模式扫描，
  不是专用扫描器全覆盖声明。

此审计允许首次推送到当前私有空仓库，但不允许立即打标签或发布。已验证的遗留问题：

1. **P1 - 撤销竞争窗口**：`gateway/relay/app.py:864` 附近的命令路由与设备撤销没有共享原子授权门禁，
   已撤销设备可能派发已在途命令。
2. **P1 - 远程媒体预加载**：`src/mobile/markdown-renderer.js:73` 附近在 DOM 事后清理前可能已发起远程媒体请求。
3. **P1 - 所有权回执未验证**：`installer/claudian_remote_lifecycle/transaction.py:924` 附近把“回执文件存在”当成
   安装 ready 的一部分，未在 ready 路径重用完整绑定和摘要验证。
4. **P1 - Mac 附件下载无读超时**：`gateway/mac_companion/upload_receiver.py:98` 使用 `timeout=None`，并在网络流期间
   持有全局锁，停滞流可阻塞清理和后续下载。
5. **P1 - 手机附件请求无截止时间**：`src/mobile/attachment-controller.js:94` 的 create/chunk/finalize/delete 路径
   没有独立超时，一个永不结束的请求会占用唯一附件控制流。

本交接文件完成后又运行了首推验证：`npm run verify` 通过（195 项 Node 测试），Gateway 套件
138 项通过，Installer 套件 409 项通过。构建仍会报告 `src/desktop/bridge-bootstrap.js:8` 的既有
direct-`eval` 警告；这是已知非阻断加固项，不是本次文档产生的回归。

发行签名的长期密钥目前尚未配置，因此不是本次首推泄漏项。配置真实签名密钥之前，必须使用
来自可信不可变引用的签名代码或独立签名器，并对标签/引用创建实施可强制的授权规则。仅使用受保护
Environment 不足以阻止标签中可控脚本获取密钥；这是 U8 配置密钥前的显式阻断项。

### 仍需现场处理的隐私与运行时风险

- 22 个旧提交的作者或提交者元数据包含一个本地设备作者身份。它不是密钥，但会在私有仓库暴露旧设备标识。
  用户已授权当前私有首推，
  本交接不自动重写历史。
- 本次没有读取 macOS Keychain 或旧 Obsidian 设置。源码仓库安全不等于已部署的旧 token 已完成撤销。

## 第一阶段适配开发的建议 Task Contract

以下是当前协调 Agent 基于审计和 Beta 5 依赖关系提出的建议切片。用户已确认“开始第一阶段适配开发”，
但接手 Agent 开始修改前仍应用当前对话向用户简短确认本切片，不得将它扩展成 UI 重构或发行项目。

### 目标

在不改变现有产品范围和网络拓扑的前提下，关闭上述 5 个 P1，完成一个有界修复切片，为 Beta 5 U6 的完整验证
补齐必要输入。该切片本身不构成 U6 完成或验收。

### 允许的实现范围

- 设备撤销与 HTTP/WebSocket 命令派发共享一个可证明的授权原子边界。
- 在 Markdown 交给 Obsidian 渲染器之前中和所有可发起请求的媒体标记，DOM 事后清理保留为第二道防线。
- ready 状态复用卸载/所有权验证中已有的回执 schema、operation/plan 绑定、路径白名单与文件摘要检查。
- Mac 下载使用可配置的 connect/read-idle 超时，并避免在整个网络流期间持有 receiver 全局锁。
- 移动附件 create/chunk/finalize/delete 各路径使用有界超时，并保留用户取消 `AbortSignal` 语义。
- 增加竞争、停滞流、渲染时零请求、损坏回执和超时后恢复的回归测试。

### 不在本切片内

- 不进行手机 UI 重构、动画精修或新设计系统。
- 不实现 `remote_vps`、`local_lan`、自动模式切换、多设备或多 Vault。
- 不实现远程唤醒、睡眠后执行、Windows 或 Android。
- 不提前将版本升到 beta.5，不打标签，不配置真实签名密钥，不创建 GitHub Release。
- 不绕过 Beta 4/Beta 5 的旧凭据撤销门禁，不直接删除 checkpoint、旧插件或 token。

### 验收证据

- 受控并发测试证明：撤销完成后，既有 HTTP 与 WebSocket 客户端均无法派发命令。
- 渲染器测试拦截网络，证明恶意 Markdown 在渲染期间发起 0 个远程请求。
- 损坏、错位绑定或摘要不匹配的 ownership receipt 必须让 ready 失败关闭。
- header 成功后停滞的 Mac 下载和永不返回的移动附件请求必须在明确上限内结束，清理和后续上传/下载可继续。
- `npm run verify`、Gateway 测试和 Installer 测试全部通过。
- 独立 Reviewer 以实际分支/HEAD 重新验证上述五项，不接受实现 Agent 的自评作为完成证据。

### 停止条件

- 任一修复需要改变现有网络拓扑、产品权限或凭据格式时，停止并请用户决定。
- 任一修复需要读取真实凭据、Keychain 或旧 Obsidian 私有配置时，停止并单独申请授权。
- 出现与捕获 HEAD 不可解释的分支、计划或已部署运行时漂移时，先停止。
- 不能在受控测试中复现相应缺陷时，不盲目修复；先更新审计结论。

## 未完成工作与后续顺序

1. 先完成上述第一阶段五项 P1 有界修复切片。
2. 修复切片通过独立审查后，仍需回到外部 Beta 5 计划完成 U6 全量合同：三条 journey tail、签名的
   preserve/rotate 配对政策、中断/回滚、allowlisted migration、插件互斥、重新配对、角色/Vault 检查和防重放。
3. U6 全量证据通过后，再依照 Beta 5 计划进入 U7：使安装手册和 typed lifecycle action 形成可由新 Agent
   自主讲解、有界停顿和可恢复的闭环。
4. 然后进入 U8：版本升级、签名资产绑定与实际 Beta 5 Kit 封装。
5. 最后进入 U9：干净 Mac、Beta 4 直升、旧 `whale-agent-bridge` 升级、重启/断网/蜂窝网络和安全负向矩阵。
6. U9 权威证据齐全后，才决定是否给 Beta 5 打标签和发布私有 prerelease。

## 已放弃或不得重试的方向

- 不因为仓库是私有就跳过 secret scan、权限、日志或运行时凭据检查。
- 不把本地 token 删除、旧 Relay 不可达、普通 `200/401/404/410` 或用户口头确认当成权威撤销证据。
- 不直接删除 lifecycle checkpoint 来跳过 `recovery_required`。
- 不将 GitHub 发行包与可信 Bootstrap 放在同一未验证信道中，也不使用可变分支或 `curl | shell` 作为安装源。
- 不在本阶段再次改造手机键盘动画、输入框定位或浮动层逻辑；这些需要独立的移动端真机交互任务。

## 交接时的连续性警告

- 机器本地 Beta 5 计划不在 GitHub 仓库中。新 Agent 如果不能访问当前 Mac，必须先让用户提供计划，不得自行重构
  U7-U9 范围。
- 完整安全审计报告的原始运行产物位于系统管理的临时存储中，不是持久权威；本交接已保留所有当前有效结论。
- 本地 `dist/` 内有历史 Beta Kit 与解压残留，全部被 Git 忽略。它们不是 Beta 5 发行证据，不得为了“方便”强制加入 Git。
- 首次推送只是建立私有源码基线，不表示 Beta 5 已发布、已公开或已通过 U9。

## 接手 Agent 的建议起手式

1. 只读核对 `git status --short --branch`、`git rev-parse HEAD`、`git remote -v` 和 GitHub 私有性。
2. 读取本文件与上述六个权威入口，向用户报告一次当前身份和第一阶段 Task Contract。
3. 用当前对话请用户确认开始第一阶段代码修改；交接本身不扩大写入授权。
4. 确认后先为五项 P1 建立可失败的回归测试，再实现最小修复，然后运行全套验证。
5. 实现与 Reviewer 必须分离；独立 Reviewer 核对实际分支/HEAD，不以对话摘要作为候选身份。
