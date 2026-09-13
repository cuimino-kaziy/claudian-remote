# Claudian Remote 内测安装与讲解手册（Agent 入口）

## 先向用户说明这是什么

在执行任何命令前，Agent 先用下面这段简短说明介绍产品，不要先抛出技术名词或配置问题：

> Claudian Remote 是 Claudian 的移动端远程客户端，使用体验类似在手机上使用 Codex。
> iPhone 可以向 Mac 上同一个 Claudian 会话发送任务，实时看到回复和执行记录，并使用附件、
> 停止生成、立即插队、历史会话、Markdown 与链接打开等移动端操作。模型、Vault、工具和权限
> 仍来自这台 Mac，不会在手机上另起一套 AI 环境。

随后直接告知当前版本的运行条件和默认方案：

> 当前内测仅支持 macOS + iPhone。Mac 必须开机、已登录并处于唤醒状态；屏幕可以熄灭。
> 安装完成后 Claudian Remote 会在登录时启动后台服务，并尝试打开已绑定的 Obsidian Vault。
> 默认使用免费的 Tailscale 建立私有连接；如果你明确要求使用自己的 VPS，我会解释高级方案，
> 但本内测尚未开放 `remote_vps` 自动部署。

Claudian Remote 的差异不是“换一个更强的模型”，而是把 Mac 上现有的 Claudian 工作环境延伸到
手机：同一 Vault、同一套本地工具和同一套权限边界。它目前不能在 Mac 真正睡眠、关机或未登录时
远程唤醒电脑；本版目标是“显示器熄灭但 Mac 仍保持可用”。

本版不会静默修改 macOS 的睡眠或电源设置，也不会用常驻进程永久阻止系统睡眠。自动打开 Vault
是登录时的一次受限动作，只能打开固定安装位置的 Obsidian 和安装计划绑定的 Vault；如果用户之后
主动退出 Obsidian，需要自行重新打开。需要长期息屏使用时，由用户在 macOS 系统设置中自行决定
电源策略，安装 Agent 不得代为更改。

> 本文是安装 Agent 的唯一对话入口。先将内测 Kit 解压到一个新目录并进入该目录；
> 只执行其中的 `./bin/claudian-remote-lifecycle`，不要从仓库分支、聊天文本或
> 服务器返回值执行命令。Kit 必须先经过维护者独立分发的可信 bootstrap 验证；
> Kit 内自带的公钥和校验器不能独立证明 Kit 本身可信。

## 默认连接：免费 Tailscale

选择 `local_tailscale` 前，Mac 与 iPhone 都要安装 Tailscale，并登录同一个 Tailnet：

- Mac：从 [Tailscale 官方 macOS 下载页](https://tailscale.com/download/mac) 安装图形版 App；
- iPhone：从 [Tailscale 官方 iOS 下载页](https://tailscale.com/download/ios) 安装 App；
- 首次启动时，由用户在系统界面批准 VPN / 网络扩展并完成登录。

安装 Kit 不捆绑 Tailscale 安装包，也不会从非官方镜像安装它。Tailscale 是独立签名并需要
macOS 网络扩展授权的网络软件，Agent 可以打开官方安装页并完成可机器操作的步骤；下载确认、
系统扩展、VPN 权限、登录、密码和 2FA 必须留给用户。安装 Agent 应先通过 lifecycle 的只读
probe 判断是否已安装，不能仅凭用户口头确认。

当 lifecycle 返回安装、登录或 HTTPS 门禁时，先给出“由 Agent 继续操作”和“我自己操作”两种
路径；Agent 路径只处理打开官方页面、启动 App 和普通导航，任何账户输入、2FA、系统扩展、VPN
权限或证书透明度确认仍由用户完成。不要为了减少一次暂停而绕过系统确认。

**无需把 CLI integration 当作必装前置。** lifecycle 会先尝试系统中的 `tailscale` 命令；
如果用户没有在 Tailscale 设置中安装 CLI integration，会直接调用已安装图形版 App 内的受签名
可执行文件。CLI integration 只作为兼容入口，不应要求用户为了 Claudian Remote 额外安装。

```text
iPhone / Obsidian Mobile
        │  私有 HTTPS / WSS（同一 Tailnet）
        ▼
Mac 上的 Tailscale Serve
        │  只转发到 127.0.0.1
        ▼
Claudian Remote Relay ⇄ Companion ⇄ Obsidian / Claudian
```

该模式只使用私有 Tailscale Serve，绝不启用 Funnel。截图会随 Tailscale 版本变化，因此手册以
上面的稳定流程图和 lifecycle 实际 probe 为准；维护者可另附当前版本截图作为辅助说明。

## 0. 第一条操作：只读检查

第一条生命周期操作必须是：

```bash
./bin/claudian-remote-lifecycle inspect
```

它只输出一行 JSON，结构版本是 `claudian-remote.lifecycle-result/v2`，不会修改系统。
Agent 必须先读取 `state`、`code` 和 `data.snapshot`，再决定下一步。不要先询问能由
检查结果发现的信息，也不要让用户粘贴密码、令牌、私钥、配对凭据或完整本地路径。

## 1. 对话规则

1. 一次只问一个尚未解决的问题；已记录在 lifecycle checkpoint 的答案不得重复询问。
2. Claudian 必须为 `2.0.4` 或 `2.2.6`（推荐）。不支持的版本只允许 inspect、status、diagnose、
   rollback、uninstall 等安全操作，禁止安装、更新或 Remote 写操作。
   2.2.6 的“立即插话”取决于当前提供方能力；Claude 不支持插话，但仍可普通发送和排队。
3. 若检查到多个 Vault，只问“要为哪个 Vault 安装？”；不得猜测。
4. 不询问用户是否有 Mac、iPhone、VPS 或 NAS。直接默认 `local_tailscale`；只有用户主动提出
   自有 VPS 时才解释 `remote_vps`，并明确当前内测尚未开放该自动部署路径。
5. `local_lan` 与 `remote_vps` 当前都不是可发布写入路径，不得执行、绕过或自动回退。
6. 人工说“完成了”不代表门禁通过。必须运行 resume 并由 lifecycle 的外部 probe 验证。
7. 未知或未识别的 command、state、code 或 schema 一律失败关闭：停止操作并运行 diagnose，
   不得用自然语言推测下一条命令。
8. lifecycle 不能直接或安全地写入 Obsidian WebView 的 `localStorage`。只有 inspect 通过
   OS 安全存储与 Companion secure-provisioning route 的真实 probe 后，才能认为
   Pairing Admin bootstrap 完成；仅存在 connection-profile 或引用字符串不代表可用。

正常单 Vault 的 Tailscale 路径不问配置问题；多个 Vault 时只问一次目标 Vault。用户主动提出
其他网络方式时再解释限制。登录、权限和配对属于必要门禁，不得包装成配置访谈。

## 2. 生成不可变计划

当前内测只生成 Tailscale 计划；命令会重新进行只读检查并产生确定性的 `plan_id`：

```bash
./bin/claudian-remote-lifecycle plan --mode local_tailscale --vault-id <non-secret-vault-id>
```

`remote_vps` 与 `local_lan` 名称保留在生命周期协议中供兼容性诊断，但本版写操作会失败关闭；
Agent 不得因为用户有 VPS 就声称该路径已经可用。

相同 inspection snapshot 与选择必须生成相同 plan。执行写操作前必须重新检查环境并
验证 `environment_fingerprint`；Vault、Claudian、endpoint、profile 或 generation 漂移时
停止，重新 inspect/plan。不要手工编辑 plan。

## 3. 生命周期命令

所有命令只在 stdout 输出一行 JSON。以下是完整且唯一的命令表：

```bash
./bin/claudian-remote-lifecycle inspect
./bin/claudian-remote-lifecycle plan --mode <local_tailscale|remote_vps|local_lan> --vault-id <id>
./bin/claudian-remote-lifecycle install --plan-id <plan-id>
./bin/claudian-remote-lifecycle status --operation-id <operation-id>
./bin/claudian-remote-lifecycle resume --operation-id <operation-id>
./bin/claudian-remote-lifecycle cancel --operation-id <operation-id>
./bin/claudian-remote-lifecycle verify --plan-id <plan-id>
./bin/claudian-remote-lifecycle update --plan-id <plan-id>
./bin/claudian-remote-lifecycle rollback --operation-id <operation-id>
./bin/claudian-remote-lifecycle revoke-device --device-id <device-id>
./bin/claudian-remote-lifecycle diagnose
./bin/claudian-remote-lifecycle export-diagnostics --destination <absolute-local-json-path>
./bin/claudian-remote-lifecycle uninstall --plan-id <plan-id>
./bin/claudian-remote-lifecycle purge --plan-id <plan-id>
```

正式内测的 `claudian-remote-beta-kit-<version>.tar.gz` 解压后包含本手册、入口、已签名
`release-manifest.json` 和精确 `assets/`；执行其中 `bin/claudian-remote-lifecycle` 时会自动把
该目录交给 lifecycle。开发者直接调用 Python 模块时，必须把同样结构的目录作为全局
`--release-dir <verified-release-directory>` 参数传入；缺失验签交接凭据时
安装必须返回 `verified_release_unavailable`，不得从工作树、分支或网络“最新版”回退。

不要使用 shell 拼接远端输入，不要使用 `curl | shell`，不要把秘密放进参数、环境变量、
URL、聊天或诊断。GitHub 访问在维护者向测试者交付 Kit 之前完成，lifecycle 不会代为登录
或执行发行权限 probe。Tailscale、App Store、VPS 与系统权限的敏感输入必须留在对应的
系统界面或 lifecycle 所有的临时安全通道中。

## 4. 外部门禁：Agent 操作或用户操作

收到 `code: human_action_required` 时，先读取 `gate.operator_options`：

- 有 `agent_continue` 且当前 Agent 具备浏览器或应用控制能力时，优先展示“由 Agent 继续操作”。
  用户选择后，Agent 可完成已经授权、可撤销且不涉及敏感输入的点击；只在密码、2FA、macOS
  系统权限、证书透明度确认或不可逆操作处暂停。完成后自动执行原 operation 的 `resume` 并验证，
  不要再要求用户回复“完成”。
- 选择“我自己操作”时，展示 option 中的官方 `url` 和精简步骤。用户操作后，执行同一个
  operation 的 `resume`；口头说完成不能代替 probe。
- 若结果没有 `operator_options`，逐字解释 `gate.exact_action`。系统权限、设备短码核对和敏感
  登录始终由用户完成。

继续验证使用：

```bash
./bin/claudian-remote-lifecycle resume --operation-id <operation-id>
```

只有结果明确给出 `cancellation_available: true` 和 typed `cancel` action 时，才可按用户要求
取消同一个 operation：

```bash
./bin/claudian-remote-lifecycle cancel --operation-id <operation-id>
```

取消只清除该 operation 拥有的暂存和一次性安全输入。退休请求已发出或不可逆边界已跨过后，
结果不会提供 cancel；不得自行删除 checkpoint、旧插件或凭据。门禁过期时继续执行同一个
operation 的 `resume`，lifecycle 会原地刷新门禁，不会创建新 operation。

支持的门禁与验证 probe：

| gate_type | 人工动作 | lifecycle 验证 |
|---|---|---|
| `tailscale_install_required` | 用户从官方渠道安装并打开 Tailscale App，批准 VPN / 网络扩展；CLI integration 非必需 | installed-version probe |
| `tailscale_update_required` | 用户在官方 Tailscale App 中完成受支持版本更新 | installed-version probe |
| `tailscale_login_required` | 用户在 Tailscale 完成登录 | logged-in probe |
| `tailscale_https_consent_required` | 二选一：由 Agent 打开官方 DNS 页面继续，或用户按官方链接启用 MagicDNS / HTTPS；证书透明度确认由用户完成 | Serve HTTPS probe |
| `vault_selection_required` | 用户明确选择一个 Vault | selected Vault identity probe |
| `vps_host_authorization_required` | 用户核对并接受主机指纹 | pinned host-key probe |
| `trusted_lan_consent_required` | 用户明确同意受限 LAN 暴露 | recorded consent + network probe |
| `pairing_approval_required` | 用户在 Mac 核对短码并批准设备 | active scoped credential probe |
| `pairing_admin_bootstrap_required` | 等待已签名 lifecycle 建立 OS 安全存储和 Companion 配置路由 | Companion secure-provisioning route probe |
| `desktop_plugin_bootstrap_required` | 在 Obsidian 打开或重新加载已选 Vault，等待 Remote 插件加载 | 选定 Vault 的插件向 Companion Bridge 完成认证 |
| `obsidian_close_for_migration_required` | 旧插件仍需迁移时，完全退出 Obsidian | Obsidian process closed probe |
| `legacy_authority_authorization_required` | 用户只授权属于本安装、本 authority 的旧凭据退休，并确认受影响设备需重新配对 | legacy authority capability probe；退休影响确认始终为人工边界 |
| `purge_confirmation_required` | 用户在安全界面确认清除 Remote 数据 | one-time confirmation probe |
| `diagnostic_export_confirmation_required` | 用户核对字段预览后在 macOS 对话框确认本地导出 | one-time confirmation probe |

门禁的 `operator_options` 区分两种路线：带 `requires_capability`（`browser_control` 或
`computer_control`）的选项是可代理路线，不带该字段的 `manual` 选项是人工路线。当前 Agent 具备浏览器或
应用控制能力时优先展示可代理路线；不具备能力时逐字展示 `manual` 选项里的官方 `url` 和精确导航步骤。
无论哪条路线，密码、2FA、macOS 系统权限、VPN/网络扩展批准、证书透明度确认、旧凭据退休影响确认和设备
短码核对都始终是人工边界，不得代理；具备能力的 Agent 也不得对普通导航索要不必要的二次确认。

当 plan/status 返回的结果里已经没有 Tailscale 门禁（App、登录、扩展、CLI integration、HTTPS consent
的 probe 都已通过）时，走快速路径：跳过这些已满足的说明，直接进入 staging、activation 和 pairing。
CLI integration 从来不是必装前置，也不应为了快速路径要求用户单独安装。

Agent 会话丢失后先运行：

```bash
./bin/claudian-remote-lifecycle status --operation-id <operation-id>
```

根据返回的 phase、gate 和 recovery action 恢复；不要新建重复操作。

## 5. 结果代码与唯一恢复动作

| code | 含义 | Agent 动作 |
|---|---|---|
| `inspection_ready` | 支持的只读快照已产生 | 单 Vault 直接生成 Tailscale plan；多 Vault 只询问目标 Vault |
| `unsupported_desktop_os` | 非本内测支持的 macOS | 停止；仅 diagnose |
| `unsupported_claudian_version` | Claudian 不是 2.0.4 或 2.2.6 | 提示安装受支持版本后重新 inspect |
| `claudian_not_enabled` | Claudian 未启用 | 让用户在 Obsidian 启用后重新 inspect |
| `vault_not_found` | 未发现 Vault | 让用户在 Obsidian 打开目标 Vault 后重新 inspect |
| `vault_selection_required` | 多 Vault 有歧义 | 一次只问用户选择哪个 Vault，再 plan |
| `plan_prepared` | 确定性 plan 已生成 | 保存 plan_id；进入对应写操作 |
| `operation_status` | checkpoint 已读取 | 按 phase/gate 执行 resume 或恢复动作 |
| `human_action_required` | 外部动作未通过 probe | 解释 exact_action；完成后 resume |
| `resume_prepared` | 门禁 probe 已验证 | 用同一 operation_id 继续 |
| `operation_not_found` | operation_id 无 checkpoint | 停止；diagnose，不猜测或重装 |
| `lifecycle_operation_busy` | 另一写操作持锁 | 等待其 status 到安全状态后重试 |
| `environment_drift` | 环境与 plan 不一致 | 停止写操作；重新 inspect 和 plan |
| `secure_provisioning_missing` | 缺少可验证的安全配置桥 | 保持阻塞；不得把秘密写入 localStorage 或聊天 |
| `tailscale_install_required` | Mac 未发现可调用的 Tailscale App | 引导用户从官方渠道安装图形版 App；不要要求单独安装 CLI integration |
| `tailscale_update_required` | 已安装的 Tailscale 低于受支持版本 | 在官方 App 中更新后，用同一 operation_id resume |
| `trusted_lan_not_release_eligible` | 本内测尚无真机抓包与网络切换证据，LAN 模式不可发布 | 不得启用或回退明文 LAN；改选 Tailscale 或 VPS |
| `obsidian_close_for_migration_required` | 旧插件仍在且 Obsidian 正运行 | 完全退出 Obsidian，再用同一 operation_id resume |
| `legacy_credential_revocation_unavailable` | 该旧 lineage 没有受支持的可验证退休适配器，尚未 staging | 停止；保留旧插件与旧凭据，不改动旧安装；联系维护者确认 lineage |
| `legacy_credential_revocation_required` | 退休尝试未返回可验证结果，staging 已清理且旧凭据保留 | 停止；不假定已撤销；用同一 operation 的 status 读取 typed 结果并只执行返回的 recovery action |
| `legacy_authority_unsupported` | 旧 authority 布局无法识别或非受支持 lineage | 停止；不改动旧安装，联系维护者 |
| `shared_credential_scope_unsupported` | 旧凭据的消费者无法证明只属于当前安装 | 提交前停止；不改动旧凭据 |
| `legacy_authority_authorization_required` | 需要人工授权属于本安装的旧凭据退休 | 解释重配对影响，用同一 operation resume 并完成授权 |
| `retirement_outcome_unknown` | 退休请求已派发但 authority 结果未知 | 保持锁定；只执行同一 operation 的只读对账或 manual recovery |
| `post_retirement_finish_forward_required` | 退休已确认，需向前完成激活与重新配对 | 用同一 operation_id finish_forward；禁止回滚或另开安装 |
| `verified_release_unavailable` | 缺少已验签发行目录或 bootstrap 回执 | 停止；重新获取同一私有发行资产 |
| `manifest_signature_unverified` | bootstrap 验签回执无效 | 停止；不得安装或改用源码 |
| `installation_ready` | 本地 Relay、Companion、插件与 Tailscale Serve 均通过验证 | 执行 verify，再进行真机配对验收 |
| `verification_ready` | 已安装集合仍满足本地健康检查 | 进入真机验收或正常使用 |
| `pairing_approval_required` | 本地运行时就绪，尚无已批准手机 | 完成短码核对并用同一 operation_id resume |
| `desktop_plugin_bootstrap_required` | 运行时已启动，但自动打开已选 Vault 后插件仍未向 Companion 认证 | 检查 Obsidian 登录/插件启用状态，再用同一 operation_id resume |
| `post_activation_verification_failed` | 激活后健康检查失败并已回滚 | 保持 rolled_back；检查 status 后重新 plan |
| `installation_compensation_failed` | 自动补偿未能证明完成，operation 处于 recovery_required | 先 status；只执行返回的 allowlisted recovery_action。若为 manual_recovery_required，停止并联系维护者，不猜测 resume/rollback |
| `operation_interrupted` | Agent/进程在事务边界中断，checkpoint 可恢复 | 用返回的 operation_id 执行 resume |
| `diagnostic_summary_ready` | 已生成字段白名单内的简短诊断摘要 | 可口头报告；没有上传任何内容 |
| `diagnostic_export_confirmation_required` | 已显示导出字段预览，等待系统确认 | 用同一 operation_id 执行 resume 并在 macOS 对话框确认 |
| `diagnostic_export_ready` | 本地 0600 JSON 已写入用户指定位置 | 由用户自行查看、发送或删除；系统不会上传 |
| `device_revoked` | 指定手机凭据已吊销 | 需要继续使用时重新配对 |
| `uninstall_completed` | 已移除不冲突的受管代码、进程和暴露配置 | Vault 与 Claudian 对话仍保留 |
| `uninstall_precondition_incomplete` | 凭据撤销或受管服务停止只完成了一部分 | 保留 operation_id；排除系统阻塞后执行 resume，不能另开卸载操作 |
| `purge_completed` | 系统确认后已清除全部 Remote 本地状态 | Vault 与 Claudian 对话仍保留 |
| `operation_not_implemented` | 当前构建尚未提供该操作 | 不得宣称成功；安装更新的已验证发行版 |
| `invalid_lifecycle_input` | 输入或结构未通过验证 | 停止；检查命令表并 diagnose |

当前内测切片已交付 `local_tailscale` 的事务 install/update、验签资产、按兼容集隔离且依赖锁定的
managed runtime、动态 LaunchAgent、Keychain 安全配置、Pairing Admin Companion 代理、
verify/resume/rollback/revoke-device/diagnose/export-diagnostics/uninstall/purge。
`remote_vps` 与 `local_lan` 写操作仍必须返回 `operation_not_implemented` 或模式专用阻塞码，
Agent 不得绕过或声称 ready。

### 旧凭据退休的 typed 结果与恢复/取消边界

Beta 5 不再循环追问“撤销旧凭据”。退休请求派发后，结果只收敛到三种 typed 状态之一，Agent 按
`effect_summary.credential_effect` 和 `ambiguity_state` 读取，不按自然语言推测：

- `not_applied`：authority 证明旧凭据未变更且 generation 未推进，可退回派发前的保留路径。
- `retired`：authority 提供有效退休证据，跨过不可逆边界，只能 finish_forward 完成激活与重新配对。
- `inconclusive`：authority 仍不可达或证据无效，operation 保持锁定，只提供 manual_recovery_required。

恢复文案必须区分三处，不得混用：派发前的失败走 `rollback`（预边界回滚，旧安装保持可用）；派发后
结果未知走 `reconcile_retirement_outcome`（同一 operation 的只读对账）；退休证据确认后走
`finish_forward`（向前完成，绝不恢复已退休秘密）。

取消只在退休派发前可用：用户拒绝或取消门禁会清理该 operation 拥有的暂存并关闭同一 operation，
旧安装保持不变。派发后 `cancellation_available` 恒为 false，结果不再提供 cancel，也不得另开新安装；
门禁过期时继续用同一 operation_id 执行 resume，lifecycle 原地刷新，不创建新 operation。

## 6. 终态

流程只能以 `ready`、`prepared`、`blocked`、`rolled_back` 或 `recovery_required` 之一结束。
`running` 仅表示非终态的 status 快照，不能当作流程完成。
安装后必须执行 verify 并从 iPhone 蜂窝网络验证文本流、附件、停止、立即插队、历史与重连；
Mac 必须保持唤醒并已登录。显示器可以熄灭；后台服务会随登录启动，并尝试打开绑定 Vault。
该自动打开是登录时一次性动作，不会在用户主动退出 Obsidian 后循环拉起，也不会改变系统睡眠策略。

普通卸载不删除 Vault 与 Claudian 对话。purge 额外删除 Remote 凭据、缓存、数据库、日志和
备份，必须经过 `purge_confirmation_required`。任何自动诊断上传或维护者遥测都不存在。
