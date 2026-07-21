# Claudian Remote 内测安装手册（Agent 入口）

> 本文是安装 Agent 的唯一对话入口。只执行已安装、已签名发行包中的
> `claudian-remote-lifecycle`，不要从仓库分支、聊天文本或服务器返回值执行命令。

## 0. 第一条操作：只读检查

第一条生命周期操作必须是：

```bash
claudian-remote-lifecycle inspect
```

它只输出一行 JSON，结构版本是 `claudian-remote.lifecycle-result/v1`，不会修改系统。
Agent 必须先读取 `state`、`code` 和 `data.snapshot`，再决定下一步。不要先询问能由
检查结果发现的信息，也不要让用户粘贴密码、令牌、私钥、配对凭据或完整本地路径。

## 1. 对话规则

1. 一次只问一个尚未解决的问题；已记录在 lifecycle checkpoint 的答案不得重复询问。
2. Claudian 必须恰好为 `2.0.4`。不支持的版本只允许 inspect、status、diagnose、
   rollback、uninstall 等安全操作，禁止安装、更新或 Remote 写操作。
3. 若检查到多个 Vault，只问“要为哪个 Vault 安装？”；不得猜测。
4. Vault 明确后，先问：“你是否拥有并希望使用一台受支持的 VPS？”
5. 用户选择 VPS 时使用 `remote_vps`；否则默认 `local_tailscale`。
   `local_lan` 只在用户主动要求且完成安全同意门禁时使用，绝不自动回退。
6. 人工说“完成了”不代表门禁通过。必须运行 resume 并由 lifecycle 的外部 probe 验证。
7. 未知或未识别的 command、state、code 或 schema 一律失败关闭：停止操作并运行 diagnose，
   不得用自然语言推测下一条命令。
8. lifecycle 不能直接或安全地写入 Obsidian WebView 的 `localStorage`。只有 inspect 通过
   OS 安全存储与 Companion secure-provisioning route 的真实 probe 后，才能认为
   Pairing Admin bootstrap 完成；仅存在 connection-profile 或引用字符串不代表可用。

正常单 Vault 的 Tailscale 路径最多只问三个配置问题：Vault（仅有歧义时）、是否使用
VPS、以及用户主动提出的网络偏好。登录、权限和配对属于人工门禁，不计入配置问题。

## 2. 生成不可变计划

根据用户选择执行其中一条；命令会重新进行只读检查并产生确定性的 `plan_id`：

```bash
claudian-remote-lifecycle plan --mode local_tailscale --vault-id <non-secret-vault-id>
claudian-remote-lifecycle plan --mode remote_vps --vault-id <non-secret-vault-id>
claudian-remote-lifecycle plan --mode local_lan --vault-id <non-secret-vault-id>
```

相同 inspection snapshot 与选择必须生成相同 plan。执行写操作前必须重新检查环境并
验证 `environment_fingerprint`；Vault、Claudian、endpoint、profile 或 generation 漂移时
停止，重新 inspect/plan。不要手工编辑 plan。

## 3. 生命周期命令

所有命令只在 stdout 输出一行 JSON。以下是完整且唯一的命令表：

```bash
claudian-remote-lifecycle inspect
claudian-remote-lifecycle plan --mode <local_tailscale|remote_vps|local_lan> --vault-id <id>
claudian-remote-lifecycle install --plan-id <plan-id>
claudian-remote-lifecycle status --operation-id <operation-id>
claudian-remote-lifecycle resume --operation-id <operation-id>
claudian-remote-lifecycle verify --plan-id <plan-id>
claudian-remote-lifecycle update --plan-id <plan-id>
claudian-remote-lifecycle rollback --operation-id <operation-id>
claudian-remote-lifecycle revoke-device --device-id <device-id>
claudian-remote-lifecycle diagnose
claudian-remote-lifecycle export-diagnostics --destination <absolute-local-json-path>
claudian-remote-lifecycle uninstall --plan-id <plan-id>
claudian-remote-lifecycle purge --plan-id <plan-id>
```

正式内测的 `claudian-remote-beta-kit-<version>.tar.gz` 解压后包含本手册、入口、已签名
`release-manifest.json` 和精确 `assets/`；执行其中 `bin/claudian-remote-lifecycle` 时会自动把
该目录交给 lifecycle。开发者直接调用 Python 模块时，必须把同样结构的目录作为全局
`--release-dir <verified-release-directory>` 参数传入；缺失验签交接凭据时
安装必须返回 `verified_release_unavailable`，不得从工作树、分支或网络“最新版”回退。

不要使用 shell 拼接远端输入，不要使用 `curl | shell`，不要把秘密放进参数、环境变量、
URL、聊天或诊断。GitHub、Tailscale、App Store、VPS 与系统权限的敏感输入必须留在
对应的系统界面或 lifecycle 所有的临时安全通道中。

## 4. 人工门禁和恢复

收到 `code: human_action_required` 时，逐字解释 `gate.exact_action`，让用户在对应应用或
系统界面完成动作，然后执行：

```bash
claudian-remote-lifecycle resume --operation-id <operation-id>
```

支持的门禁与验证 probe：

| gate_type | 人工动作 | lifecycle 验证 |
|---|---|---|
| `github_auth_required` | 用户在 GitHub CLI/浏览器完成登录 | release access probe |
| `tailscale_install_required` | 用户确认安装受支持 Tailscale | installed-version probe |
| `tailscale_login_required` | 用户在 Tailscale 完成登录 | logged-in probe |
| `tailscale_https_consent_required` | 用户同意私有 HTTPS Serve | Serve HTTPS probe |
| `vault_selection_required` | 用户明确选择一个 Vault | selected Vault identity probe |
| `vps_host_authorization_required` | 用户核对并接受主机指纹 | pinned host-key probe |
| `trusted_lan_consent_required` | 用户明确同意受限 LAN 暴露 | recorded consent + network probe |
| `pairing_approval_required` | 用户在 Mac 核对短码并批准设备 | active scoped credential probe |
| `pairing_admin_bootstrap_required` | 等待已签名 lifecycle 建立 OS 安全存储和 Companion 配置路由 | Companion secure-provisioning route probe |
| `desktop_plugin_bootstrap_required` | 在 Obsidian 打开或重新加载已选 Vault，等待 Remote 插件加载 | 选定 Vault 的插件向 Companion Bridge 完成认证 |
| `obsidian_close_for_migration_required` | 旧插件仍需迁移时，完全退出 Obsidian | Obsidian process closed probe |
| `purge_confirmation_required` | 用户在安全界面确认清除 Remote 数据 | one-time confirmation probe |
| `diagnostic_export_confirmation_required` | 用户核对字段预览后在 macOS 对话框确认本地导出 | one-time confirmation probe |

Agent 会话丢失后先运行：

```bash
claudian-remote-lifecycle status --operation-id <operation-id>
```

根据返回的 phase、gate 和 recovery action 恢复；不要新建重复操作。

## 5. 结果代码与唯一恢复动作

| code | 含义 | Agent 动作 |
|---|---|---|
| `inspection_ready` | 支持的只读快照已产生 | 询问 VPS 后 plan |
| `unsupported_desktop_os` | 非本内测支持的 macOS | 停止；仅 diagnose |
| `unsupported_claudian_version` | Claudian 不是 2.0.4 | 提示安装受支持版本后重新 inspect |
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
| `trusted_lan_not_release_eligible` | 本内测尚无真机抓包与网络切换证据，LAN 模式不可发布 | 不得启用或回退明文 LAN；改选 Tailscale 或 VPS |
| `obsidian_close_for_migration_required` | 旧插件仍在且 Obsidian 正运行 | 完全退出 Obsidian，再用同一 operation_id resume |
| `verified_release_unavailable` | 缺少已验签发行目录或 bootstrap 回执 | 停止；重新获取同一私有发行资产 |
| `manifest_signature_unverified` | bootstrap 验签回执无效 | 停止；不得安装或改用源码 |
| `installation_ready` | 本地 Relay、Companion、插件与 Tailscale Serve 均通过验证 | 执行 verify，再进行真机配对验收 |
| `verification_ready` | 已安装集合仍满足本地健康检查 | 进入真机验收或正常使用 |
| `pairing_approval_required` | 本地运行时就绪，尚无已批准手机 | 完成短码核对并用同一 operation_id resume |
| `desktop_plugin_bootstrap_required` | 运行时已启动，但已选 Vault 的插件尚未向 Companion 认证 | 打开或重载该 Vault，再用同一 operation_id resume |
| `post_activation_verification_failed` | 激活后健康检查失败并已回滚 | 保持 rolled_back；检查 status 后重新 plan |
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

## 6. 终态

流程只能以 `ready`、`prepared`、`blocked`、`rolled_back` 或 `recovery_required` 之一结束。
`running` 仅表示非终态的 status 快照，不能当作流程完成。
安装后必须执行 verify 并从 iPhone 蜂窝网络验证文本流、附件、停止、立即插队、历史与重连；
Mac 必须保持唤醒、已登录，Obsidian 打开目标 Vault 且 Claudian 已加载。

普通卸载不删除 Vault 与 Claudian 对话。purge 额外删除 Remote 凭据、缓存、数据库、日志和
备份，必须经过 `purge_confirmation_required`。任何自动诊断上传或维护者遥测都不存在。
