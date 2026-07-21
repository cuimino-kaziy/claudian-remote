# Claudian Remote 内测故障排查

先运行 `claudian-remote-lifecycle inspect`；若已有 `operation_id`，再运行
`claudian-remote-lifecycle status --operation-id <operation-id>`。请只转述 `code`、
`state`、phase 和 Agent-safe summary，不要发送配置文件、完整路径、URL 查询参数、
令牌、短码、QR、主机私钥或诊断数据库。

## 常见阻塞

- `unsupported_claudian_version`：安装并启用 Claudian `2.0.4`，重新 inspect。不要尝试写操作。
- `vault_selection_required`：在 Obsidian 打开并明确选择唯一目标 Vault，再重新 plan。
- `human_action_required`：完成返回值中的 `exact_action`，随后用原 `operation_id` resume。
  在聊天中回复“完成”不会满足门禁。
- `lifecycle_operation_busy`：已有生命周期写操作持锁。查询原操作 status，不要并行重装。
- `environment_drift`：环境已经变化。重新 inspect 和 plan，不要继续使用旧 plan_id。
- `secure_provisioning_missing`：Companion 的安全配置桥或 OS 安全存储尚未通过真实 probe。
  不要尝试从 lifecycle 写 Obsidian WebView localStorage，也不要把 Pairing Admin 秘密交给 Agent。
- `operation_not_implemented`：当前开发构建没有该写操作；没有发生修改，也不能视为成功。
- `operation_not_found`：停止恢复，不要创建重复服务；运行 diagnose 并向维护者口头提供摘要。

## 安全失败原则

- 连接模式不会静默切换；Tailscale 失败不会自动暴露 LAN 或改用 VPS。
- 未知 schema/state/code 必须停止并运行 `claudian-remote-lifecycle diagnose`。
- `claudian-remote-lifecycle export-diagnostics` 是独立的人工确认操作；普通 diagnose 不导出文件。
- 不运行可变分支、服务器返回的命令或 `curl | shell`。
- 不删除 Vault、Claudian 对话、全局 Tailscale、共享代理/TLS 或系统/Homebrew 的共享工具。

## 仍需人工支持时

口头提供：生命周期版本、结果 code、当前 phase、连接模式以及最近一次 probe 的非敏感结果。
不要提供消息内容、附件、路径、网络身份或任何凭据。维护者不会要求远程屏幕控制或秘密。
