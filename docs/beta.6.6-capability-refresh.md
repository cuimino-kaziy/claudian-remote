# 0.2.0-beta.6.6 能力状态刷新候选

## 问题与原因

手机 beta.6.5 报告显示：连接正常、Mac 在线、Claudian 能力就绪，但 Mac→Relay 的兼容状态仍为 `required_capability_missing`。Mac 握手时若 Claudian 标签或控制器尚未就绪，旧结果会被 Relay 保留。后来 `capability.state` 更新为就绪，却不能刷新握手结果，导致手机持续只读。

链路位置：`DesktopBridgeRouter.bind` → `AsyncMacCompanion.run_connection` 的 `mac.hello` → `PresenceRegistry.register_mac`。手机分别保留两层检查，不能用 Claudian 的就绪消息覆盖 Mac 握手的失败。

## 当前恢复结果

本轮在 Mac 调用现有重连入口，连接代数从 7 更新到 8。Mac 重新绑定且能力检查就绪；用户随后确认手机已显示“已就绪”。当前运行版本仍为 beta.6.5，无需重新配对。

## 防止再次发生

候选在绑定时记录 Claudian 能力状态，并由现有运行时刷新检查当前活动标签。状态变化时先废止旧绑定，再复用现有重连与握手流程。等待新绑定期间不重复重连；旧代数的失效消息不能清除新绑定。版本不匹配或实际缺失的能力仍会阻止发送。

功能改动仅在 `src/desktop/companion-channel.js`、`src/plugin.js`，回归加入现有 `tests/companion-channel.test.js`。修改前已复现失败；修改后覆盖加载完成、能力降级、不变状态、非活动标签干扰和迟到的绑定消息。没有修改输入栏、配对或传输协议。

## 交付状态

277 项 JavaScript 与 699 项 Python 测试通过；有针对性的独立审查未发现阻断问题。安装包已构建并通过签名校验。

beta.6.6 作为下次更新的候选交付，尚未安装到 Mac 或同步仓库，未做该候选的手机真机验收。当前已恢复的 beta.6.5 继续运行。本轮未部署 VPS、未发布 GitHub Release 或插件市场。
