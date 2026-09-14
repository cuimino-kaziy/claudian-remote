# Claudian Remote 0.2.0

本版已在 [Obsidian 社区插件目录](https://community.obsidian.md/plugins/claudian-remote) 发布，可点击 **Add to Obsidian** 安装。官方扫描完成，并确认发布的 `main.js` 与仓库构建结果逐字节一致。

## 改动

- 插件、Relay、Companion 和安装器统一到 0.2.0，发行标签与插件版本完全一致。
- 社区插件由 Obsidian 安装和更新。Mac Kit 只读核验插件，管理后台服务；后台回退和卸载不会覆盖或删除社区插件。
- 区分“已安装插件但没有后台服务”和“已有后台待升级”，从 beta.6.7 配套升级时保留原配对。
- 设置与指南改用“服务器连接”。VPS、云服务器和自有 Linux 主机均可作为部署目标，仍需满足文档中的系统、运行时、HTTPS 与网络条件；没有新增服务器自动部署入口。
- 调整命令名称和设置标题以适配 Obsidian 规范，去除动态 eval 加载，明确桌面文件访问边界。保留已验收的聊天布局与键盘处理逻辑。
- 提供外置公开 Kit 校验说明，保留签名、固定指纹和完整性检查。

## 安装与升级

先在两端安装并启用同版插件，再下载 `claudian-remote-kit-0.2.0.tar.gz` 安装或更新 Mac 后台服务。按 [下载与校验说明](install-verification-0.2.0.md) 核验来源和完整包，再按 [入门指南](getting-started.md) 操作。

Mac、手机与后台服务必须使用匹配版本；升级中途暂时只读是预期行为，不需要因此重新配对。旧 beta.6.7 发行件保留，不能与本版组件混用。

## 验证范围

上一版已在用户的 Mac / iPhone 环境验收。本版的社区安装分工通过本地自动化验证后发布，不将其等同于新版本真机验收。iPad、Intel Mac 和公开原版 Claudian 2.2.7 的完整端到端验收仍未覆盖。

默认自动安装路径为 Tailscale。自建服务器需要维护者按 [部署说明](self-host-vps.md) 准备，服务器不能替代 Mac 运行 Claudian。Mac 仍须开机、登录、唤醒并打开目标仓库。
