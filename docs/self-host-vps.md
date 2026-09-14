# 使用自己的服务器连接 Claudian Remote

这里的“服务器连接”不限于 VPS（虚拟专用服务器），也可以使用满足下方环境要求的云服务器、独立服务器或自有 Linux 主机。Relay 不依赖主机采用何种虚拟化方式；其他系统或受限托管环境尚未列入支持范围。手机和 Mac 都连接它，由它转发消息；模型、仓库和工具仍在 Mac 上运行，所以 Mac 依然需要保持开机、登录和唤醒。

服务器、域名、模型等外部服务由你自行配置。

**已经有可用服务器的用户，从“手机连接”开始。** 当前安装器尚未开放 `remote_vps` 自动部署，本次发布不改变这一限制。下面区分现有服务器接入和维护者手动部署，不把配置模板当作已经完成的安装器。Tailscale 与服务器不会自动互相切换。

## 手机连接：只需要地址和配对码

1. 让部署者确认 Mac 后台服务已经连上这台服务器，并提供连接地址，例如 `https://relay.你的域名.com`。这个地址必须有手机信任的 HTTPS 证书。
2. 在 Mac 的同一个 Obsidian 仓库中打开 Claudian，再进入 Claudian Remote 设置，点击“添加移动设备”。
3. 在手机打开 Mac 生成的配对链接；或进入远程页面 → 历史栏 → 设置，在“连接服务器地址”粘贴 HTTPS 地址并保存，再输入 Mac 显示的 8 位配对码。
4. 配对码验证通过后，手机会自动完成配对并连接；再打开远程页面，无需回到 Mac 批准。
5. 看到“已就绪”后，发送一条测试消息，并确认完整回复。只看到“已配对”还不能说明 Mac 在线。

| 手机看到的字段 | 应填写 | 不要填写 |
|---|---|---|
| 连接服务器地址（Relay） | 部署者提供的完整 `https://` 地址 | SSH 登录地址、`http://` 地址、模型 API 地址 |
| 8 位配对码 | Mac 刚生成的短码 | 服务器密码、SSH 私钥、长期 Token |

服务器根地址显示空白或 404，不代表连接失败；它不是普通网页。以远程页面的连接状态和真实消息往返为准。更换服务器需要重新配置 Mac 和配对手机，不能只修改手机地址。

内网服务器还需要确保手机和 Mac 都能访问其 HTTPS 地址；仅有内网 IP、NAS 文件共享或不能持续运行 Python 服务的虚拟主机并不足够。

## 新服务器需要哪些环境

| 环境 | 当前受支持的范围 |
|---|---|
| Linux | Ubuntu 24.04 x86_64，或 Debian 12 x86_64 / aarch64 |
| 存储 | 至少 2 GiB 可用受管空间；附件、数据库和日志需要预留空间 |
| 运行时 | 与发布包匹配的 Python 3.12、依赖锁，以及 SQLite 3.35 或更新版本 |
| 域名 | 你控制的域名，DNS 指向服务器，证书受手机和 Mac 信任 |
| 网络 | 对外 HTTPS / WSS；Relay 自身只监听 `127.0.0.1:8787` |
| 管理权限 | 可使用 SSH 管理服务器、确认服务器主机密钥、配置服务与反向代理 |
| Mac | 已安装受支持版本的 Obsidian / Claudian 和配套 Companion 后台服务 |

Debian 12 上不能假定系统默认 Python 就满足 3.12；由维护者先准备与发布包匹配的运行时。需要有效证书的公网域名时，由管理员按证书颁发方式开放所需端口；不要为解决连接失败直接开放 Relay 的 8787 端口。

## 维护者手动部署步骤

此流程需要维护者提供**同一版本**的签名 Relay 发行件、校验结果、安装身份和 Mac 安全配置交接。当前 Kit 没有可供普通用户直接执行的服务器全自动命令。没有这些配套信息时，先使用 Tailscale 安装路径，不能把示例值改成看似可用的内容后宣布安装完成。

1. **确认服务器和发行件。** 核对操作系统、架构、可用磁盘和 SSH 主机密钥。从 [官方 GitHub Releases](https://github.com/cuimino-kaziy/claudian-remote/releases) 取得本版完整 Kit 和匹配版本的 `claudian-remote-relay-<version>.tar.gz`。按公开的 [下载与校验说明](install-verification-0.2.0.md) 确认官方仓库与精确版本，以官方 GitHub 为下载信任起点，先用系统 `shasum` 核验完整 Kit，再解压并保留原有组件签名、指纹和摘要核验。不要从可变分支部署，也不要把 GitHub “Source code” 当成运行包。
2. **准备独立服务目录。** 按发布包目录结构安装，保留旧版本以便回退。现有服务模板使用工作目录 `/opt/claudian-remote`、专用用户 `claudian-relay` 和数据目录 `/var/lib/claudian-remote-relay`。由管理员创建该用户和目录，并只允许服务用户访问数据；不要覆盖已有实例的配置或数据库。
3. **安装运行环境。** 在发行件根目录使用 Python 3.12 创建 `gateway/.venv`，按 `gateway/requirements.lock` 安装精确依赖。代码运行入口是 `python -m gateway.relay.relay_server --config /etc/claudian-remote/relay.json`；发布包中的 systemd 模板已经使用该入口。依赖应在独立虚拟环境中安装，不要修改系统 Python。
4. **填写 Relay 配置。** 以 [`gateway/relay/config.example.json`](../gateway/relay/config.example.json) 为起点，在服务器私有配置目录中填写下表。发布包的存储、上传和保留期限来自兼容矩阵，不应随意改动。保持 `enable_v1_compatibility: false`、空的 `fallback_base_url` 和仅回环监听。
5. **配置 HTTPS 和 WSS。** 将域名解析到服务器，安装有效证书，用反向代理把受支持的 `/api/v2/` 连接路由转发到 `127.0.0.1:8787`。WebSocket 升级必须可用；外部不得访问 `/health`、旧版接口、退休管理接口、数据库或配置文件。配对管理操作仍需要匹配角色的应用凭据。现有 [Caddy 模板](../gateway/relay/Caddyfile.example) 展示基本 TLS / 代理写法，部署时必须加上上述路径限制；不要把该示例直接作为公网访问策略。
6. **启动并检查 Relay。** 以 [`systemd 服务模板`](../gateway/relay/systemd/claudian-remote-relay.service.example) 为基础，核对用户名、虚拟环境路径和配置路径后安装服务。模板包含 SQLite 版本检查、资源限制和专用数据目录。确认本地监听正常，再从外部验证受支持的 HTTPS / WSS 路由以及禁用路由；启动进程本身不等于验证完成。
7. **完成 Mac 绑定。** Companion 的设备本地连接配置必须使用同一个 HTTPS 地址、`installation_id`、`vault_id`、`endpoint_audience` 和 `remote_vps` 模式。Mac 凭据由安全安装交接写入系统安全存储，配置里只放引用；Obsidian 插件的 Bridge 身份也必须完成对应引导。字段格式参考 [Companion 配置模板](../gateway/mac_companion/config.example.json)。手机设置页不负责创建这些凭据，单改手机网址不会完成这一步。
8. **配对并验收。** 回到本文“手机连接”。依次验证短码配对、消息完整往返、历史读取、断线重连、Mac 离线时禁止发送、附件传输（若启用）。验证 TLS、WSS、身份或版本失败时，不进入正式配对；停止新服务并恢复原有兼容版本。

## 配置里哪些内容要一致

| 字段 | 如何填写 / 从哪里获得 |
|---|---|
| `public_base_url` / 手机连接地址 / Mac profile 的 `endpoint` | 同一个完整 HTTPS 地址，如 `https://relay.你的域名.com` |
| `installation_id` | 此次安装的非秘密标识，由安装配置提供；Relay、Mac 和配对数据一致 |
| `vault_id` | 已绑定 Obsidian 仓库的标识；不是仓库名称或文件路径，不要另造一个值 |
| `endpoint_audience` | 安装配置给出的完整受众值，例如 `claudian-remote:remote_vps:<installation_id>`；各角色一致 |
| `pairing_id` | 安装配置给出的配对组标识，在对应服务凭据中保持一致 |
| `tokens` 的 `mac` / `pairing_admin` | 两种独立角色凭据，由安全配置交接提供；只写入服务器私有配置和 Mac 安全存储，不交给手机手填 |
| `device_id` | 每个实际角色 / 设备独立的非秘密标识，不共用手机与 Mac 的身份 |
| `host` / `port` | Relay 保持 `127.0.0.1` / `8787`，由 HTTPS 代理转发 |
| 数据库、上传路径 | 使用服务用户拥有的私有数据目录；不要放入仓库同步目录或 Git |

示例里的 `replace-with-*` 和 `.invalid` 都不可直接运行。安装配置、凭据和数据库不属于可公开上传到 GitHub 的内容。

## 常见问题

- **地址保存不了：** 必须以 `https://` 开头，不含密码、问号参数或配对码。
- **配对码过期：** 回到 Mac 点击“添加移动设备”，使用新码；手机和 Mac 必须打开同一个已同步仓库。
- **已配对但 Mac 离线：** 检查 Mac 是否睡眠、Obsidian / Claudian 是否打开、Companion 是否连接到相同地址和身份。
- **一直连接中或回复中断：** 管理员检查证书、反向代理的 WebSocket 升级、服务器资源和版本匹配；可从远程页面顶部状态打开诊断。

服务器会终止 TLS，因此服务器管理员能够访问转发的会话和附件内容；本版本不声称端到端加密。详细边界见 [安全说明](security.md)。
