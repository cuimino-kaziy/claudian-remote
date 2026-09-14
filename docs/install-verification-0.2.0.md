# 0.2.0 下载与校验

只使用 [cuimino-kaziy/claudian-remote 的 0.2.0 发行页](https://github.com/cuimino-kaziy/claudian-remote/releases/tag/0.2.0)。本版本的标签是 `0.2.0`，没有 `v` 前缀；旧 `v0.2.0-beta.6.7` 是另一个发行版。

## 插件

从 [Obsidian 社区插件目录](https://community.obsidian.md/plugins/claudian-remote) 安装和更新插件。如需手动安装，可从上述发行页取得 `main.js`、`manifest.json`、`styles.css`，将同一版本三份文件放入目标仓库的 `.obsidian/plugins/claudian-remote/`，保留已有 `data.json`，再启用或重新加载插件。Mac 与手机都应加载 **0.2.0**，并打开同一个已同步仓库。

## Mac 后台服务

1. 下载 `claudian-remote-kit-0.2.0.tar.gz` 和同页的 **`CLAUDIAN_REMOTE_INSTALL_VERIFICATION-0.2.0.md`**。
2. 打开外置校验说明。它包含本次实际完整 Kit 的 SHA-256、维护者签名公钥指纹，以及使用系统 `/usr/bin/shasum` 的精确命令。该说明不在 Kit 内，无需先运行下载包中的程序。
3. 先用系统工具核对完整 Kit；仅当结果匹配且命令成功退出，才解压到新目录。
4. 按包内 `CLAUDIAN_REMOTE_INSTALL.md` 执行。安装入口仍会验证 Ed25519 签名、固定公钥指纹、组件摘要和锁定依赖，不能关闭这些检查。

插件 ZIP、GitHub “Source code”、旧版 Kit 均不能替代这份后台服务包。签名或摘要不符时停止，不要改校验值来强行安装。

维护者公钥指纹：

```text
ace5a202634648deff4058a124e3d51c83554dd76a2a96f6b656e70ca8687023
```

首次下载以官方 GitHub 仓库身份为信任起点。这是同一来源的完整性校验，不是独立渠道验证，也不能防御发布账号本身失陷。已有用户可同时对照此前保存的可信指纹。无需邀请、私聊领取校验文件或另一套下载渠道。

## 升级与恢复

社区插件由 Obsidian 管理，Kit 不覆盖插件目录。先更新两端插件，再用匹配 Kit 更新后台服务；中间版本暂时不匹配时保持只读，正常升级保留原配对。仅市场插件存在而没有后台时，按首次安装后台处理。

已有未完成的安装操作应恢复原操作，不能新建操作覆盖它。后台卸载或回退不会删除或替换社区插件；如需移除插件，在 Obsidian 中操作。请先查看 [安装手册](../CLAUDIAN_REMOTE_INSTALL.md) 和 [故障排查](troubleshooting.md)。
