# 公开测试：下载与安装包校验

本版通过官方 GitHub 公开分发，免费下载，无需邀请、私聊领取校验文件或购买安装资格。模型服务、可选 VPS 与同步服务的费用由各提供方决定。

## 1. 确认官方入口

只从 [cuimino-kaziy/claudian-remote](https://github.com/cuimino-kaziy/claudian-remote) 的 [v0.2.0-beta.6.7 发布页](https://github.com/cuimino-kaziy/claudian-remote/releases/tag/v0.2.0-beta.6.7) 下载本版。

核对浏览器地址中的 `github.com`、账号 `cuimino-kaziy`、仓库 `claudian-remote` 和版本号；同名项目、第三方网盘、搜索广告或 fork 不自动视为官方来源。

首次安装以你确认的官方 GitHub 发布者身份为信任起点。本页与安装包都通过 GitHub 提供，属于同一信任来源，不能防御官方 GitHub 账号本身被攻破；它们不被描述为独立渠道。已有用户仍可与自己此前保存的签名指纹核对，发现变化时停止安装。

## 2. 下载完整包并核对摘要

首次安装和本次升级都使用：

```text
claudian-remote-recovery-kit-0.2.0-beta.6.7.tar.gz
```

完整包 SHA-256：

```text
14eb15669db2ccbd01023702ab6ea6a6ec140c7c168049257bcfc2859b933cd4
```

维护者 Ed25519 签名公钥指纹：

```text
ace5a202634648deff4058a124e3d51c83554dd76a2a96f6b656e70ca8687023
```

安装助手先使用 macOS 自带工具核对整个压缩包。**校验前不要解压，不运行包里的脚本。** 在下载文件所在目录执行以下检查，成功时会显示“安装包校验通过”，失败时退出状态为 1：

```sh
if test "$(shasum -a 256 'claudian-remote-recovery-kit-0.2.0-beta.6.7.tar.gz' | awk '{print $1}')" = '14eb15669db2ccbd01023702ab6ea6a6ec140c7c168049257bcfc2859b933cd4'; then
  echo '安装包校验通过'
else
  echo '校验失败，请停止安装并从官方发布页重新下载。' >&2
  exit 1
fi
```

不要把 `SHA256SUMS` 当作额外的独立信任来源；它用于核对本次下载文件的完整性。不要用 GitHub 自动生成的 “Source code”、同版本旧 Kit 或单独的插件 ZIP 代替完整包。

## 3. 校验通过后安装

将通过检查的 Kit 解压到一个新的目录，让本地安装助手按其中的 `CLAUDIAN_REMOTE_INSTALL.md` 操作。它仍须核对固定公钥指纹、Ed25519 签名、精确版本和组件摘要；任何不匹配都不能继续。

请按 [安装与连接指南](getting-started.md) 完成 Mac 服务配置、手机插件同步、一次性短码配对和最终核验。已有安装沿用升级流程，保留配对身份。

## 旧手册中的交付方式

这份公开测试说明替代旧包手册中“受邀内测”“必须通过私聊单独领取可信 Bootstrap”的分发要求。安装助手无需再要求用户提供私人联系渠道；先完成本页的官方来源确认与完整 Kit 校验即可进入包内安装流程。

其余安装、签名、版本、数据保护和恢复要求继续有效。已签名安装包保持原字节，其中的 `private_beta` 是沿用的安装器通道值，不是邀请鉴权；不要修改清单、跳过验签或改成 `community`。
