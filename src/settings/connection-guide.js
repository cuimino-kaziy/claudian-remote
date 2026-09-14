export const CONNECTION_GUIDES = {
  local_tailscale: {
    name: "Tailscale 私有连接（推荐）",
    example: "https://你的Mac名称.你的网络.ts.net",
    summary: "不需要购买服务器。手机通过 Tailscale 私有网络连接你的 Mac。",
    steps: [
      "在 Mac 和手机安装 Tailscale，登录同一个账号，并在两台设备上打开连接。",
      "在 Mac 打开同一个 Obsidian 仓库，确认 Claudian 可以正常对话，再完成 Mac 安装包中的后台服务安装。Mac 需要保持开机、登录和唤醒。",
      "按安装引导启用 Tailscale 的 MagicDNS 和 HTTPS。安装完成后，从 Mac 的连接设置复制完整 HTTPS 地址；不需要填写 IP 或端口。",
      "在手机打开 Mac 生成的配对链接，或保存下方连接地址后输入 8 位配对码。验证通过后会自动配对并连接。"
    ],
    help: "两台设备需要处于同一个 Tailscale 网络。连接失败时先检查 Tailscale 是否已连接，以及 Mac 是否睡眠。"
  },
  remote_vps: {
    name: "已有 VPS 服务器",
    example: "https://relay.你的域名.com",
    summary: "手机和 Mac 通过你自己的服务器连接。服务器只负责转发，Claudian 仍在 Mac 上运行。",
    steps: [
      "准备受支持的 Linux VPS、至少 2 GiB 可用存储、你控制的域名和有效 HTTPS 证书；需要有人能够通过 SSH 管理这台服务器。",
      "部署与插件匹配的 Relay 服务，配置域名和 HTTPS / WebSocket 转发，再把 Mac 后台服务连接到同一服务器。详细字段和现有模板见 VPS 手册。",
      "让部署者提供完整 HTTPS 连接地址。在手机填写该地址，或直接打开 Mac 生成的配对链接。不要填写 SSH 地址、服务器密码或模型 API Key。",
      "输入 Mac 上的 8 位配对码，验证通过后会自动配对并连接，再打开远程页面确认已就绪。"
    ],
    help: "本页可连接已经部署的 VPS。当前内测安装器尚未开放 VPS 自动部署；选择此说明不会迁移现有连接。VPS 管理者能够访问经过服务器转发的内容。"
  }
};

export function normalizeConnectionAddress(value) {
  const text = String(value || "").trim().replace(/\/+$/, "");
  if (!text) throw new Error("pairing_endpoint_missing");
  let url;
  try { url = new URL(text); } catch { throw new Error("pairing_endpoint_invalid"); }
  if (url.protocol !== "https:" || !url.hostname || url.username || url.password || url.search || url.hash) {
    throw new Error("pairing_endpoint_invalid");
  }
  return text;
}

export function connectionErrorMessage(error) {
  const code = String(error?.message || "");
  if (code === "pairing_endpoint_missing") return "请先复制 Mac 上的连接地址，填写并保存后再配对。";
  if (code === "pairing_endpoint_invalid") return "请填写完整的 https:// 地址，不要包含密码、配对码或问号后的参数。";
  if (code === "pairing_short_code_missing") return "请输入 Mac 上显示的 8 位配对码。";
  if (["claim_expired", "claim_replayed", "claim_not_found", "credential_delivery_expired"].includes(code)) {
    return "配对码已失效或已使用。请在 Mac 点击“添加移动设备”，使用新生成的配对码。";
  }
  if (["pairing_wrong_vault", "pairing_vault_missing"].includes(code)) return "请先在手机打开与 Mac 相同、已同步的 Obsidian 仓库，再重新配对。";
  if (["pairing_wrong_installation", "pairing_wrong_audience", "pairing_admin_profile_mismatch"].includes(code)) {
    return "此配对信息属于另一套连接。请使用当前 Mac 生成的链接；更换服务器需要重新配置和配对。";
  }
  if (["bridge_not_ready", "pairing_admin_unavailable", "bridge_disconnected", "bridge_not_connected"].includes(code)) {
    return "Mac 后台服务尚未就绪。请打开 Claudian 和已安装的后台服务，再刷新设备列表。首次使用请先完成 Mac 安装。";
  }
  if (code === "device_local_persistence_unavailable") return "本设备无法保存配对信息。请重启 Obsidian 后重试。";
  return "操作未完成。请检查连接地址、Tailscale 或 VPS 是否可达，以及 Mac 后台服务是否运行，然后重试。";
}
