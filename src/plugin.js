import { Notice, Platform, Plugin, PluginSettingTab, Setting, requestUrl } from "obsidian";
import { DesktopAdapter } from "./desktop/adapter.js";
import {
  CompanionChannel,
  DesktopBridgeRouter
} from "./desktop/companion-channel.js";
import { SourceCapture, discoverClaudianTabs } from "./source-capture.js";
import { SemanticStreamNormalizer } from "./stream-normalizer.js";
import { ClaudianRemoteMobileView, MOBILE_VIEW_TYPE } from "./mobile/view.js";
import {
  createOfflineReplicaCache,
  recoveryMetadata,
  restoreOfflineReplicaCache,
  restoreRecoveryMetadata
} from "./mobile/persistence.js";
import { importFileIntoVault } from "./desktop/vault-import.js";
import { COMPATIBILITY_SET, evaluateCompatibilitySet } from "./protocol/compatibility.js";
import { DeviceStore, migrateLegacySynchronizedState } from "./storage/device-store.js";
import { sanitizeSyncPreferences } from "./storage/sync-preferences.js";
import { MobilePairingController } from "./mobile/pairing-controller.js";
import { DesktopDeviceManager } from "./desktop/device-manager.js";
import { consumeBridgeBootstrap } from "./desktop/bridge-bootstrap.js";
import { CONNECTION_GUIDES, connectionErrorMessage, normalizeConnectionAddress } from "./settings/connection-guide.js";

function id(prefix) {
  return `${prefix}-${globalThis.crypto?.randomUUID?.() || `${Date.now()}-${Math.random().toString(36).slice(2)}`}`;
}

export class RemoteSettingsTab extends PluginSettingTab {
  constructor(app, plugin) { super(app, plugin); this.plugin = plugin; }

  async runPairingAction(button, action, success = "") {
    if (this.pairingBusy || this.busy) return;
    this.pairingBusy = true;
    button.setDisabled(true);
    const notice = new Notice("正在处理设备配对…", 0);
    try {
      await action();
      this.feedback = success;
    } catch (error) {
      this.feedback = connectionErrorMessage(error);
      this.plugin.showPairingError(error);
    } finally {
      notice.hide();
      button.setDisabled(false);
      this.pairingBusy = false;
      this.display();
    }
  }

  async runAction(action, success = "") {
    if (this.busy || this.pairingBusy) return;
    this.busy = true;
    try { await action(); this.feedback = success; }
    catch (error) { this.feedback = connectionErrorMessage(error); }
    finally { this.busy = false; this.display(); }
  }

  openSection(section, focus = false) {
    this.activeSection = section;
    this.display();
    if (focus) this.containerEl.querySelector(`[data-settings-tab="${section}"]`)?.focus();
  }

  group(parent, title) {
    const group = parent.createDiv({ cls: "claudian-remote-settings-group" });
    group.createEl("h3", { text: title });
    return group;
  }

  help(parent, title) {
    const details = parent.createEl("details", { cls: "claudian-remote-settings-help" });
    details.createEl("summary", { text: title });
    return details;
  }

  display() {
    this.containerEl.empty();
    const root = this.containerEl.createDiv({ cls: "claudian-remote-settings" });
    const tabs = [["connection", "连接"], ["devices", "设备"], ["help", "帮助"]];
    this.activeSection ||= "connection";
    const navigation = root.createEl("div", { cls: "claudian-remote-settings-tabs", attr: { role: "tablist", "aria-label": "Claudian Remote 设置" } });
    for (const [index, [key, label]] of tabs.entries()) {
      const selected = this.activeSection === key;
      const button = navigation.createEl("button", {
        text: label, cls: "claudian-remote-settings-tab",
        attr: { type: "button", role: "tab", id: `claudian-remote-settings-tab-${key}`, "data-settings-tab": key,
          "aria-selected": String(selected), "aria-controls": "claudian-remote-settings-panel", tabindex: selected ? "0" : "-1" }
      });
      button.addEventListener("click", () => this.openSection(key, true));
      button.addEventListener("keydown", (event) => {
        const next = event.key === "ArrowRight" ? (index + 1) % tabs.length
          : event.key === "ArrowLeft" ? (index + tabs.length - 1) % tabs.length
          : event.key === "Home" ? 0 : event.key === "End" ? tabs.length - 1 : -1;
        if (next < 0) return;
        event.preventDefault();
        this.openSection(tabs[next][0], true);
      });
    }
    const panel = root.createEl("div", { cls: "claudian-remote-settings-panel", attr: {
      role: "tabpanel", id: "claudian-remote-settings-panel", "aria-labelledby": `claudian-remote-settings-tab-${this.activeSection}`
    } });
    const feedback = this.pairingBusy ? "正在处理设备配对…" : this.busy ? "正在处理…" : this.feedback;
    if (feedback) panel.createEl("p", { cls: "claudian-remote-settings-feedback", text: feedback, attr: { role: "status", "aria-live": "polite" } });
    const profile = this.plugin.deviceStore.read("connection-profile") || {};
    const paired = Boolean(this.plugin.settings.mobile_token);
    if (this.activeSection === "devices") this.renderDevices(panel, paired);
    else if (this.activeSection === "help") this.renderHelp(panel);
    else this.renderConnection(panel, profile, paired);
    if (this.busy || this.pairingBusy) {
      for (const button of panel.querySelectorAll("button")) button.disabled = true;
    }
  }

  renderConnection(panel, profile, paired) {
    const boundEndpoint = profile.endpoint || "";
    new Setting(panel)
      .setName(paired ? "本设备已配对" : !Platform.isMobileApp && boundEndpoint ? "Mac 连接已配置" : "尚未配对")
      .setDesc(paired ? "可在远程页面查看连接状态。" : !Platform.isMobileApp
        ? "在“设备”中添加和管理手机。" : "填写连接地址后，在“设备”中完成配对。")
      .addButton((button) => button.setButtonText("打开远程页面").onClick(() => void this.plugin.openMobileView()));
    const connection = this.group(panel, "连接服务器");
    let address = boundEndpoint || (this.addressDraft ?? this.plugin.settings.relay_base_url);
    const addressSetting = new Setting(connection)
      .setName("服务器地址")
      .setDesc(boundEndpoint ? "由 Mac 安装配置提供。" : "复制 Mac 提供的完整 HTTPS 连接地址。")
      .addText((text) => text
        .setPlaceholder("https://你的Mac名称.你的网络.ts.net")
        .setValue(address)
        .setDisabled(Boolean(boundEndpoint))
        .onChange((value) => { address = value; this.addressDraft = value; }));
    if (!boundEndpoint) addressSetting.addButton((button) => button.setButtonText("保存地址").onClick(() => this.runAction(async () => {
      const submittedAddress = address;
      const normalized = normalizeConnectionAddress(submittedAddress);
      const previousAddress = this.plugin.settings.relay_base_url;
      this.plugin.settings.relay_base_url = normalized;
      try { await this.plugin.saveSettings(); }
      catch (error) {
        if (this.plugin.settings.relay_base_url === normalized) this.plugin.settings.relay_base_url = previousAddress;
        throw error;
      }
      if (this.addressDraft === submittedAddress) this.addressDraft = undefined;
    }, "地址已保存。接下来在“设备”中使用 Mac 生成的配对码。")));
    else addressSetting.addButton((button) => button.setButtonText("复制地址").onClick(() => this.runAction(
      () => navigator.clipboard.writeText(boundEndpoint), "连接地址已复制。"
    )));
    const help = this.help(connection, "连接地址设置帮助");
    help.createEl("p", { text: "Relay 是在手机与 Mac 之间转发消息的连接服务。这里填写它的 HTTPS 地址，不是模型地址、SSH 地址或配对码。" });
    help.createEl("pre").createEl("code", { text: `Tailscale：${CONNECTION_GUIDES.local_tailscale.example}\nVPS：${CONNECTION_GUIDES.remote_vps.example}` });
    help.createEl("p", { text: "示例不能直接连接。更换服务器需在 Mac 重新配置并配对，不能只改手机地址。首次安装的环境和步骤请查看“帮助”。" });
    const preferences = this.group(panel, "使用偏好");
    new Setting(preferences)
      .setName("附件导入目录")
      .setDesc("相对于当前仓库，由 Mac 端导入附件。")
      .addText((text) => text
        .setPlaceholder("Claudian Remote/Uploads")
        .setValue(this.plugin.settings.upload_directory)
        .onChange(async (value) => { this.plugin.settings.upload_directory = value.trim() || "Claudian Remote/Uploads"; await this.plugin.saveSettings(); }));
    new Setting(preferences)
      .setName("电脑端权限")
      .setDesc("沿用 Claudian 的权限模式。手机可回应当前审批，无需在这里切换全局权限。");
  }

  renderDevices(panel, paired) {
    const pairingGroup = this.group(panel, "设备配对");
    const pairing = new Setting(pairingGroup)
      .setName("移动设备配对")
      .setDesc(!Platform.isMobileApp ? "生成一次性配对码，手机填码后即可连接。"
        : paired ? "已配对，连接凭据保存在本设备；断线、重启和普通升级无需重新配对。" : "输入 Mac 上的一次性配对码。");
    if (Platform.isMobileApp) {
      let shortCode = this.shortCodeDraft || "";
      pairing.addText((text) => text
        .setPlaceholder("8 位配对码")
        .setValue(shortCode)
        .onChange((value) => { shortCode = value; this.shortCodeDraft = value; }));
      pairing.addButton((button) => button
        .setButtonText("配对")
        .onClick(() => this.runPairingAction(button, async () => {
          const submittedCode = shortCode;
          await this.plugin.mobilePairing.acceptShortCode(submittedCode);
          if (this.shortCodeDraft === submittedCode) this.shortCodeDraft = "";
          const result = await this.plugin.startMobilePairingPolling();
          if (result?.paired) await this.plugin.openMobileView();
        })));
    } else {
      pairing.addButton((button) => button
        .setButtonText("添加移动设备")
        .onClick(() => this.runPairingAction(button, () => this.plugin.createPairingClaim())));
      pairing.addExtraButton((button) => button
        .setIcon("refresh-cw")
        .setTooltip("刷新设备列表")
        .onClick(() => this.runPairingAction(button, () => this.plugin.refreshPairingManagementState(), "设备列表已刷新。")));
    }
    if (Platform.isMobileApp && this.plugin.mobilePairing?.pending) {
      new Setting(pairingGroup)
        .setName(this.plugin.mobilePairing.pending.status === "approved" ? "正在完成配对" : "旧版服务等待批准")
        .setDesc(this.plugin.mobilePairing.pending.status === "approved"
          ? "验证码已验证。若连接中断，可点“完成/刷新”重试。"
          : "请更新 Mac 后台服务后重新生成配对码；旧版请求仍可在 Mac 批准。")
        .addButton((button) => button.setButtonText("完成/刷新").setCta().onClick(() => this.runPairingAction(button, () => this.plugin.mobilePairing.complete())))
        .addButton((button) => button.setButtonText("取消").onClick(() => {
          this.plugin.mobilePairing.cancel();
          this.display();
        }));
    }
    const claim = this.plugin.currentPairingClaim();
    if (claim) {
      new Setting(pairingGroup)
        .setName(`配对码：${claim.short_code}`)
        .setDesc("5 分钟内有效，仅可使用一次。手机填码或打开配对链接后即可连接。")
        .addButton((button) => button.setButtonText("复制配对链接").onClick(() => this.runAction(
          () => navigator.clipboard.writeText(claim.deep_link), "配对链接已复制，请在手机上打开。"
        )));
    }
    const help = this.help(pairingGroup, "设备配对设置帮助");
    help.createEl("p", { text: Platform.isMobileApp
      ? "先在“连接”中保存服务器地址。在 Mac 点击“添加移动设备”，把 8 位配对码填入上方即可连接。也可以直接在手机打开 Mac 生成的配对链接，地址会自动带入。"
      : "点击“添加移动设备”，用 AirDrop 或设备间剪贴板将配对链接带到手机；也可以让手机填写连接地址和 8 位配对码。验证成功后自动连接，可在下方管理已配对设备。" });
    help.createEl("p", { text: "手机和 Mac 需打开同一个已同步的 Obsidian 仓库。配对链接是短时凭据，请勿公开分享。" });
    if (this.plugin.pendingPairingClaims?.length) {
      const pendingGroup = this.group(panel, "旧版待批准请求");
      for (const pending of this.plugin.pendingPairingClaims) {
        new Setting(pendingGroup)
          .setName(pending.device_name || "待审批移动设备")
          .setDesc(`设备 ID：${pending.device_id}`)
          .addButton((button) => button.setButtonText("批准").setCta().onClick(() => this.runPairingAction(button,
            () => this.plugin.approvePairingClaim(pending.claim_id, pending.device_id), "设备已批准，请在手机打开远程页面。"
          )))
          .addButton((button) => button.setButtonText("拒绝").onClick(() => this.runPairingAction(button,
            () => this.plugin.rejectPairingClaim(pending.claim_id), "配对请求已拒绝。"
          )));
      }
    }
    if (this.plugin.pairedDevices?.length) {
      const devicesGroup = this.group(panel, "已配对设备");
      for (const device of this.plugin.pairedDevices) {
        new Setting(devicesGroup)
          .setName(device.device_name || "移动设备")
          .setDesc(`${device.device_id} · ${device.status === "active" ? "已配对" : "已撤销"}`)
          .addButton((button) => button
            .setButtonText(device.status === "active" ? "撤销" : "已撤销")
            .setDisabled(device.status !== "active")
            .onClick(() => this.runPairingAction(button, () => this.plugin.revokePairedDevice(device.device_id), "设备已撤销，需要重新配对才能连接。")));
      }
    }
  }

  renderHelp(panel) {
    const installation = this.group(panel, "安装与连接");
    const downloads = new Setting(installation).setName("安装包与插件").setDesc(`当前版本 ${COMPATIBILITY_SET.plugin}。Mac 后台服务与插件需使用匹配版本。`);
    downloads.controlEl.createEl("a", { text: "打开下载页", href: "https://github.com/cuimino-kaziy/claudian-remote/releases", attr: { target: "_blank", rel: "noopener noreferrer" } });
    for (const [mode, guide] of Object.entries(CONNECTION_GUIDES)) {
      const help = this.help(installation, mode === "remote_vps" ? "VPS 设置帮助" : "Tailscale 设置帮助");
      help.createEl("p", { text: guide.summary });
      const steps = help.createEl("ol");
      for (const step of guide.steps) steps.createEl("li", { text: step });
      help.createEl("pre").createEl("code", { text: guide.example });
      help.createEl("p", { text: guide.help });
      help.createEl("a", {
        text: mode === "remote_vps" ? "VPS 环境、部署与字段说明" : "完整安装与配对手册",
        href: `https://github.com/cuimino-kaziy/claudian-remote/blob/v${COMPATIBILITY_SET.plugin}/${mode === "remote_vps" ? "docs/self-host-vps.md" : "CLAUDIAN_REMOTE_INSTALL.md"}`,
        attr: { target: "_blank", rel: "noopener noreferrer" }
      });
    }
    const troubleshooting = this.group(panel, "使用与排查");
    const help = this.help(troubleshooting, "连接异常排查帮助");
    help.createEl("p", { text: "Mac 需要保持开机、登录和唤醒，并运行 Obsidian、Claudian 与后台服务。Mac 离线时，手机只能阅读已同步内容。" });
    help.createEl("p", { text: "Tailscale 连接请先检查两台设备是否已连接同一个 Tailscale 网络；VPS 连接请检查域名、HTTPS 和 Relay 服务。打开远程页面后，点击顶部连接状态可查看具体原因。" });
  }

}

export default class ClaudianRemotePlugin extends Plugin {
  async onload() {
    await this.loadSettings();
    if (!Platform.isMobileApp) await this.consumeLifecycleBridgeBootstrap();
    this.initializePairing();
    this.registerObsidianProtocolHandler("claudian-remote", (params) => {
      if (!Platform.isMobileApp) return;
      void this.mobilePairing.acceptProtocolParams(params).then(async () => {
        const result = await this.startMobilePairingPolling();
        if (result?.paired) return this.openMobileView();
      }).catch((error) => {
        this.showPairingError(error);
        this.openConnectionSettings(connectionErrorMessage(error));
      });
    });
    this.registerView(MOBILE_VIEW_TYPE, (leaf) => new ClaudianRemoteMobileView(leaf, this));
    this.addCommand({ id: "open-claudian-remote", name: "打开 Claudian Remote", callback: () => void this.openMobileView() });
    this.remoteSettingsTab = new RemoteSettingsTab(this.app, this);
    this.addSettingTab(this.remoteSettingsTab);
    if (Platform.isMobileApp) this.addRibbonIcon("message-circle", "Claudian Remote", () => void this.openMobileView());
    if (Platform.isMobileApp) return;
    this.normalizer = new SemanticStreamNormalizer({
      sourceInstanceId: id("bridge"),
      exactSecrets: this.sourceFirewallSecrets(),
      emit: (event) => this.companionChannel?.publish(event)
    });
    this.refreshRuntime();
    this.registerEvent(this.app.workspace.on("layout-change", () => this.refreshRuntime()));
    this.registerEvent(this.app.workspace.on("active-leaf-change", () => this.refreshRuntime()));
    this.registerInterval(globalThis.setInterval(() => this.refreshRuntime(), 2000));
  }

  onunload() {
    this.capture?.unload();
    this.adapter?.unload?.();
    this.companionChannel?.disconnect();
    this.normalizer?.dispose();
    this.mobilePairing?.dispose();
  }

  async loadSettings() {
    const data = await this.loadData() || {};
    const initialSyncPreferences = sanitizeSyncPreferences(data);
    if (!initialSyncPreferences.vault_id) initialSyncPreferences.vault_id = id("vault");
    this.deviceStore = new DeviceStore({
      namespace: `claudian-remote:${this.manifest.id}:${initialSyncPreferences.vault_id}`
    });
    let migration;
    try {
      migration = await migrateLegacySynchronizedState({
        synchronized: data,
        deviceStore: this.deviceStore,
        // The signed lifecycle must revoke a legacy shared credential at its
        // authoritative Relay before this device-local migration can commit.
        // A plugin-only upgrade cannot prove that, so it fails closed and
        // requires the guided lifecycle/re-pairing path.
        revokeLegacyCredential: async () => false
      });
    } catch {
      migration = { synchronized: sanitizeSyncPreferences(data), rePairRequired: true };
    }
    this.syncedSettings = { ...migration.synchronized, vault_id: initialSyncPreferences.vault_id };
    const identity = this.deviceStore.read("identity") || {};
    const localPreferences = this.deviceStore.read("local-preferences") || {};
    this.settings = {
      relay_base_url: String(localPreferences.relay_base_url || "").replace(/\/+$/, ""),
      mobile_token: migration.rePairRequired ? "" : String(identity.mobile_token || ""),
      device_id: migration.rePairRequired ? id("mobile-device") : String(identity.device_id || id("mobile-device")),
      client_instance_id: migration.rePairRequired ? id("mobile-view") : String(identity.client_instance_id || id("mobile-view")),
      upload_directory: String(localPreferences.upload_directory || "Claudian Remote/Uploads"),
      notifications_enabled: this.syncedSettings.notifications_enabled,
      haptics_enabled: this.syncedSettings.haptics_enabled,
      re_pair_required: migration.rePairRequired === true
    };
    await this.saveSettings();
  }

  async saveSettings() {
    this.normalizer?.setExactSecrets(this.sourceFirewallSecrets());
    this.syncedSettings = sanitizeSyncPreferences({
      ...this.syncedSettings,
      notifications_enabled: this.settings.notifications_enabled,
      haptics_enabled: this.settings.haptics_enabled
    });
    const identitySaved = this.deviceStore.write("identity", {
      ...(this.deviceStore.read("identity") || {}),
      mobile_token: this.settings.mobile_token,
      device_id: this.settings.device_id,
      client_instance_id: this.settings.client_instance_id
    });
    const preferencesSaved = this.deviceStore.write("local-preferences", {
      relay_base_url: this.settings.relay_base_url,
      upload_directory: this.settings.upload_directory
    });
    if (!identitySaved || !preferencesSaved) {
      this.settings.mobile_token = "";
      this.settings.re_pair_required = true;
    }
    this.saveTail = (this.saveTail || Promise.resolve()).then(() => this.saveData(this.syncedSettings));
    await this.saveTail;
  }

  sourceFirewallSecrets() {
    const bridge = this.deviceStore?.read("bridge-identity") || {};
    const pairingAdmin = this.deviceStore?.read("pairing-admin-identity") || {};
    return new Set([
      this.settings?.mobile_token,
      bridge.secret,
      pairingAdmin.secret,
      this.mobilePairing?.pending?.redemption_handle
    ].filter(Boolean));
  }

  pairingProfile() {
    const profile = this.deviceStore.read("connection-profile") || {};
    return {
      ...profile,
      relay_base_url: profile.endpoint || this.settings.relay_base_url,
      vault_id: profile.vault_id || this.syncedSettings.vault_id
    };
  }

  initializePairing() {
    this.mobilePairing = new MobilePairingController({
      requestImpl: requestUrl,
      profileProvider: () => this.pairingProfile(),
      deviceStore: this.deviceStore,
      deviceContext: () => ({
        device_id: this.settings.device_id,
        device_name: Platform.isIosApp ? "iPhone / iPad" : "Mobile Obsidian"
      }),
      onPaired: () => {
        const identity = this.deviceStore.read("identity") || {};
        const profile = this.deviceStore.read("connection-profile") || {};
        this.settings.mobile_token = String(identity.mobile_token || "");
        this.settings.device_id = String(identity.device_id || this.settings.device_id);
        this.settings.client_instance_id = String(identity.client_instance_id || this.settings.client_instance_id);
        this.settings.re_pair_required = false;
        this.settings.relay_base_url = String(profile.endpoint || this.settings.relay_base_url).replace(/\/+$/, "");
        void this.saveSettings();
      }
    });
    if (!Platform.isMobileApp) {
      this.deviceManager = new DesktopDeviceManager({
        managementRequest: (operation, payload) => {
          if (!this.companionChannel) throw new Error("bridge_not_ready");
          return this.companionChannel.management(operation, payload);
        }
      });
      this.pendingPairingClaims = [];
      this.pairedDevices = [];
    }
  }

  async consumeLifecycleBridgeBootstrap() {
    let bootstrap;
    try {
      bootstrap = consumeBridgeBootstrap({ expectedVaultId: this.syncedSettings.vault_id });
    }
    catch (error) {
      console.warn("Claudian Remote secure bootstrap failed", error?.message || "bridge_bootstrap_invalid");
      return false;
    }
    if (!bootstrap) return false;
    this.syncedSettings = { ...this.syncedSettings, vault_id: bootstrap.vault_id };
    this.deviceStore = new DeviceStore({
      namespace: `claudian-remote:${this.manifest.id}:${bootstrap.vault_id}`
    });
    const profileSaved = this.deviceStore.installBridgeProfile({
      bridgeIdentity: {
        credential_id: bootstrap.credential_id,
        secret: bootstrap.secret
      },
      connectionProfile: {
        schema_version: 1,
        mode: "local_tailscale",
        installation_id: bootstrap.installation_id,
        vault_id: bootstrap.vault_id,
        endpoint: bootstrap.endpoint,
        endpoint_audience: bootstrap.endpoint_audience
      },
      retireNames: ["pairing-admin-identity"]
    });
    if (!profileSaved) throw new Error("device_local_persistence_unavailable");
    this.settings.relay_base_url = bootstrap.endpoint;
    const preferences = this.deviceStore.read("local-preferences") || {};
    this.settings.upload_directory = String(preferences.upload_directory || this.settings.upload_directory || "Claudian Remote/Uploads");
    await this.saveSettings();
    return true;
  }

  showPairingError(error) {
    const messages = {
      pairing_endpoint_missing: "请先填写 Relay 地址。",
      pairing_endpoint_invalid: "Relay 地址必须是有效的 HTTPS 地址。",
      pairing_short_code_missing: "请先输入 Mac 上的配对码。",
      claim_expired: "配对码已过期，请在 Mac 生成新码。",
      claim_replayed: "配对码已使用，请在 Mac 生成新码。",
      claim_invalid: "配对码无效，请检查或在 Mac 生成新码。",
      attempt_limit_exceeded: "尝试次数过多，请稍后在 Mac 生成新码。",
      credential_delivery_expired: "配对已过期，请在 Mac 生成新码。",
      device_local_persistence_unavailable: "本设备无法保存连接凭据，请检查 Obsidian 的存储权限后重新配对。",
      pairing_wrong_vault: "请打开与 Mac 同步的同一个仓库。",
      wrong_vault: "请打开与 Mac 同步的同一个仓库。",
      pairing_request_timeout: "连接超时，请检查 Relay 地址和两端的 Tailscale 连接。"
    };
    new Notice(`配对失败：${messages[error?.message] || "请检查 Relay 地址和两端的 Tailscale 连接后重试。"}`, 10000);
  }

  startMobilePairingPolling() {
    if (!this.mobilePairing?.pending) return;
    return this.mobilePairing.pollUntilComplete({ intervalMs: 1000, maxAttempts: 60 })
      .then((result) => {
        if (result.paired) new Notice("配对成功，正在连接 Claudian Remote。");
        return result;
      });
  }

  currentPairingClaim() {
    this.deviceManager?.clearExpired();
    return this.deviceManager?.activeClaim ? { ...this.deviceManager.activeClaim } : null;
  }

  async createPairingClaim() {
    if (!this.deviceManager) throw new Error("pairing_admin_unavailable");
    return this.deviceManager.createClaim();
  }

  async refreshPendingPairingClaims() {
    this.pendingPairingClaims = this.deviceManager ? await this.deviceManager.pending() : [];
    return this.pendingPairingClaims;
  }

  async refreshPairingManagementState() {
    if (!this.deviceManager) return { claims: [], devices: [] };
    const [claims, devices] = await Promise.all([
      this.deviceManager.pending(),
      this.deviceManager.devices()
    ]);
    this.pendingPairingClaims = claims;
    this.pairedDevices = devices;
    return { claims, devices };
  }

  async approvePairingClaim(claimId, deviceId) {
    const result = await this.deviceManager.approve(claimId, deviceId);
    await this.refreshPairingManagementState();
    return result;
  }

  async rejectPairingClaim(claimId) {
    const result = await this.deviceManager.reject(claimId);
    await this.refreshPendingPairingClaims();
    return result;
  }

  async revokePairedDevice(deviceId) {
    const result = await this.deviceManager.revoke(deviceId, "revoked");
    await this.refreshPairingManagementState();
    return result;
  }

  recoverySeed() {
    const cache = restoreOfflineReplicaCache(this.deviceStore.read("offline-cache"));
    const recovery = restoreRecoveryMetadata(this.deviceStore.read("recovery"));
    return { ...cache, ...recovery, relay: recovery.relay, commands: {} };
  }

  async saveRecovery(state) {
    const recoverySaved = this.deviceStore.write("recovery", recoveryMetadata(state));
    const cacheSaved = this.deviceStore.write("offline-cache", createOfflineReplicaCache(state));
    if (!recoverySaved || !cacheSaved) throw new Error("device_local_persistence_unavailable");
  }

  clearDeviceStateForRevocation() {
    this.settings.mobile_token = "";
    this.settings.re_pair_required = true;
    return this.deviceStore.clearRevokedDevice();
  }

  purgeDeviceLocalState() {
    this.settings.mobile_token = "";
    this.settings.re_pair_required = true;
    return this.deviceStore.clearRemoteState({ includeMigration: true });
  }

  openConnectionSettings(message = "") {
    if (message && this.remoteSettingsTab) this.remoteSettingsTab.feedback = message;
    this.app.setting?.open?.();
    this.app.setting?.openTabById?.(this.manifest.id);
  }

  async openMobileView() {
    const existing = this.app.workspace.getLeavesOfType(MOBILE_VIEW_TYPE)[0];
    const leaf = existing || this.app.workspace.getLeaf("tab");
    if (!existing) await leaf.setViewState({ type: MOBILE_VIEW_TYPE, active: true });
    this.app.setting?.close?.();
    this.app.workspace.revealLeaf(leaf);
  }

  getClaudian() {
    const plugins = this.app.plugins?.plugins;
    return plugins?.realclaudian || plugins?.claudian || null;
  }

  getActiveTab() {
    return discoverClaudianTabs(this.getClaudian())[0] || null;
  }

  refreshRuntime() {
    const claudian = this.getClaudian();
    if (!claudian) return;
    if (!this.capture || this.capture.claudian !== claudian) {
      this.capture?.unload();
      this.adapter?.unload?.();
      this.capture = new SourceCapture({
        claudian,
        normalizer: this.normalizer,
        diagnostic: (item) => console.warn("Claudian Remote compatibility event", item.type, item.error_type || item.reason || "")
      });
      this.adapter = new DesktopAdapter({
        claudian, capture: this.capture, getActiveTab: () => this.getActiveTab(),
        macSessionId: null, connectionGeneration: null
      });
      this.companionChannel?.disconnect();
      this.bridgeRouter = new DesktopBridgeRouter({
        adapter: this.adapter,
        capture: this.capture,
        getActiveTab: () => this.getActiveTab(),
        evaluateCompatibility: evaluateCompatibilitySet,
        componentSet: COMPATIBILITY_SET,
        importUpload: async (body) => {
          const tab = this.getActiveTab();
          if (!tab) throw new Error("active_claudian_tab_required");
          const result = await importFileIntoVault({ app: this.app, body, directory: this.settings.upload_directory });
          const conversationId = tab?.conversationId || tab?.state?.currentConversationId || "conversation-pending";
          const turnId = tab?.state?.remoteTurnId || `turn-${conversationId}`;
          await this.normalizer.emit("artifact.available", { conversationId, turnId }, result);
          return result;
        }
      });
      this.companionChannel = new CompanionChannel({
        credentialProvider: async () => this.deviceStore.read("bridge-identity"),
        router: this.bridgeRouter,
        diagnostic: (item) => console.warn("Claudian Remote bridge event", item.type)
      });
      if (this.deviceStore.read("bridge-identity")) this.companionChannel.connect();
    }
    const tabs = discoverClaudianTabs(claudian);
    this.capture.refresh(tabs);
    this.adapter.refreshApprovals(tabs);
    if (this.companionChannel?.authenticated && this.bridgeRouter?.refreshCompatibility()) {
      this.companionChannel.connect();
    }
    const active = tabs[0];
    const conversationId = active?.conversationId || active?.state?.currentConversationId || (active ? "conversation-pending" : null);
    if (this.adapter?.macSessionId && conversationId && conversationId !== this.lastBootstrappedConversationId) {
      this.lastBootstrappedConversationId = conversationId;
      void this.capture.emitBootstrap(active).catch((error) => {
        console.warn("Claudian Remote bootstrap failed", error?.name || "Error");
      });
    }
  }

  installBridgeIdentity(identity, { confirmed = false } = {}) {
    if (!confirmed || !identity?.credential_id || !identity?.secret) {
      throw new Error("bridge_bootstrap_not_confirmed");
    }
    if (!this.deviceStore.write("bridge-identity", {
      credential_id: String(identity.credential_id),
      secret: String(identity.secret)
    })) throw new Error("device_local_persistence_unavailable");
    this.normalizer?.setExactSecrets(this.sourceFirewallSecrets());
    this.companionChannel?.connect();
    return { installed: true };
  }
}
