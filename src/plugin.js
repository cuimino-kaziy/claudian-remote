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

function id(prefix) {
  return `${prefix}-${globalThis.crypto?.randomUUID?.() || `${Date.now()}-${Math.random().toString(36).slice(2)}`}`;
}

class RemoteSettingsTab extends PluginSettingTab {
  constructor(app, plugin) { super(app, plugin); this.plugin = plugin; }

  async runPairingAction(button, action) {
    if (this.pairingBusy) return;
    this.pairingBusy = true;
    button.setDisabled(true);
    const notice = new Notice("正在处理设备配对…", 0);
    try {
      await action();
      this.display();
    } catch (error) {
      this.plugin.showPairingError(error);
    } finally {
      notice.hide();
      button.setDisabled(false);
      this.pairingBusy = false;
    }
  }

  display() {
    this.containerEl.empty();
    this.containerEl.createEl("h2", { text: "Claudian Remote" });
    this.containerEl.createEl("p", { text: "手机端直接连接 Relay；Mac 离线时仅保留已同步内容，不会排队补发。" });
    new Setting(this.containerEl)
      .setName("Relay 地址")
      .setDesc("例如 https://relay.example.com，凭据不会放入 WebSocket 链接。")
      .addText((text) => text
        .setPlaceholder("https://relay.example.com")
        .setValue(this.plugin.settings.relay_base_url)
        .onChange(async (value) => { this.plugin.settings.relay_base_url = value.trim().replace(/\/+$/, ""); await this.plugin.saveSettings(); }));
    const pairing = new Setting(this.containerEl)
      .setName("移动设备配对")
      .setDesc(this.plugin.settings.mobile_token ? "已配对；凭据仅保存在本设备。" : "未配对；不再手工填写共享 token。");
    if (Platform.isMobileApp) {
      let shortCode = "";
      pairing.addText((text) => text
        .setPlaceholder("8 位配对码")
        .onChange((value) => { shortCode = value; }));
      pairing.addButton((button) => button
        .setButtonText("配对")
        .onClick(() => this.runPairingAction(button, async () => {
          await this.plugin.mobilePairing?.acceptShortCode(shortCode);
          this.plugin.startMobilePairingPolling();
        })));
    } else {
      pairing.addButton((button) => button
        .setButtonText("添加移动设备")
        .onClick(() => this.runPairingAction(button, async () => {
          await this.plugin.createPairingClaim();
        })));
    }
    if (Platform.isMobileApp && this.plugin.mobilePairing?.pending) {
      new Setting(this.containerEl)
        .setName("等待 Mac 批准")
        .setDesc("批准后点“完成/刷新”；页面保持打开时也会有界自动检查。")
        .addButton((button) => button.setButtonText("完成/刷新").setCta().onClick(() => this.runPairingAction(button, async () => {
          await this.plugin.mobilePairing.complete();
        })))
        .addButton((button) => button.setButtonText("取消").onClick(() => {
          this.plugin.mobilePairing.cancel();
          this.display();
        }));
    }
    const claim = this.plugin.currentPairingClaim();
    if (claim) {
      this.containerEl.createEl("p", { text: `配对码：${claim.short_code}（过期后自动清除）` });
      const link = this.containerEl.createEl("a", { text: "在移动端 Obsidian 打开", href: claim.deep_link });
      link.setAttr("rel", "noreferrer");
    }
    for (const pending of this.plugin.pendingPairingClaims || []) {
      new Setting(this.containerEl)
        .setName(pending.device_name || "待审批移动设备")
        .setDesc(`设备 ID：${pending.device_id}`)
        .addButton((button) => button.setButtonText("批准").setCta().onClick(() => this.runPairingAction(button, async () => {
          await this.plugin.approvePairingClaim(pending.claim_id, pending.device_id);
        })))
        .addButton((button) => button.setButtonText("拒绝").onClick(() => this.runPairingAction(button, async () => {
          await this.plugin.rejectPairingClaim(pending.claim_id);
        })));
    }
    for (const device of this.plugin.pairedDevices || []) {
      new Setting(this.containerEl)
        .setName(device.device_name || "移动设备")
        .setDesc(`${device.device_id} · ${device.status === "active" ? "已配对" : "已撤销"}`)
        .addButton((button) => button
          .setButtonText(device.status === "active" ? "撤销" : "已撤销")
          .setDisabled(device.status !== "active")
          .onClick(() => this.runPairingAction(button, async () => {
            await this.plugin.revokePairedDevice(device.device_id);
          })));
    }
    if (!Platform.isMobileApp) pairing.addExtraButton((button) => button
      .setIcon("refresh-cw")
      .setTooltip("刷新待审批设备")
      .onClick(() => this.runPairingAction(button, async () => {
        await this.plugin.refreshPairingManagementState();
      })));
    new Setting(this.containerEl)
      .setName("附件导入目录")
      .setDesc("相对于当前 Vault，只由 Mac 端导入器写入。")
      .addText((text) => text
        .setPlaceholder("Claudian Remote/Uploads")
        .setValue(this.plugin.settings.upload_directory)
        .onChange(async (value) => { this.plugin.settings.upload_directory = value.trim() || "Claudian Remote/Uploads"; await this.plugin.saveSettings(); }));
    new Setting(this.containerEl)
      .setName("电脑端权限")
      .setDesc("沿用电脑端 Claudian 的默认权限模式；手机端可回应当前审批，但不提供全局权限切换。");
  }
}

export default class ClaudianRemotePlugin extends Plugin {
  async onload() {
    await this.loadSettings();
    if (!Platform.isMobileApp) await this.consumeLifecycleBridgeBootstrap();
    this.initializePairing();
    this.registerObsidianProtocolHandler("claudian-remote", (params) => {
      if (!Platform.isMobileApp) return;
      void this.mobilePairing.acceptProtocolParams(params).then(() => {
        this.startMobilePairingPolling();
        return this.openMobileView();
      }).catch((error) => this.showPairingError(error));
    });
    this.registerView(MOBILE_VIEW_TYPE, (leaf) => new ClaudianRemoteMobileView(leaf, this));
    this.addCommand({ id: "open-claudian-remote", name: "打开 Claudian Remote", callback: () => void this.openMobileView() });
    this.addSettingTab(new RemoteSettingsTab(this.app, this));
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
      pairing_wrong_vault: "请打开与 Mac 同步的同一个仓库。",
      wrong_vault: "请打开与 Mac 同步的同一个仓库。",
      pairing_request_timeout: "连接超时，请检查 Relay 地址和两端的 Tailscale 连接。"
    };
    new Notice(`配对失败：${messages[error?.message] || "请检查 Relay 地址和两端的 Tailscale 连接后重试。"}`, 10000);
  }

  startMobilePairingPolling() {
    if (!this.mobilePairing?.pending) return;
    return this.mobilePairing.pollUntilComplete({ intervalMs: 1000, maxAttempts: 60 })
      .then((result) => { if (result.paired) new Notice("配对成功，可以打开 Claudian Remote。"); })
      .catch((error) => this.showPairingError(error));
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

  async openMobileView() {
    const existing = this.app.workspace.getLeavesOfType(MOBILE_VIEW_TYPE)[0];
    const leaf = existing || this.app.workspace.getLeaf("tab");
    if (!existing) await leaf.setViewState({ type: MOBILE_VIEW_TYPE, active: true });
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
    const active = tabs[0];
    const conversationId = active?.conversationId || active?.state?.currentConversationId || null;
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
