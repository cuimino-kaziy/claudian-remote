import { Platform, Plugin, PluginSettingTab, Setting } from "obsidian";
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

function id(prefix) {
  return `${prefix}-${globalThis.crypto?.randomUUID?.() || `${Date.now()}-${Math.random().toString(36).slice(2)}`}`;
}

class RemoteSettingsTab extends PluginSettingTab {
  constructor(app, plugin) { super(app, plugin); this.plugin = plugin; }

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
    new Setting(this.containerEl)
      .setName("手机端访问凭据")
      .setDesc("只用于向 Relay 领取一次性连接票据。")
      .addText((text) => {
        text.inputEl.type = "password";
        text.setValue(this.plugin.settings.mobile_token)
          .onChange(async (value) => { this.plugin.settings.mobile_token = value.trim(); await this.plugin.saveSettings(); });
      });
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
        // U6 supplies the Relay-side revocation operation. U3 deliberately
        // invalidates the local copy and records the one-time migration gate.
        revokeLegacyCredential: async () => {}
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
    return new Set([this.settings?.mobile_token, bridge.secret].filter(Boolean));
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
