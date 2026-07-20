import { Platform, Plugin, PluginSettingTab, Setting } from "obsidian";
import { DesktopAdapter } from "./desktop-adapter.js";
import { LocalSseHub } from "./local-sse.js";
import { SourceCapture, discoverClaudianTabs } from "./source-capture.js";
import { SemanticStreamNormalizer } from "./stream-normalizer.js";
import { ClaudianRemoteMobileView, MOBILE_VIEW_TYPE } from "./mobile/view.js";
import { recoveryMetadata, restoreRecoveryMetadata } from "./mobile/persistence.js";
import { importFileIntoVault } from "./desktop/vault-import.js";

function id(prefix) {
  return `${prefix}-${globalThis.crypto?.randomUUID?.() || `${Date.now()}-${Math.random().toString(36).slice(2)}`}`;
}

function json(response, status, body) {
  response.status?.(status);
  response.statusCode = status;
  response.json?.(body);
  if (!response.json) response.end?.(JSON.stringify(body));
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
    this.sse = new LocalSseHub();
    this.normalizer = new SemanticStreamNormalizer({
      sourceInstanceId: id("bridge"),
      exactSecrets: this.sourceFirewallSecrets(),
      emit: (event) => this.sse.publish(event)
    });
    this.refreshRuntime();
    this.registerEvent(this.app.workspace.on("layout-change", () => this.refreshRuntime()));
    this.registerEvent(this.app.workspace.on("active-leaf-change", () => this.refreshRuntime()));
    this.registerEvent(this.app.workspace.on("obsidian-local-rest-api:loaded", () => this.registerRoutes()));
    this.registerInterval(globalThis.setInterval(() => this.refreshRuntime(), 2000));
    this.registerRoutes();
  }

  onunload() {
    this.capture?.unload();
    this.adapter?.unload?.();
    this.sse?.closeAll();
    this.normalizer?.dispose();
  }

  async loadSettings() {
    const data = await this.loadData() || {};
    this.privateData = data;
    this.settings = {
      relay_base_url: String(data.relay_base_url || data.relayUrl || "").replace(/\/+$/, ""),
      mobile_token: String(data.mobile_token || data.relayToken || ""),
      device_id: String(data.device_id || id("mobile-device")),
      client_instance_id: String(data.client_instance_id || id("mobile-view")),
      upload_directory: String(data.upload_directory || "Claudian Remote/Uploads")
    };
    if (!data.device_id || !data.client_instance_id) await this.saveSettings();
  }

  async saveSettings() {
    this.normalizer?.setExactSecrets(this.sourceFirewallSecrets());
    this.privateData = {
      ...this.privateData,
      relay_base_url: this.settings.relay_base_url,
      mobile_token: this.settings.mobile_token,
      device_id: this.settings.device_id,
      client_instance_id: this.settings.client_instance_id,
      upload_directory: this.settings.upload_directory
    };
    this.saveTail = (this.saveTail || Promise.resolve()).then(() => this.saveData(this.privateData));
    await this.saveTail;
  }

  sourceFirewallSecrets() {
    return new Set([this.settings?.mobile_token].filter(Boolean));
  }

  recoverySeed() {
    return restoreRecoveryMetadata(this.privateData?.remote_v2_recovery);
  }

  async saveRecovery(state) {
    this.privateData = { ...this.privateData, remote_v2_recovery: recoveryMetadata(state) };
    this.saveTail = (this.saveTail || Promise.resolve()).then(() => this.saveData(this.privateData));
    await this.saveTail;
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

  registerRoutes() {
    if (this.routesRegistered) return;
    const localRest = this.app.plugins?.plugins?.["obsidian-local-rest-api"];
    if (!localRest?.getPublicApi) return;
    try {
      const api = localRest.getPublicApi(this.manifest);
      api.addRoute("/claudian-remote/v2/events").get((request, response) => {
        const last = request.headers?.["last-event-id"] || request.get?.("Last-Event-ID") || 0;
        this.sse.open(response, last);
      });
      api.addRoute("/claudian-remote/v2/capabilities").get((_request, response) => {
        const tab = this.getActiveTab();
        json(response, 200, {
          ok: true, protocol: "claudian.remote.v2", mac_session_id: this.adapter?.macSessionId || null,
          mac_connection_generation: this.adapter?.connectionGeneration || null,
          revision: this.normalizer.revisionFor(tab?.conversationId || tab?.state?.currentConversationId || "conversation-pending"),
          capabilities: this.capture?.capabilities(tab) || {}, compatibility_mode: Boolean(this.capture?.compatibilityMode)
        });
      });
      api.addRoute("/claudian-remote/v2/transport/bind").post(async (request, response) => {
        try {
          const binding = this.adapter.bindTransport(request.body || {});
          const tab = this.getActiveTab();
          if (tab) {
            this.lastBootstrappedConversationId = tab?.conversationId || tab?.state?.currentConversationId || null;
            await this.capture.emitBootstrap(tab);
          }
          json(response, 200, { ok: true, binding });
        }
        catch (error) { json(response, 400, { ok: false, error: error?.message || "invalid_transport_binding" }); }
      });
      api.addRoute("/claudian-remote/v2/transport/invalidate").post((request, response) => {
        json(response, 200, { ok: true, invalidated: this.adapter.invalidateTransport(request.body || {}) });
      });
      api.addRoute("/claudian-remote/v2/command").post(async (request, response) => {
        try { json(response, 200, { ok: true, result: await this.adapter.execute(request.body || {}) }); }
        catch (error) { json(response, 400, { ok: false, error: error?.name || "command_failed" }); }
      });
      const keyframeHandler = async (_request, response) => {
        const tab = this.getActiveTab();
        if (!tab) return json(response, 503, { ok: false, error: "active_claudian_tab_required" });
        try {
          const result = await this.capture.emitBootstrap(tab);
          json(response, 200, { ok: true, ...result });
        } catch (error) {
          json(response, 500, { ok: false, error: error?.name || "keyframe_failed" });
        }
      };
      const keyframeRoute = api.addRoute("/claudian-remote/v2/keyframe");
      keyframeRoute.get(keyframeHandler);
      keyframeRoute.post(keyframeHandler);
      api.addRoute("/claudian-remote/v2/import").post(async (request, response) => {
        const tab = this.getActiveTab();
        if (!tab) return json(response, 503, { ok: false, error: "active_claudian_tab_required" });
        try {
          const result = await importFileIntoVault({
            app: this.app,
            body: request.body || {},
            directory: this.settings.upload_directory
          });
          const conversationId = tab?.conversationId || tab?.state?.currentConversationId || "conversation-pending";
          const turnId = tab?.state?.remoteTurnId || `turn-${conversationId}`;
          await this.normalizer.emit("artifact.available", { conversationId, turnId }, result);
          json(response, 200, { ok: true, result });
        } catch (error) {
          json(response, 400, { ok: false, error: error?.message || "vault_import_failed" });
        }
      });
      this.routesRegistered = true;
    } catch (error) {
      console.warn("Claudian Remote v2 routes unavailable", error?.name || "Error");
    }
  }
}
