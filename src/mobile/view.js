import { ItemView, Notice, requestUrl } from "obsidian";
import { MobileReplica } from "./reducer.js";
import { RemoteClient } from "./remote-client.js";
import { MobileRecoveryController } from "./recovery.js";
import { buildCommand, createDeliveryId } from "./command-builder.js";
import { activeConversationModel } from "./view-model.js";
import { classifyLink, handleContentAction } from "./link-actions.js";
import { element, button } from "./dom.js";
import { AttachmentController } from "./attachment-controller.js";
import { createObsidianFetch } from "./obsidian-http.js";
import { buildDiagnosticReport } from "./diagnostic-report.js";
import { MobileHeader } from "./components/header.js";
import { HistoryDrawer } from "./components/history-drawer.js";
import { MessageList } from "./components/message-list.js";
import { MobileComposer } from "./components/composer.js";
import { FrameRenderScheduler } from "./render-scheduler.js";
import { pairingStatusFromSettings } from "./readiness.js";

export const MOBILE_VIEW_TYPE = "claudian-remote-mobile";

export class ClaudianRemoteMobileView extends ItemView {
  constructor(leaf, plugin) {
    super(leaf);
    this.plugin = plugin;
    this.frameTail = Promise.resolve();
  }

  getViewType() { return MOBILE_VIEW_TYPE; }
  getDisplayText() { return "Claudian Remote"; }
  getIcon() { return "message-circle"; }

  async onOpen() {
    this.closing = false;
    this.activeSurface = "none";
    this.attachmentDeliveries = new Set();
    this.contentEl.empty();
    this.contentEl.addClass("claudian-remote-mobile-view");
    this.root = element("div", "claudian-remote-shell");
    this.contentEl.append(this.root);
    this.renderScheduler = new FrameRenderScheduler({ render: () => this.renderNow() });
    const seed = this.plugin.recoverySeed();
    seed.pairing = { status: pairingStatusFromSettings(this.plugin.settings) };
    this.replica = new MobileReplica(seed);
    const http = createObsidianFetch(requestUrl);
    this.client = new RemoteClient({
      baseUrl: this.plugin.settings.relay_base_url,
      tokenProvider: () => this.plugin.settings.mobile_token,
      deviceId: this.plugin.settings.device_id,
      clientInstanceId: this.plugin.settings.client_instance_id,
      fetchImpl: http,
      onFrame: (frame) => this.enqueueFrame(frame)
    });
    this.lifecycle = new MobileRecoveryController({
      client: this.client,
      replica: this.replica,
      persist: (state) => this.plugin.saveRecovery(state)
    });
    this.attachments = new AttachmentController({
      baseUrl: this.plugin.settings.relay_base_url,
      tokenProvider: () => this.plugin.settings.mobile_token,
      getSession: () => {
        const mac = this.replica.state.presence.mac;
        return mac.status === "online" && this.replica.state.transport.status === "connected"
          ? { mac_session_id: mac.sessionId, mac_connection_generation: mac.connectionGeneration }
          : null;
      },
      fetchImpl: http,
      onChange: () => this.scheduleRender()
    });
    this.unsubscribe = this.replica.subscribe(() => this.scheduleRender());

    this.header = new MobileHeader(this.root, {
      onHistory: () => void this.openHistory(),
      onDetails: () => void this.openDetails()
    });
    this.messages = new MessageList(this.root, {
      app: this.app,
      sourcePath: "",
      onApproval: (approvalId, value) => void this.send("approval.respond", { approval_id: approvalId, value }),
      onArtifact: (artifact) => this.openArtifact(artifact)
    });
    this.composer = new MobileComposer(this.root, {
      app: this.app,
      onSend: (text) => void this.sendMessage(text, false),
      onSteer: (text) => void this.sendMessage(text, true),
      onStop: () => void this.send("turn.stop", {}),
      onAttach: (file) => void this.uploadAttachment(file),
      onRemoveAttachment: () => void this.attachments.cancel(),
      onRetryAttachment: () => void this.retryAttachment()
    });
    this.history = new HistoryDrawer(this.root, {
      onClose: () => this.setHistoryOpen(false),
      onRefresh: () => void this.loadHistory(),
      onSelect: (conversationId) => void this.selectHistory(conversationId),
      onNew: () => void this.createHistory(),
      onRename: (conversationId, title) => void this.renameHistory(conversationId, title),
      onArchive: (conversationId) => void this.archiveHistory(conversationId)
    });
    this.createDetailsSheet();
    this.root.addEventListener("click", (event) => this.handleLinkClick(event));
    this.registerDomEvent(document, "visibilitychange", () => void this.lifecycle.setVisible(document.visibilityState !== "hidden"));
    this.pairingWatcher = globalThis.setInterval(() => this.refreshPairingState(), 1000);
    this.renderScheduler.flush();

    if (!this.plugin.settings.relay_base_url || !this.plugin.settings.mobile_token) {
      void this.openDetails();
    } else {
      void this.lifecycle.setVisible(document.visibilityState !== "hidden").catch(() => {
        if (!this.closing) this.replica.requireReset("mobile_connect_failed");
      });
    }
  }

  refreshPairingState() {
    if (this.closing || !this.replica) return false;
    const status = pairingStatusFromSettings(this.plugin.settings);
    if (!this.replica.setPairingStatus(status)) return false;
    if (status === "required") {
      void this.lifecycle?.setVisible(false);
      return true;
    }
    this.client.baseUrl = String(this.plugin.settings.relay_base_url || "").replace(/\/+$/, "");
    this.client.deviceId = this.plugin.settings.device_id;
    this.client.clientInstanceId = this.plugin.settings.client_instance_id;
    this.attachments.baseUrl = this.client.baseUrl;
    if (document.visibilityState !== "hidden") void this.lifecycle?.setVisible(true);
    return true;
  }

  enqueueFrame(frame) {
    this.frameTail = this.frameTail
      .then(() => this.replica.applyFrame(frame))
      .catch(() => this.replica.requireReset("mobile_reducer_error"));
    return this.frameTail;
  }

  createDetailsSheet() {
    this.detailsOverlay = element("div", "claudian-remote-overlay");
    this.detailsOverlay.setAttribute("aria-hidden", "true");
    this.detailsOverlay.inert = true;
    this.detailsOverlay.addEventListener("click", (event) => { if (event.target === this.detailsOverlay) this.setDetailsOpen(false); });
    const sheet = element("aside", "claudian-remote-sheet claudian-remote-details");
    const header = element("div", "claudian-remote-sheet-header");
    header.append(element("h2", "", "连接详情"), button("claudian-remote-icon-button", "关闭", () => this.setDetailsOpen(false)));
    header.lastElementChild.textContent = "×";
    this.detailsBody = element("div", "claudian-remote-details-body");
    const reconnect = button("mod-cta", "重新连接", () => void this.lifecycle.setVisible(true));
    const copyReport = button("", "复制诊断报告", () => void this.copyDiagnosticReport());
    const settings = button("", "打开插件设置", () => {
      this.setDetailsOpen(false);
      this.app.setting?.open?.();
      this.app.setting?.openTabById?.(this.plugin.manifest.id);
    });
    const actions = element("div", "claudian-remote-details-actions");
    actions.append(reconnect, copyReport, settings);
    sheet.append(header, this.detailsBody, actions);
    this.detailsOverlay.append(sheet);
    this.root.append(this.detailsOverlay);
  }

  setActiveSurface(surface = "none") {
    this.activeSurface = surface;
    const detailsOpen = surface === "details";
    const historyOpen = surface === "history";
    this.detailsOverlay.classList.toggle("is-open", detailsOpen);
    this.detailsOverlay.setAttribute("aria-hidden", String(!detailsOpen));
    this.detailsOverlay.inert = !detailsOpen;
    this.history.setOpen(historyOpen);
  }

  setDetailsOpen(open) {
    this.setActiveSurface(open ? "details" : (this.activeSurface === "details" ? "none" : this.activeSurface));
  }

  setHistoryOpen(open) {
    this.setActiveSurface(open ? "history" : (this.activeSurface === "history" ? "none" : this.activeSurface));
  }

  async openDetails() {
    this.composer.input.blur();
    if (!this.closing) this.setActiveSurface("details");
  }

  async copyDiagnosticReport() {
    const report = buildDiagnosticReport(this.replica.state, this.attachments.snapshot());
    try {
      await navigator.clipboard.writeText(report);
      new Notice("诊断报告已复制（不含对话正文和凭据）");
    } catch {
      new Notice("无法访问剪贴板，请在系统权限中允许 Obsidian 复制");
    }
  }

  async openHistory() {
    this.composer.input.blur();
    if (this.closing) return;
    this.setHistoryOpen(true);
    if (!this.replica.state.history.loaded) await this.loadHistory();
  }

  async loadHistory() {
    await this.send("history.list", { page: 0 });
  }

  async selectHistory(conversationId) {
    const model = activeConversationModel(this.replica.state);
    const browsing = this.replica.selectConversationForViewing(conversationId);
    if (!browsing) return new Notice("该对话尚未同步到本机缓存");
    if (!model.controls.historySelect) {
      new Notice(model.executionTurn?.status === "running"
        ? "正在查看历史；当前任务仍在原对话中运行"
        : "当前为只读历史，未切换电脑端对话");
      this.setHistoryOpen(false);
      return;
    }
    const selected = await this.send("history.select", { conversation_id: conversationId });
    if (!selected) this.replica.selectConversationForViewing(model.executionConversationId, { pinned: false });
    this.setHistoryOpen(false);
  }

  async createHistory() {
    const created = await this.send("history.new", {});
    if (created) this.setHistoryOpen(false);
  }

  async renameHistory(conversationId, title) {
    await this.send("history.rename", { conversation_id: conversationId, title });
  }

  async archiveHistory(conversationId) {
    const archived = await this.send("history.archive", { conversation_id: conversationId });
    if (!archived) new Notice("当前 Claudian 暂不支持归档；没有删除任何对话");
  }

  async sendMessage(text, steer) {
    const value = String(text || "").trim();
    const readyAttachmentRefs = this.attachments.references();
    if (!value && !readyAttachmentRefs.length) return;
    if (steer) {
      this.composer.clear();
      const submitted = await this.send("turn.steer", { text: value }, value);
      if (!submitted) this.composer.setDraft(value);
      return;
    }
    const deliveryId = readyAttachmentRefs.length ? createDeliveryId() : null;
    const attachmentRefs = deliveryId ? this.attachments.reserveReady(deliveryId) : [];
    if (readyAttachmentRefs.length && !attachmentRefs.length) {
      new Notice("附件正在等待上一条消息回执");
      return;
    }
    if (deliveryId) {
      this.attachmentDeliveries.add(deliveryId);
      this.composer.syncAttachments(this.attachments.snapshot());
    }
    this.composer.clear();
    const submitted = await this.send(
      "message.submit",
      { text: value, attachment_refs: attachmentRefs, mode: "enqueue" },
      value,
      { deliveryId }
    );
    if (!submitted) {
      if (deliveryId) {
        this.attachments.releaseReservation(deliveryId);
        this.attachmentDeliveries.delete(deliveryId);
        this.composer.syncAttachments(this.attachments.snapshot());
      }
      this.composer.setDraft(value);
    }
  }

  async uploadAttachment(file) {
    try { await this.attachments.upload(file); }
    catch (error) {
      const labels = { one_upload_at_a_time: "请先处理当前附件", mac_offline: "Mac 离线，无法上传" };
      new Notice(labels[error?.message] || "附件上传中断，可在同一 Mac 会话中继续");
    }
  }

  async retryAttachment() {
    try { await this.attachments.resume(); }
    catch { new Notice("当前 Mac 会话已变化，请重新选择文件"); }
  }

  async send(commandType, payload, draftText = "", { deliveryId = null } = {}) {
    let command;
    try { command = buildCommand(this.replica.state, commandType, payload, { deliveryId }); }
    catch (error) {
      new Notice(error?.message === "mac_offline" ? "Mac 离线，未发送" : "当前对话尚未准备好");
      return null;
    }
    this.replica.beginCommand({ deliveryId: command.delivery_id, commandType, text: draftText });
    try {
      const response = await this.client.submit(command);
      await this.replica.applyFrame(response);
      const state = this.replica.state.commands[command.delivery_id];
      if (state?.status === "rejected" && state?.errorCode === "capability_missing") {
        new Notice(`当前 Claudian 不支持 ${state.capability || "此操作"}`);
      }
      return !state || state.status === "rejected" ? null : command;
    } catch {
      await this.replica.applyFrame({
        type: "command.unknown",
        delivery_id: command.delivery_id,
        error: "connection_lost"
      });
      new Notice("连接状态未知，请勿重复发送；恢复后将按同一消息编号校准");
      return command;
    }
  }

  openArtifact(artifact) {
    if (artifact.vault_path) {
      const found = this.app.metadataCache?.getFirstLinkpathDest?.(artifact.vault_path, "");
      if (this.app.metadataCache?.getFirstLinkpathDest && !found) {
        new Notice("文件尚未同步到当前 Vault");
        return;
      }
      this.app.workspace.openLinkText(artifact.vault_path, "", false);
      return;
    }
    const action = classifyLink(artifact.url || "");
    if (action.kind === "external") globalThis.open?.(action.href, "_blank", "noopener");
    else new Notice("该文件链接不可用");
  }

  handleLinkClick(event) {
    const anchor = event.target?.closest?.("a");
    if (!anchor || !this.root.contains(anchor)) return;
    event.preventDefault();
    const action = handleContentAction({ app: this.app, sourcePath: "", anchor });
    if (action.kind === "blocked") new Notice("已拒绝不安全或本机路径链接");
    if (action.kind === "missing") new Notice("文件尚未同步到当前 Vault");
  }

  scheduleRender() {
    if (!this.closing) this.renderScheduler?.request();
  }

  renderNow() {
    if (this.closing || !this.replica || !this.header) return;
    const model = activeConversationModel(this.replica.state);
    const currentMac = model.macOnline ? {
      mac_session_id: this.replica.state.presence.mac.sessionId,
      mac_connection_generation: this.replica.state.presence.mac.connectionGeneration
    } : null;
    this.attachments.invalidateSession(currentMac);
    for (const turn of model.turns) {
      for (const artifactId of turn.artifactOrder) this.attachments.onArtifact(turn.artifacts[artifactId]);
    }
    if (!this.composer.value()) {
      const restoredDrafts = this.replica.claimRestoredDrafts(1);
      if (restoredDrafts.length) this.composer.setDraft(restoredDrafts[0]);
    }
    for (const deliveryId of Array.from(this.attachmentDeliveries)) {
      const command = this.replica.state.commands[deliveryId];
      if (["desktop_accepted", "terminal", "reconciled"].includes(command?.status)) {
        this.attachments.consumeReservation(deliveryId);
        this.attachmentDeliveries.delete(deliveryId);
      } else if (command?.status === "rejected") {
        this.attachments.releaseReservation(deliveryId);
        this.attachmentDeliveries.delete(deliveryId);
      }
    }
    this.header.render(model);
    this.messages.render(model);
    this.composer.render({
      controls: model.controls,
      isStreaming: model.executionTurn?.status === "running",
      offline: !model.macOnline,
      uploadEnabled: model.controls.send,
      attachments: this.attachments.snapshot()
    });
    this.history.render(
      this.replica.state.history,
      model.executionConversationId,
      model.controls,
      model.id
    );
    const transportLabel = {
      connected: "已连接",
      connecting: "正在连接",
      disconnected: "未连接"
    }[model.transportStatus] || "未连接";
    const detailValues = [
      ["Remote", transportLabel],
      ["Mac", model.macOnline ? "在线" : "离线"],
      ["状态", `${model.readiness.label} (${model.readiness.reason_code})`],
      ["同步", model.recovering ? "正在校准" : `游标 ${this.replica.state.relay.appliedCursor}`],
      ["权限", "沿用电脑端 Claudian 默认设置"]
    ];
    const detailsKey = JSON.stringify(detailValues);
    if (detailsKey !== this.detailsRenderKey) {
      this.detailsRenderKey = detailsKey;
      this.detailsBody.replaceChildren(...detailValues.map(([label, value]) => this.detailRow(label, value)));
    }
    for (const _signal of this.replica.drainCompletionSignals()) {
      new Notice("Claudian 已完成回复");
      try { if (typeof navigator?.vibrate === "function") navigator.vibrate(35); } catch { /* iOS may not expose vibration. */ }
    }
  }

  detailRow(label, value) {
    const row = element("div", "claudian-remote-detail-row");
    row.append(element("span", "", label), element("strong", "", value));
    return row;
  }

  async onClose() {
    this.closing = true;
    globalThis.clearInterval(this.pairingWatcher);
    this.unsubscribe?.();
    this.renderScheduler?.dispose();
    this.composer?.dispose();
    await this.attachments?.dispose();
    this.messages?.dispose();
    await this.lifecycle?.dispose();
    await this.frameTail.catch(() => {});
    this.contentEl.removeClass("claudian-remote-mobile-view");
    this.contentEl.empty();
  }
}
