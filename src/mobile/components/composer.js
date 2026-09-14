import { button, element } from "../dom.js";

export class MobileComposer {
  constructor(container, { onSend, onSteer, onStop, onAttach, onRemoveAttachment, onRetryAttachment }) {
    this.draft = "";
    this.attachments = [];
    this.state = { controls: {}, isStreaming: false, offline: true, uploadEnabled: false };
    this.onSend = onSend;
    this.onSteer = onSteer;
    this.onRemoveAttachment = onRemoveAttachment;
    this.onRetryAttachment = onRetryAttachment;
    this.el = element("section", "claudian-remote-composer-wrap");
    this.attachmentTray = element("div", "claudian-remote-composer-attachments");
    this.input = element("textarea", "claudian-remote-composer-input");
    this.input.rows = 1;
    this.input.placeholder = "输入消息…";
    this.input.setAttribute("aria-label", "输入给 Claudian 的消息");
    this.input.addEventListener("input", () => {
      this.draft = this.input.value;
      this.resizeInput();
      this.renderActions();
    });
    this.input.addEventListener("keydown", (event) => {
      if (event.key === "Enter" && (event.metaKey || event.ctrlKey) && !event.isComposing && event.keyCode !== 229 && this.canSubmit()) {
        event.preventDefault();
        this.submit(false);
      }
    });
    this.fileInput = element("input", "claudian-remote-composer-file-input");
    this.fileInput.type = "file";
    this.fileInput.tabIndex = 0;
    this.fileInput.setAttribute("aria-label", "添加附件");
    this.fileInput.addEventListener("change", () => {
      const file = this.fileInput.files?.[0];
      this.fileInput.value = "";
      if (file && !this.attach.disabled) onAttach(file);
    });
    // Keep the native file input at the actual touch target so iOS can anchor
    // its picker there. Forwarding a click to a display:none input loses that geometry.
    this.attach = this.fileInput;
    this.attachControl = element("span", "claudian-remote-composer-attach-control");
    const attachSymbol = element("span", "claudian-remote-composer-attach", "+");
    attachSymbol.setAttribute("aria-hidden", "true");
    this.attachControl.append(attachSymbol, this.fileInput);
    this.stop = button("claudian-remote-composer-stop", "停止", () => {
      if (!this.stop.disabled && !this.stop.hidden) onStop();
    });
    this.steer = button("claudian-remote-composer-steer", "插队", () => this.submit(true));
    this.send = button("mod-cta claudian-remote-composer-send", "发送", () => this.submit(false));
    this.actions = element("div", "claudian-remote-composer-actions");
    this.actions.append(this.stop, this.steer, this.send);
    this.row = element("div", "claudian-remote-composer");
    this.row.append(this.attachControl, this.input, this.actions);
    this.hint = element("div", "claudian-remote-composer-hint");
    this.el.append(this.attachmentTray, this.row, this.hint);
    container.append(this.el);
    this.resizeInput();
    this.renderActions();
  }

  value() { return this.draft.trim(); }

  setDraft(value) {
    this.draft = String(value || "");
    if (this.input.value !== this.draft) this.input.value = this.draft;
    this.resizeInput();
    this.renderActions();
  }

  clear() { this.setDraft(""); }

  resizeInput() {
    this.input.style.height = "auto";
    const height = this.input.scrollHeight || 40;
    this.input.style.height = `${Math.min(height, 128)}px`;
    this.input.style.overflowY = "auto";
  }

  canSubmit() {
    const hasReadyAttachment = this.attachments.some((item) => item.status === "ready" && !item.reserved);
    const attachmentsReady = this.attachments.every((item) => item.status === "ready" && !item.reserved);
    return Boolean(!this.disposed && !this.state.offline && this.state.controls.send && attachmentsReady && (this.value() || hasReadyAttachment));
  }

  submit(steer) {
    if (steer ? this.steer.disabled : !this.canSubmit()) return;
    if (steer) this.onSteer(this.value());
    else this.onSend(this.value());
  }

  syncAttachments(items = []) {
    this.attachments = items;
    this.renderActions();
    this.renderAttachments();
  }

  render({ controls, isStreaming, offline, uploadEnabled = false, attachments = [] }) {
    this.state = { controls, isStreaming: Boolean(isStreaming), offline, uploadEnabled };
    this.hint.textContent = offline ? "Mac 离线，可先编辑草稿" : "";
    this.syncAttachments(attachments);
  }

  renderActions() {
    const online = !this.disposed && !this.state.offline;
    this.attach.disabled = !online || !this.state.controls.send || !this.state.uploadEnabled;
    this.stop.hidden = !this.state.isStreaming;
    this.stop.disabled = !online || !this.state.controls.stop;
    this.steer.hidden = !this.state.isStreaming || !this.state.controls.steer || this.attachments.length > 0;
    this.steer.disabled = !online || this.steer.hidden || !this.value();
    this.send.textContent = this.state.isStreaming ? "排队" : "发送";
    this.send.setAttribute("aria-label", this.send.textContent);
    this.send.disabled = !this.canSubmit();
  }

  renderAttachments() {
    this.attachmentTray.replaceChildren();
    this.attachmentTray.hidden = this.attachments.length === 0;
    const labels = {
      hashing: "正在校验", starting: "正在准备", uploading: "上传中", finalizing: "正在校验",
      importing: "正在导入 Vault", ready: "已就绪", paused: "已暂停", failed: "失败"
    };
    for (const item of this.attachments) {
      const row = element("div", "claudian-remote-composer-attachment");
      const name = element("span", "claudian-remote-composer-attachment-name", item.name);
      const label = item.reserved ? "等待电脑回执" : labels[item.status] || item.status;
      name.append(element("small", "", `${label}${item.status === "uploading" ? ` ${Math.round(item.progress * 100)}%` : ""}`));
      row.append(element("span", "", "▧"), name);
      if (item.status === "paused") {
        const retry = button("claudian-remote-attachment-action", "继续上传", this.onRetryAttachment);
        retry.disabled = this.attach.disabled || Boolean(item.reserved);
        row.append(retry);
      }
      const remove = button("claudian-remote-attachment-action", "移除附件", this.onRemoveAttachment);
      remove.disabled = Boolean(item.reserved);
      row.append(remove);
      this.attachmentTray.append(row);
    }
  }

  dispose() {
    this.disposed = true;
    this.renderActions();
    this.input.blur();
    this.el.remove();
  }
}
