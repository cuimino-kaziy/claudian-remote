import { Modal } from "obsidian";
import { button, element } from "../dom.js";

export class MessageInputModal extends Modal {
  constructor(app, { onPresentedChange, onDraft, onSend, onSteer, onStop, onAttach, onRemoveAttachment, onRetryAttachment }) {
    super(app);
    this.onPresentedChange = onPresentedChange;
    this.onDraft = onDraft;
    this.onSend = onSend;
    this.onSteer = onSteer;
    this.onStop = onStop;
    this.onAttach = onAttach;
    this.onRemoveAttachment = onRemoveAttachment;
    this.onRetryAttachment = onRetryAttachment;
    this.state = { draft: "", attachments: [], controls: {}, isStreaming: false, offline: true, uploadEnabled: false };
    this.presented = false;
  }

  openWith(state) {
    this.state = { ...this.state, ...state };
    if (this.presented) this.renderState();
    else this.open();
  }

  update(state) {
    this.state = { ...this.state, ...state };
    if (this.presented) this.renderState();
  }

  setDraft(value) {
    this.state.draft = String(value || "");
    if (this.input && this.input.value !== this.state.draft) this.input.value = this.state.draft;
  }

  onOpen() {
    this.presented = true;
    this.onPresentedChange(true);
    this.modalEl.classList.add("claudian-remote-input-modal");
    // Obsidian's modal chrome duplicates the compact mobile toolbar and costs
    // almost a full action row on small screens.
    this.titleEl.hidden = true;
    const closeButton = this.modalEl.querySelector(".modal-close-button");
    if (closeButton) closeButton.hidden = true;
    this.contentEl.empty();

    this.input = element("textarea", "claudian-remote-modal-input");
    this.input.rows = 5;
    this.input.placeholder = "输入给 Claudian 的消息…";
    this.input.setAttribute("aria-label", "输入给 Claudian 的消息");
    this.input.addEventListener("input", () => {
      this.state.draft = this.input.value;
      this.onDraft(this.input.value);
      this.renderActions();
    });
    this.input.addEventListener("keydown", (event) => {
      if (event.key === "Enter" && !event.shiftKey && !event.isComposing && this.canSubmit()) {
        event.preventDefault();
        this.submit(false);
      }
    });

    this.attachmentTray = element("div", "claudian-remote-modal-attachments");
    this.fileInput = element("input", "claudian-remote-modal-file-input");
    this.fileInput.type = "file";
    this.fileInput.tabIndex = -1;
    this.fileInput.addEventListener("change", () => {
      const file = this.fileInput.files?.[0];
      this.fileInput.value = "";
      if (file) this.onAttach(file);
    });

    this.toolbar = element("div", "claudian-remote-modal-toolbar");
    this.attach = button("claudian-remote-modal-attach", "附件", () => this.fileInput.click());
    this.stop = button("claudian-remote-modal-stop", "停止", () => {
      this.close();
      this.onStop();
    });
    this.steer = button("claudian-remote-modal-steer", "插队", () => this.submit(true));
    this.send = button("mod-cta claudian-remote-modal-send", "发送", () => this.submit(false));
    this.toolbar.append(this.attach, this.stop, this.steer, this.send);
    this.contentEl.append(this.toolbar, this.input, this.attachmentTray, this.fileInput);
    this.renderState();

    requestAnimationFrame(() => {
      if (this.presented) this.input?.focus({ preventScroll: true });
    });
  }

  onClose() {
    if (this.input) this.onDraft(this.input.value);
    this.presented = false;
    this.onPresentedChange(false);
    this.contentEl.empty();
    this.input = null;
  }

  canSubmit() {
    const hasReadyAttachment = this.state.attachments.some((item) => item.status === "ready" && !item.reserved);
    const attachmentsReady = this.state.attachments.every((item) => item.status === "ready" && !item.reserved);
    return Boolean(this.state.controls?.send && attachmentsReady && (this.input?.value.trim() || hasReadyAttachment));
  }

  submit(steer) {
    const value = this.input?.value.trim() || "";
    if (steer && this.steer.disabled) return;
    if (!steer && !this.canSubmit()) return;
    this.onDraft(value);
    this.close();
    if (steer) this.onSteer(value);
    else this.onSend(value);
  }

  renderState() {
    if (!this.presented || !this.input) return;
    if (this.input.value !== this.state.draft) this.input.value = this.state.draft || "";
    this.input.disabled = !this.state.controls?.send;
    this.renderAttachments();
    this.renderActions();
  }

  renderActions() {
    if (!this.presented) return;
    const hasAttachments = this.state.attachments.length > 0;
    this.attach.disabled = !this.state.controls?.send || !this.state.uploadEnabled;
    this.stop.hidden = !this.state.isStreaming;
    this.stop.disabled = !this.state.controls?.stop;
    this.steer.hidden = !this.state.isStreaming || !this.state.controls?.steer || hasAttachments;
    this.steer.disabled = this.steer.hidden || !this.input?.value.trim();
    this.send.textContent = this.state.isStreaming ? "排队" : "发送";
    this.send.disabled = !this.canSubmit();
  }

  renderAttachments() {
    this.attachmentTray.replaceChildren();
    const labels = {
      hashing: "正在校验", starting: "正在准备", uploading: "上传中", finalizing: "正在校验",
      importing: "正在导入 Vault", ready: "已就绪", paused: "已暂停", failed: "失败"
    };
    for (const item of this.state.attachments) {
      const row = element("div", "claudian-remote-modal-attachment");
      const name = element("span", "claudian-remote-modal-attachment-name", item.name);
      const label = item.reserved ? "等待电脑回执" : labels[item.status] || item.status;
      name.append(element("small", "", `${label}${item.status === "uploading" ? ` ${Math.round(item.progress * 100)}%` : ""}`));
      row.append(element("span", "", "▧"), name);
      if (item.status === "paused") row.append(button("claudian-remote-attachment-action", "继续上传", this.onRetryAttachment));
      const remove = button("claudian-remote-attachment-action", "移除附件", this.onRemoveAttachment);
      remove.disabled = Boolean(item.reserved);
      row.append(remove);
      this.attachmentTray.append(row);
    }
  }
}
