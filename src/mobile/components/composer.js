import { button, element } from "../dom.js";
import { MessageInputModal } from "./message-input-modal.js";

export class MobileComposer {
  constructor(container, { app, onSend, onSteer, onStop, onAttach, onRemoveAttachment, onRetryAttachment }) {
    this.draft = "";
    this.attachments = [];
    this.state = { controls: { send: false, stop: false, steer: false }, isStreaming: false, offline: true, uploadEnabled: false };
    this.el = element("section", "claudian-remote-composer-wrap");
    this.launch = button("claudian-remote-composer-launch", "输入消息", () => this.openInput());
    this.launchIcon = element("span", "claudian-remote-composer-launch-icon", "+");
    this.launchText = element("span", "claudian-remote-composer-launch-text", "输入消息…");
    this.launchArrow = element("span", "claudian-remote-composer-launch-arrow", "›");
    this.launch.replaceChildren(this.launchIcon, this.launchText, this.launchArrow);
    this.hint = element("div", "claudian-remote-composer-hint");
    this.el.append(this.launch, this.hint);
    container.append(this.el);

    this.modal = new MessageInputModal(app, {
      onPresentedChange: (presented) => { this.el.hidden = presented; },
      onDraft: (value) => this.setDraft(value, { syncModal: false }),
      onSend,
      onSteer,
      onStop,
      onAttach,
      onRemoveAttachment,
      onRetryAttachment
    });
  }

  openInput() {
    if (this.launch.disabled) return;
    this.modal.openWith({ ...this.state, draft: this.draft, attachments: this.attachments });
  }

  value() { return this.draft.trim(); }

  setDraft(value, { syncModal = true } = {}) {
    this.draft = String(value || "");
    if (syncModal) this.modal.setDraft(this.draft);
    this.renderPreview();
  }

  clear() { this.setDraft(""); }

  renderPreview() {
    const attachmentCount = this.attachments.filter((item) => !item.reserved).length;
    this.launchText.textContent = this.value()
      || (attachmentCount ? `已选择 ${attachmentCount} 个附件` : "输入消息…");
    this.launch.classList.toggle("has-draft", Boolean(this.value() || attachmentCount));
  }

  syncAttachments(items = []) {
    this.attachments = items;
    this.renderPreview();
    this.modal.update({ ...this.state, draft: this.draft, attachments: this.attachments });
  }

  render({ controls, isStreaming, offline, uploadEnabled = false, attachments = [] }) {
    this.state = { controls, isStreaming: Boolean(isStreaming), offline, uploadEnabled };
    this.launch.disabled = !controls.send;
    this.launch.setAttribute("aria-label", offline ? "Mac 离线，暂不能发送" : "打开消息输入");
    this.launchArrow.textContent = this.state.isStreaming ? "…" : "›";
    this.hint.textContent = offline
      ? "Mac 离线，可查看已同步内容，暂不能发送"
      : this.state.isStreaming ? "点击输入，可选择正常排队或立即插队" : "";
    this.syncAttachments(attachments);
  }

  dispose() { this.modal.close(); }
}
