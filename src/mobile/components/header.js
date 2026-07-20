import { button, element } from "../dom.js";

export class MobileHeader {
  constructor(container, { onHistory, onDetails }) {
    this.el = element("header", "claudian-remote-header");
    this.history = button("claudian-remote-icon-button", "历史对话", onHistory);
    this.history.textContent = "☰";
    this.title = element("div", "claudian-remote-header-title");
    this.status = button("claudian-remote-status-pill", "连接详情", onDetails);
    this.el.append(this.history, this.title, this.status);
    container.append(this.el);
  }

  render(model) {
    this.title.textContent = model.title || "Claudian";
    this.title.title = model.title || "Claudian";
    const state = model.recovering ? "校准中" : model.macOnline ? (model.compatibilityMode ? "只读" : "在线") : "离线";
    this.status.textContent = `● ${state}`;
    this.status.dataset.state = model.recovering ? "recovering" : model.macOnline ? "online" : "offline";
  }
}
