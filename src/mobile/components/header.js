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
    const readiness = model.readiness || { label: model.macOnline ? "在线" : "离线", status: model.macOnline ? "ready" : "blocked", reason_code: "unknown" };
    this.status.textContent = `● ${readiness.label}`;
    this.status.dataset.state = readiness.status;
    this.status.dataset.reason = readiness.reason_code;
  }
}
