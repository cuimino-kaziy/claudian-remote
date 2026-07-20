import { button, element } from "../dom.js";

export class HistoryDrawer {
  constructor(container, { onClose, onRefresh, onSelect }) {
    this.onSelect = onSelect;
    this.overlay = element("div", "claudian-remote-overlay");
    this.overlay.setAttribute("aria-hidden", "true");
    this.overlay.inert = true;
    this.overlay.addEventListener("click", (event) => { if (event.target === this.overlay) onClose(); });
    this.sheet = element("aside", "claudian-remote-sheet claudian-remote-history");
    const header = element("div", "claudian-remote-sheet-header");
    header.append(element("h2", "", "历史对话"), button("claudian-remote-icon-button", "刷新历史", onRefresh), button("claudian-remote-icon-button", "关闭", onClose));
    header.children[1].textContent = "↻";
    header.children[2].textContent = "×";
    this.list = element("div", "claudian-remote-history-list");
    this.sheet.append(header, this.list);
    this.overlay.append(this.sheet);
    container.append(this.overlay);
  }

  setOpen(open) {
    this.overlay.classList.toggle("is-open", open);
    this.overlay.setAttribute("aria-hidden", String(!open));
    this.overlay.inert = !open;
  }

  render(history, activeId, enabled) {
    const renderKey = JSON.stringify([
      history.loaded,
      history.nextPage,
      activeId,
      Boolean(enabled),
      ...history.items.flatMap((item) => [item.conversation_id, item.title, item.message_count])
    ]);
    if (renderKey === this.renderKey) return;
    this.renderKey = renderKey;
    this.list.replaceChildren();
    if (!history.loaded) this.list.append(element("p", "claudian-remote-empty", "正在读取电脑端历史…"));
    else if (!history.items.length) this.list.append(element("p", "claudian-remote-empty", "暂无历史对话"));
    for (const item of history.items) {
      const row = button("claudian-remote-history-row", item.title || "未命名对话", () => this.onSelect(item.conversation_id));
      row.disabled = !enabled || item.conversation_id === activeId;
      row.dataset.active = item.conversation_id === activeId ? "true" : "false";
      const meta = element("span", "claudian-remote-history-meta", `${item.message_count || 0} 条消息`);
      row.append(meta);
      this.list.append(row);
    }
  }
}
