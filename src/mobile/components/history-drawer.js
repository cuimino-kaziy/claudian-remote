import { button, element } from "../dom.js";

function normalizeHistoryItem(item) {
  const conversationId = String(item?.conversation_id || item?.id || "");
  return { ...item, conversation_id: conversationId };
}

export function filterHistoryItems(items, query = "") {
  const needle = String(query || "").trim().toLocaleLowerCase();
  return (Array.isArray(items) ? items : [])
    .map(normalizeHistoryItem)
    .filter((item) => item.conversation_id && (!needle || String(item.title || "").toLocaleLowerCase().includes(needle)));
}

export class HistoryDrawer {
  constructor(container, { onClose, onRefresh, onSelect, onNew, onRename, onArchive }) {
    this.onSelect = onSelect;
    this.onRename = onRename;
    this.onArchive = onArchive;
    this.query = "";
    this.overlay = element("div", "claudian-remote-overlay");
    this.overlay.setAttribute("aria-hidden", "true");
    this.overlay.inert = true;
    this.overlay.addEventListener("click", (event) => { if (event.target === this.overlay) onClose(); });
    this.sheet = element("aside", "claudian-remote-sheet claudian-remote-history");
    const header = element("div", "claudian-remote-sheet-header");
    this.newButton = button("claudian-remote-icon-button", "新建对话", onNew);
    this.newButton.textContent = "+";
    const refresh = button("claudian-remote-icon-button", "刷新历史", onRefresh);
    refresh.textContent = "↻";
    const close = button("claudian-remote-icon-button", "关闭", onClose);
    close.textContent = "×";
    header.append(element("h2", "", "历史对话"), this.newButton, refresh, close);
    this.search = element("input", "claudian-remote-history-search");
    this.search.type = "search";
    this.search.placeholder = "搜索历史对话";
    this.search.setAttribute("aria-label", "搜索历史对话");
    this.search.addEventListener("input", () => {
      this.query = this.search.value;
      this.renderKey = null;
      this.render(this.lastHistory, this.lastActiveId, this.lastControls, this.lastViewingId);
    });
    this.list = element("div", "claudian-remote-history-list");
    this.sheet.append(header, this.search, this.list);
    this.overlay.append(this.sheet);
    container.append(this.overlay);
  }

  setOpen(open) {
    this.overlay.classList.toggle("is-open", open);
    this.overlay.setAttribute("aria-hidden", String(!open));
    this.overlay.inert = !open;
  }

  requestRename(item) {
    const title = globalThis.prompt?.("重命名对话", item.title || "")?.trim();
    if (title && title !== item.title) this.onRename(item.conversation_id, title);
  }

  render(history = {}, activeId, controls = {}, viewingId = activeId) {
    this.lastHistory = history;
    this.lastActiveId = activeId;
    this.lastControls = controls;
    this.lastViewingId = viewingId;
    const items = filterHistoryItems(history.items, this.query);
    const renderKey = JSON.stringify([
      history.loaded,
      history.nextPage,
      activeId,
      viewingId,
      this.query,
      controls,
      ...items.flatMap((item) => [item.conversation_id, item.title, item.message_count, item.archived])
    ]);
    if (renderKey === this.renderKey) return;
    this.renderKey = renderKey;
    this.newButton.disabled = !controls.historyNew;
    this.newButton.title = controls.historyNew ? "新建对话" : "当前状态或 Claudian 版本不支持新建";
    this.list.replaceChildren();
    if (!history.loaded) this.list.append(element("p", "claudian-remote-empty", "正在读取电脑端历史…"));
    else if (!items.length) this.list.append(element("p", "claudian-remote-empty", this.query ? "没有匹配的对话" : "暂无历史对话"));
    for (const item of items) {
      const wrapper = element("div", "claudian-remote-history-item");
      const row = button("claudian-remote-history-row", item.title || "未命名对话", () => this.onSelect(item.conversation_id));
      row.disabled = !controls.history && item.conversation_id !== viewingId;
      row.dataset.active = item.conversation_id === activeId ? "true" : "false";
      row.dataset.viewing = item.conversation_id === viewingId ? "true" : "false";
      row.append(element("span", "claudian-remote-history-meta", `${item.message_count || 0} 条消息`));
      const actions = element("div", "claudian-remote-history-actions");
      const rename = button("claudian-remote-history-action", "重命名对话", () => this.requestRename(item));
      rename.textContent = "重命名";
      rename.disabled = !controls.historyRename;
      const archive = button("claudian-remote-history-action", "归档对话", () => this.onArchive(item.conversation_id));
      archive.textContent = "归档";
      archive.disabled = !controls.historyArchive;
      archive.title = controls.historyArchive ? "归档对话" : "当前 Claudian 暂不支持归档";
      actions.append(rename, archive);
      wrapper.append(row, actions);
      this.list.append(wrapper);
    }
  }
}
