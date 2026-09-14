import { button, element } from "../dom.js";

function normalizeHistoryItem(item) {
  const conversationId = String(item?.conversation_id || item?.id || "");
  return { ...item, conversation_id: conversationId };
}

export function filterHistoryItems(items, query = "", scope = "all") {
  const needle = String(query || "").trim().toLocaleLowerCase();
  return (Array.isArray(items) ? items : [])
    .map(normalizeHistoryItem)
    .filter((item) => (scope === "all" || Boolean(item.archived) === (scope === "archived")) && item.conversation_id && (!needle || String(item.title || "").toLocaleLowerCase().includes(needle)));
}

export class HistoryDrawer {
  constructor(container, { onClose, onRefresh, onSelect, onNew, onRename, onArchive, onSettings, onActions }) {
    this.onSelect = onSelect;
    this.onRename = onRename;
    this.onArchive = onArchive;
    this.query = "";
    this.scope = "active";
    this.isOpen = false;
    this.onActions = onActions;
    this.overlay = element("div", "claudian-remote-overlay claudian-remote-history-overlay");
    this.overlay.setAttribute("aria-hidden", "true");
    this.overlay.inert = true;
    this.overlay.addEventListener("click", (event) => { if (event.target === this.overlay) onClose(); });
    this.overlay.addEventListener("keydown", (event) => {
      if (event.key === "Escape") { event.preventDefault(); onClose(); }
    });
    this.sheet = element("aside", "claudian-remote-sheet claudian-remote-history");
    this.sheet.setAttribute("role", "dialog");
    this.sheet.setAttribute("aria-label", "历史对话");
    this.sheet.tabIndex = -1;
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
    this.tabs = element("div", "claudian-remote-history-tabs");
    for (const [scope, label] of [["active", "对话"], ["archived", "已归档"]]) {
      const tab = button("claudian-remote-history-tab", label, () => {
        this.scope = scope;
        this.render(this.lastHistory, this.lastActiveId, this.lastControls, this.lastViewingId);
      });
      tab.dataset.scope = scope;
      this.tabs.append(tab);
    }
    this.list = element("div", "claudian-remote-history-list");
    const footer = element("footer", "claudian-remote-history-footer");
    const settings = button("claudian-remote-history-settings", "设置", onSettings);
    settings.append(element("small", "", "连接与设备"));
    footer.append(settings);
    this.sheet.append(header, this.search, this.tabs, this.list, footer);
    this.overlay.append(this.sheet);
    container.append(this.overlay);
  }

  setOpen(open) {
    open = Boolean(open);
    if (open === this.isOpen) return;
    this.isOpen = open;
    this.overlay.classList.toggle("is-open", open);
    this.overlay.setAttribute("aria-hidden", String(!open));
    this.overlay.inert = !open;
    if (open) this.sheet.focus({ preventScroll: true });
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
    const items = filterHistoryItems(history.items, this.query, this.scope);
    for (const tab of this.tabs.children) tab.setAttribute("aria-pressed", String(tab.dataset.scope === this.scope));
    const renderKey = JSON.stringify([
      history.loaded,
      history.nextPage,
      activeId,
      viewingId,
      this.query,
      this.scope,
      controls,
      ...items.flatMap((item) => [item.conversation_id, item.title, item.message_count, item.archived])
    ]);
    if (renderKey === this.renderKey) return;
    this.renderKey = renderKey;
    this.newButton.disabled = !controls.historyNew;
    this.newButton.title = controls.historyNew ? "新建对话" : "当前状态或 Claudian 版本不支持新建";
    this.list.replaceChildren();
    if (!history.loaded) this.list.append(element("p", "claudian-remote-empty", "正在读取电脑端历史…"));
    else if (!items.length) this.list.append(element("p", "claudian-remote-empty", this.query ? "没有匹配的对话" : this.scope === "archived" ? "暂无归档对话" : "暂无历史对话"));
    for (const item of items) {
      const wrapper = element("div", "claudian-remote-history-item");
      const row = button("claudian-remote-history-row", item.title || "未命名对话", () => this.onSelect(item.conversation_id));
      row.disabled = !controls.history && item.conversation_id !== viewingId;
      row.dataset.active = item.conversation_id === activeId ? "true" : "false";
      row.dataset.viewing = item.conversation_id === viewingId ? "true" : "false";
      row.setAttribute("aria-current", item.conversation_id === viewingId ? "page" : "false");
      row.textContent = "";
      row.append(element("span", "claudian-remote-history-title", item.title || "未命名对话"));
      const actions = button("claudian-remote-history-action", "对话操作", (event) => this.onActions?.(item, event));
      actions.textContent = "⋯";
      actions.disabled = !controls.historyRename && !controls.historyArchive;
      wrapper.append(row, actions);
      this.list.append(wrapper);
    }
  }
}
