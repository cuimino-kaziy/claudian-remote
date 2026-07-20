import { element } from "../dom.js";

export function activityCard(model) {
  const card = element("div");
  updateActivityCard(card, model);
  return card;
}

export function updateActivityCard(card, model) {
  const entries = Array.isArray(model.entries) ? model.entries : [];
  const expandable = entries.length > 0;
  const classes = ["claudian-remote-activity"];
  if (model.running) classes.push("is-running");
  if (!expandable) classes.push("is-status-only");
  card.className = classes.join(" ");
  if (model.running) {
    card.setAttribute("aria-busy", "true");
  } else card.removeAttribute("aria-busy");
  const summary = element(expandable ? "summary" : "div", "claudian-remote-activity-summary");
  if (model.running) summary.setAttribute("aria-live", "polite");
  const current = entries.at(-1);
  summary.textContent = model.running ? (current?.label || "正在处理…") : `执行记录 · ${entries.length} 项`;
  if (model.running && !current) summary.textContent = "正在思考…";
  if (!expandable) {
    card.replaceChildren(summary);
    return card;
  }
  let details = card.firstElementChild?.tagName === "DETAILS" ? card.firstElementChild : null;
  if (!details) {
    details = element("details");
    details.open = Boolean(model.running);
    card.replaceChildren(details);
  }
  const list = element("ol", "claudian-remote-activity-list");
  for (const entry of entries) {
    const item = element("li", "claudian-remote-activity-row");
    item.dataset.status = entry.status || "running";
    item.append(element("span", "claudian-remote-activity-dot", entry.status === "completed" ? "✓" : entry.status === "failed" ? "!" : "•"));
    const text = element("span", "", entry.label || entry.stage || entry.name || "正在处理");
    if (entry.summary) text.append(element("small", "claudian-remote-activity-detail", entry.summary));
    if (entry.duration_ms != null) text.append(element("small", "claudian-remote-activity-time", `${Math.round(entry.duration_ms / 100) / 10}s`));
    item.append(text);
    list.append(item);
  }
  details.replaceChildren(summary, list);
  return card;
}
