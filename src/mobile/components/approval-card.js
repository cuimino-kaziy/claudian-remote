import { button, element } from "../dom.js";

export function approvalCard(approval, { enabled, onRespond }) {
  const card = element("section", "claudian-remote-approval");
  card.append(element("strong", "", approval.title || "需要电脑端权限确认"));
  const actions = element("div", "claudian-remote-approval-actions");
  for (const option of approval.options || []) {
    const action = button("mod-cta", option.label || option.id, () => onRespond(approval.id, option.id));
    action.disabled = !enabled || approval.status !== "pending";
    actions.append(action);
  }
  card.append(actions);
  return card;
}
