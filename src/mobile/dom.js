export function element(tag, className = "", text = "") {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text) node.textContent = text;
  return node;
}

export function button(className, label, onClick) {
  const node = element("button", className, label);
  node.type = "button";
  node.setAttribute("aria-label", label);
  node.addEventListener("click", onClick);
  return node;
}
