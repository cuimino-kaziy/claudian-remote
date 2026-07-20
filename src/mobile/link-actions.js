const ABSOLUTE_LOCAL = /^(?:file:|\/|[A-Za-z]:\\|(?:\/Users|\/Volumes|\/private)\/)/i;

export function classifyLink(rawHref, { internalTarget = "" } = {}) {
  const href = String(internalTarget || rawHref || "").trim();
  if (!href || ABSOLUTE_LOCAL.test(href)) return { kind: "blocked", reason: "local_or_empty" };
  if (/^https?:\/\//i.test(href)) return { kind: "external", href };
  if (/^[A-Za-z][A-Za-z0-9+.-]*:/i.test(href)) return { kind: "blocked", reason: "scheme_not_allowed" };
  try { return { kind: "vault", target: decodeURIComponent(href.replace(/^\.\//, "")) }; }
  catch { return { kind: "blocked", reason: "malformed_link" }; }
}

export function handleContentAction({ app, sourcePath = "", anchor, openExternal = (url) => globalThis.open?.(url, "_blank", "noopener") }) {
  const internalTarget = anchor?.dataset?.href || anchor?.getAttribute?.("data-vault-path") || "";
  const action = classifyLink(anchor?.getAttribute?.("href") || "", { internalTarget });
  if (action.kind === "vault") {
    const resolver = app.metadataCache?.getFirstLinkpathDest?.bind(app.metadataCache);
    if (resolver && !resolver(action.target, sourcePath)) return { kind: "missing", target: action.target };
    app.workspace.openLinkText(action.target, sourcePath, false);
  }
  else if (action.kind === "external") openExternal(action.href);
  return action;
}
