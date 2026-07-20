import { button, element } from "../dom.js";

export function artifactCard(artifact, { onOpen }) {
  const card = button("claudian-remote-artifact", artifact.label || artifact.vault_path || "打开文件", () => onOpen(artifact));
  const meta = element("small", "", artifact.kind === "markdown" ? "Markdown 笔记" : artifact.kind || "文件");
  card.prepend(element("span", "claudian-remote-artifact-icon", "▧"));
  card.append(meta, element("span", "claudian-remote-artifact-arrow", "›"));
  return card;
}
