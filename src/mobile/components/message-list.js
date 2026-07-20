import { element } from "../dom.js";
import { StreamingMarkdownRenderer } from "../markdown-renderer.js";
import { FrameRenderScheduler } from "../render-scheduler.js";
import { shouldFollowBottom, currentOperationModel, shouldShowOperationCard } from "../view-model.js";
import { activityCard, updateActivityCard } from "./activity-card.js";
import { approvalCard } from "./approval-card.js";
import { artifactCard } from "./artifact-card.js";

export class MessageList {
  constructor(container, { app, sourcePath = "", onApproval, onArtifact }) {
    this.app = app;
    this.sourcePath = sourcePath;
    this.onApproval = onApproval;
    this.onArtifact = onArtifact;
    this.el = element("main", "claudian-remote-messages");
    this.list = element("div", "claudian-remote-message-list");
    this.newContent = element("button", "claudian-remote-new-content", "有新内容 ↓");
    this.newContent.type = "button";
    this.newContent.hidden = true;
    this.newContent.addEventListener("click", () => { this.following = true; this.scrollToBottom(); });
    this.el.append(this.list, this.newContent);
    container.append(this.el);
    this.nodes = new Map();
    this.activityNodes = new Map();
    this.approvalNodes = new Map();
    this.artifactNodes = new Map();
    this.scrollScheduler = new FrameRenderScheduler({ render: () => {
      if (!this.following) return;
      this.el.scrollTop = this.el.scrollHeight;
      this.newContent.hidden = true;
    } });
    this.following = true;
    this.el.addEventListener("scroll", () => {
      this.following = shouldFollowBottom(this.el);
      if (this.following) this.newContent.hidden = true;
    }, { passive: true });
  }

  createMessage(item) {
    const article = element("article", `claudian-remote-message is-${item.role === "user" ? "user" : "assistant"}`);
    const label = element("div", "claudian-remote-message-label", item.role === "user" ? "你" : "Claudian");
    const body = element("div", "claudian-remote-message-body");
    const status = element("small", "claudian-remote-delivery-status");
    article.append(label, body, status);
    const node = { el: article, body, status, text: null, isFinal: null, renderer: null };
    if (item.role !== "user") {
      node.renderer = new StreamingMarkdownRenderer({
        app: this.app,
        sourcePath: this.sourcePath,
        onRendered: () => this.afterContentChange()
      });
    }
    return node;
  }

  updateMessage(node, item, isFinal) {
    if (node.text !== item.text || node.isFinal !== isFinal) {
      node.text = item.text;
      node.isFinal = isFinal;
      if (item.role === "user") node.body.textContent = item.text;
      else node.renderer.schedule(node.body, item.text || "\u200b", { final: isFinal });
    }
    const statusLabels = {
      local_pending: "正在发送…",
      relay_accepted: "已送达中转",
      desktop_accepted: "电脑已接收",
      terminal: "已完成",
      unknown: "回执待确认，请勿重复发送",
      rejected: item.deliveryError === "mac_offline" ? "Mac 已离线，未发送" : "发送失败，草稿已保留"
    };
    node.status.textContent = statusLabels[item.deliveryStatus] || "";
    node.status.hidden = !node.status.textContent;
  }

  render(model) {
    const wasFollowing = this.following;
    const desired = [];
    const desiredActivityTurns = new Set();
    const desiredApprovals = new Set();
    const desiredArtifacts = new Set();
    const finalTurns = new Set(model.turns.filter((turn) => turn.status !== "running").map((turn) => turn.id));
    for (const item of model.messages) {
      let node = this.nodes.get(item.key);
      if (!node) {
        node = this.createMessage(item);
        this.nodes.set(item.key, node);
      }
      this.updateMessage(node, item, !item.turnId || finalTurns.has(item.turnId));
      desired.push([item.key, node.el]);
    }
    for (const turn of model.turns) {
      const operations = currentOperationModel(turn);
      if (shouldShowOperationCard(operations)) {
        let node = this.activityNodes.get(turn.id);
        if (!node) {
          node = activityCard(operations);
          this.activityNodes.set(turn.id, node);
        } else updateActivityCard(node, operations);
        desiredActivityTurns.add(turn.id);
        desired.push([`operations:${turn.id}`, node]);
      }
      for (const approvalId of turn.approvalOrder) {
        const approval = turn.approvals[approvalId];
        const key = `approval:${turn.id}:${approvalId}`;
        const signature = JSON.stringify({ approval, enabled: model.controls.approval });
        let entry = this.approvalNodes.get(key);
        if (!entry || entry.signature !== signature) {
          entry?.el.remove();
          entry = {
            signature,
            el: approvalCard(approval, { enabled: model.controls.approval, onRespond: this.onApproval })
          };
          this.approvalNodes.set(key, entry);
        }
        desiredApprovals.add(key);
        desired.push([key, entry.el]);
      }
      for (const artifactId of turn.artifactOrder) {
        const artifact = turn.artifacts[artifactId];
        const key = `artifact:${turn.id}:${artifactId}`;
        const signature = JSON.stringify(artifact);
        let entry = this.artifactNodes.get(key);
        if (!entry || entry.signature !== signature) {
          entry?.el.remove();
          entry = { signature, el: artifactCard(artifact, { onOpen: this.onArtifact }) };
          this.artifactNodes.set(key, entry);
        }
        desiredArtifacts.add(key);
        desired.push([key, entry.el]);
      }
    }

    for (const [turnId, node] of this.activityNodes) {
      if (!desiredActivityTurns.has(turnId)) {
        node.remove();
        this.activityNodes.delete(turnId);
      }
    }
    for (const [key, entry] of this.approvalNodes) {
      if (!desiredApprovals.has(key)) {
        entry.el.remove();
        this.approvalNodes.delete(key);
      }
    }
    for (const [key, entry] of this.artifactNodes) {
      if (!desiredArtifacts.has(key)) {
        entry.el.remove();
        this.artifactNodes.delete(key);
      }
    }

    const desiredKeys = new Set(desired.map(([key]) => key));
    for (const [key, node] of this.nodes) {
      if (!desiredKeys.has(key)) {
        node.renderer?.dispose();
        node.el.remove();
        this.nodes.delete(key);
      }
    }
    for (const [, node] of desired) this.list.append(node);
    if (wasFollowing) this.scrollToBottom();
    else if (desired.length) this.newContent.hidden = false;
  }

  afterContentChange() {
    if (this.following) this.scrollToBottom();
    else this.newContent.hidden = false;
  }

  scrollToBottom() {
    this.scrollScheduler.request();
  }

  dispose() {
    this.scrollScheduler.dispose();
    for (const node of this.nodes.values()) node.renderer?.dispose();
    this.nodes.clear();
    for (const node of this.activityNodes.values()) node.remove();
    this.activityNodes.clear();
    for (const entry of this.approvalNodes.values()) entry.el.remove();
    this.approvalNodes.clear();
    for (const entry of this.artifactNodes.values()) entry.el.remove();
    this.artifactNodes.clear();
  }
}
