const path = require("path");
const vscode = require("vscode");

const PRIORITY_META = {
  P0: { label: "P0 · Review first", icon: "flame", color: "errorForeground" },
  P1: { label: "P1 · High attention", icon: "warning", color: "editorWarning.foreground" },
  P2: { label: "P2 · Review queue", icon: "eye", color: "editorInfo.foreground" },
};

class AuditQueueProvider {
  constructor(session) {
    this.session = session;
    this._changed = new vscode.EventEmitter();
    this.onDidChangeTreeData = this._changed.event;
    this.subscription = session.onDidChange(() => this.refresh());
  }
  refresh() { this._changed.fire(undefined); }
  getTreeItem(element) { return element; }
  getChildren(element) {
    const hideReviewed = vscode.workspace.getConfiguration("traceguard").get("hideReviewedTargets", false);
    const items = this.session.snapshot.items.filter(item => !hideReviewed || item.status !== "reviewed");
    if (!element) return ["P0", "P1", "P2"].map(priority => new PriorityItem(priority, items.filter(item => item.priority === priority).length)).filter(item => item.count);
    if (element.kind === "priority") return items.filter(item => item.priority === element.priority).map(item => new AuditItem(item));
    return [];
  }
  dispose() { this.subscription.dispose(); this._changed.dispose(); }
}

class PriorityItem extends vscode.TreeItem {
  constructor(priority, count) {
    const meta = PRIORITY_META[priority];
    super(`${meta.label} (${count})`, vscode.TreeItemCollapsibleState.Expanded);
    this.kind = "priority"; this.priority = priority; this.count = count;
    this.iconPath = new vscode.ThemeIcon(meta.icon, new vscode.ThemeColor(meta.color));
  }
}

class AuditItem extends vscode.TreeItem {
  constructor(item) {
    super(item.title, vscode.TreeItemCollapsibleState.None);
    this.auditItem = item;
    this.description = `${statusLabel(item.status)} · ${item.language} · ${path.basename(item.relativePath)}:${item.line}`;
    this.tooltip = new vscode.MarkdownString(`**${item.priority} · ${item.title}**\n\n${item.reasons.map(reason => `- ${reason}`).join("\n")}\n\nAudit coverage status: **${statusLabel(item.status)}**`);
    this.iconPath = new vscode.ThemeIcon(item.status === "reviewed" ? "pass-filled" : item.status === "in_review" ? "debug-pause" : item.status === "blocked" ? "circle-slash" : "circle-outline");
    this.contextValue = "traceguard.auditItem";
    this.command = { command: "traceguard.focusAuditItem", title: "Audit this target", arguments: [item] };
  }
}

class AuditSummaryProvider {
  constructor(session) {
    this.session = session;
    this._changed = new vscode.EventEmitter();
    this.onDidChangeTreeData = this._changed.event;
    this.subscription = session.onDidChange(() => this.refresh());
  }
  refresh() { this._changed.fire(undefined); }
  getTreeItem(element) { return element; }
  getChildren() {
    const data = this.session.snapshot;
    if (!data.indexed_at) return [new MetricItem("Indexing review clues…", "", "sync~spin")];
    const languages = Object.keys(data.languages).join(", ") || "none";
    return [
      new MetricItem("Review coverage", `${data.coverage}%`, "pie-chart"),
      new MetricItem("Attack surface", `${data.entries.length} entry points`, "globe"),
      new MetricItem("Review queue", `${data.items.length} targets`, "checklist"),
      new MetricItem("Code indexed", `${data.files} files · ${data.functions} functions`, "symbol-method"),
      new MetricItem("Languages", languages, "code"),
      new MetricItem("Audit notes", `${data.evidence.length} records`, "notebook"),
    ];
  }
  dispose() { this.subscription.dispose(); this._changed.dispose(); }
}

class MetricItem extends vscode.TreeItem {
  constructor(label, description, icon) { super(label, vscode.TreeItemCollapsibleState.None); this.description = description; this.iconPath = new vscode.ThemeIcon(icon); }
}

class EvidenceProvider {
  constructor(session) {
    this.session = session;
    this._changed = new vscode.EventEmitter();
    this.onDidChangeTreeData = this._changed.event;
    this.subscription = session.onDidChange(() => this.refresh());
  }
  refresh() { this._changed.fire(undefined); }
  getTreeItem(element) { return element; }
  getChildren(element) {
    const evidence = this.session.snapshot.evidence;
    if (!element) {
      const types = [...new Set(evidence.map(item => item.type))];
      return types.map(type => new EvidenceGroup(type, evidence.filter(item => item.type === type).length));
    }
    if (element.kind === "evidenceGroup") return evidence.filter(item => item.type === element.type).map(item => new EvidenceItem(item));
    return [];
  }
  dispose() { this.subscription.dispose(); this._changed.dispose(); }
}

class EvidenceGroup extends vscode.TreeItem {
  constructor(type, count) { super(`${type} (${count})`, vscode.TreeItemCollapsibleState.Expanded); this.kind = "evidenceGroup"; this.type = type; this.iconPath = new vscode.ThemeIcon(evidenceIcon(type)); }
}

class EvidenceItem extends vscode.TreeItem {
  constructor(item) {
    super(item.note || item.code.trim().slice(0, 70) || `${item.type} evidence`, vscode.TreeItemCollapsibleState.None);
    this.description = `${path.basename(item.relativePath)}:${item.line}`;
    this.tooltip = new vscode.MarkdownString(`**${item.type}**\n\n\`${item.code.replaceAll("`", "\\`")}\`\n\n${item.note || ""}`);
    this.iconPath = new vscode.ThemeIcon("bookmark");
    this.evidenceItem = item;
    this.contextValue = "traceguard.evidence";
    this.command = { command: "traceguard.openEvidence", title: "Open evidence", arguments: [item] };
  }
}

class AuditCodeLensProvider {
  constructor(session) {
    this.session = session;
    this._changed = new vscode.EventEmitter();
    this.onDidChangeCodeLenses = this._changed.event;
    this.subscription = session.onDidChange(() => this._changed.fire());
  }
  provideCodeLenses(document) {
    return this.session.itemsForUri(document.uri).map(item => {
      const position = new vscode.Position(Math.max(0, item.line - 1), 0);
      const status = statusLabel(item.status);
      return new vscode.CodeLens(new vscode.Range(position, position), {
        command: "traceguard.focusAuditItem",
        title: `$(references) ${item.priority} review · ${status} · ${item.counts.sources} inputs / ${item.counts.sinks} sensitive ops`,
        arguments: [item],
      });
    });
  }
  dispose() { this.subscription.dispose(); this._changed.dispose(); }
}

class AuditHoverProvider {
  constructor(session) { this.session = session; }
  provideHover(document, position) {
    const signals = this.session.signalsAt(document.uri, position.line);
    if (!signals.length) return undefined;
    const markdown = new vscode.MarkdownString();
    markdown.appendMarkdown("### TraceGuard audit signal\n\n");
    for (const signal of signals) markdown.appendMarkdown(`- **${signal.kind.toUpperCase()}** · ${signal.label}\n`);
    markdown.appendMarkdown("\nThis is an audit clue, not a confirmed vulnerability. Trace its callers, controls and downstream effects.");
    return new vscode.Hover(markdown);
  }
}

function statusLabel(status) { return { unreviewed: "Not reviewed", in_review: "In review", reviewed: "Reviewed", blocked: "Needs context" }[status] || "Not reviewed"; }
function evidenceIcon(type) { return { Source: "arrow-right", Sink: "target", Authorization: "lock", Validation: "verified", Observation: "note" }[type] || "bookmark"; }

module.exports = { AuditCodeLensProvider, AuditHoverProvider, AuditQueueProvider, AuditSummaryProvider, EvidenceProvider, statusLabel };
