const path = require("path");
const vscode = require("vscode");

const PRIORITY_META = {
  P0: { label: "P0 · Review first", icon: "flame", color: "errorForeground" },
  P1: { label: "P1 · High attention", icon: "warning", color: "editorWarning.foreground" },
  P2: { label: "P2 · Review queue", icon: "eye", color: "editorInfo.foreground" },
};

const SEVERITY_META = {
  critical: { label: "Critical impact", icon: "error", color: "errorForeground" },
  high: { label: "High impact", icon: "warning", color: "editorWarning.foreground" },
  medium: { label: "Medium impact", icon: "info", color: "editorInfo.foreground" },
  low: { label: "Low impact", icon: "circle-outline", color: "descriptionForeground" },
};

class AttackSurfaceProvider {
  constructor(session) {
    this.session = session;
    this._changed = new vscode.EventEmitter();
    this.onDidChangeTreeData = this._changed.event;
    this.subscription = session.onDidChange(() => this.refresh());
  }
  refresh() { this._changed.fire(undefined); }
  getTreeItem(element) { return element; }
  getChildren() { return this.session.snapshot.entries.map(entry => new AttackSurfaceItem(entry)); }
  dispose() { this.subscription.dispose(); this._changed.dispose(); }
}

class AttackSurfaceItem extends vscode.TreeItem {
  constructor(entry) {
    super(entry.title, vscode.TreeItemCollapsibleState.None);
    this.description = `${entry.language} · ${path.basename(entry.relativePath)}:${entry.line}`;
    this.tooltip = new vscode.MarkdownString();
    this.tooltip.appendMarkdown("**Attack surface**\n\n");
    this.tooltip.appendText(entry.title);
    this.tooltip.appendMarkdown("\n\n");
    this.tooltip.appendCodeblock(`${entry.relativePath}:${entry.line}`);
    this.iconPath = new vscode.ThemeIcon("globe");
    this.contextValue = "traceguard.attackSurfaceItem";
    this.command = { command: "traceguard.openAuditLocation", title: "Open entry point", arguments: [entry] };
  }
}

class FindingProvider {
  constructor(session) {
    this.session = session;
    this._changed = new vscode.EventEmitter();
    this.onDidChangeTreeData = this._changed.event;
    this.subscription = session.onDidChange(() => this.refresh());
  }
  refresh() { this._changed.fire(undefined); }
  getTreeItem(element) { return element; }
  getChildren(element) {
    const findings = this.session.snapshot.findings;
    if (!element) return ["critical", "high", "medium", "low"]
      .map(severity => new SeverityItem(severity, findings.filter(item => item.severity === severity).length))
      .filter(item => item.count);
    if (element.kind === "severity") return findings.filter(item => item.severity === element.severity).map(item => new FindingItem(item));
    return [];
  }
  dispose() { this.subscription.dispose(); this._changed.dispose(); }
}

class SeverityItem extends vscode.TreeItem {
  constructor(severity, count) {
    const meta = SEVERITY_META[severity];
    super(`${meta.label} (${count})`, vscode.TreeItemCollapsibleState.Expanded);
    this.kind = "severity";
    this.severity = severity;
    this.count = count;
    this.iconPath = new vscode.ThemeIcon(meta.icon, new vscode.ThemeColor(meta.color));
  }
}

class FindingItem extends vscode.TreeItem {
  constructor(finding) {
    super(finding.title, vscode.TreeItemCollapsibleState.None);
    const missing = finding.missingGuards.length ? finding.missingGuards.join(", ") : "none from this rule";
    const observed = finding.observedGuards.length ? finding.observedGuards.join(", ") : "none observed";
    this.description = `${finding.confidence} confidence · ${path.basename(finding.relativePath)}:${finding.line}${finding.pathCount > 1 ? ` · ${finding.pathCount} paths` : ""}`;
    this.tooltip = new vscode.MarkdownString(`**${finding.severity.toUpperCase()} impact · ${finding.confidence} confidence**\n\n${finding.title} (${finding.cwe})\n\nCandidate paths: ${finding.pathCount}\n\nSource: \`${finding.sourceKind}\`\n\nSink: \`${finding.sinkKind}\`\n\nObserved guards: ${observed}\n\nGuards to verify: ${missing}\n\nThis is a possible path for manual review, not a confirmed vulnerability.`);
    this.iconPath = new vscode.ThemeIcon(SEVERITY_META[finding.severity]?.icon || "warning");
    this.contextValue = "traceguard.finding";
    this.command = { command: "traceguard.openAuditLocation", title: "Open finding sink", arguments: [finding] };
  }
}

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
    this.tooltip = new vscode.MarkdownString();
    this.tooltip.appendMarkdown(`**${item.priority}** · `);
    this.tooltip.appendText(item.title);
    this.tooltip.appendMarkdown(`\n\n${item.reasons.map(reason => `- ${reason}`).join("\n")}\n\nAudit coverage status: **${statusLabel(item.status)}**`);
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
      ...(data.indexIncomplete ? [new MetricItem("Index coverage", `${data.indexScope === "current-files" ? "Current files only" : data.indexTruncated ? "File limit reached" : "Partial"}${data.indexSkippedFiles ? ` · ${data.indexSkippedFiles} skipped` : ""}`, "warning")] : []),
      new MetricItem("Review coverage", `${data.coverage}%`, "pie-chart"),
      new MetricItem("Attack surface", `${data.entries.length} entry points`, "globe"),
      new MetricItem("Potential findings", `${data.findings.length} paths${data.findingPathsTruncated ? " · prioritized subset" : ""}`, "warning"),
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
    this.tooltip = new vscode.MarkdownString();
    this.tooltip.appendMarkdown(`**${item.type}**\n\n`);
    this.tooltip.appendCodeblock(item.code);
    if (item.note) { this.tooltip.appendMarkdown("\n"); this.tooltip.appendText(item.note); }
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
  refresh() { this._changed.fire(); }
  provideCodeLenses(document) {
    const showFlowCodeLens = vscode.workspace.getConfiguration("traceguard", document.uri).get("showFlowCodeLens", true);
    return this.session.itemsForUri(document.uri).flatMap(item => {
      const position = new vscode.Position(Math.max(0, item.line - 1), 0);
      const status = statusLabel(item.status);
      const range = new vscode.Range(position, position);
      const lenses = [
        new vscode.CodeLens(range, {
          command: "traceguard.focusAuditItem",
          title: `$(references) ${item.priority} review · ${status} · ${item.counts.sources} inputs / ${item.counts.sinks} sensitive ops`,
          arguments: [item],
        }),
      ];
      if (showFlowCodeLens) lenses.push(new vscode.CodeLens(range, {
          command: "traceguard.traceCrossFileFlow",
          title: "$(git-compare) Trace Source → Sink across files",
          arguments: [item],
        }));
      return lenses;
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

module.exports = { AttackSurfaceProvider, AuditCodeLensProvider, AuditHoverProvider, AuditQueueProvider, AuditSummaryProvider, EvidenceProvider, FindingProvider, statusLabel };
