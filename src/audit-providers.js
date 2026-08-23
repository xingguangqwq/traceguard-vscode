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
    const route = entry.route ? `${entry.method || "ANY"} ${entry.route}` : undefined;
    this.description = `${path.basename(entry.relativePath)}:${entry.line}`;
    this.tooltip = new vscode.MarkdownString();
    this.tooltip.appendMarkdown("$(globe) **Attack surface**\n\n");
    this.tooltip.appendText(entry.title);
    this.tooltip.appendMarkdown("\n\n");
    if (route) this.tooltip.appendMarkdown(`Route: \`${route}\`\n\n`);
    this.tooltip.appendMarkdown(`Language: \`${entry.language}\`\n\n`);
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
    if (element.kind === "finding") return (element.finding.path?.steps || []).map((step, index) => new FindingPathStep(step, index));
    return [];
  }
  dispose() { this.subscription.dispose(); this._changed.dispose(); }
}

class SeverityItem extends vscode.TreeItem {
  constructor(severity, count) {
    const meta = SEVERITY_META[severity];
    super(meta.label, vscode.TreeItemCollapsibleState.Expanded);
    this.kind = "severity";
    this.severity = severity;
    this.count = count;
    this.description = `${count} finding${count === 1 ? "" : "s"}`;
    this.tooltip = new vscode.MarkdownString(`**${meta.label}**\n\n${count} candidate finding${count === 1 ? "" : "s"} waiting for your review decision. Candidates are clues, not confirmed vulnerabilities.`);
    this.iconPath = new vscode.ThemeIcon(meta.icon, new vscode.ThemeColor(meta.color));
  }
}

class FindingItem extends vscode.TreeItem {
  constructor(finding) {
    super(finding.title, finding.path?.steps?.length ? vscode.TreeItemCollapsibleState.Collapsed : vscode.TreeItemCollapsibleState.None);
    const missing = finding.missingGuards.length ? finding.missingGuards.join(", ") : "none from this rule";
    const observed = finding.observedGuards.length ? finding.observedGuards.join(", ") : "none observed";
    const statusGlyph = { reviewed: "$(pass-filled)", false_positive: "$(circle-slash)", accepted_risk: "$(shield)", suppressed: "$(eye-closed)" }[finding.status] || "$(circle-filled)";
    this.description = `${path.basename(finding.relativePath)}:${finding.line}${finding.pathCount > 1 ? ` · ${finding.pathCount} paths` : ""}`;
    const confidenceReason = finding.explanation?.confidenceReason || "Review the path and call resolution.";
    const severityMeta = SEVERITY_META[finding.severity] || SEVERITY_META.medium;
    const resolved = finding.status !== "open";
    this.tooltip = new vscode.MarkdownString(`$(error) **${finding.severity.toUpperCase()} impact** · ${finding.confidence} confidence · ${findingStatusLabel(finding.status)}\n\n${finding.title} (${finding.cwe})\n\nCandidate paths: ${finding.pathCount}\n\nSource: \`${finding.sourceKind}\`\n\nSink: \`${finding.sinkKind}\`\n\nObserved guards: ${observed}\n\nGuards to verify: ${missing}\n\nConfidence: ${confidenceReason}\n\nExpand this item to inspect the Source → Sink path.`);
    this.iconPath = resolved
      ? new vscode.ThemeIcon(statusGlyph.replace(/\$\((.*)\)/, "$1"), new vscode.ThemeColor("descriptionForeground"))
      : new vscode.ThemeIcon(severityMeta.icon, new vscode.ThemeColor(severityMeta.color));
    this.contextValue = "traceguard.finding";
    this.kind = "finding";
    this.finding = finding;
    this.command = { command: "traceguard.openAuditLocation", title: "Open finding sink", arguments: [finding] };
  }
}

class FindingPathStep extends vscode.TreeItem {
  constructor(step, index) {
    super(`${index + 1}. ${step.label}`, vscode.TreeItemCollapsibleState.None);
    this.description = `${step.kind} · ${path.basename(step.relativePath)}:${step.line}`;
    this.tooltip = new vscode.MarkdownString();
    this.tooltip.appendMarkdown(`**${step.kind.toUpperCase()}** · `);
    this.tooltip.appendText(step.label);
    if (step.code) this.tooltip.appendCodeblock(step.code);
    if (step.candidateReason) this.tooltip.appendMarkdown(`\nCall resolution: ${step.candidateReason}`);
    this.iconPath = new vscode.ThemeIcon({ source: "arrow-right", sink: "target", call: "call-outgoing", return: "call-incoming", validation: "verified", authorization: "lock" }[step.kind] || "circle-small-filled");
    this.command = { command: "traceguard.openAuditLocation", title: "Open path step", arguments: [step] };
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
    super(meta.label, vscode.TreeItemCollapsibleState.Expanded);
    this.kind = "priority"; this.priority = priority; this.count = count;
    this.description = `${count} target${count === 1 ? "" : "s"}`;
    this.tooltip = new vscode.MarkdownString(`**${meta.label}**\n\n${count} review target${count === 1 ? "" : "s"} in this reading-order tier.`);
    this.iconPath = new vscode.ThemeIcon(meta.icon, new vscode.ThemeColor(meta.color));
  }
}

class AuditItem extends vscode.TreeItem {
  constructor(item) {
    super(item.title, vscode.TreeItemCollapsibleState.None);
    this.auditItem = item;
    this.description = `${item.language} · ${path.basename(item.relativePath)}:${item.line}`;
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
    if (!data.indexed_at) {
      if (data.indexing) return [new MetricItem(
        "Indexing review clues…",
        data.indexStage?.message || "Preparing analysis",
        "sync~spin",
        undefined,
        "TraceGuard is actively building the workspace audit map.",
      )];
      if (data.indexError) return [new MetricItem(
        "Index failed",
        data.indexError,
        "error",
        "errorForeground",
        "The previous audit map was kept. Run Refresh Code Review Index to try again and open the TraceGuard Audit output for details.",
        "traceguard.refreshAudit",
      )];
      return [new MetricItem(
        "Review queue not built",
        "Run Build Review Queue",
        "play",
        undefined,
        "Workspace indexing is off by default. Select this item or run Build Review Queue to start it.",
        "traceguard.startAudit",
      )];
    }
    const languages = Object.keys(data.languages).join(", ") || "none";
    const parserCapabilities = Object.entries(data.languageCapabilities || {}).map(([language, capability]) =>
      `${language}: ${capability.astFiles}/${capability.files} AST · ${capability.capability || "fallback"}${capability.degradedFiles ? ` · ${capability.degradedFiles} degraded` : ""}`,
    ).join("; ") || "none";
    const degraded = Object.entries(data.languageCapabilities || {}).flatMap(([language, capability]) =>
      (capability.reasons || []).map(reason => `${language}: ${reason}`),
    );
    const projectConfiguration = data.projectConfiguration || { loaded: false, semanticModels: 0, excludedPatterns: 0, issues: [] };
    const coverage = Math.max(0, Math.min(100, Number(data.coverage) || 0));
    const openFindings = data.findings.filter(finding => finding.status === "open");
    const blockingFindings = openFindings.filter(finding => finding.severity === "critical" || finding.severity === "high").length;
    const findingTone = blockingFindings ? "errorForeground" : openFindings.length ? "editorWarning.foreground" : "testing.iconPassed";
    return [
      ...(data.indexIncomplete ? [new MetricItem("Partial index", data.indexScope === "current-files" ? "Current files only" : `${data.indexSkippedFiles || 0} files skipped`, "warning", "editorWarning.foreground")] : []),
      new MetricItem("Coverage", `${progressBar(coverage)} ${data.coverage}%`, "check-all", coverage >= 80 ? "testing.iconPassed" : coverage >= 40 ? "editorWarning.foreground" : "descriptionForeground"),
      new MetricItem("Entry points", `${data.entries.length}`, "globe"),
      new MetricItem("Findings", `${openFindings.length} open · ${data.findings.length} total`, "shield", findingTone),
      new MetricItem("Queue", `${data.statusCounts.unreviewed} left · ${data.items.length} targets`, "checklist"),
      new MetricItem("Indexed", `${formatCount(data.files)} files · ${formatCount(data.functions)} functions`, "symbol-method"),
      new MetricItem("Languages", languages, "code"),
      new MetricItem("Parser capability", parserCapabilities, "symbol-structure"),
      ...(degraded.length ? [new MetricItem("Degraded parsing", degraded.join("; "), "warning", "editorWarning.foreground")] : []),
      ...(projectConfiguration.loaded || projectConfiguration.issues.length ? [new MetricItem(
        "Project semantics",
        projectConfiguration.issues.length
          ? `${projectConfiguration.issues.length} issue${projectConfiguration.issues.length === 1 ? "" : "s"} · last valid model kept`
          : `${projectConfiguration.semanticModels} custom models`,
        projectConfiguration.issues.length ? "warning" : "settings-gear",
        projectConfiguration.issues.length ? "editorWarning.foreground" : undefined,
      )] : []),
      new MetricItem("Notes", `${data.evidence.length}`, "bookmark"),
    ];
  }
  dispose() { this.subscription.dispose(); this._changed.dispose(); }
}

class MetricItem extends vscode.TreeItem {
  constructor(label, description, icon, color, tooltip, command) {
    super(label, vscode.TreeItemCollapsibleState.None);
    this.description = description;
    this.iconPath = color
      ? new vscode.ThemeIcon(icon.replace("~spin", ""), new vscode.ThemeColor(color))
      : new vscode.ThemeIcon(icon);
    this.tooltip = tooltip || (icon.endsWith("~spin") ? "Analysis in progress" : undefined);
    if (command) this.command = { command, title: label };
  }
}

function progressBar(percent, width = 10) {
  const clamped = Math.max(0, Math.min(100, Number(percent) || 0));
  const filled = Math.round((clamped / 100) * width);
  return "▰".repeat(filled) + "▱".repeat(width - filled);
}

function formatCount(value) {
  return Number(value).toLocaleString("en-US");
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
  constructor(type, count) {
    super(type, vscode.TreeItemCollapsibleState.Expanded);
    this.kind = "evidenceGroup";
    this.type = type;
    this.description = `${count} note${count === 1 ? "" : "s"}`;
    this.iconPath = new vscode.ThemeIcon(evidenceIcon(type));
  }
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

const QUERY_STATUS_META = {
  verified: { label: "verified", icon: "pass-filled", color: "testing.iconPassed" },
  "syntax-only": { label: "syntax-only", icon: "symbol-structure", color: "editorInfo.foreground" },
  heuristic: { label: "heuristic", icon: "question", color: "editorWarning.foreground" },
  unresolved: { label: "unresolved", icon: "circle-slash", color: "errorForeground" },
};

class AuditQueryProvider {
  constructor() {
    this.result = undefined;
    this._changed = new vscode.EventEmitter();
    this.onDidChangeTreeData = this._changed.event;
  }

  setResult(result) {
    this.result = result;
    this._changed.fire(undefined);
  }

  clear() {
    this.setResult(undefined);
  }

  get current() {
    return this.result;
  }

  getTreeItem(element) {
    return element;
  }

  getChildren(element) {
    if (!element) {
      if (!this.result) return [];
      return [new AuditQueryResultItem(this.result)];
    }
    if (element.kind === "query-result") return (element.result.roots || []).map(node => new AuditQueryNodeItem(node));
    if (element.kind === "query-node") return (element.node.children || []).map(node => new AuditQueryNodeItem(node));
    return [];
  }

  dispose() {
    this._changed.dispose();
  }
}

class AuditQueryResultItem extends vscode.TreeItem {
  constructor(result) {
    super(result.title, vscode.TreeItemCollapsibleState.Expanded);
    this.kind = "query-result";
    this.result = result;
    const nodes = Number(result.summary?.nodes) || countQueryNodes(result.roots || []);
    this.description = `${nodes} step${nodes === 1 ? "" : "s"}${result.truncated ? " · truncated" : ""}`;
    this.tooltip = new vscode.MarkdownString();
    this.tooltip.appendMarkdown(`**${result.title}**\n\n`);
    this.tooltip.appendText(`${nodes} analysis steps${result.truncated ? "; the configured query limit was reached" : ""}.`);
    this.iconPath = new vscode.ThemeIcon(result.truncated ? "warning" : "list-tree");
    this.contextValue = "traceguard.auditQueryResult";
  }
}

class AuditQueryNodeItem extends vscode.TreeItem {
  constructor(node) {
    const children = node.children || [];
    super(node.label, children.length ? vscode.TreeItemCollapsibleState.Collapsed : vscode.TreeItemCollapsibleState.None);
    this.kind = "query-node";
    this.node = node;
    const meta = QUERY_STATUS_META[node.status] || QUERY_STATUS_META.heuristic;
    const location = node.location;
    const locationLabel = location?.relativePath
      ? `${path.basename(location.relativePath)}:${location.line}`
      : location?.absolutePath ? `${path.basename(location.absolutePath)}:${location.line}` : "no source location";
    this.description = `${locationLabel} · $(${meta.icon})`;
    this.tooltip = new vscode.MarkdownString();
    this.tooltip.appendMarkdown(`**${meta.label} · ${node.kind || "step"}**\n\n`);
    this.tooltip.appendText(node.reason || "No connection explanation was produced.");
    if (location?.code) this.tooltip.appendCodeblock(location.code);
    const details = Object.entries(node.details || {}).filter(([, value]) => value !== undefined && value !== "");
    if (details.length) {
      this.tooltip.appendMarkdown("\n\n**Analysis facts**\n\n");
      for (const [key, value] of details) this.tooltip.appendMarkdown(`- ${escapeMarkdown(key)}: \`${escapeMarkdown(formatDetail(value))}\`\n`);
    }
    this.iconPath = new vscode.ThemeIcon(queryKindIcon(node.kind) || meta.icon, new vscode.ThemeColor(meta.color));
    this.contextValue = "traceguard.auditQueryNode";
    if (location?.absolutePath && location?.line) {
      this.command = { command: "traceguard.openAuditLocation", title: "Open analysis step", arguments: [location] };
    }
  }
}

function countQueryNodes(nodes) {
  return nodes.reduce((count, node) => count + 1 + countQueryNodes(node.children || []), 0);
}

function queryKindIcon(kind) {
  return {
    source: "arrow-right",
    sink: "target",
    call: "call-outgoing",
    caller: "call-incoming",
    callee: "call-outgoing",
    return: "reply",
    assignment: "symbol-variable",
    parameter: "symbol-parameter",
    entry: "globe",
    guard: "verified",
    unresolved: "circle-slash",
    empty: "circle-outline",
  }[kind];
}

function formatDetail(value) {
  if (Array.isArray(value)) return value.join(", ");
  if (value && typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function escapeMarkdown(value) {
  return String(value).replace(/[\\`*_{}[\]()#+\-.!]/g, "\\$&");
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
          title: `$(references) ${item.priority} review · ${status}`,
          arguments: [item],
        }),
      ];
      if (showFlowCodeLens) lenses.push(new vscode.CodeLens(range, {
          command: "traceguard.traceCrossFileFlow",
          title: "$(git-compare) Trace Source → Sink",
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
    markdown.appendMarkdown(`### $(references) TraceGuard audit signal${signals.length === 1 ? "" : "s"}\n\n`);
    for (const signal of signals) {
      markdown.appendMarkdown(`- $(eye) **${signal.kind.toUpperCase()}** · ${escapeMarkdown(signal.label)}\n`);
    }
    markdown.appendMarkdown("\n---\n\nThis is an audit clue, not a confirmed vulnerability. Trace its callers, controls and downstream effects.");
    return new vscode.Hover(markdown);
  }
}

function statusLabel(status) { return { unreviewed: "Not reviewed", in_review: "In review", reviewed: "Reviewed", blocked: "Needs context" }[status] || "Not reviewed"; }
function findingStatusLabel(status) { return { open: "Open", reviewed: "Reviewed", false_positive: "False positive", accepted_risk: "Accepted risk", suppressed: "Suppressed" }[status] || "Open"; }
function evidenceIcon(type) { return { Source: "arrow-right", Sink: "target", Authorization: "lock", Validation: "verified", Observation: "note" }[type] || "bookmark"; }

module.exports = { AttackSurfaceProvider, AuditCodeLensProvider, AuditHoverProvider, AuditQueryProvider, AuditQueueProvider, AuditSummaryProvider, EvidenceProvider, FindingProvider, statusLabel };
