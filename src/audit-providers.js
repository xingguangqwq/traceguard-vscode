"use strict";

const path = require("path");
const vscode = require("vscode");
const { findingPaths, findingPool, pathVerificationStatus } = require("./review/finding-pool");

// Visual system: one canonical declaration for severity, priority, proof status
// and step-kind presentation, so every view speaks the same visual language.
const SEVERITY_META = {
  critical: { label: "Critical", icon: "error", color: "errorForeground", rank: 0 },
  high: { label: "High", icon: "warning", color: "editorWarning.foreground", rank: 1 },
  medium: { label: "Medium", icon: "info", color: "editorInfo.foreground", rank: 2 },
  low: { label: "Low", icon: "circle-outline", color: "descriptionForeground", rank: 3 },
};

const PRIORITY_META = {
  P0: { label: "P0", icon: "flame", color: "errorForeground", rank: 0 },
  P1: { label: "P1", icon: "warning", color: "editorWarning.foreground", rank: 1 },
  P2: { label: "P2", icon: "eye", color: "editorInfo.foreground", rank: 2 },
  Backlog: { label: "Backlog", icon: "archive", color: "descriptionForeground", rank: 3 },
};

const PRIORITY_GUIDANCE = {
  P0: "Entry points that reach a dangerous operation without a proven guard. Start the review here.",
  P1: "Entry paths whose calls could not be fully resolved; supply the missing context before judging them.",
  P2: "Security-sensitive helpers worth reading once entry-backed work is done.",
  Backlog: "Ordinary reachable functions with no direct security signal. Review opportunistically.",
};

const FINDING_STATUS_GLYPH = { reviewed: "pass-filled", false_positive: "circle-slash", accepted_risk: "shield", suppressed: "eye-closed" };

const QUERY_STATUS_META = {
  verified: { label: "verified", icon: "pass-filled", color: "testing.iconPassed" },
  "syntax-only": { label: "syntax-only", icon: "symbol-structure", color: "editorInfo.foreground" },
  heuristic: { label: "heuristic", icon: "question", color: "editorWarning.foreground" },
  unresolved: { label: "unresolved", icon: "circle-slash", color: "errorForeground" },
};

const STEP_KIND_ICONS = {
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
  validation: "verified",
  authorization: "lock",
  unresolved: "circle-slash",
  empty: "circle-outline",
};

const EVIDENCE_TYPE_ORDER = [
  "Source", "Sink", "Controllability", "Authorization", "Validation",
  "Dynamic Validation", "Exploit Condition", "Missing Context",
  "False Positive Reason", "Remediation", "Observation",
];

const TREE_REFRESH_DEBOUNCE_MS = 150;

// Base provider: coalesces bursty session updates into one tree rebuild and
// guarantees timer/subscription cleanup on dispose.
class SessionTreeProvider {
  constructor(session) {
    this.session = session;
    this._changed = new vscode.EventEmitter();
    this.onDidChangeTreeData = this._changed.event;
    this.refreshTimer = undefined;
    this.subscription = session.onDidChange(() => this.refresh());
  }
  refresh() {
    clearTimeout(this.refreshTimer);
    this.refreshTimer = setTimeout(() => {
      this.refreshTimer = undefined;
      this.invalidate();
      this._changed.fire(undefined);
    }, TREE_REFRESH_DEBOUNCE_MS);
  }
  invalidate() {}
  getTreeItem(element) { return element; }
  dispose() {
    clearTimeout(this.refreshTimer);
    this.subscription.dispose();
    this._changed.dispose();
  }
}

// --- Scope view ---------------------------------------------------------------

class AttackSurfaceProvider extends SessionTreeProvider {
  getChildren(element) {
    if (element?.kind === "diagnostics") return element.children;
    if (element?.kind === "surface-method" || element?.kind === "attack-entry") {
      return element.childNodes || [];
    }
    if (element) return [];
    const data = this.session.snapshot;
    if (!data.indexed_at) return scopePlaceholderItems(data);
    const rows = [new ScopeOverviewItem(data), ...buildCoverageRows(data)];
    rows.push(...buildAttackSurface(data));
    rows.push(new DiagnosticsItem(buildDiagnostics(data)));
    return rows;
  }
}

function scopePlaceholderItems(data) {
  if (data.indexing) {
    return [new MetricItem(
      "Indexing workspace",
      data.indexStage?.message || "Preparing analysis",
      "sync~spin",
      undefined,
      "TraceGuard is building the workspace audit map.",
    )];
  }
  if (data.indexError) {
    return [new MetricItem(
      "Index failed",
      data.indexError,
      "error",
      "errorForeground",
      "The previous audit map was kept. Run Refresh Code Review Index to try again and open the TraceGuard Audit output for details.",
      "traceguard.refreshAudit",
    )];
  }
  return [new MetricItem(
    "Review queue not built",
    "Run Build Review Queue",
    "play",
    undefined,
    "Workspace indexing is off by default. Select this item or run Build Review Queue to start it.",
    "traceguard.startAudit",
  )];
}

// Posture header: the one-glance answer to "what is this view telling me".
class ScopeOverviewItem extends vscode.TreeItem {
  constructor(data) {
    super("Audit posture", vscode.TreeItemCollapsibleState.None);
    this.kind = "scope-overview";
    this.id = "traceguard:scope:overview";
    const openFindings = (data.findings || []).filter(finding => finding.status === "open");
    const verified = openFindings.filter(finding => findingPool(finding) === "verified");
    const hypotheses = openFindings.filter(finding => findingPool(finding) === "review");
    const worst = worstSeverityMeta(verified);
    const unreviewed = data.statusCounts?.unreviewed ?? 0;
    this.description = [
      `${(data.entries || []).length} endpoint${(data.entries || []).length === 1 ? "" : "s"}`,
      verified.length ? `${verified.length} verified flow${verified.length === 1 ? "" : "s"}` : "",
      hypotheses.length ? `${hypotheses.length} hypothes${hypotheses.length === 1 ? "is" : "es"}` : "",
      `${unreviewed} to review`,
    ].filter(Boolean).join(" · ");
    this.iconPath = verified.length
      ? new vscode.ThemeIcon("shield", new vscode.ThemeColor(worst?.color || "editorWarning.foreground"))
      : hypotheses.length
        ? new vscode.ThemeIcon("question", new vscode.ThemeColor("editorInfo.foreground"))
        : new vscode.ThemeIcon("pass-filled", new vscode.ThemeColor("testing.iconPassed"));
    this.tooltip = new vscode.MarkdownString();
    this.tooltip.appendMarkdown("$(shield) **Audit posture**\n\n");
    this.tooltip.appendMarkdown(
      verified.length
        ? `${verified.length} open verified flow${verified.length === 1 ? "" : "s"} connect an entry to a dangerous operation. Expand the Review Queue and start with P0.`
        : hypotheses.length
          ? "No verified flows are open. Review hypotheses preserve evidence that still needs human confirmation."
          : "No open flows in the current audit map. A clean result is not proof that the project is secure.",
    );
    this.tooltip.appendMarkdown(`\n\n${unreviewed} review target${unreviewed === 1 ? "" : "s"} still await a human decision.`);
  }
}

function worstSeverityMeta(findings) {
  let worst;
  for (const finding of findings || []) {
    const meta = SEVERITY_META[finding.severity];
    if (meta && (!worst || meta.rank < worst.rank)) worst = meta;
  }
  return worst;
}

function buildCoverageRows(data) {
  const coverage = data.analysisCoverage || {};
  const indexed = coverage.indexed || data.files || 0;
  const discovered = coverage.discovered || data.files || 0;
  const percent = discovered ? Math.round((indexed / discovered) * 100) : 100;
  return [
    new MetricItem(
      "API endpoints",
      `${data.entries.length}`,
      "globe",
      undefined,
      "Externally reachable framework entries included in the current analysis scope.",
    ),
    new MetricItem(
      "Analysis coverage",
      `${indexed} / ${discovered} files (${percent}%)`,
      coverage.complete ? "pass-filled" : "warning",
      coverage.complete ? "testing.iconPassed" : "editorWarning.foreground",
      "Automatic index coverage. This is separate from manual review progress.",
    ),
    new MetricItem(
      "Files skipped",
      `${coverage.skipped || 0}`,
      coverage.skipped ? "warning" : "pass",
      coverage.skipped ? "editorWarning.foreground" : "testing.iconPassed",
      coverage.skipped ? "Skipped files remain explicit coverage gaps in this scope." : "No supported source file was skipped.",
    ),
    new MetricItem(
      "Partial paths",
      `${coverage.partialPaths || 0}`,
      coverage.partialPaths ? "debug-disconnect" : "pass",
      coverage.partialPaths ? "editorWarning.foreground" : "testing.iconPassed",
      coverage.partialPaths ? flowTruncationDescription(data.findingPathTruncationReasons) : "No path analysis was interrupted by a configured budget.",
    ),
  ];
}

function buildAttackSurface(data) {
  const entries = data.entries || [];
  if (!entries.length) return [new EmptySurfaceItem()];
  const openFindings = (data.findings || []).filter(finding => finding.status === "open");
  const groups = new Map();
  for (const entry of entries) {
    const method = String(entry.method || (entry.route ? "ANY" : "ENTRY")).toUpperCase();
    if (!groups.has(method)) groups.set(method, []);
    groups.get(method).push(new AttackEntryItem(entry, findingsTouchingEntry(entry, openFindings)));
  }
  return [...groups.entries()]
    .map(([method, childNodes]) => new SurfaceMethodItem(method, childNodes))
    .sort((left, right) => left.worstRank - right.worstRank
      || surfaceMethodRank(left.method) - surfaceMethodRank(right.method)
      || left.method.localeCompare(right.method));
}

// An entry "owns" a finding when a flow step runs through its handler function;
// entries without a resolved functionId fall back to same-file, same-line proof.
function findingsTouchingEntry(entry, findings) {
  const entryFunctionId = String(entry.functionId || "");
  const entryKey = workspaceRecordKey(entry);
  return findings.filter(finding => findingPaths(finding).some(flow => (flow.steps || []).some(step => {
    if (entryFunctionId && String(step.functionId || "") === entryFunctionId) return true;
    return !entryFunctionId && workspaceRecordKey(step) === entryKey && Number(step.line) === Number(entry.line);
  })));
}

function surfaceMethodRank(method) {
  return { POST: 0, PUT: 1, PATCH: 2, DELETE: 3, ANY: 4, REQUEST: 5, GET: 6, HEAD: 7, OPTIONS: 8, ENTRY: 9 }[method] ?? 10;
}

class SurfaceMethodItem extends vscode.TreeItem {
  constructor(method, childNodes) {
    super(method === "ENTRY" ? "Other entry points" : `${method} endpoints`, vscode.TreeItemCollapsibleState.Collapsed);
    this.kind = "surface-method";
    this.method = method;
    this.childNodes = childNodes.sort((left, right) => left.worstRank - right.worstRank || left.label.localeCompare(right.label));
    this.id = `traceguard:surface:method:${method}`;
    this.worstRank = childNodes.reduce((rank, item) => Math.min(rank, item.worstRank), 4);
    const withFlows = childNodes.filter(item => item.openFindingCount).length;
    this.description = withFlows ? `${childNodes.length} · ${withFlows} with flows` : `${childNodes.length}`;
    this.iconPath = new vscode.ThemeIcon("symbol-method", this.worstRank < 4 ? new vscode.ThemeColor(SEVERITY_META[severityNameForRank(this.worstRank)]?.color || "editorWarning.foreground") : undefined);
    this.tooltip = `${childNodes.length} externally reachable ${method === "ENTRY" ? "entry point" : method + " endpoint"}${childNodes.length === 1 ? "" : "s"}${withFlows ? `; ${withFlows} ${withFlows === 1 ? "has" : "have"} open flows and ${withFlows === 1 ? "is" : "are"} listed first` : ""}.`;
  }
}

function severityNameForRank(rank) {
  return Object.keys(SEVERITY_META).find(name => SEVERITY_META[name].rank === rank);
}

class AttackEntryItem extends vscode.TreeItem {
  constructor(entry, entryFindings = []) {
    const route = entry.route && entry.route !== "<dynamic>" ? entry.route : entry.title;
    const method = String(entry.method || "ANY").toUpperCase();
    const label = entry.route ? `${method} ${route}` : entry.title;
    super(label, vscode.TreeItemCollapsibleState.None);
    this.kind = "attack-entry";
    this.entry = entry;
    this.childNodes = [];
    this.contextValue = "traceguard.attackEntry";
    this.id = `traceguard:surface:entry:${entry.id || `${workspaceRecordKey(entry)}:${entry.line}:${method}:${route}`}`;
    this.openFindingCount = entryFindings.length;
    const worst = worstSeverityMeta(entryFindings.filter(finding => findingPool(finding) === "verified"));
    this.worstRank = worst?.rank ?? 4;
    const framework = entry.framework || entry.language || "endpoint";
    this.description = `${framework} · ${path.basename(entry.relativePath || entry.absolutePath || "unknown")}:${entry.line}`
      + (this.openFindingCount ? ` · ${this.openFindingCount} open flow${this.openFindingCount === 1 ? "" : "s"}` : "");
    this.iconPath = new vscode.ThemeIcon("globe", worst ? new vscode.ThemeColor(worst.color) : undefined);
    this.tooltip = new vscode.MarkdownString();
    this.tooltip.appendMarkdown(`$(globe) **${md(label)}**\n\n`);
    this.tooltip.appendMarkdown(`Handler: ${md(entry.title)}\n\n`);
    this.tooltip.appendCodeblock(`${entry.relativePath}:${entry.line}`);
    if (entryFindings.length) {
      this.tooltip.appendMarkdown(`\n\n**Open flows through this entry (${entryFindings.length})**\n`);
      for (const finding of entryFindings.slice(0, 5)) {
        const meta = SEVERITY_META[finding.severity] || SEVERITY_META.low;
        this.tooltip.appendMarkdown(`\n- $(${meta.icon}) ${md(finding.title)} · ${findingPool(finding) === "verified" ? "verified" : "hypothesis"} · sink line ${finding.line}`);
      }
      if (entryFindings.length > 5) this.tooltip.appendMarkdown(`\n- … ${entryFindings.length - 5} more`);
      this.tooltip.appendMarkdown("\n\n");
    }
    this.tooltip.appendMarkdown("Use **Trace from Entry** to inspect reachable calls and security-sensitive operations.");
    this.command = { command: "traceguard.openAuditLocation", title: "Open endpoint", arguments: [entry] };
  }
}

class EmptySurfaceItem extends vscode.TreeItem {
  constructor() {
    super("No externally reachable APIs indexed", vscode.TreeItemCollapsibleState.None);
    this.iconPath = new vscode.ThemeIcon("circle-outline", new vscode.ThemeColor("descriptionForeground"));
    this.description = "Refresh after adding routes";
    this.tooltip = "No supported framework route or request entry point is present in the current audit map.";
  }
}

function buildDiagnostics(data) {
  const languages = Object.keys(data.languages).join(", ") || "none";
  const parserCapabilities = Object.entries(data.languageCapabilities || {}).map(([language, capability]) =>
    `${language}: ${capability.astFiles}/${capability.files} AST · ${capability.capability || "fallback"}${capability.degradedFiles ? ` · ${capability.degradedFiles} degraded` : ""}`,
  ).join("; ") || "none";
  const degraded = Object.entries(data.languageCapabilities || {}).flatMap(([language, capability]) =>
    (capability.reasons || []).map(reason => `${language}: ${reason}`),
  );
  const projectConfiguration = data.projectConfiguration || { loaded: false, semanticModels: 0, excludedPatterns: 0, issues: [] };
  const rows = [
    new MetricItem("Indexed", `${formatCount(data.files)} files · ${formatCount(data.functions)} functions`, "files"),
    new MetricItem("Languages", languages, "code"),
    new MetricItem("Parser capability", parserCapabilities, "symbol-structure"),
  ];
  if (degraded.length) rows.push(new MetricItem("Degraded parsing", degraded.join("; "), "warning", "editorWarning.foreground"));
  if (projectConfiguration.loaded || projectConfiguration.issues.length || projectConfiguration.temporarySemanticModels) {
    rows.push(new MetricItem(
      "Project semantics",
      projectConfiguration.issues.length
        ? `${projectConfiguration.issues.length} issue${projectConfiguration.issues.length === 1 ? "" : "s"} · last valid model kept`
        : `${projectConfiguration.semanticModels} project · ${projectConfiguration.temporarySemanticModels || 0} temporary models`,
      projectConfiguration.issues.length ? "warning" : "settings-gear",
      projectConfiguration.issues.length ? "editorWarning.foreground" : undefined,
    ));
  }
  return rows;
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

class DiagnosticsItem extends vscode.TreeItem {
  constructor(children) {
    super("Diagnostics", vscode.TreeItemCollapsibleState.Collapsed);
    this.kind = "diagnostics";
    this.children = children;
    this.description = `${children.length} detail${children.length === 1 ? "" : "s"}`;
    this.iconPath = new vscode.ThemeIcon("debug-console");
    this.tooltip = "Index, parser and project-configuration details behind the current audit map.";
  }
}

// --- Review Queue view ----------------------------------------------------------

class CodeTreeProvider extends SessionTreeProvider {
  constructor(session) {
    super(session);
    this._tree = undefined;
    this.filter = { id: "priority", label: "P0 / P1 first" };
  }

  invalidate() {
    this._tree = undefined;
  }

  setFilter(filter) {
    this.filter = filter || { id: "priority", label: "P0 / P1 first" };
    this._tree = undefined;
    this._changed.fire(undefined);
  }

  getChildren(element) {
    if (!element) {
      this._ensureTree();
      return this._tree.roots;
    }
    if (element.kind === "section") return element.childNodes || [];
    if (element.kind === "finding") {
      const finding = this.session.snapshot.findings.find(candidate => candidate.id === element.findingId);
      const paths = findingPaths(finding);
      if (paths.length > 1) return paths.map((flow, index) => new FindingPathItem(flow, index, element.findingId));
      return findingPathChildren(paths[0], element.findingId, 0);
    }
    if (element.kind === "findingPath") {
      return findingPathChildren(element.flow, element.findingId, element.pathIndex);
    }
    return [];
  }

  _ensureTree() {
    if (this._tree) return;
    const hideReviewed = vscode.workspace.getConfiguration("traceguard").get("hideReviewedTargets", false);
    const snapshot = this.session.snapshot;
    const activeEditor = vscode.window.activeTextEditor;
    const activeFile = normalizeTreePath(activeEditor?.document?.uri?.fsPath);
    const currentTarget = activeEditor
      ? this.session.itemAt(activeEditor.document.uri, activeEditor.selection.active.line)
      : undefined;
    const currentEndpointIds = currentTarget?.kind === "endpoint"
      ? [currentTarget.functionId]
      : currentTarget?.entryFunctionIds || [];
    const visibleTargets = (snapshot.items || [])
      .filter(item => !hideReviewed || item.status !== "reviewed")
      .filter(item => reviewTargetMatchesFilter(item, this.filter.id, activeFile, currentEndpointIds));
    const roots = [
      new ManualCoverageItem(snapshot.manualReviewCoverage || { reviewed: snapshot.statusCounts.reviewed, total: snapshot.items.length }),
      new QueueFilterItem(this.filter.label, visibleTargets.length, snapshot.items.length),
    ];
    const priorities = [
      ["P0", "Entry reaches dangerous operation", vscode.TreeItemCollapsibleState.Expanded],
      ["P1", "Entry with unresolved cross-file calls", vscode.TreeItemCollapsibleState.Expanded],
      ["P2", "Security-sensitive helper", vscode.TreeItemCollapsibleState.Collapsed],
      ["Backlog", "Ordinary reachable functions", vscode.TreeItemCollapsibleState.Collapsed],
    ];
    for (const [priority, label, state] of priorities) {
      const childNodes = visibleTargets.filter(item => item.priority === priority).map(item => new AuditItem(item));
      if (childNodes.length || ["P0", "P1"].includes(priority)) {
        roots.push(new ReviewQueueSection(priority, label, childNodes, state));
      }
    }
    const pools = [
      ["Verified Flow", "verified-filled", "verified"],
      ["Review Hypothesis", "question", "review"],
      ["Dismissed / Resolved", "archive", "resolved"],
    ];
    for (const [label, icon, pool] of pools) {
      const childNodes = (snapshot.findings || [])
        .filter(finding => findingPool(finding) === pool)
        .sort((left, right) => findingSortRank(left) - findingSortRank(right))
        .map(finding => new FindingItem(finding));
      if (childNodes.length) roots.push(new FileSectionItem(label, icon, `flows:${pool}`, childNodes));
    }
    this._tree = { roots };
  }
}

function reviewTargetMatchesFilter(item, filter, activeFile, currentEndpointIds = []) {
  if (filter === "unreviewed") return item.status === "unreviewed";
  if (filter === "in_review") return item.status === "in_review";
  if (filter === "blocked") return item.status === "blocked";
  if (filter === "reviewed") return item.status === "reviewed";
  if (filter === "current_file") return activeFile && normalizeTreePath(item.absolutePath) === activeFile;
  if (filter === "current_endpoint") {
    const selected = new Set(currentEndpointIds.filter(Boolean));
    return selected.size > 0 && (item.entryFunctionIds || [item.functionId]).some(id => selected.has(id));
  }
  if (filter === "reachable") return Boolean(item.reachableFromEntry || item.kind === "endpoint");
  if (filter === "unresolved") return Boolean(item.containsUnresolvedCalls);
  return true;
}

class ManualCoverageItem extends vscode.TreeItem {
  constructor(coverage) {
    super("Manual review coverage", vscode.TreeItemCollapsibleState.None);
    const reviewed = coverage.reviewed || 0;
    const total = coverage.total || 0;
    const percent = total ? Math.round((reviewed / total) * 100) : 0;
    const complete = total > 0 && reviewed >= total;
    this.description = `${reviewed} / ${total}${total ? ` (${percent}%)` : ""}`;
    this.iconPath = new vscode.ThemeIcon(complete ? "pass-filled" : "check-all", new vscode.ThemeColor(complete ? "testing.iconPassed" : "descriptionForeground"));
    this.tooltip = complete
      ? "Every review target has a recorded human decision."
      : `Human review progress only (${percent}% complete). Automatic analysis coverage is reported separately in Scope.`;
  }
}

class QueueFilterItem extends vscode.TreeItem {
  constructor(label, visible, total) {
    super(`Filter: ${label}`, vscode.TreeItemCollapsibleState.None);
    this.description = `${visible} / ${total} targets`;
    this.iconPath = new vscode.ThemeIcon("filter");
    this.command = { command: "traceguard.filterReviewQueue", title: "Filter Review Queue" };
  }
}

class ReviewQueueSection extends vscode.TreeItem {
  constructor(priority, label, childNodes, state) {
    super(`${priority} · ${label}`, state);
    this.kind = "section";
    this.childNodes = childNodes;
    this.id = `traceguard:queue:${priority}`;
    this.description = `${childNodes.length}`;
    const meta = PRIORITY_META[priority] || {};
    this.iconPath = new vscode.ThemeIcon(meta.icon || "circle-outline", new vscode.ThemeColor(meta.color || "descriptionForeground"));
    const guidance = PRIORITY_GUIDANCE[priority] || "Targets ordered for human review.";
    this.tooltip = childNodes.length
      ? `${guidance}\n\n${childNodes.length} target${childNodes.length === 1 ? "" : "s"} in this queue.`
      : `${guidance}\n\nNo target currently matches this queue and filter.`;
  }
}

function workspaceFileIdentity(record) {
  const absolutePath = String(record.absolutePath || "");
  const folder = absolutePath ? vscode.workspace.getWorkspaceFolder(vscode.Uri.file(absolutePath)) : undefined;
  const configuredRoot = String(record.workspaceRoot || folder?.uri.fsPath || "workspace");
  const rootKey = normalizeTreePath(configuredRoot) || "workspace";
  const rootName = folder?.name || path.basename(configuredRoot) || "Workspace";
  const relativePath = normalizeTreePath(
    folder && absolutePath
      ? path.relative(folder.uri.fsPath, absolutePath)
      : record.relativePath || (absolutePath && configuredRoot !== "workspace" ? path.relative(configuredRoot, absolutePath) : path.basename(absolutePath)),
  );
  return { rootKey, rootName, relativePath: relativePath || path.basename(absolutePath) || "unknown" };
}

function workspaceRecordKey(record) {
  const identity = workspaceFileIdentity(record);
  return `${identity.rootKey}::${identity.relativePath}`;
}

function normalizeTreePath(value) {
  return String(value || "").replaceAll("\\", "/").replace(/^\.\//, "").replace(/\/{2,}/g, "/");
}

function findingSortRank(finding) {
  const resolved = finding.status !== "open";
  return (resolved ? 10 : 0) + (SEVERITY_META[finding.severity]?.rank ?? 4);
}

class FileSectionItem extends vscode.TreeItem {
  constructor(label, icon, key, childNodes) {
    super(label, vscode.TreeItemCollapsibleState.Collapsed);
    this.kind = "section";
    this.key = key;
    this.childNodes = childNodes;
    this.id = `traceguard:${key}`;
    this.description = `${childNodes.length}`;
    this.iconPath = new vscode.ThemeIcon(icon, new vscode.ThemeColor("descriptionForeground"));
  }
}

class FindingItem extends vscode.TreeItem {
  constructor(finding) {
    super(finding.title, findingPaths(finding).some(flow => flow.steps?.length) ? vscode.TreeItemCollapsibleState.Collapsed : vscode.TreeItemCollapsibleState.None);
    this.id = `traceguard:finding:${finding.id}`;
    this.kind = "finding";
    this.findingId = finding.id;
    this.finding = finding;
    this.contextValue = "traceguard.finding";
    const resolved = finding.status !== "open";
    const reviewOnly = findingPool(finding) === "review";
    this.description = `L${finding.line}`
      + `${reviewOnly ? " · review" : ""}`
      + `${finding.pathCount > 1 ? ` · ${finding.pathCount} paths` : ""}`
      + `${resolved ? ` · ${findingStatusLabel(finding.status)}` : ""}`;
    this.tooltip = buildFindingTooltip(finding);
    this.iconPath = resolved
      ? new vscode.ThemeIcon(FINDING_STATUS_GLYPH[finding.status] || "circle-filled", new vscode.ThemeColor("descriptionForeground"))
      : reviewOnly
        ? new vscode.ThemeIcon("question", new vscode.ThemeColor("descriptionForeground"))
        : new vscode.ThemeIcon(SEVERITY_META[finding.severity]?.icon || "circle-outline", new vscode.ThemeColor(SEVERITY_META[finding.severity]?.color || "descriptionForeground"));
    this.command = { command: "traceguard.openAuditLocation", title: "Open flow sink", arguments: [finding] };
  }
}

class FindingPathItem extends vscode.TreeItem {
  constructor(flow, index, findingId) {
    const status = pathVerificationStatus(flow);
    super(`Path ${index + 1}`, vscode.TreeItemCollapsibleState.Collapsed);
    this.kind = "findingPath";
    this.findingId = findingId;
    this.pathIndex = index;
    this.flow = flow;
    this.id = `traceguard:path:${findingId}:${flow.id || index}`;
    this.description = `${status} · ${(flow.steps || []).length} steps`;
    const meta = QUERY_STATUS_META[status === "review" ? "heuristic" : status] || QUERY_STATUS_META.heuristic;
    this.iconPath = new vscode.ThemeIcon(meta.icon, new vscode.ThemeColor(meta.color));
    this.tooltip = `${status} path with ${(flow.steps || []).length} analysis steps.`;
  }
}

function buildFindingTooltip(finding) {
  const missing = finding.missingGuards.length ? finding.missingGuards.join(", ") : "none from this rule";
  const observed = finding.observedGuards.length ? finding.observedGuards.join(", ") : "none observed";
  const pool = findingPool(finding) === "verified" ? "Verified Flow" : findingPool(finding) === "review" ? "Review Hypothesis" : "Dismissed / Resolved";
  const markdown = new vscode.MarkdownString();
  markdown.appendMarkdown(`$(debug-stackframe) **${pool}** · ${String(finding.severity).toUpperCase()} review impact · ${md(finding.confidence)} confidence\n\n`);
  markdown.appendMarkdown(`${md(finding.title)} (${md(finding.cwe)})\n\n`);
  markdown.appendMarkdown("TraceGuard has classified the data-flow evidence, not confirmed a vulnerability.\n\n");
  markdown.appendMarkdown(`Candidate paths: ${finding.pathCount}\n\nSource: \`${md(finding.sourceKind)}\`\n\nSink: \`${md(finding.sinkKind)}\`\n\n`);
  markdown.appendMarkdown(`Observed guards: ${md(observed)}\n\nConditions to verify manually: ${md(missing)}`);
  if (finding.guardHints?.length) {
    markdown.appendMarkdown("\n\n**Control evidence requiring review:**\n");
    for (const hint of finding.guardHints) markdown.appendMarkdown(`\n- ${md(hint.label)}: ${md(hint.reason)}`);
  }
  const confidenceReason = finding.explanation?.confidenceReason || "Review the path and call resolution.";
  markdown.appendMarkdown(`\n\nConnection confidence: ${md(confidenceReason)}`);
  if (finding.explanation?.heuristics?.length) {
    markdown.appendMarkdown("\n\n**Review notes:**\n");
    for (const note of finding.explanation.heuristics) markdown.appendMarkdown(`\n- ${md(note)}`);
  }
  markdown.appendMarkdown("\n\nExpand to inspect the Source → Sink evidence chain.");
  return markdown;
}

function findingPathChildren(flow, findingId, pathIndex) {
  if (!flow) return [];
  const children = (flow.steps || []).map((step, index) => new FindingPathStep(step, index, findingId, pathIndex));
  const interruption = traceInterruption(flow);
  if (interruption) children.push(new TraceInterruptionItem(interruption, `finding:${findingId}:${pathIndex}`));
  return children;
}

class FindingPathStep extends vscode.TreeItem {
  constructor(step, index, findingId, pathIndex = 0) {
    super(`${index + 1}. ${step.label}`, vscode.TreeItemCollapsibleState.None);
    this.id = `traceguard:step:${findingId}:${pathIndex}:${index}`;
    const status = stepAnalysisStatus(step);
    this.description = `${QUERY_STATUS_META[status].label} · ${path.basename(step.relativePath)}:${step.line}`;
    const stepIcon = STEP_KIND_ICONS[step.kind] || "circle-small-filled";
    this.tooltip = new vscode.MarkdownString();
    this.tooltip.appendMarkdown(`$(${stepIcon}) **${String(step.kind).toUpperCase()} · ${index + 1}** — `);
    this.tooltip.appendText(step.label);
    if (step.code) this.tooltip.appendCodeblock(step.code);
    if (step.candidateReason) this.tooltip.appendMarkdown(`\n\nCall resolution: ${md(step.candidateReason)}`);
    if (step.reason) this.tooltip.appendMarkdown(`\n\nEvidence status: ${md(step.reason)}`);
    if (step.kind === "sink" && (step.semanticVerification === "candidate" || /unverified/.test(step.candidateStatus || ""))) {
      this.tooltip.appendMarkdown("\n\nReview required: the method name matches a sink, but its receiver type was not resolved.");
    }
    this.iconPath = new vscode.ThemeIcon(stepIcon, new vscode.ThemeColor(QUERY_STATUS_META[status].color));
    this.command = { command: "traceguard.openAuditLocation", title: "Open path step", arguments: [step] };
  }
}

class AuditItem extends vscode.TreeItem {
  constructor(item) {
    super(item.title, vscode.TreeItemCollapsibleState.None);
    this.id = `traceguard:target:${item.id}`;
    this.auditItem = item;
    this.contextValue = "traceguard.auditItem";
    this.description = `${path.basename(item.relativePath)}:${item.line} · ${statusLabel(item.status)}`;
    const priorityMeta = PRIORITY_META[item.priority] || {};
    const statusMeta = {
      reviewed: { icon: "pass-filled", color: "testing.iconPassed" },
      in_review: { icon: "debug-pause", color: "editorWarning.foreground" },
      blocked: { icon: "circle-slash", color: "errorForeground" },
      unreviewed: { icon: priorityMeta.icon || "circle-outline", color: priorityMeta.color },
    }[item.status] || { icon: priorityMeta.icon || "circle-outline", color: priorityMeta.color };
    this.tooltip = new vscode.MarkdownString();
    this.tooltip.appendMarkdown(`$(${statusMeta.icon}) **${item.priority}** · `);
    this.tooltip.appendText(item.title);
    this.tooltip.appendMarkdown(`\n\n${item.reasons.map(reason => `- ${md(reason)}`).join("\n")}\n\nReview status: **${statusLabel(item.status)}**`);
    this.iconPath = statusMeta.color
      ? new vscode.ThemeIcon(statusMeta.icon, new vscode.ThemeColor(statusMeta.color))
      : new vscode.ThemeIcon(statusMeta.icon);
    this.command = { command: "traceguard.focusAuditItem", title: "Audit this target", arguments: [item] };
  }
}

// --- Notes view -----------------------------------------------------------------

class EvidenceProvider extends SessionTreeProvider {
  getChildren(element) {
    const evidence = this.session.snapshot.evidence;
    if (!element) {
      const types = [...new Set(evidence.map(item => item.type))].sort(compareEvidenceTypes);
      return types.map(type => new EvidenceGroup(type, evidence.filter(item => item.type === type).length));
    }
    if (element.kind === "evidenceGroup") return evidence.filter(item => item.type === element.type).map(item => new EvidenceItem(item));
    return [];
  }
}

function compareEvidenceTypes(left, right) {
  const leftRank = EVIDENCE_TYPE_ORDER.indexOf(left);
  const rightRank = EVIDENCE_TYPE_ORDER.indexOf(right);
  return (leftRank < 0 ? EVIDENCE_TYPE_ORDER.length : leftRank) - (rightRank < 0 ? EVIDENCE_TYPE_ORDER.length : rightRank)
    || String(left).localeCompare(String(right));
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
    this.id = `traceguard:evidence:${item.id}`;
    this.description = `${path.basename(item.relativePath)}:${item.line}`;
    const tone = { Source: "editorInfo.foreground", Sink: "errorForeground", Authorization: "testing.iconPassed", Validation: "charts.green", Controllability: "editorInfo.foreground", "Missing Context": "editorWarning.foreground", "Exploit Condition": "errorForeground", Remediation: "testing.iconPassed", Observation: "descriptionForeground" }[item.type] || "descriptionForeground";
    this.tooltip = new vscode.MarkdownString();
    this.tooltip.appendMarkdown(`$(bookmark) **${md(item.type)}** · ${path.basename(item.relativePath)}:${item.line}\n\n`);
    this.tooltip.appendCodeblock(item.code);
    if (item.note) { this.tooltip.appendMarkdown("\n\n"); this.tooltip.appendText(item.note); }
    this.iconPath = new vscode.ThemeIcon(evidenceIcon(item.type), new vscode.ThemeColor(tone));
    this.evidenceItem = item;
    this.contextValue = "traceguard.evidence";
    this.command = { command: "traceguard.openEvidence", title: "Open evidence", arguments: [item] };
  }
}

// --- Trace view -----------------------------------------------------------------

class AuditQueryProvider {
  constructor() {
    this.result = undefined;
    this.trace = undefined;
    this.traceCursor = 0;
    this._changed = new vscode.EventEmitter();
    this.onDidChangeTreeData = this._changed.event;
  }

  setResult(result) {
    this.result = result;
    this.trace = undefined;
    this.traceCursor = 0;
    this._changed.fire(undefined);
  }

  setTrace(flowPath, cursor = 0) {
    this.result = undefined;
    this.trace = flowPath;
    this.traceCursor = boundedTraceIndex(flowPath, cursor);
    this._changed.fire(undefined);
    return this.currentTraceStep;
  }

  selectTraceStep(index) {
    if (!this.trace) return undefined;
    this.traceCursor = boundedTraceIndex(this.trace, index);
    this._changed.fire(undefined);
    return this.currentTraceStep;
  }

  moveTrace(delta) {
    return this.selectTraceStep(this.traceCursor + delta);
  }

  clear() {
    this.result = undefined;
    this.trace = undefined;
    this.traceCursor = 0;
    this._changed.fire(undefined);
  }

  get current() {
    return this.result;
  }

  get currentTrace() {
    return this.trace;
  }

  get currentTraceStep() {
    return this.trace?.steps?.[this.traceCursor];
  }

  getTreeItem(element) {
    return element;
  }

  getChildren(element) {
    if (!element) {
      if (this.trace) return [new InteractiveTraceItem(this.trace, this.traceCursor)];
      if (!this.result) return [];
      return [new AuditQueryResultItem(this.result)];
    }
    if (element.kind === "interactive-trace") {
      const children = (element.flowPath.steps || []).map((step, index) => new InteractiveTraceStepItem(step, index, element.cursor));
      const interruption = traceInterruption(element.flowPath);
      if (interruption) children.push(new TraceInterruptionItem(interruption, `interactive:${element.flowPath.id || "selected"}`));
      return children;
    }
    if (element.kind === "query-result") return (element.result.roots || []).map(node => new AuditQueryNodeItem(node, true));
    if (element.kind === "query-node") {
      const children = (element.node.children || []).map(node => new AuditQueryNodeItem(node));
      if (element.interruption) children.push(new TraceInterruptionItem(element.interruption, `query:${element.node.id}`));
      return children;
    }
    return [];
  }

  dispose() {
    this._changed.dispose();
  }
}

function boundedTraceIndex(flowPath, index) {
  const last = Math.max(0, (flowPath?.steps?.length || 1) - 1);
  return Math.max(0, Math.min(last, Number.isFinite(Number(index)) ? Number(index) : 0));
}

class InteractiveTraceItem extends vscode.TreeItem {
  constructor(flowPath, cursor) {
    const steps = flowPath.steps || [];
    const source = flowPath.source?.label || steps.find(step => step.kind === "source")?.label || "Source";
    const sink = flowPath.sink?.label || [...steps].reverse().find(step => step.kind === "sink")?.label || "Sink";
    super(`${source} → ${sink}`, vscode.TreeItemCollapsibleState.Expanded);
    this.kind = "interactive-trace";
    this.flowPath = flowPath;
    this.cursor = cursor;
    this.id = `traceguard:interactive-trace:${flowPath.id || "selected"}`;
    this.description = `Step ${Math.min(cursor + 1, steps.length)}/${steps.length} · ${pathVerificationStatus(flowPath)}`;
    this.iconPath = new vscode.ThemeIcon("debug-stackframe", new vscode.ThemeColor("editorInfo.foreground"));
    this.tooltip = new vscode.MarkdownString();
    this.tooltip.appendMarkdown(`$(debug-stackframe) **Interactive Source → Sink trace**\n\n`);
    this.tooltip.appendText(`${steps.length} steps across ${flowPath.files?.length || new Set(steps.map(step => step.relativePath).filter(Boolean)).size} files.`);
    this.tooltip.appendMarkdown("\n\nUse the previous and next buttons in the view title, or select any step below.");
    this.contextValue = "traceguard.interactiveTrace";
  }
}

class InteractiveTraceStepItem extends vscode.TreeItem {
  constructor(step, index, cursor) {
    const current = index === cursor;
    super(`${index + 1}. ${step.label}`, vscode.TreeItemCollapsibleState.None);
    this.kind = "interactive-trace-step";
    this.step = step;
    this.index = index;
    this.id = `traceguard:interactive-step:${index}:${step.functionId || "step"}:${step.operationId || step.line || 0}`;
    const status = stepAnalysisStatus(step);
    this.description = `${current ? "CURRENT · " : ""}${QUERY_STATUS_META[status].label} · ${path.basename(step.relativePath || step.absolutePath || "unknown")}:${step.line || "?"}`;
    const icon = current ? "debug-stackframe" : stepKindIcon(step.kind);
    this.iconPath = new vscode.ThemeIcon(icon, new vscode.ThemeColor(current ? "editorInfo.foreground" : QUERY_STATUS_META[status].color));
    this.tooltip = new vscode.MarkdownString();
    const heading = current ? "$(debug-stackframe) **Current step**" : `**Step ${index + 1}**`;
    this.tooltip.appendMarkdown(`${heading} · **${md(step.kind || "flow")}** · \`${status}\`\n\n`);
    this.tooltip.appendText(step.label || "Analysis step");
    if (step.code) this.tooltip.appendCodeblock(step.code);
    if (step.candidateReason) this.tooltip.appendMarkdown(`\n\nResolution: ${md(step.candidateReason)}`);
    this.contextValue = current ? "traceguard.currentTraceStep" : "traceguard.traceStep";
    this.command = { command: "traceguard.selectTraceStep", title: "Open trace step", arguments: [index] };
  }
}

class TraceInterruptionItem extends vscode.TreeItem {
  constructor(interruption, identity) {
    super("Path interrupted — inspect next", vscode.TreeItemCollapsibleState.None);
    this.kind = "trace-interruption";
    this.id = `traceguard:interruption:${identity}`;
    this.description = interruption.status;
    this.iconPath = new vscode.ThemeIcon("debug-disconnect", new vscode.ThemeColor("editorWarning.foreground"));
    this.tooltip = new vscode.MarkdownString();
    this.tooltip.appendMarkdown(`$(debug-disconnect) **Why the path stopped**\n\n${md(interruption.reason)}\n\n`);
    this.tooltip.appendMarkdown(`**Suggested manual check**\n\n${md(interruption.next)}`);
    if (interruption.location?.absolutePath) {
      this.command = { command: "traceguard.openAuditLocation", title: "Inspect unresolved call", arguments: [interruption.location] };
    }
  }
}

function stepAnalysisStatus(step = {}) {
  if (["verified", "syntax-only", "heuristic", "unresolved"].includes(step.analysisStatus)) return step.analysisStatus;
  if (step.semanticVerification === "candidate" || /unverified|unresolved/.test(`${step.candidateStatus || ""} ${step.candidateReason || ""}`)) return "unresolved";
  if (step.semanticVerification === "syntax") return "syntax-only";
  if ((step.kind === "call" && step.candidateMatch && step.candidateMatch !== "high") || step.heuristic) return "heuristic";
  return "verified";
}

function traceInterruption(flow = {}) {
  const steps = flow.steps || [];
  const unresolved = steps.find(step => ["unresolved", "heuristic"].includes(stepAnalysisStatus(step)));
  if (unresolved) {
    const detail = `${unresolved.candidateReason || unresolved.reason || unresolved.candidateStatus || "The call target could not be resolved to one verified symbol."}`;
    const lower = detail.toLowerCase();
    const next = /dynamic|container|service locator/.test(lower)
      ? `Inspect where ${unresolved.receiver || unresolved.label || "the receiver"} is constructed or fetched from the dependency container.`
      : /reflect|dispatch|magic/.test(lower)
        ? "Inspect reflection metadata, dynamic dispatch registration, or framework configuration that selects the implementation."
        : /ambiguous|candidate|same.name|receiver/.test(lower)
          ? `Inspect the receiver type and implementation of ${unresolved.label || "this call"}; same-named methods are intentionally not joined as verified.`
          : "Inspect the call receiver, imports and available dependency source to identify the concrete implementation.";
    return { status: stepAnalysisStatus(unresolved), reason: detail, next, location: unresolved };
  }
  if (flow.truncated || flow.truncationReasons?.length) {
    return {
      status: "partial",
      reason: flowTruncationDescription(flow.truncationReasons || []),
      next: "Narrow the trace around the current variable or raise the relevant path budget, then inspect the last completed call manually.",
      location: steps.at(-1),
    };
  }
  return undefined;
}

function stepKindIcon(kind) {
  return STEP_KIND_ICONS[kind] || "circle-small-filled";
}

function flowTruncationDescription(reasons = []) {
  const labels = {
    "analysis-timeout": "analysis time budget reached",
    "trace-step-budget": "trace-step limit reached",
    "path-candidate-budget": "path candidate limit reached",
    "flow-state-budget": "flow-state limit reached",
    "flow-event-budget": "flow-event limit reached",
    "per-root-state-budget": "per-entry state limit reached",
    "per-root-event-budget": "per-entry event limit reached",
    "cfg-path-budget": "control-flow path limit reached",
    "call-candidate-budget": "call-target limit reached",
    "call-depth-budget": "call-depth limit reached",
  };
  const values = [...new Set(reasons || [])].map(reason => labels[reason] || String(reason).replaceAll("-", " "));
  return values.length ? values.join(" · ") : "Configured path-analysis limit reached";
}

class AuditQueryResultItem extends vscode.TreeItem {
  constructor(result) {
    super(result.title, vscode.TreeItemCollapsibleState.Expanded);
    this.kind = "query-result";
    this.result = result;
    const nodes = Number(result.summary?.nodes) || countQueryNodes(result.roots || []);
    this.description = `${nodes} step${nodes === 1 ? "" : "s"}${result.truncated ? " · truncated" : ""}`;
    this.tooltip = new vscode.MarkdownString();
    this.tooltip.appendMarkdown(`**${md(result.title)}**\n\n`);
    this.tooltip.appendText(`${nodes} analysis steps${result.truncated ? "; the configured query limit was reached" : ""}.`);
    this.iconPath = new vscode.ThemeIcon(result.truncated ? "warning" : "list-tree");
    this.contextValue = "traceguard.auditQueryResult";
  }
}

class AuditQueryNodeItem extends vscode.TreeItem {
  constructor(node, expand = false) {
    const children = node.children || [];
    const interruption = queryNodeInterruption(node);
    const hasChildren = children.length > 0 || Boolean(interruption);
    super(node.label, hasChildren && expand ? vscode.TreeItemCollapsibleState.Expanded : hasChildren ? vscode.TreeItemCollapsibleState.Collapsed : vscode.TreeItemCollapsibleState.None);
    this.kind = "query-node";
    this.node = node;
    this.interruption = interruption;
    const meta = QUERY_STATUS_META[node.status] || QUERY_STATUS_META.heuristic;
    const location = node.location;
    const locationLabel = location?.relativePath
      ? `${path.basename(location.relativePath)}:${location.line}`
      : location?.absolutePath ? `${path.basename(location.absolutePath)}:${location.line}` : "no source location";
    this.description = `${locationLabel} · $(${meta.icon})`;
    this.tooltip = new vscode.MarkdownString();
    this.tooltip.appendMarkdown(`**${meta.label} · ${md(node.kind || "step")}**\n\n`);
    this.tooltip.appendText(node.reason || "No connection explanation was produced.");
    if (interruption) this.tooltip.appendMarkdown(`\n\n**Suggested manual check**\n\n${md(interruption.next)}`);
    if (location?.code) this.tooltip.appendCodeblock(location.code);
    const details = Object.entries(node.details || {}).filter(([, value]) => value !== undefined && value !== "");
    if (details.length) {
      this.tooltip.appendMarkdown("\n\n**Analysis facts**\n\n");
      for (const [key, value] of details) this.tooltip.appendMarkdown(`- ${md(key)}: \`${md(formatDetail(value))}\`\n`);
    }
    this.iconPath = new vscode.ThemeIcon(STEP_KIND_ICONS[node.kind] || meta.icon, new vscode.ThemeColor(meta.color));
    this.contextValue = "traceguard.auditQueryNode";
    if (location?.absolutePath && location?.line) {
      this.command = { command: "traceguard.openAuditLocation", title: "Open analysis step", arguments: [location] };
    }
  }
}

function queryNodeInterruption(node) {
  if ((node.children || []).length || !["heuristic", "unresolved"].includes(node.status)) return undefined;
  return traceInterruption({ steps: [{
    ...(node.location || {}),
    analysisStatus: node.status,
    label: node.label,
    candidateReason: node.reason,
    receiver: node.details?.receiver,
  }] });
}

// --- Editor integration -----------------------------------------------------------

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
    return this.session.itemsForUri(document.uri).map(item => {
      const position = new vscode.Position(Math.max(0, item.line - 1), 0);
      const status = statusLabel(item.status);
      const range = new vscode.Range(position, position);
      const findingCount = item.verifiedFindingIds?.length || 0;
      const traceFinding = showFlowCodeLens && findingCount > 0;
      return new vscode.CodeLens(range, {
        command: traceFinding ? "traceguard.traceCrossFileFlow" : "traceguard.focusAuditItem",
        title: traceFinding
          ? `$(debug-stackframe) ${findingCount} verified flow${findingCount === 1 ? "" : "s"} · Inspect evidence`
          : `$(checklist) ${item.priority} review · ${status}`,
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
    markdown.appendMarkdown(`### $(references) TraceGuard audit signal${signals.length === 1 ? "" : "s"}\n\n`);
    for (const signal of signals) {
      markdown.appendMarkdown(`- $(eye) **${String(signal.kind).toUpperCase()}** · ${md(signal.label)}\n`);
    }
    markdown.appendMarkdown("\n---\n\nThis is an audit clue, not a confirmed vulnerability. Trace its callers, controls and downstream effects.");
    return new vscode.Hover(markdown);
  }
}

// --- Shared helpers ---------------------------------------------------------------

function countQueryNodes(nodes) {
  return nodes.reduce((count, node) => count + 1 + countQueryNodes(node.children || []), 0);
}

function formatDetail(value) {
  if (Array.isArray(value)) return value.join(", ");
  if (value && typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function formatCount(value) {
  return Number(value).toLocaleString("en-US");
}

function md(value) {
  return String(value ?? "").replace(/[\\`*_{}[\]()#+\-.!]/g, "\\$&");
}

function statusLabel(status) { return { unreviewed: "Not reviewed", in_review: "In review", reviewed: "Reviewed", blocked: "Needs context" }[status] || "Not reviewed"; }
function findingStatusLabel(status) { return { open: "Open", reviewed: "Reviewed", false_positive: "False positive", accepted_risk: "Accepted risk", suppressed: "Suppressed" }[status] || "Open"; }
function evidenceIcon(type) { return { Source: "arrow-right", Sink: "target", Authorization: "lock", Validation: "verified", Controllability: "radio-tower", "Missing Context": "question", "Dynamic Validation": "pulse", "Exploit Condition": "warning", "False Positive Reason": "circle-slash", Remediation: "tools", Observation: "note" }[type] || "bookmark"; }

module.exports = {
  AttackSurfaceProvider,
  AuditCodeLensProvider,
  AuditHoverProvider,
  AuditQueryProvider,
  CodeTreeProvider,
  EvidenceProvider,
  statusLabel,
};
