const path = require("path");
const vscode = require("vscode");
const { affectsAnalysisModel } = require("./analysis/configuration");
const { AttackSurfaceProvider, AuditCodeLensProvider, AuditHoverProvider, AuditQueryProvider, CodeTreeProvider, EvidenceProvider } = require("./audit-providers");
const { buildInteractiveModel, callDetailsAtPosition, callNameAtPosition, mergeInteractiveModel, selectedCallName } = require("./config/interactive-model");
const { AuditSession, workspaceRelativePath } = require("./audit-session");
const { SUPPORTED_LABEL, SUPPORTED_SELECTORS, languageForPath } = require("./language-support");
const { markdownFence } = require("./markdown");
const { normalizeAccessPath } = require("./ir/access-path");
const { QueryKind, formatQueryMarkdown } = require("./query/audit-query-engine");
const { buildSarif } = require("./sarif");
const { normalizePath } = require("./identity");
const { findingPool } = require("./review/finding-pool");

const INTERACTIVE_SINK_KINDS = [
  { label: "$(database) SQL query", description: "Dynamic database query text", kind: "SQL_QUERY" },
  { label: "$(terminal) Command execution", description: "Shell or process command", kind: "COMMAND_EXEC" },
  { label: "$(symbol-key) Dynamic execution", description: "Runtime evaluation or dynamic code loading", kind: "DYNAMIC_EXEC" },
  { label: "$(file) File access", description: "Filesystem path or file operation", kind: "FILE_ACCESS" },
  { label: "$(radio-tower) Outbound HTTP request", description: "URL or network destination", kind: "HTTP_REQUEST" },
  { label: "$(link-external) Redirect", description: "User-controlled redirect target", kind: "REDIRECT" },
  { label: "$(output) Response output", description: "Rendered or reflected response content", kind: "RESPONSE_OUTPUT" },
  { label: "$(package) Deserialization", description: "Untrusted object or data deserialization", kind: "DESERIALIZATION" },
  { label: "$(folder) Directory lookup", description: "Directory service or naming lookup", kind: "DIRECTORY_LOOKUP" },
  { label: "$(shield) Sensitive operation", description: "Project-specific security-sensitive effect", kind: "SENSITIVE_OPERATION" },
];

const INTERACTIVE_SANITIZER_CAPABILITIES = [
  { label: "$(terminal) Shell argument escaping", description: "Protects command arguments", kind: "SHELL_ESCAPE" },
  { label: "$(database) SQL parameterization", description: "Binds data separately from SQL text", kind: "SQL_PARAMETERIZATION" },
  { label: "$(folder) Path confinement", description: "Proves a path remains under a trusted root", kind: "PATH_CONFINEMENT" },
  { label: "$(file-code) Path canonicalization", description: "Returns a normalized or canonical path", kind: "PATH_CANONICALIZATION" },
  { label: "$(code) Output encoding", description: "Returns context-safe response content", kind: "OUTPUT_ENCODING" },
  { label: "$(globe) URL policy", description: "Enforces an approved destination or host policy", kind: "URL_POLICY" },
  { label: "$(shield) Deserialization allowlist", description: "Restricts constructed classes or types", kind: "DESERIALIZATION_ALLOWLIST" },
  { label: "$(verified) General input validation", description: "Validates a value without a sink-specific proof", kind: "INPUT_VALIDATION" },
];

class AuditController {
  constructor(context, output) {
    this.context = context;
    this.output = output;
    this.session = new AuditSession(context, output);
    this.codeProvider = new CodeTreeProvider(this.session);
    this.queryProvider = new AuditQueryProvider();
    this.summaryProvider = new AttackSurfaceProvider(this.session);
    this.evidenceProvider = new EvidenceProvider(this.session);
    this.codeLensProvider = new AuditCodeLensProvider(this.session);
    this.status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
    this.status.name = "TraceGuard Manual Review Coverage";
    this.status.command = "traceguard.openAuditView";
    this.status.show();
    this.problemDiagnostics = vscode.languages.createDiagnosticCollection("TraceGuard");
    this.configurationDiagnostics = vscode.languages.createDiagnosticCollection("TraceGuard Configuration");
    this.lastAuditQuery = undefined;
    this.documentTimers = new Map();
    this.decorations = createDecorations();
    this.tracePathDecorations = createTracePathDecorations();
    this.traceDecoration = vscode.window.createTextEditorDecorationType({
      backgroundColor: new vscode.ThemeColor("editor.wordHighlightBackground"),
      borderColor: new vscode.ThemeColor("editor.findMatchBorder"),
      borderStyle: "dotted",
      borderWidth: "0 0 1px 0",
    });
    this._register();
    this.subscription = this.session.onDidChange(() => this._onSessionChanged());
  }

  _register() {
    this.context.subscriptions.push(
      this.session,
      this.codeProvider,
      this.queryProvider,
      this.summaryProvider,
      this.evidenceProvider,
      this.codeLensProvider,
      this.status,
      this.problemDiagnostics,
      this.configurationDiagnostics,
      ...Object.values(this.decorations),
      ...Object.values(this.tracePathDecorations),
      this.traceDecoration,
      vscode.window.registerTreeDataProvider("traceguard.code", this.codeProvider),
      vscode.window.registerTreeDataProvider("traceguard.auditQueries", this.queryProvider),
      vscode.window.registerTreeDataProvider("traceguard.summary", this.summaryProvider),
      vscode.window.registerTreeDataProvider("traceguard.evidence", this.evidenceProvider),
      vscode.languages.registerCodeLensProvider(SUPPORTED_SELECTORS, this.codeLensProvider),
      vscode.languages.registerHoverProvider(SUPPORTED_SELECTORS, new AuditHoverProvider(this.session)),
      vscode.commands.registerCommand("traceguard.startAudit", () => this.startAudit()),
      vscode.commands.registerCommand("traceguard.refreshAudit", () => this.refresh(true)),
      vscode.commands.registerCommand("traceguard.openAuditView", () => this.openAuditView()),
      vscode.commands.registerCommand("traceguard.auditCurrentFunction", () => this.auditCurrentFunction()),
      vscode.commands.registerCommand("traceguard.showCurrentFileTargets", () => this.showCurrentFileTargets()),
      vscode.commands.registerCommand("traceguard.showCurrentFunctionSignals", () => this.showCurrentFunctionSignals()),
      vscode.commands.registerCommand("traceguard.traceSelectedSymbol", () => this.executeAuditQuery(QueryKind.TRACE_FORWARD)),
      vscode.commands.registerCommand("traceguard.traceBackward", () => this.executeAuditQuery(QueryKind.TRACE_BACKWARD)),
      vscode.commands.registerCommand("traceguard.traceForward", () => this.executeAuditQuery(QueryKind.TRACE_FORWARD)),
      vscode.commands.registerCommand("traceguard.findCallers", () => this.executeAuditQuery(QueryKind.FIND_CALLERS)),
      vscode.commands.registerCommand("traceguard.findCallees", () => this.executeAuditQuery(QueryKind.FIND_CALLEES)),
      vscode.commands.registerCommand("traceguard.traceToEntry", () => this.executeAuditQuery(QueryKind.TRACE_TO_ENTRY)),
      vscode.commands.registerCommand("traceguard.showReachableSinks", () => this.executeAuditQuery(QueryKind.REACHABLE_SINKS)),
      vscode.commands.registerCommand("traceguard.explainAnalysisHere", () => this.executeAuditQuery(QueryKind.EXPLAIN)),
      vscode.commands.registerCommand("traceguard.copyAuditQueryMarkdown", () => this.copyAuditQueryMarkdown()),
      vscode.commands.registerCommand("traceguard.exportAnalysisDebugJson", () => this.exportAnalysisDebugJson()),
      vscode.commands.registerCommand("traceguard.clearAuditQuery", () => this.clearAuditQuery()),
      vscode.commands.registerCommand("traceguard.searchFindings", () => this.searchFindings()),
      vscode.commands.registerCommand("traceguard.filterReviewQueue", () => this.filterReviewQueue()),
      vscode.commands.registerCommand("traceguard.searchEntries", () => this.searchEntries()),
      vscode.commands.registerCommand("traceguard.openProjectConfiguration", () => this.openProjectConfiguration()),
      vscode.commands.registerCommand("traceguard.traceCrossFileFlow", item => this.traceCrossFileFlow(item)),
      vscode.commands.registerCommand("traceguard.traceFromEntry", item => this.traceFromEntry(item)),
      vscode.commands.registerCommand("traceguard.traceFinding", item => this.traceFinding(item)),
      vscode.commands.registerCommand("traceguard.previousTraceStep", () => this.moveTraceStep(-1)),
      vscode.commands.registerCommand("traceguard.nextTraceStep", () => this.moveTraceStep(1)),
      vscode.commands.registerCommand("traceguard.selectTraceStep", index => this.selectTraceStep(index)),
      vscode.commands.registerCommand("traceguard.clearSymbolTrace", () => this.clearSymbolTrace()),
      vscode.commands.registerCommand("traceguard.nextAuditTarget", () => this.navigateTarget(1)),
      vscode.commands.registerCommand("traceguard.previousAuditTarget", () => this.navigateTarget(-1)),
      vscode.commands.registerCommand("traceguard.markCurrentReviewed", () => this.markCurrentReviewed()),
      vscode.commands.registerCommand("traceguard.focusAuditItem", item => this.focusItem(item)),
      vscode.commands.registerCommand("traceguard.openAuditLocation", item => item && openLocation(item.absolutePath, item.line, item.endLine || item.line)),
      vscode.commands.registerCommand("traceguard.markReviewed", item => item ? this.setStatus((item.auditItem || item).id, "reviewed") : this.setCurrentStatus("reviewed")),
      vscode.commands.registerCommand("traceguard.markInReview", item => item ? this.setStatus((item.auditItem || item).id, "in_review") : this.setCurrentStatus("in_review")),
      vscode.commands.registerCommand("traceguard.markNeedsContext", item => item ? this.setStatus((item.auditItem || item).id, "blocked") : this.setCurrentStatus("blocked")),
      vscode.commands.registerCommand("traceguard.resetReviewStatus", item => item ? this.setStatus((item.auditItem || item).id, "unreviewed") : this.setCurrentStatus("unreviewed")),
      vscode.commands.registerCommand("traceguard.addEvidence", () => this.addSelectionEvidence()),
      vscode.commands.registerCommand("traceguard.markSelectionAsSource", () => this.markSelectedCall("source")),
      vscode.commands.registerCommand("traceguard.markSelectionAsSink", () => this.markSelectedCall("sink")),
      vscode.commands.registerCommand("traceguard.markSelectionAsTemporarySanitizer", () => this.markTemporarySelection("sanitizer")),
      vscode.commands.registerCommand("traceguard.markSelectionAsTemporarySink", () => this.markTemporarySelection("sink")),
      vscode.commands.registerCommand("traceguard.clearTemporaryModels", () => this.clearTemporaryModels()),
      vscode.commands.registerCommand("traceguard.openEvidence", item => this.openEvidence(item)),
      vscode.commands.registerCommand("traceguard.removeEvidence", item => this.session.removeEvidence((item.evidenceItem || item).id)),
      vscode.commands.registerCommand("traceguard.generateAuditReport", () => this.generateReport()),
      vscode.commands.registerCommand("traceguard.exportSarif", () => this.exportSarif()),
      vscode.commands.registerCommand("traceguard.markFindingReviewed", item => this.setFindingStatus(item, "reviewed")),
      vscode.commands.registerCommand("traceguard.markFindingFalsePositive", item => this.setFindingStatus(item, "false_positive")),
      vscode.commands.registerCommand("traceguard.acceptFindingRisk", item => this.setFindingStatus(item, "accepted_risk")),
      vscode.commands.registerCommand("traceguard.suppressFinding", item => this.setFindingStatus(item, "suppressed")),
      vscode.commands.registerCommand("traceguard.resetFindingStatus", item => this.setFindingStatus(item, "open")),
      vscode.commands.registerCommand("traceguard.exportReviewSession", () => this.exportReviewSession()),
      vscode.commands.registerCommand("traceguard.importReviewSession", () => this.importReviewSession()),
      vscode.workspace.onDidSaveTextDocument(document => this._onSaved(document)),
      vscode.workspace.onDidChangeTextDocument(event => this._onChanged(event.document)),
      vscode.workspace.onDidCreateFiles(event => { void this._runBackground("Created-file indexing", () => this._onFilesCreated(event.files)); }),
      vscode.workspace.onDidDeleteFiles(event => { void this._runBackground("Deleted-file indexing", () => this._onFilesDeleted(event.files)); }),
      vscode.workspace.onDidRenameFiles(event => { void this._runBackground("Renamed-file indexing", () => this._onFilesRenamed(event.files)); }),
      vscode.window.onDidChangeActiveTextEditor(editor => {
        if (this.tracedEditor && this.tracedEditor !== editor) this._clearTraceEditor(this.tracedEditor);
        this._updateDecorations(editor);
        this._updateTraceDecorations(editor);
      }),
      vscode.workspace.onDidChangeConfiguration(event => {
        if (event.affectsConfiguration("traceguard.showAuditSignals")) this._updateDecorations(vscode.window.activeTextEditor);
        if (event.affectsConfiguration("traceguard.hideReviewedTargets")) this.codeProvider.refresh();
        if (event.affectsConfiguration("traceguard.showFlowCodeLens")) this.codeLensProvider.refresh();
        if (event.affectsConfiguration("traceguard.maxSourceFileKiB")) void this._runBackground("Source budget refresh", () => this.refresh(false));
        if (affectsAnalysisModel(event)) void this._runBackground("Analysis model refresh", () => this.session.rebuildModel());
      }),
    );
  }

  async initialize() {
    if (!vscode.workspace.isTrusted || !vscode.workspace.workspaceFolders?.length) {
      this._updateStatus();
      return;
    }
    await this.session.reloadProjectConfiguration({ rebuild: false, silent: true });
    if (!vscode.workspace.getConfiguration("traceguard").get("indexOnStartup", false)) {
      this._updateStatus();
      return;
    }
    await this.refresh(false);
    const snapshot = this.session.snapshot;
    const firstRun = !this.context.globalState.get("traceguard.auditHelperOnboarded", false);
    if (firstRun && snapshot.items.length) {
      await this.context.globalState.update("traceguard.auditHelperOnboarded", true);
      const action = await vscode.window.showInformationMessage(
        `TraceGuard prepared ${snapshot.items.length} code-review targets from ${snapshot.entries.length} entry points. Everything stays in VS Code.`,
        "Open Audit Sidebar",
      );
      if (action) await this.openAuditView();
    }
  }

  async startAudit() {
    await this.refresh(true);
    await this.openAuditView();
    await vscode.commands.executeCommand("traceguard.summary.focus");
  }

  async openAuditView() {
    await vscode.commands.executeCommand("workbench.view.extension.traceguard");
  }

  async refresh(showNotification) {
    if (!vscode.workspace.isTrusted) {
      vscode.window.showWarningMessage("Trust this workspace before TraceGuard indexes code for review.");
      return;
    }
    this.status.text = "$(sync~spin) Mapping audit surface";
    try {
      await vscode.window.withProgress({
        location: showNotification ? vscode.ProgressLocation.Notification : vscode.ProgressLocation.Window,
        title: "TraceGuard is building the audit map",
        cancellable: true,
      }, (progress, token) => this.session.indexWorkspace(progress, token));
      const indexStatus = this.session.indexStatus;
      if (showNotification) {
        if (indexStatus.cancelled) {
          vscode.window.showInformationMessage("TraceGuard indexing was cancelled. The previous audit map was kept unchanged.");
          return;
        }
        const data = this.session.snapshot;
        if (data.indexIncomplete) {
          vscode.window.showWarningMessage(`Partial audit map ready: ${data.files} files indexed${data.indexTruncated ? `; the ${data.indexDiscoveredFiles - 1}+ file workspace limit was reached` : ""}${data.indexSkippedFiles ? `; ${data.indexSkippedFiles} files were skipped` : ""}.`);
        } else {
          vscode.window.showInformationMessage(`Audit map ready: ${data.entries.length} entry points, ${data.items.length} review targets, ${data.files} files indexed.`);
        }
      }
    } catch (error) {
      const message = firstLine(error?.message || error);
      this.output.error(`Audit indexing failed:\n${String(error?.stack || error?.message || error)}`);
      if (showNotification) {
        const action = await vscode.window.showErrorMessage(
          `TraceGuard could not build the review index: ${message}`,
          "Open TraceGuard Output",
        );
        if (action) this.output.show(true);
      }
    } finally {
      this._updateStatus();
    }
  }

  async auditCurrentFunction() {
    const editor = vscode.window.activeTextEditor;
    if (!editor || !languageForPath(editor.document.uri.fsPath)) {
      vscode.window.showInformationMessage(`Open a ${SUPPORTED_LABEL} function to review it.`);
      return;
    }
    let item = this.session.itemAt(editor.document.uri, editor.selection.active.line);
    if (!item) {
      await this.session.reindexFile(editor.document.uri);
      item = this.session.itemAt(editor.document.uri, editor.selection.active.line);
    }
    if (!item) {
      vscode.window.showInformationMessage("No sensitive audit target was inferred around this function. Select relevant code and add it as evidence instead.");
      return;
    }
    await this.setStatus(item.id, item.status === "unreviewed" ? "in_review" : item.status);
    await this.openItem(item.id);
  }

  async showCurrentFileTargets() {
    const editor = vscode.window.activeTextEditor;
    if (!editor || !languageForPath(editor.document.uri.fsPath)) {
      vscode.window.showInformationMessage(`Open a ${SUPPORTED_LABEL} file first.`);
      return;
    }
    await this.session.reindexDocument(editor.document);
    const items = this.session.itemsForUri(editor.document.uri);
    if (!items.length) {
      vscode.window.showInformationMessage("No review targets were inferred in this file. You can still select code and add an audit note.");
      return;
    }
    const selected = await vscode.window.showQuickPick(items.map(item => ({
      label: `$(${priorityIcon(item.priority)}) ${item.priority} · ${item.title}`,
      description: `${statusLabel(item.status)} · line ${item.line}`,
      detail: item.reasons.join(" · "),
      item,
    })), { placeHolder: `Review targets in ${path.basename(editor.document.uri.fsPath)}`, matchOnDescription: true, matchOnDetail: true });
    if (selected) await this.focusItem(selected.item);
  }

  async showCurrentFunctionSignals() {
    const editor = vscode.window.activeTextEditor;
    if (!editor || !languageForPath(editor.document.uri.fsPath)) {
      vscode.window.showInformationMessage(`Open a ${SUPPORTED_LABEL} file first.`);
      return;
    }
    await this.session.reindexDocument(editor.document);
    const item = this.session.itemAt(editor.document.uri, editor.selection.active.line);
    const analysis = this.session.analysisForUri(editor.document.uri);
    const signals = (item?.signals || analysis?.signals || []).slice().sort((a, b) => a.line - b.line);
    if (!signals.length) {
      vscode.window.showInformationMessage("No input, sensitive-operation, authorization or validation clues were inferred here.");
      return;
    }
    const selected = await vscode.window.showQuickPick(signals.map(signal => ({
      label: `$(${signalIcon(signal.kind)}) Line ${signal.line} · ${signal.label}`,
      description: signal.kind,
      detail: signal.code,
      signal,
    })), { placeHolder: item ? `Security clues in ${item.title}` : "Security clues in the current file", matchOnDetail: true });
    if (selected) await openLocation(editor.document.uri.fsPath, selected.signal.line, selected.signal.line);
  }

  async executeAuditQuery(kind) {
    const editor = vscode.window.activeTextEditor;
    if (!editor || !languageForPath(editor.document.uri.fsPath)) {
      vscode.window.showInformationMessage(`Open a ${SUPPORTED_LABEL} file first.`);
      return undefined;
    }
    const identifier = selectedAccessPath(editor);
    if ((kind === QueryKind.TRACE_BACKWARD || kind === QueryKind.TRACE_FORWARD) && !identifier) {
      vscode.window.showInformationMessage("Select a variable or property path, or place the cursor on one before tracing it.");
      return undefined;
    }
    await this.session.reindexDocument(editor.document);
    const result = await vscode.window.withProgress({
      location: vscode.ProgressLocation.Window,
      title: "TraceGuard is querying the analysis graph",
      cancellable: false,
    }, () => this.session.queryAudit(editor.document.uri, editor.selection.active.line, kind, identifier));
    if (result.coverage?.incomplete && result.coverage.workspaceGraph) {
      void vscode.window.showWarningMessage("TraceGuard queried a partial workspace index. Missing callers, entries or sinks may exist in files that have not been indexed.");
    }
    this.lastAuditQuery = result;
    this.queryProvider.setResult(result);
    this.clearSymbolTrace();
    await vscode.commands.executeCommand("setContext", "traceguard.hasAuditQuery", true);
    await vscode.commands.executeCommand("setContext", "traceguard.hasTracePath", false);
    await this.openAuditView();
    await vscode.commands.executeCommand("traceguard.auditQueries.focus");
    if (result.truncated) {
      vscode.window.showWarningMessage(`The audit query reached its ${result.summary?.nodes || "configured"}-step limit. Narrow the subject or raise TraceGuard: Query Max Nodes.`);
    }
    return result;
  }

  async filterReviewQueue() {
    const options = [
      { id: "priority", label: "$(list-ordered) P0 / P1 first", description: "All targets, ordered by audit value" },
      { id: "unreviewed", label: "$(circle-outline) Unreviewed" },
      { id: "in_review", label: "$(debug-pause) In review" },
      { id: "blocked", label: "$(circle-slash) Needs context" },
      { id: "reviewed", label: "$(pass-filled) Reviewed" },
      { id: "current_endpoint", label: "$(globe) Current endpoint" },
      { id: "current_file", label: "$(file) Current file" },
      { id: "reachable", label: "$(type-hierarchy-sub) Reachable from entry" },
      { id: "unresolved", label: "$(debug-disconnect) Contains unresolved calls" },
    ];
    const selected = await vscode.window.showQuickPick(options, {
      placeHolder: "Filter the human review queue",
      matchOnDescription: true,
    });
    if (!selected) return;
    this.codeProvider.setFilter({ id: selected.id, label: selected.label.replace(/^\$\([^)]*\)\s*/, "") });
  }

  async copyAuditQueryMarkdown() {
    if (!this.lastAuditQuery) {
      vscode.window.showInformationMessage("Run an audit query before copying its path.");
      return;
    }
    await vscode.env.clipboard.writeText(formatQueryMarkdown(this.lastAuditQuery));
    vscode.window.setStatusBarMessage("$(copy) TraceGuard analysis path copied as Markdown", 2500);
  }

  async exportAnalysisDebugJson() {
    const editor = vscode.window.activeTextEditor;
    if (!editor || !languageForPath(editor.document.uri.fsPath)) {
      vscode.window.showInformationMessage(`Open a ${SUPPORTED_LABEL} file before exporting analysis details.`);
      return;
    }
    await this.session.reindexDocument(editor.document);
    const payload = await this.session.debugAnalysisForUri(editor.document.uri, this.lastAuditQuery);
    if (!payload) {
      vscode.window.showInformationMessage("No analysis model is available for the current file.");
      return;
    }
    const folder = vscode.workspace.getWorkspaceFolder(editor.document.uri) || vscode.workspace.workspaceFolders?.[0];
    const defaultUri = folder
      ? vscode.Uri.joinPath(folder.uri, `${path.basename(editor.document.uri.fsPath)}.traceguard-debug.json`)
      : vscode.Uri.file(`${editor.document.uri.fsPath}.traceguard-debug.json`);
    const target = await vscode.window.showSaveDialog({
      defaultUri,
      filters: { "TraceGuard analysis debug": ["json"] },
      saveLabel: "Export Analysis Debug JSON",
      title: "Export the current frontend, IR, finding and query facts",
    });
    if (!target) return;
    await vscode.workspace.fs.writeFile(target, Buffer.from(`${JSON.stringify(payload, null, 2)}\n`, "utf8"));
    const action = await vscode.window.showInformationMessage(`TraceGuard analysis details exported to ${target.fsPath}.`, "Open File");
    if (action) await vscode.window.showTextDocument(target);
  }

  async openProjectConfiguration() {
    const folders = vscode.workspace.workspaceFolders || [];
    if (!folders.length) {
      vscode.window.showInformationMessage("Open a workspace before creating .traceguard.json.");
      return;
    }
    let folder = folders[0];
    if (folders.length > 1) {
      const selected = await vscode.window.showQuickPick(folders.map(candidate => ({ label: candidate.name, description: candidate.uri.fsPath, folder: candidate })), {
        placeHolder: "Choose the workspace folder for .traceguard.json",
      });
      if (!selected) return;
      folder = selected.folder;
    }
    const uri = vscode.Uri.joinPath(folder.uri, ".traceguard.json");
    try {
      await vscode.workspace.fs.stat(uri);
    } catch (error) {
      if (!/not.?found/i.test(String(error?.message || "")) && error?.code !== "FileNotFound") throw error;
      const template = {
        version: 1,
        sources: [],
        sinks: [],
        sanitizers: [],
        propagators: [],
        rules: {},
        excludePaths: [],
      };
      await vscode.workspace.fs.writeFile(uri, Buffer.from(`${JSON.stringify(template, null, 2)}\n`, "utf8"));
    }
    await vscode.window.showTextDocument(uri, { preview: false });
  }

  clearAuditQuery() {
    this.lastAuditQuery = undefined;
    this.queryProvider.clear();
    this.clearSymbolTrace();
    void vscode.commands.executeCommand("setContext", "traceguard.hasAuditQuery", false);
    void vscode.commands.executeCommand("setContext", "traceguard.hasTracePath", false);
  }

  async searchFindings() {
    const findings = this.session.snapshot.findings.filter(finding => !["false_positive", "suppressed"].includes(finding.status));
    if (!findings.length) {
      vscode.window.showInformationMessage("There are no active TraceGuard flows or review hypotheses to search.");
      return;
    }
    const selected = await vscode.window.showQuickPick(findings.map(finding => ({
      label: `$(${findingSeverityIcon(finding.severity)}) ${finding.title}`,
      description: `${findingPool(finding) === "verified" ? "Verified Flow" : "Review Hypothesis"} · ${finding.confidence} · ${finding.relativePath}:${finding.line}`,
      detail: `${finding.sourceKind} → ${finding.sinkKind} · ${finding.pathCount || 1} candidate path${finding.pathCount === 1 ? "" : "s"}`,
      finding,
    })), {
      placeHolder: `Search ${findings.length} active TraceGuard flow${findings.length === 1 ? "" : "s"}`,
      matchOnDescription: true,
      matchOnDetail: true,
    });
    if (selected) await openLocation(selected.finding.absolutePath, selected.finding.line, selected.finding.endLine || selected.finding.line);
  }

  async searchEntries() {
    const entries = this.session.snapshot.entries || [];
    if (!entries.length) {
      vscode.window.showInformationMessage("No supported API entry points are present in the current audit index.");
      return;
    }
    const selected = await vscode.window.showQuickPick(entries.map(entry => {
      const method = String(entry.method || "ANY").toUpperCase();
      const route = entry.route && entry.route !== "<dynamic>" ? entry.route : entry.title;
      return {
        label: `$(globe) ${method} ${route}`,
        description: entry.framework || entry.language || "entry",
        detail: `${entry.relativePath}:${entry.line} · ${entry.title}`,
        entry,
      };
    }).sort((left, right) => left.label.localeCompare(right.label)), {
      placeHolder: `Filter ${entries.length} indexed API entries by method, route, framework or file`,
      matchOnDescription: true,
      matchOnDetail: true,
    });
    if (selected) await openLocation(selected.entry.absolutePath, selected.entry.line, selected.entry.endLine || selected.entry.line);
  }

  async traceCrossFileFlow(item) {
    const activeEditor = vscode.window.activeTextEditor;
    const targetPath = item?.absolutePath || activeEditor?.document.uri.fsPath;
    if (!targetPath || !languageForPath(targetPath)) {
      vscode.window.showInformationMessage(`Open a ${SUPPORTED_LABEL} file first.`);
      return;
    }
    const document = activeEditor && normalizePath(activeEditor.document.uri.fsPath) === normalizePath(targetPath)
      ? activeEditor.document
      : await vscode.workspace.openTextDocument(vscode.Uri.file(targetPath));
    const targetLine = item ? Math.max(0, Number(item.line || 1) - 1) : activeEditor.selection.active.line;
    const selectedText = item ? "" : activeEditor.document.getText(activeEditor.selection).trim();
    const identifier = /^[A-Za-z_$][\w$]*$/.test(selectedText) ? selectedText : "";
    await this.session.reindexDocument(document);
    const safeLine = Math.min(targetLine, Math.max(0, document.lineCount - 1));
    const paths = await this.session.sourceSinkPathsFrom(
      document.uri,
      safeLine,
      identifier,
      identifier ? document.lineAt(safeLine).text.trim() : "",
    );
    if (!paths.length) {
      const subject = identifier ? `“${identifier}”` : "this function";
      vscode.window.showInformationMessage(`No project-internal Source → Sink path was found from ${subject}. Try selecting an input variable or refresh the workspace index.`);
      return;
    }
    const selectedPath = await vscode.window.showQuickPick(paths.map(flowPath => ({
      label: `$(git-compare) ${flowPath.finding ? `${flowPath.finding.severity.toUpperCase()} · ${flowPath.finding.title}` : `${flowPath.source.label} → ${flowPath.sink.label}`}`,
      description: `${flowReviewLabel(flowPath)} · ${flowConfidenceLabel(flowPath.confidence)} · ${flowPath.calls} call${flowPath.calls === 1 ? "" : "s"} · ${flowPath.files.length} file${flowPath.files.length === 1 ? "" : "s"}`,
      detail: flowPathSummary(flowPath),
      flowPath,
    })), {
      placeHolder: paths.truncated
        ? `Showing ${paths.length} prioritized paths from at least ${paths.totalCandidates}; narrow the selection or raise the path limit`
        : `${paths.length} possible Source → Sink path${paths.length === 1 ? "" : "s"}; choose one to inspect`,
      matchOnDescription: true,
      matchOnDetail: true,
    });
    if (!selectedPath) return;
    await this.startInteractiveTrace(selectedPath.flowPath);
  }

  async traceFromEntry(item) {
    const entry = item?.entry || item;
    if (entry?.absolutePath) await this.traceCrossFileFlow(entry);
  }

  async traceFinding(item) {
    const finding = item?.finding || item;
    if (!finding?.id) return;
    const paths = uniqueFindingPaths(finding);
    if (!paths.length) {
      vscode.window.showInformationMessage("This finding does not contain an inspectable Source → Sink path.");
      return;
    }
    let selected = paths[0];
    if (paths.length > 1) {
      const picked = await vscode.window.showQuickPick(paths.map((flowPath, index) => ({
        label: `$(git-compare) Path ${index + 1}`,
        description: `${flowReviewLabel(flowPath)} · ${flowPath.steps?.length || 0} steps`,
        detail: flowPathSummary(flowPath),
        flowPath,
      })), { placeHolder: `Choose one of ${paths.length} candidate paths to inspect`, matchOnDetail: true });
      if (!picked) return;
      selected = picked.flowPath;
    }
    await this.startInteractiveTrace(selected);
  }

  async startInteractiveTrace(flowPath) {
    if (!flowPath?.steps?.length) return;
    this.lastAuditQuery = undefined;
    this.queryProvider.setTrace(flowPath, 0);
    await vscode.commands.executeCommand("setContext", "traceguard.hasAuditQuery", false);
    await vscode.commands.executeCommand("setContext", "traceguard.hasTracePath", true);
    await this.openAuditView();
    await vscode.commands.executeCommand("traceguard.auditQueries.focus");
    await this.openCurrentTraceStep();
  }

  async selectTraceStep(index) {
    const step = this.queryProvider.selectTraceStep(Number(index));
    if (step) await this.openCurrentTraceStep();
  }

  async moveTraceStep(delta) {
    const step = this.queryProvider.moveTrace(delta);
    if (step) await this.openCurrentTraceStep();
  }

  async openCurrentTraceStep() {
    const step = this.queryProvider.currentTraceStep;
    if (!step?.absolutePath || !step.line) return;
    const editor = await openLocation(step.absolutePath, step.line, step.line);
    const line = Math.max(0, Math.min(editor.document.lineCount - 1, Number(step.line) - 1));
    const range = traceStepRange(editor.document, step);
    editor.selection = new vscode.Selection(range.start, range.end);
    editor.revealRange(range, vscode.TextEditorRevealType.InCenterIfOutsideViewport);
    this._updateTraceDecorations(editor);
    editor.setDecorations(this.traceDecoration, [{
      range,
      hoverMessage: tracePathHover(this.queryProvider.currentTrace, this.queryProvider.traceCursor),
    }]);
    this.tracedEditor = editor;
    vscode.window.setStatusBarMessage(`$(debug-stackframe) Trace ${this.queryProvider.traceCursor + 1}/${this.queryProvider.currentTrace.steps.length} · ${step.kind || "flow"}`, 2200);
  }

  clearSymbolTrace() {
    this._clearTraceEditor(this.tracedEditor);
    this.tracedEditor = undefined;
  }

  _clearTraceEditor(editor) {
    if (!editor) return;
    editor.setDecorations(this.traceDecoration, []);
    for (const decoration of Object.values(this.tracePathDecorations)) editor.setDecorations(decoration, []);
  }

  async navigateTarget(direction) {
    const items = this.session.snapshot.items;
    if (!items.length) {
      vscode.window.showInformationMessage("The review queue is empty. Run “TraceGuard: Start Code Review” first.");
      return;
    }
    const editor = vscode.window.activeTextEditor;
    const currentPath = editor ? normalizePath(editor.document.uri.fsPath) : "";
    const currentLine = editor?.selection.active.line + 1 || 0;
    let index = items.findIndex(item => normalizePath(item.absolutePath) === currentPath && currentLine >= item.line && currentLine <= item.endLine);
    index = index < 0 ? (direction > 0 ? 0 : items.length - 1) : (index + direction + items.length) % items.length;
    await this.focusItem(items[index]);
  }

  async markCurrentReviewed() {
    await this.setCurrentStatus("reviewed");
  }

  async setCurrentStatus(status) {
    const editor = vscode.window.activeTextEditor;
    const item = editor && this.session.itemAt(editor.document.uri, editor.selection.active.line);
    if (!item) {
      vscode.window.showInformationMessage("Place the cursor inside a review target before changing its review state.");
      return;
    }
    await this.setStatus(item.id, status);
    vscode.window.setStatusBarMessage(`$(check) ${statusLabel(status)} · ${item.title}`, 2500);
  }

  async focusItem(item) {
    if (!item) return;
    if (item.status === "unreviewed") await this.setStatus(item.id, "in_review");
    await this.openItem(item.id);
  }

  async openItem(itemId, line) {
    const item = this.session.snapshot.items.find(candidate => candidate.id === itemId);
    if (!item) return;
    await openLocation(item.absolutePath, line || item.line, item.endLine);
  }

  async setStatus(itemId, status) {
    await this.session.setStatus(itemId, status);
  }

  async setFindingStatus(item, status) {
    const finding = item?.finding || item;
    if (!finding?.id) return;
    await this.session.setFindingStatus(finding.id, status);
  }

  async markSelectedCall(role) {
    const editor = vscode.window.activeTextEditor;
    const language = editor && languageForPath(editor.document.uri.fsPath);
    if (!editor || !language) {
      vscode.window.showInformationMessage(`Open a ${SUPPORTED_LABEL} file and place the cursor on a call first.`);
      return;
    }
    const callContext = await this._interactiveCallContext(editor);
    const inferred = callContext.functionName;
    const functionName = await vscode.window.showInputBox({
      title: role === "source" ? "Mark selected call as Source" : "Mark selected call as Sink",
      prompt: "Confirm the function or qualified call name stored in this workspace's .traceguard.json.",
      placeHolder: "For example: requestValue, os.system, Runtime.exec",
      value: inferred,
      validateInput: value => selectedCallName(value) ? undefined : "Enter a function or qualified call name.",
    });
    if (!functionName) return;
    let kind = "EXTERNAL_INPUT";
    let argumentIndexes = [];
    if (role === "sink") {
      const picked = await vscode.window.showQuickPick(INTERACTIVE_SINK_KINDS, {
        title: `What security effect does ${selectedCallName(functionName)} have?`,
        placeHolder: "Choose the Sink category used by Source → Sink rules",
        matchOnDescription: true,
      });
      if (!picked) return;
      kind = picked.kind;
      argumentIndexes = await this._pickInteractiveArguments(callContext, "Sink");
      if (!argumentIndexes) return;
    }
    const folder = vscode.workspace.getWorkspaceFolder(editor.document.uri);
    if (!folder) {
      vscode.window.showInformationMessage("Open the file inside a workspace before adding a project semantic model.");
      return;
    }
    const uri = vscode.Uri.joinPath(folder.uri, ".traceguard.json");
    let configuration = { version: 1, sources: [], sinks: [], sanitizers: [], propagators: [], rules: {}, excludePaths: [] };
    try {
      const bytes = await vscode.workspace.fs.readFile(uri);
      configuration = JSON.parse(Buffer.from(bytes).toString("utf8"));
    } catch (error) {
      if (!isFileNotFoundError(error)) {
        const action = await vscode.window.showErrorMessage(`TraceGuard did not change .traceguard.json: ${firstLine(error?.message || error)}`, "Open Configuration");
        if (action) await vscode.window.showTextDocument(uri, { preview: false });
        return;
      }
    }
    let update;
    try {
      const model = buildInteractiveModel({
        role,
        language,
        functionName: selectedCallName(functionName),
        kind,
        arguments: argumentIndexes,
        ...interactiveIdentity(callContext, functionName),
      });
      update = mergeInteractiveModel(configuration, role, model);
    } catch (error) {
      vscode.window.showErrorMessage(`TraceGuard did not add the semantic model: ${firstLine(error?.message || error)}`);
      return;
    }
    if (!update.changed) {
      vscode.window.setStatusBarMessage(`$(info) ${selectedCallName(functionName)} is already configured as a ${role}`, 3000);
      return;
    }
    await vscode.workspace.fs.writeFile(uri, Buffer.from(`${JSON.stringify(update.configuration, null, 2)}\n`, "utf8"));
    await vscode.window.withProgress({
      location: vscode.ProgressLocation.Window,
      title: `TraceGuard is applying the new ${role} model`,
      cancellable: false,
    }, () => this.session.reloadProjectConfiguration({ rebuild: true }));
    const action = await vscode.window.showInformationMessage(
      `Marked ${selectedCallName(functionName)} as a project ${role}. Source → Sink paths were rebuilt.`,
      "Open Configuration",
    );
    if (action) await vscode.window.showTextDocument(uri, { preview: false });
  }

  async markTemporarySelection(role) {
    const editor = vscode.window.activeTextEditor;
    const language = editor && languageForPath(editor.document.uri.fsPath);
    if (!editor || !language) {
      vscode.window.showInformationMessage(`Open a ${SUPPORTED_LABEL} file and place the cursor on a function or call first.`);
      return;
    }
    const callContext = await this._interactiveCallContext(editor);
    const inferred = callContext.functionName;
    const functionName = await vscode.window.showInputBox({
      title: role === "sanitizer" ? "TraceGuard: mark as temporary Sanitizer" : "TraceGuard: mark as temporary Sink",
      prompt: "This model stays in memory for the current VS Code session and is never written to the project.",
      placeHolder: "For example: sanitizePath, db.query, Runtime.exec",
      value: inferred,
      validateInput: value => selectedCallName(value) ? undefined : "Enter a function or qualified call name.",
    });
    if (!functionName) return;
    const choices = role === "sanitizer" ? INTERACTIVE_SANITIZER_CAPABILITIES : INTERACTIVE_SINK_KINDS;
    const picked = await vscode.window.showQuickPick(choices, {
      title: role === "sanitizer" ? "What security guarantee does this Sanitizer provide?" : "What security effect does this Sink perform?",
      placeHolder: role === "sanitizer" ? "Choose the narrowest capability that is actually guaranteed" : "Choose the Sink category used by Source → Sink rules",
      matchOnDescription: true,
    });
    if (!picked) return;
    const argumentIndexes = await this._pickInteractiveArguments(callContext, role === "sanitizer" ? "Sanitizer" : "Sink");
    if (!argumentIndexes) return;
    let model;
    try {
      model = buildInteractiveModel({
        role,
        language,
        functionName: selectedCallName(functionName),
        kind: picked.kind,
        arguments: argumentIndexes,
        ...interactiveIdentity(callContext, functionName),
      });
    } catch (error) {
      vscode.window.showErrorMessage(`TraceGuard did not add the temporary model: ${firstLine(error?.message || error)}`);
      return;
    }
    let result;
    try {
      result = await vscode.window.withProgress({
        location: vscode.ProgressLocation.Window,
        title: `TraceGuard is applying a temporary ${role} model`,
        cancellable: false,
      }, async () => {
        const added = await this.session.addTemporarySemanticModel(editor.document.uri, role, model);
        if (editor.document.isDirty || !this.session.analysisForUri(editor.document.uri)) await this.session.reindexDocument(editor.document);
        return added;
      });
    } catch (error) {
      vscode.window.showErrorMessage(`TraceGuard could not apply the temporary ${role}: ${firstLine(error?.message || error)}`);
      return;
    }
    if (!result.changed) {
      vscode.window.setStatusBarMessage(`$(info) ${selectedCallName(functionName)} is already active as a temporary ${role}`, 3000);
      return;
    }
    const action = await vscode.window.showInformationMessage(
      `Temporary ${role} active for ${selectedCallName(functionName)}. Findings and paths were rebuilt in memory.`,
      "Clear Temporary Models",
    );
    if (action) await this.clearTemporaryModels();
  }

  async _interactiveCallContext(editor) {
    if (editor.document.isDirty || !this.session.analysisForUri(editor.document.uri)) {
      await this.session.reindexDocument(editor.document);
    }
    const position = editor.selection.active;
    const lineText = editor.document.lineAt(position.line).text;
    const fallback = callDetailsAtPosition(lineText, position.character);
    const semantic = await this.session.semanticCallAt(editor.document.uri, position.line, position.character);
    const symbolIdentity = semantic?.symbol || {};
    const proofVerified = Boolean(symbolIdentity.verified && !symbolIdentity.unresolvedType && (
      symbolIdentity.receiverType || symbolIdentity.moduleName || /[.\\:#]/.test(String(symbolIdentity.qualifiedName || ""))
    ));
    return {
      functionName: semantic?.functionName || fallback?.functionName || callNameAtPosition(lineText, position.character) || selectedCallName(lineText),
      arguments: semantic?.arguments?.length ? semantic.arguments : fallback?.arguments || [],
      selectedArgumentIndex: fallback?.selectedArgumentIndex ?? -1,
      receiverType: proofVerified ? symbolIdentity.receiverType : undefined,
      qualifiedName: proofVerified ? symbolIdentity.qualifiedName : undefined,
      symbol: proofVerified ? symbolIdentity.qualifiedName : undefined,
      certainty: proofVerified ? "verified" : "review",
    };
  }

  async _pickInteractiveArguments(callContext, roleLabel) {
    const argumentsList = callContext.arguments || [];
    if (!argumentsList.length) {
      vscode.window.showWarningMessage(`TraceGuard could not identify any arguments for this ${roleLabel}. No model was added.`);
      return undefined;
    }
    if (argumentsList.length === 1) return [0];
    const choices = argumentsList.map((value, index) => ({
      label: `Argument ${index}`,
      description: String(value || "").replace(/\s+/g, " ").slice(0, 120),
      index,
      picked: index === callContext.selectedArgumentIndex,
    }));
    const picked = await vscode.window.showQuickPick(choices, {
      title: `Which arguments does this ${roleLabel} consume or protect?`,
      placeHolder: "Select every security-relevant argument; TraceGuard will not assume argument 0",
      canPickMany: true,
      matchOnDescription: true,
    });
    if (!picked?.length) return undefined;
    return picked.map(item => item.index).sort((left, right) => left - right);
  }

  async clearTemporaryModels() {
    let changed;
    try {
      changed = await this.session.clearTemporarySemanticModels();
    } catch (error) {
      vscode.window.showErrorMessage(`TraceGuard could not clear the temporary models: ${firstLine(error?.message || error)}`);
      return;
    }
    if (changed) vscode.window.showInformationMessage("TraceGuard cleared all temporary semantic models and rebuilt the current findings.");
    else vscode.window.setStatusBarMessage("$(info) No temporary TraceGuard models are active", 2500);
  }

  async addSelectionEvidence() {
    const editor = vscode.window.activeTextEditor;
    if (!editor || !languageForPath(editor.document.uri.fsPath)) {
      vscode.window.showInformationMessage(`Select ${SUPPORTED_LABEL} code before adding an audit note.`);
      return;
    }
    const selection = editor.selection.isEmpty ? editor.document.lineAt(editor.selection.active.line).range : editor.selection;
    const code = editor.document.getText(selection).trim();
    const type = await vscode.window.showQuickPick([
      "Controllability", "Missing Context", "Dynamic Validation", "Exploit Condition", "False Positive Reason", "Remediation",
      "Source", "Sink", "Authorization", "Validation", "Observation",
    ], { placeHolder: "What does this code prove or require you to verify?" });
    if (!type) return;
    const note = await vscode.window.showInputBox({ prompt: "Audit note (optional)", placeHolder: "Why this evidence matters, assumptions, or follow-up question" });
    if (note === undefined) return;
    await this.session.addEvidence({ type, note, code, absolutePath: editor.document.uri.fsPath, relativePath: workspaceRelativePath(editor.document.uri), line: selection.start.line + 1, endLine: selection.end.line + 1 });
    vscode.window.showInformationMessage(`Added ${type.toLowerCase()} evidence to the audit notebook.`);
  }

  async addEvidenceForItem(itemId) {
    const item = this.session.snapshot.items.find(candidate => candidate.id === itemId);
    if (!item) return;
    const type = await vscode.window.showQuickPick([
      "Controllability", "Missing Context", "Dynamic Validation", "Exploit Condition", "False Positive Reason", "Remediation",
      "Source", "Sink", "Authorization", "Validation", "Observation",
    ], { placeHolder: "Evidence type" });
    if (!type) return;
    const note = await vscode.window.showInputBox({ prompt: "What did you verify or what still needs investigation?" });
    if (note === undefined) return;
    const code = item.signals.slice(0, 3).map(signal => `${signal.line}: ${signal.code}`).join("\n") || item.title;
    await this.session.addEvidence({ type, note, code, absolutePath: item.absolutePath, relativePath: item.relativePath, line: item.line, endLine: item.endLine, auditItemId: item.id });
  }

  async openEvidence(item) { if (item) await openLocation(item.absolutePath, item.line, item.endLine); }
  async openEvidenceById(id) { const item = this.session.snapshot.evidence.find(candidate => candidate.id === id); if (item) await this.openEvidence(item); }

  async generateReport() {
    const folder = vscode.workspace.workspaceFolders?.[0];
    if (!folder) return;
    const target = await vscode.window.showSaveDialog({ defaultUri: vscode.Uri.joinPath(folder.uri, "traceguard-audit-report.md"), filters: { Markdown: ["md"] }, saveLabel: "Generate Audit Report" });
    if (!target) return;
    const report = buildReport(this.session.snapshot);
    await vscode.workspace.fs.writeFile(target, Buffer.from(report, "utf8"));
    const action = await vscode.window.showInformationMessage(`Audit report generated: ${target.fsPath}`, "Open Report");
    if (action) vscode.window.showTextDocument(target);
  }

  async exportSarif() {
    const folder = vscode.workspace.workspaceFolders?.[0];
    if (!folder) return;
    const target = await vscode.window.showSaveDialog({
      defaultUri: vscode.Uri.joinPath(folder.uri, "traceguard-results.sarif"),
      filters: { SARIF: ["sarif", "json"] },
      saveLabel: "Export SARIF",
      title: "Export explainable TraceGuard findings for CI or security platforms",
    });
    if (!target) return;
    const sarif = this.createSarif();
    await vscode.workspace.fs.writeFile(target, Buffer.from(`${JSON.stringify(sarif, null, 2)}\n`, "utf8"));
    vscode.window.showInformationMessage(`Exported ${sarif.runs[0].results.length} TraceGuard findings to SARIF.`);
  }

  createSarif() {
    const folders = vscode.workspace.workspaceFolders || [];
    const multipleRoots = folders.length > 1;
    const sourceRoots = folders.map((folder, index) => ({
      id: multipleRoots ? `SRCROOT_${index + 1}` : "SRCROOT",
      uri: folder.uri.toString(),
      pathPrefix: multipleRoots ? `${folder.name}/` : "",
      description: `TraceGuard workspace folder ${folder.name}.`,
    }));
    return buildSarif(this.session.snapshot, { sourceRoots });
  }

  async exportReviewSession() {
    const folder = vscode.workspace.workspaceFolders?.[0];
    if (!folder) {
      vscode.window.showInformationMessage("Open a workspace before exporting a review session.");
      return;
    }
    const target = await vscode.window.showSaveDialog({
      defaultUri: vscode.Uri.joinPath(folder.uri, "traceguard-review-session.json"),
      filters: { "TraceGuard review session": ["json"] },
      saveLabel: "Export Review Session",
      title: "Export review state and saved code-note snippets",
    });
    if (!target) return;
    const payload = this.session.exportPortableState();
    await vscode.workspace.fs.writeFile(target, Buffer.from(`${JSON.stringify(payload, null, 2)}\n`, "utf8"));
    vscode.window.showInformationMessage(`Review session exported with ${Object.keys(payload.statuses).length} target states, ${Object.keys(payload.findingStatuses || {}).length} finding states and ${payload.evidence.length} notes.`);
  }

  async importReviewSession() {
    const selected = await vscode.window.showOpenDialog({
      canSelectMany: false,
      canSelectFiles: true,
      canSelectFolders: false,
      filters: { "TraceGuard review session": ["json"] },
      openLabel: "Import and Merge Review Session",
      title: "Import review states and notes into this workspace",
    });
    if (!selected?.[0]) return;
    try {
      const bytes = await vscode.workspace.fs.readFile(selected[0]);
      if (bytes.byteLength > 10 * 1024 * 1024) throw new Error("Review-session files must be 10 MB or smaller.");
      const payload = JSON.parse(Buffer.from(bytes).toString("utf8"));
      const imported = await this.session.importPortableState(payload);
      vscode.window.showInformationMessage(`Merged ${imported.statuses} target states, ${imported.findingStatuses} finding states and ${imported.evidence} audit notes.`);
    } catch (error) {
      vscode.window.showErrorMessage(`TraceGuard could not import the review session: ${error.message}`);
    }
  }

  _onSaved(document) {
    if (isProjectConfigurationUri(document.uri) && vscode.workspace.isTrusted) {
      void this._runBackground("Project configuration reload", () => this._reloadProjectConfiguration());
      return;
    }
    if (isProjectIdentityUri(document.uri) && vscode.workspace.isTrusted) {
      void this._runBackground("Project identity reload", () => this._reloadProjectIdentity());
      return;
    }
    if (!languageForPath(document.uri.fsPath) || !vscode.workspace.isTrusted) return;
    const key = document.uri.toString();
    clearTimeout(this.documentTimers.get(key));
    this.documentTimers.delete(key);
    void this._runBackground("Saved-document indexing", async () => {
      await this.session.reindexDocument(document);
      this._updateDecorations(vscode.window.activeTextEditor);
      this._updateTraceDecorations(vscode.window.activeTextEditor);
    });
  }

  _onChanged(document) {
    if (!languageForPath(document.uri.fsPath) || !vscode.workspace.isTrusted) return;
    if (this.session.indexing) {
      void this._runBackground("Dirty-document replay", () => this.session.reindexDocument(document));
      return;
    }
    if (!vscode.workspace.getConfiguration("traceguard", document.uri).get("liveIndex", false)) return;
    const key = document.uri.toString();
    clearTimeout(this.documentTimers.get(key));
    this.documentTimers.set(key, setTimeout(() => {
      this.documentTimers.delete(key);
      void this._runBackground("Live document indexing", async () => {
        await this.session.reindexDocument(document);
        if (vscode.window.activeTextEditor?.document === document) {
          this._updateDecorations(vscode.window.activeTextEditor);
          this._updateTraceDecorations(vscode.window.activeTextEditor);
        }
      });
    }, 850));
  }

  async _onFilesCreated(files) {
    if (!vscode.workspace.isTrusted) return;
    if (files.some(isProjectConfigurationUri)) await this._reloadProjectConfiguration();
    if (files.some(isProjectIdentityUri)) await this._reloadProjectIdentity();
    for (const uri of files) await this.session.reindexFile(uri);
  }

  async _onFilesDeleted(files) {
    if (!vscode.workspace.isTrusted) return;
    await this.session.removeFiles(files);
    if (files.some(isProjectConfigurationUri)) await this._reloadProjectConfiguration();
    if (files.some(isProjectIdentityUri)) await this._reloadProjectIdentity();
  }

  async _onFilesRenamed(files) {
    if (!vscode.workspace.isTrusted) return;
    await this.session.migrateEvidencePaths(files);
    await this.session.removeFiles(files.map(item => item.oldUri));
    for (const item of files) await this.session.reindexFile(item.newUri);
    if (files.some(item => isProjectConfigurationUri(item.oldUri) || isProjectConfigurationUri(item.newUri))) await this._reloadProjectConfiguration();
    if (files.some(item => isProjectIdentityUri(item.oldUri) || isProjectIdentityUri(item.newUri))) await this._reloadProjectIdentity();
  }

  async _reloadProjectConfiguration() {
    const result = await this.session.reloadProjectConfiguration({ rebuild: !this.session.workspaceIndexBuilt });
    if (result.changed && this.session.workspaceIndexBuilt) await this.refresh(false);
  }

  async _reloadProjectIdentity() {
    const result = await this.session.reloadProjectIdentities();
    if (result.changed && this.session.workspaceIndexBuilt) await this.refresh(false);
  }

  _runBackground(label, operation) {
    return Promise.resolve()
      .then(operation)
      .catch(error => {
        this.output.error(`${label} failed:\n${String(error?.stack || error?.message || error)}`);
      });
  }

  _onSessionChanged() {
    this._updateStatus();
    this._updateDecorations(vscode.window.activeTextEditor);
    this._updateTraceDecorations(vscode.window.activeTextEditor);
    this._updateDiagnostics();
    this._updateConfigurationDiagnostics();
    vscode.commands.executeCommand("setContext", "traceguard.hasAuditTargets", this.session.snapshot.items.length > 0);
    vscode.commands.executeCommand("setContext", "traceguard.hasAuditQuery", Boolean(this.lastAuditQuery));
  }

  _updateStatus() {
    const data = this.session.snapshot;
    if (!vscode.workspace.isTrusted) {
      this.status.text = "$(lock) TraceGuard";
      this.status.tooltip = new vscode.MarkdownString("Trust the workspace to build a local audit map.");
      return;
    }
    if (!data.indexed_at) {
      this.status.text = "$(references) TraceGuard · Start review";
      this.status.tooltip = new vscode.MarkdownString("Open the TraceGuard sidebar and choose **Build Review Queue** to index this workspace.");
      return;
    }
    const verifiedFindings = data.findings.filter(finding => findingPool(finding) === "verified");
    const reviewCandidates = data.findings.filter(finding => findingPool(finding) === "review");
    const blocking = verifiedFindings.filter(finding => finding.severity === "critical" || finding.severity === "high").length;
    const minor = verifiedFindings.length - blocking;
    const manual = data.manualReviewCoverage || { reviewed: data.statusCounts.reviewed, total: data.items.length };
    const parts = [`$(references) ${manual.reviewed}/${manual.total}`];
    if (blocking) parts.push(`$(error)${blocking}`);
    if (minor) parts.push(`$(warning)${minor}`);
    if (reviewCandidates.length) parts.push(`$(question)${reviewCandidates.length}`);
    parts.push(data.statusCounts.unreviewed ? `${data.statusCounts.unreviewed} left` : "$(check)");
    if (data.indexIncomplete) parts.push("partial");
    this.status.text = parts.join(" · ");
    const tooltip = new vscode.MarkdownString();
    tooltip.isTrusted = true;
    tooltip.appendMarkdown(`### $(references) TraceGuard review\n\n`);
    tooltip.appendMarkdown(`- Manual review coverage: **${manual.reviewed} / ${manual.total}**\n`);
    tooltip.appendMarkdown(`- Analysis coverage: **${data.analysisCoverage?.indexed || data.files || 0} / ${data.analysisCoverage?.discovered || data.files || 0} files**${data.indexIncomplete ? " _(partial)_" : ""}\n`);
    tooltip.appendMarkdown(`- Entry points: **${data.entries.length}** · Review targets: **${data.items.length}**\n`);
    tooltip.appendMarkdown(`- Verified flows: **${verifiedFindings.length}**${blocking ? ` · $(error) ${blocking} critical/high impact` : ""}${minor ? ` · $(warning) ${minor} medium/low impact` : ""}\n`);
    tooltip.appendMarkdown(`- Review hypotheses: **${reviewCandidates.length}** _(not in Problems)_\n`);
    tooltip.appendMarkdown(`- Audit notes: **${data.evidence.length}**\n\n`);
    if (data.findingPathsTruncated) tooltip.appendMarkdown("_Showing the prioritized subset of candidate paths._\n\n");
    tooltip.appendMarkdown("[Open the TraceGuard sidebar](command:traceguard.openAuditView)");
    this.status.tooltip = tooltip;
  }

  _updateDecorations(editor) {
    if (!editor || !languageForPath(editor.document.uri.fsPath)) return;
    const enabled = vscode.workspace.getConfiguration("traceguard", editor.document.uri).get("showAuditSignals", false);
    const hoverIcons = { source: "$(arrow-right)", sink: "$(target)", auth: "$(lock)", sanitizer: "$(verified)" };
    for (const [kind, decoration] of Object.entries(this.decorations)) {
      const ranges = enabled ? (this.session.analysisForUri(editor.document.uri)?.signals || [])
        .filter(signal => signal.kind === kind && signal.line > 0 && signal.line <= editor.document.lineCount)
        .map(signal => {
          const hover = new vscode.MarkdownString();
          hover.appendMarkdown(`${hoverIcons[kind] || "$(eye)"} **TraceGuard ${kind}** — ${signal.label}\n\n`);
          hover.appendMarkdown("$(info) Audit clue, not a confirmed vulnerability.");
          return { range: editor.document.lineAt(Math.max(0, signal.line - 1)).range, hoverMessage: hover };
        }) : [];
      editor.setDecorations(decoration, ranges);
    }
  }

  _updateTraceDecorations(editor) {
    if (!editor || !languageForPath(editor.document.uri.fsPath)) return;
    const flowPath = this.queryProvider.currentTrace;
    const groups = { source: [], flow: [], sink: [] };
    if (flowPath?.steps?.length) {
      const target = normalizePath(editor.document.uri.fsPath);
      const seen = new Set();
      flowPath.steps.forEach((step, index) => {
        if (!step.absolutePath || normalizePath(step.absolutePath) !== target || !step.line) return;
        const range = traceStepRange(editor.document, step);
        const kind = step.kind === "source" ? "source" : step.kind === "sink" ? "sink" : "flow";
        const key = `${kind}:${range.start.line}:${range.start.character}:${range.end.character}`;
        if (seen.has(key)) return;
        seen.add(key);
        groups[kind].push({ range, hoverMessage: tracePathHover(flowPath, index) });
      });
    }
    for (const [kind, decoration] of Object.entries(this.tracePathDecorations)) {
      editor.setDecorations(decoration, groups[kind]);
    }
    if (flowPath) this.tracedEditor = editor;
  }

  _updateDiagnostics() {
    const byUri = new Map();
    for (const finding of this.session.snapshot.findings) {
      if (findingPool(finding) !== "verified" || !finding.absolutePath) continue;
      const uri = vscode.Uri.file(finding.absolutePath);
      const key = uri.toString();
      const line = Math.max(0, Number(finding.line || 1) - 1);
      const diagnostic = new vscode.Diagnostic(
        new vscode.Range(line, 0, line, 1),
        `Verified Flow · ${finding.title} · ${finding.confidence} connection · ${finding.sourceKind} → ${finding.sinkKind}; human review required`,
        diagnosticSeverity(finding.severity, finding.confidence),
      );
      diagnostic.source = "TraceGuard";
      diagnostic.code = finding.ruleId || finding.cwe;
      const sourceStep = (finding.path?.steps || []).find(step => step.kind === "source" && step.absolutePath && step.line);
      if (sourceStep) {
        diagnostic.relatedInformation = [new vscode.DiagnosticRelatedInformation(
          new vscode.Location(vscode.Uri.file(sourceStep.absolutePath), new vscode.Position(Math.max(0, sourceStep.line - 1), 0)),
          `Source: ${sourceStep.label}`,
        )];
      }
      if (!byUri.has(key)) byUri.set(key, { uri, diagnostics: [] });
      byUri.get(key).diagnostics.push(diagnostic);
    }
    this.problemDiagnostics.clear();
    this.problemDiagnostics.set([...byUri.values()].map(item => [item.uri, item.diagnostics]));
  }

  _updateConfigurationDiagnostics() {
    const byUri = new Map();
    for (const issue of [...(this.session.projectConfigurationIssues || []), ...(this.session.projectIdentityIssues || [])]) {
      if (!issue.source) continue;
      const uri = vscode.Uri.file(issue.source);
      const key = uri.toString();
      const line = Math.max(0, Number(issue.line || 1) - 1);
      const column = Math.max(0, Number(issue.column || 1) - 1);
      const diagnostic = new vscode.Diagnostic(
        new vscode.Range(line, column, line, column + 1),
        `${issue.path}: ${issue.message}`,
        issue.severity === "warning" ? vscode.DiagnosticSeverity.Warning : vscode.DiagnosticSeverity.Error,
      );
      diagnostic.source = "TraceGuard Configuration";
      diagnostic.code = "traceguard-project-config";
      if (!byUri.has(key)) byUri.set(key, { uri, diagnostics: [] });
      byUri.get(key).diagnostics.push(diagnostic);
    }
    this.configurationDiagnostics.clear();
    this.configurationDiagnostics.set([...byUri.values()].map(item => [item.uri, item.diagnostics]));
  }

  dispose() {
    this.subscription?.dispose();
    for (const timer of this.documentTimers.values()) clearTimeout(timer);
  }
}

function statusLabel(status) { return { unreviewed: "Not reviewed", in_review: "In review", reviewed: "Reviewed", blocked: "Needs context" }[status] || "Not reviewed"; }
function interactiveIdentity(callContext, functionName) {
  const selected = selectedCallName(functionName);
  if (!selected || selected.split(".").at(-1) !== String(callContext.functionName || "").split(".").at(-1)) {
    return { certainty: "review" };
  }
  return {
    receiverType: callContext.receiverType,
    qualifiedName: callContext.qualifiedName,
    symbol: callContext.symbol,
    certainty: callContext.certainty || "review",
  };
}
function priorityIcon(priority) { return { P0: "flame", P1: "warning", P2: "eye" }[priority] || "circle-outline"; }
function signalIcon(kind) { return { source: "arrow-right", sink: "target", auth: "key", sanitizer: "verified" }[kind] || "circle-outline"; }
function findingSeverityIcon(severity) { return { critical: "error", high: "warning", medium: "info", low: "circle-outline" }[severity] || "warning"; }

function diagnosticSeverity(severity, confidence = "high") {
  if (["low", "review"].includes(confidence)) return vscode.DiagnosticSeverity.Information;
  if (confidence === "medium" && (severity === "critical" || severity === "high")) return vscode.DiagnosticSeverity.Warning;
  if (severity === "critical" || severity === "high") return vscode.DiagnosticSeverity.Error;
  if (severity === "medium") return vscode.DiagnosticSeverity.Warning;
  return vscode.DiagnosticSeverity.Information;
}

function firstLine(value) {
  return String(value || "Unknown indexing error").split(/\r?\n/)[0].slice(0, 280);
}

function isProjectConfigurationUri(uri) {
  return path.basename(uri?.fsPath || "").toLowerCase() === ".traceguard.json";
}

function isProjectIdentityUri(uri) {
  return path.basename(uri?.fsPath || "").toLowerCase() === "composer.json";
}

function isFileNotFoundError(error) {
  return error?.code === "FileNotFound" || /(?:file not found|enoent|does not exist)/i.test(String(error?.message || ""));
}

function selectedAccessPath(editor) {
  const selected = editor.document.getText(editor.selection).trim();
  const accessPath = /^\$?[A-Za-z_][\w$]*(?:(?:\?\.|\.)[A-Za-z_$][\w$]*|\[(?:\d+|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')\])*$/;
  if (accessPath.test(selected)) return normalizeAccessPath(selected, { dynamic: false });
  const range = editor.document.getWordRangeAtPosition(
    editor.selection.active,
    /\$?[A-Za-z_][\w$]*(?:(?:\?\.|\.)[A-Za-z_$][\w$]*|\[(?:\d+|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')\])*/,
  );
  return range ? normalizeAccessPath(editor.document.getText(range), { dynamic: false }) : "";
}

function flowPathSummary(flowPath) {
  const functions = [];
  for (const step of flowPath.steps) {
    if (!functions.includes(step.functionName)) functions.push(step.functionName);
  }
  return `${functions.map(name => `${name}()`).join(" → ")} · ${flowPath.category}`;
}

function uniqueFindingPaths(finding) {
  const seen = new Set();
  return [...(finding?.paths || []), finding?.path].filter(Boolean).filter(flowPath => {
    const key = flowPath.id || (flowPath.steps || []).map(step => `${step.functionId}:${step.operationId}:${step.kind}`).join("|");
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function flowReviewLabel(flowPath) {
  const validation = flowPath.controls?.validation || 0;
  const authorization = flowPath.controls?.authorization || 0;
  if (!validation && !authorization) return "No control seen";
  if (validation && authorization) return `${validation} validation · ${authorization} authorization`;
  if (validation) return `${validation} validation`;
  return `${authorization} authorization`;
}

function flowConfidenceLabel(confidence) {
  return { high: "High match", medium: "Medium match", review: "Check call target" }[confidence] || "Check match";
}

function createDecorations() {
  return {
    source: vscode.window.createTextEditorDecorationType({ isWholeLine: true, overviewRulerColor: new vscode.ThemeColor("editorInfo.foreground"), overviewRulerLane: vscode.OverviewRulerLane.Right, after: { contentText: "  ◀ input", color: new vscode.ThemeColor("editorInfo.foreground"), fontStyle: "italic" } }),
    sink: vscode.window.createTextEditorDecorationType({ isWholeLine: true, overviewRulerColor: new vscode.ThemeColor("editorError.foreground"), overviewRulerLane: vscode.OverviewRulerLane.Right, after: { contentText: "  ◀ sink", color: new vscode.ThemeColor("editorError.foreground"), fontStyle: "italic" } }),
    auth: vscode.window.createTextEditorDecorationType({ isWholeLine: true, overviewRulerColor: new vscode.ThemeColor("testing.iconPassed"), overviewRulerLane: vscode.OverviewRulerLane.Right, after: { contentText: "  ◀ authz", color: new vscode.ThemeColor("testing.iconPassed"), fontStyle: "italic" } }),
    sanitizer: vscode.window.createTextEditorDecorationType({ isWholeLine: true, overviewRulerColor: new vscode.ThemeColor("charts.green"), overviewRulerLane: vscode.OverviewRulerLane.Right, after: { contentText: "  ◀ sanitized", color: new vscode.ThemeColor("charts.green"), fontStyle: "italic" } }),
  };
}

function createTracePathDecorations() {
  return {
    source: vscode.window.createTextEditorDecorationType({
      backgroundColor: new vscode.ThemeColor("editor.wordHighlightBackground"),
      borderColor: new vscode.ThemeColor("editorInfo.foreground"),
      borderStyle: "solid",
      borderWidth: "0 0 1px 0",
      after: { contentText: "  ◀ entry", color: new vscode.ThemeColor("editorInfo.foreground"), fontStyle: "italic" },
    }),
    flow: vscode.window.createTextEditorDecorationType({
      backgroundColor: new vscode.ThemeColor("editor.wordHighlightStrongBackground"),
      borderColor: new vscode.ThemeColor("editorWarning.foreground"),
      borderStyle: "dotted",
      borderWidth: "0 0 1px 0",
      after: { contentText: "  ◀ flow", color: new vscode.ThemeColor("editorWarning.foreground"), fontStyle: "italic" },
    }),
    sink: vscode.window.createTextEditorDecorationType({
      backgroundColor: new vscode.ThemeColor("editor.findMatchHighlightBackground"),
      borderColor: new vscode.ThemeColor("editorError.foreground"),
      borderStyle: "solid",
      borderWidth: "0 0 2px 0",
      after: { contentText: "  ◀ dangerous", color: new vscode.ThemeColor("editorError.foreground"), fontStyle: "italic" },
    }),
  };
}

function traceStepRange(document, step) {
  const lineIndex = Math.max(0, Math.min(document.lineCount - 1, Number(step?.line || 1) - 1));
  const line = document.lineAt(lineIndex);
  const candidates = [
    step?.outputAccessPath,
    step?.inputAccessPath,
    ...(step?.accessPaths || []),
  ].map(value => String(value || "").trim()).filter(Boolean);
  for (const candidate of candidates) {
    const variants = [candidate, candidate.replace(/^\$/, "")];
    for (const variant of variants) {
      const index = line.text.indexOf(variant);
      if (index >= 0) return new vscode.Range(lineIndex, index, lineIndex, index + variant.length);
    }
    const leaf = candidate.match(/[A-Za-z_$][\w$]*$/)?.[0];
    if (leaf) {
      const match = new RegExp(`\\b${escapeRegExp(leaf)}\\b`).exec(line.text);
      if (match) return new vscode.Range(lineIndex, match.index, lineIndex, match.index + match[0].length);
    }
  }
  const first = line.firstNonWhitespaceCharacterIndex;
  return new vscode.Range(lineIndex, first, lineIndex, Math.max(first, line.range.end.character));
}

function tracePathHover(flowPath, activeIndex) {
  const steps = flowPath?.steps || [];
  const source = steps.find(step => step.kind === "source") || flowPath?.source;
  const sink = [...steps].reverse().find(step => step.kind === "sink") || flowPath?.sink;
  const middle = steps.filter(step => !["source", "sink"].includes(step.kind));
  const middleLabels = middle.slice(0, 3).map(traceStepSubject);
  const chain = [
    `[入口: ${traceStepSubject(source)}]`,
    ...(middleLabels.length ? [`[流向: ${middleLabels.join(" → ")}${middle.length > middleLabels.length ? " → …" : ""}]`] : []),
    `[危险: ${traceStepSubject(sink)}]`,
  ].join(" → ");
  const active = steps[activeIndex];
  const markdown = new vscode.MarkdownString();
  markdown.appendMarkdown(`### $(debug-stackframe) TraceGuard taint path · ${Math.max(1, activeIndex + 1)}/${steps.length}\n\n`);
  markdown.appendText(chain);
  if (active) {
    markdown.appendMarkdown("\n\n---\n\n");
    markdown.appendMarkdown(`**${String(active.kind || "flow").toUpperCase()}** · `);
    markdown.appendText(active.label || "Analysis step");
    if (active.code) markdown.appendCodeblock(active.code);
  }
  return markdown;
}

function traceStepSubject(step) {
  return String(step?.outputAccessPath || step?.inputAccessPath || step?.accessPaths?.[0] || step?.label || "unknown");
}

function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

async function openLocation(absolutePath, line, endLine) {
  const document = await vscode.workspace.openTextDocument(vscode.Uri.file(absolutePath));
  const editor = await vscode.window.showTextDocument(document, { preview: true, preserveFocus: false });
  const start = new vscode.Position(Math.max(0, line - 1), 0);
  const end = new vscode.Position(Math.min(document.lineCount - 1, Math.max(line - 1, (endLine || line) - 1)), 0);
  editor.selection = new vscode.Selection(start, start);
  editor.revealRange(new vscode.Range(start, end), vscode.TextEditorRevealType.InCenterIfOutsideViewport);
  return editor;
}

function buildReport(audit) {
  const lines = [
    "# TraceGuard Code Audit Report", "",
    `Generated: ${new Date().toISOString()}`, "",
    "## Manual review coverage", "",
    `- Manual review coverage: **${audit.statusCounts.reviewed} / ${audit.items.length}** targets`,
    `- Indexed: ${audit.files} files, ${audit.functions} functions, ${audit.lines} lines${audit.indexIncomplete ? ` (**partial index**${audit.indexScope === "current-files" ? "; workspace-wide indexing has not run" : ""}${audit.indexSkippedFiles ? `; ${audit.indexSkippedFiles} files skipped` : ""})` : ""}`,
    `- Attack surface: ${audit.entries.length} entry points`,
    `- Data-flow review items: ${audit.findings.length}${audit.findingPathsTruncated ? ` (prioritized subset of at least ${audit.findingPathCandidates} candidate paths)` : ""}`,
    `- Evidence records: ${audit.evidence.length}`, "",
    "## Parser and index coverage", "",
    ...Object.entries(audit.languageCapabilities || {}).map(([language, capability]) =>
      `- ${language}: ${capability.astFiles}/${capability.files} files parsed with AST${capability.degradedFiles ? `; ${capability.degradedFiles} degraded` : ""}`,
    ),
    ...(audit.indexSkippedDetails?.length ? ["", "Skipped files:", ...audit.indexSkippedDetails.map(item => `- \`${item.relativePath}\` — ${item.reason}`)] : []), "",
    "## Attack surface", "",
    ...audit.entries.map(entry => `- \`${entry.title}\` — ${entry.relativePath}:${entry.line}`), "",
    "## Verified flows and review hypotheses", "",
    ...audit.findings.flatMap(finding => [
      `### ${finding.title} (${finding.cwe})`, "",
      `- Severity/confidence: **${finding.severity.toUpperCase()} / ${finding.confidence}**`,
      `- Status: **${finding.status || "open"}**`,
      `- Sink: \`${finding.relativePath}:${finding.line}\``,
      `- Observed guards: ${(finding.observedGuards || []).join(", ") || "none"}`,
      `- Missing guards: ${(finding.missingGuards || []).join(", ") || "none"}`,
      `- Confidence reason: ${finding.explanation?.confidenceReason || "Direct local flow or resolved calls"}`, "",
      "Source → Sink path:",
      ...(finding.path?.steps || []).map((step, index) => `${index + 1}. **${step.kind}** · ${step.label} — \`${step.relativePath}:${step.line}\``),
      "",
    ]),
    "## Review targets", "",
  ];
  for (const item of audit.items) {
    lines.push(`### ${item.priority} · ${item.title}`, "", `- Location: \`${item.relativePath}:${item.line}\``, `- Status: **${item.status}**`, `- Review reasons: ${item.reasons.join("; ")}`, "", "Checklist:", ...item.checklist.map(check => `- [${check.state === "observed" ? "x" : " "}] ${check.label} — ${check.evidence}`), "");
  }
  lines.push("## Evidence notebook", "");
  for (const evidence of audit.evidence) {
    const fence = markdownFence(evidence.code);
    lines.push(`### ${evidence.type} · ${evidence.relativePath}:${evidence.line}`, "", evidence.note || "No note", "", fence, evidence.code, fence, "");
  }
  lines.push("---", "TraceGuard audit signals are reviewer aids, not proof that code is secure or vulnerable.", "");
  return lines.join("\n");
}

module.exports = { AuditController, buildReport, createDecorations, createTracePathDecorations, selectedAccessPath, traceStepRange };
