const { registerAuditCommands } = require("./ui/commands");
const { updateDiagnostics, updateConfigurationDiagnostics } = require("./ui/diagnostics");
const { buildReport } = require("./ui/report");
const { selectedAccessPath, openLocation } = require("./ui/navigation");
const { createDecorations, createTracePathDecorations, createTraceLineDecorations, traceStepRange, queryNodeHover, tracePathHover } = require("./ui/decorations");
const { ScopeViewProvider } = require("./ui/webview/scope-view-provider");
const { TraceInspectorPanel } = require("./ui/webview/trace-inspector-panel");
const path = require("path");
const vscode = require("vscode");
const { affectsAnalysisModel } = require("./analysis/configuration");
const { WorkspaceFileMonitor } = require("./analysis/workspace-file-monitor");
const { isRelevantDiskChange, synchronizeWorkspaceChanges } = require("./analysis/workspace-file-sync");
const { AttackSurfaceProvider, AuditCodeLensProvider, AuditHoverProvider, AuditQueryProvider, CodeTreeProvider, EvidenceProvider } = require("./audit-providers");
const { buildInteractiveModel, callDetailsAtPosition, callNameAtPosition, mergeInteractiveModel, selectedCallName } = require("./config/interactive-model");
const { AuditSession, workspaceRelativePath } = require("./audit-session");
const { SUPPORTED_LABEL, SUPPORTED_SELECTORS, languageForPath } = require("./language-support");
const { QueryKind } = require("./query/audit-query-engine");
const { buildSliceContext, formatSliceMarkdown } = require("./query/slice-context");
const { AiController } = require("./ai/controller");
const { buildSarif } = require("./sarif");
const { normalizePath } = require("./identity");
const { findingPool } = require("./review/finding-pool");
const { createEvidenceAnchor, resolveEvidenceLocation } = require("./review/evidence-anchor");

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
  { label: "$(search) LDAP filter", description: "Directory search filter text", kind: "LDAP_QUERY" },
  { label: "$(file-code) Template source", description: "Server-side template source code", kind: "TEMPLATE_RENDER" },
  { label: "$(shield) Sensitive operation", description: "Project-specific security-sensitive effect", kind: "SENSITIVE_OPERATION" },
];

const INTERACTIVE_SANITIZER_CAPABILITIES = [
  { label: "$(terminal) Shell argument escaping", description: "Protects command arguments", kind: "SHELL_ESCAPE" },
  { label: "$(database) SQL parameterization", description: "Binds data separately from SQL text", kind: "SQL_PARAMETERIZATION" },
  { label: "$(search) LDAP filter escaping", description: "Escapes LDAP search filter values", kind: "LDAP_FILTER_ESCAPE" },
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
    const isActive = () => vscode.workspace.isTrusted && (this.session.workspaceIndexBuilt || this.session.indexing || this.session.analyses.length > 0);
    this.fileMonitor = new WorkspaceFileMonitor(vscode.workspace, {
      isActive,
      isRelevant: (uri, kind) => isActive() && isRelevantDiskChange(vscode.workspace, this.session, uri, kind),
      onBatch: batch => synchronizeWorkspaceChanges(vscode.workspace, this.session, batch),
      onPending: pending => this.session.setFilesystemSyncPending(pending),
      onError: error => this.output.error(`Filesystem synchronization failed: ${firstLine(error?.message || error)}`),
    });
    this.codeProvider = new CodeTreeProvider(this.session);
    this.queryProvider = new AuditQueryProvider(context.workspaceState.get("traceguard.traceReviewKeys", []));
    this.traceHighlightsEnabled = true;
    this.summaryProvider = new AttackSurfaceProvider(this.session);
    this.scopeViewProvider = new ScopeViewProvider(this);
    this.evidenceProvider = new EvidenceProvider(this.session);
    this.codeLensProvider = new AuditCodeLensProvider(this.session);
    this.traceInspector = new TraceInspectorPanel(context, this);
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
    this.traceLineDecorations = createTraceLineDecorations();
    this.traceDecoration = vscode.window.createTextEditorDecorationType({
      backgroundColor: new vscode.ThemeColor("editor.wordHighlightBackground"),
      borderColor: new vscode.ThemeColor("editor.findMatchBorder"),
      borderStyle: "dotted",
      borderWidth: "0 0 1px 0",
    });
    this._register();
    this.ai = new AiController(context, this);
    this.traceInspector.bindAiEvents(this.ai);
    this.subscription = this.session.onDidChange(() => this._onSessionChanged());
  }

  _register() {
    this.codeTreeView = vscode.window.createTreeView("traceguard.code", {
      treeDataProvider: this.codeProvider,
      showCollapseAll: true,
    });
    this.queryTreeView = vscode.window.createTreeView("traceguard.auditQueries", {
      treeDataProvider: this.queryProvider,
      showCollapseAll: true,
    });
    this.evidenceTreeView = vscode.window.createTreeView("traceguard.evidence", {
      treeDataProvider: this.evidenceProvider,
      showCollapseAll: true,
    });
    this.context.subscriptions.push(
      this.session,
      this.fileMonitor,
      this.codeProvider,
      this.queryProvider,
      this.summaryProvider,
      this.scopeViewProvider,
      this.evidenceProvider,
      this.codeLensProvider,
      this.traceInspector,
      this.codeTreeView,
      this.queryTreeView,
      this.evidenceTreeView,
      this.status,
      this.problemDiagnostics,
      this.configurationDiagnostics,
      ...Object.values(this.decorations),
      ...Object.values(this.tracePathDecorations),
      ...Object.values(this.traceLineDecorations),
      this.traceDecoration,
      vscode.window.registerWebviewViewProvider("traceguard.summary", this.scopeViewProvider, {
        webviewOptions: { retainContextWhenHidden: true },
      }),
      vscode.languages.registerCodeLensProvider(SUPPORTED_SELECTORS, this.codeLensProvider),
      vscode.languages.registerHoverProvider(SUPPORTED_SELECTORS, new AuditHoverProvider(this.session)),
      ...registerAuditCommands(this),

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
      vscode.window.onDidChangeVisibleTextEditors(editors => {
        for (const editor of editors) this._updateTraceDecorations(editor);
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
    const queryLine = editor.selection.active.line;
    if ((kind === QueryKind.TRACE_BACKWARD || kind === QueryKind.TRACE_FORWARD) && !identifier) {
      vscode.window.showInformationMessage("Select a variable or property path, or place the cursor on one before tracing it.");
      return undefined;
    }
    await this.session.reindexDocument(editor.document);
    this.lastAuditRequest = { uri: editor.document.uri, line: queryLine, kind, identifier };
    const result = await vscode.window.withProgress({
      location: vscode.ProgressLocation.Window,
      title: "TraceGuard is querying the analysis graph",
      cancellable: false,
    }, () => this.session.queryAudit(editor.document.uri, queryLine, kind, identifier));
    if (result.coverage?.incomplete && result.coverage.workspaceGraph) {
      void vscode.window.showWarningMessage("TraceGuard queried a partial workspace index. Missing callers, entries or sinks may exist in files that have not been indexed.");
    }
    this.lastAuditQuery = result;
    this.queryProvider.setResult(result);
    this.traceInspector.setContext({ finding: null, pathIndex: 0 });
    this.clearSymbolTrace();
    this.traceHighlightsEnabled = true;
    this._updateTraceDecorations(editor);
    await vscode.commands.executeCommand("setContext", "traceguard.hasAuditQuery", true);
    await vscode.commands.executeCommand("setContext", "traceguard.hasTracePath", false);
    await this.openAuditView();
    await vscode.commands.executeCommand("traceguard.auditQueries.focus");
    await this.traceInspector.show({ finding: null, preserveFocus: true });
    if (result.truncated) {
      vscode.window.showWarningMessage(`The audit query reached its ${result.summary?.nodes || "configured"}-step limit. Narrow the subject or raise TraceGuard: Query Max Nodes.`);
    }
    return result;
  }

  applyQueueFilter(filter) {
    this.codeProvider.setFilter(filter);
    this._updateTreeViewChrome();
    this.scopeViewProvider?.pushState();
  }

  applyQueueSearch(query) {
    this.codeProvider.setSearchQuery(query);
    this._updateTreeViewChrome();
  }

  async filterReviewQueue() {
    const options = [
      { id: "priority", label: "$(list-ordered) P0 / P1 first", description: "All targets, ordered by audit value" },
      { id: "verified", label: "$(verified-filled) Verified flows", description: "Entry targets and verified Source → Sink flows" },
      { id: "hypothesis", label: "$(question) Review hypotheses", description: "Targets with unresolved calls or review hypotheses" },
      { id: "unreviewed", label: "$(circle-outline) Unreviewed" },
      { id: "needs_review", label: "$(refresh) Changed since review", description: "Code, dependencies or analysis models changed" },
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
    this.applyQueueFilter({ id: selected.id, label: selected.label.replace(/^\$\([^)]*\)\s*/, "") });
  }

  async copyAuditQueryMarkdown() {
    const chain = this.queryProvider.current || this.queryProvider.currentTrace;
    if (!chain) {
      vscode.window.showInformationMessage("Run an audit query before copying its path.");
      return;
    }
    const slice = await this.buildCurrentSlice(chain);
    await vscode.env.clipboard.writeText(formatSliceMarkdown(slice));
    vscode.window.setStatusBarMessage("$(copy) TraceGuard analysis path copied as Markdown", 2500);
  }

  async buildCurrentSlice(chain = this.queryProvider.current || this.queryProvider.currentTrace, signal) {
    if (!chain) throw new Error("Run a trace before building a slice.");
    return buildSliceContext(chain, {
      signal,
      isReviewed: node => this.queryProvider.isReviewed(node),
      languageAssets: this.session._flowOptions().languageAssets,
      readSource: async absolutePath => {
        const document = await vscode.workspace.openTextDocument(vscode.Uri.file(absolutePath));
        return { text: document.getText(), language: languageForPath(absolutePath) };
      },
    });
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
    this.traceInspector.setContext({ finding: null, pathIndex: 0 });
    this.clearSymbolTrace();
    void vscode.commands.executeCommand("setContext", "traceguard.hasAuditQuery", false);
    void vscode.commands.executeCommand("setContext", "traceguard.hasTracePath", false);
    void vscode.commands.executeCommand("setContext", "traceguard.hasTraceHighlights", false);
    if (this.traceInspector.isOpen) void this.traceInspector.refresh();
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
    let selectedIndex = 0;
    if (paths.length > 1) {
      const picked = await vscode.window.showQuickPick(paths.map((flowPath, index) => ({
        label: `$(git-compare) Path ${index + 1}`,
        description: `${flowReviewLabel(flowPath)} · ${flowPath.steps?.length || 0} steps`,
        detail: flowPathSummary(flowPath),
        flowPath,
        index,
      })), { placeHolder: `Choose one of ${paths.length} candidate paths to inspect`, matchOnDetail: true });
      if (!picked) return;
      selectedIndex = picked.index;
    }
    await this.startInteractiveTrace(paths[selectedIndex], { finding, pathIndex: selectedIndex, preserveFocus: true });
  }

  async openAuditLocation(item) {
    if (!item) return;
    const record = item.finding || item;
    if (record.id && (record.paths?.length || record.path?.steps?.length)) {
      const paths = uniqueFindingPaths(record);
      if (paths.length) {
        await this.startInteractiveTrace(paths[0], { finding: record, pathIndex: 0, preserveFocus: true });
        return;
      }
    }
    if (record.absolutePath) {
      await openLocation(record.absolutePath, record.line, record.endLine || record.line);
    }
  }

  async openTraceInspector(item) {
    const finding = item?.finding || (item?.id && (item?.paths || item?.path) ? item : undefined);
    if (finding) {
      const paths = uniqueFindingPaths(finding);
      if (paths.length) {
        await this.startInteractiveTrace(paths[0], { finding, pathIndex: 0, preserveFocus: false });
        return;
      }
    }
    await this.traceInspector.show({ preserveFocus: false });
  }

  async startInteractiveTrace(flowPath, options = {}) {
    if (!flowPath?.steps?.length) return;
    this.lastAuditQuery = undefined;
    this.queryProvider.setTrace(flowPath, 0);
    this.traceHighlightsEnabled = true;
    const finding = options.finding !== undefined ? options.finding : (flowPath.finding || null);
    const pathIndex = options.pathIndex || 0;
    await vscode.commands.executeCommand("setContext", "traceguard.hasAuditQuery", false);
    await vscode.commands.executeCommand("setContext", "traceguard.hasTracePath", true);
    await this.openAuditView();
    await vscode.commands.executeCommand("traceguard.auditQueries.focus");
    await this.traceInspector.show({ finding, pathIndex, preserveFocus: true });
    await this.openCurrentTraceStep();
    if (this.traceInspector.isOpen) void this.traceInspector.refresh();
  }

  async selectTraceStep(index) {
    const step = this.queryProvider.selectTraceStep(Number(index));
    if (step) {
      await this.openCurrentTraceStep();
      if (this.traceInspector.isOpen) void this.traceInspector.refresh();
    }
  }

  async selectQueryNode(node) {
    if (!node?.location?.absolutePath || !node.location.line) return;
    this.traceHighlightsEnabled = true;
    const editor = await openLocation(node.location.absolutePath, node.location.line, node.location.line);
    this._updateTraceDecorations(editor);
    const range = traceStepRange(editor.document, node.location);
    editor.selection = new vscode.Selection(range.start, range.end);
    editor.setDecorations(this.traceDecoration, this._isQueryNodeReviewed(node) ? [] : [{ range, hoverMessage: queryNodeHover(node) }]);
    this.tracedEditor = editor;
  }

  async moveTraceStep(delta) {
    const step = this.queryProvider.moveTrace(delta);
    if (step) await this.openCurrentTraceStep();
  }

  async openCurrentTraceStep() {
    const step = this.queryProvider.currentTraceStep;
    if (!step?.absolutePath || !step.line) return;
    this.traceHighlightsEnabled = true;
    const editor = await openLocation(step.absolutePath, step.line, step.line);
    const line = Math.max(0, Math.min(editor.document.lineCount - 1, Number(step.line) - 1));
    const range = traceStepRange(editor.document, step);
    editor.selection = new vscode.Selection(range.start, range.end);
    editor.revealRange(range, vscode.TextEditorRevealType.InCenterIfOutsideViewport);
    this._updateTraceDecorations(editor);
    editor.setDecorations(this.traceDecoration, this.queryProvider.isReviewed(step) ? [] : [{
      range,
      hoverMessage: tracePathHover(this.queryProvider.currentTrace, this.queryProvider.traceCursor),
    }]);
    this.tracedEditor = editor;
    vscode.window.setStatusBarMessage(`$(debug-stackframe) Trace ${this.queryProvider.traceCursor + 1}/${this.queryProvider.currentTrace.steps.length} · ${step.kind || "flow"}`, 2200);
  }

  clearSymbolTrace() {
    for (const editor of new Set([this.tracedEditor, ...vscode.window.visibleTextEditors])) this._clearTraceEditor(editor);
    this.tracedEditor = undefined;
  }

  clearTraceHighlights() {
    this.traceHighlightsEnabled = false;
    this.clearSymbolTrace();
    void vscode.commands.executeCommand("setContext", "traceguard.hasTraceHighlights", false);
  }

  async toggleTraceReviewed(item) {
    const keys = this.queryProvider.toggleReviewed(item);
    if (!keys) return;
    await this.context.workspaceState.update("traceguard.traceReviewKeys", keys);
    this.clearSymbolTrace();
    for (const editor of vscode.window.visibleTextEditors) this._updateTraceDecorations(editor);
  }

  _isQueryNodeReviewed(target) {
    const visit = (nodes, inherited = false) => {
      for (const node of nodes || []) {
        const reviewed = inherited || this.queryProvider.isReviewed(node);
        if (node === target || this.queryProvider.review.key(node) === this.queryProvider.review.key(target)) return reviewed;
        const found = visit(node.children, reviewed);
        if (found !== undefined) return found;
      }
    };
    return visit(this.queryProvider.current?.roots) || false;
  }

  _clearTraceEditor(editor) {
    if (!editor) return;
    editor.setDecorations(this.traceDecoration, []);
    for (const decoration of Object.values(this.tracePathDecorations)) editor.setDecorations(decoration, []);
    for (const decoration of Object.values(this.traceLineDecorations)) editor.setDecorations(decoration, []);
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

  async modelInterruptedCall(item) {
    const location = item?.interruption?.location || item?.node?.location || item?.location;
    if (!location?.absolutePath || !location.line) return;
    const request = this.queryProvider.current ? this.lastAuditRequest : undefined;
    const trace = this.queryProvider.currentTrace;
    const root = trace?.steps?.[0];
    const editor = await openLocation(location.absolutePath, location.line, location.line);
    const selected = await vscode.window.showQuickPick([
      { id: "callees", label: "Inspect candidate callees", description: "Inspect available implementations before modeling" },
      { id: "propagator", label: "Model argument → return propagation", description: "Save selected argument propagation in .traceguard.json" },
      { id: "source", label: "Model an external input Source", description: "Save an input-returning API in .traceguard.json" },
      { id: "sink", label: "Model a sensitive Sink", description: "Save the API effect and affected arguments in .traceguard.json" },
    ], { title: "Continue analysis at this interruption", matchOnDescription: true });
    if (!selected) return;
    if (selected.id === "callees") return this.executeAuditQuery(QueryKind.FIND_CALLEES);
    const changed = await this.markSelectedCall(selected.id, { editor, suppressNotice: true });
    if (!changed) return;
    const rerun = request || { uri: vscode.Uri.file(root?.absolutePath || location.absolutePath),
      line: Math.max(0, (root?.line || location.line) - 1), kind: QueryKind.REACHABLE_SINKS };
    const result = await this.session.queryAudit(rerun.uri, rerun.line, rerun.kind, rerun.identifier);
    this.lastAuditRequest = rerun;
    this.lastAuditQuery = result;
    this.queryProvider.setResult(result);
    this.clearSymbolTrace();
    await vscode.commands.executeCommand("setContext", "traceguard.hasAuditQuery", true);
    await vscode.commands.executeCommand("setContext", "traceguard.hasTracePath", false);
    await vscode.commands.executeCommand("traceguard.auditQueries.focus");
    vscode.window.setStatusBarMessage("$(refresh) Model applied; trace recomputed with current proof status", 5000);
    return result;
  }

  async markSelectedCall(role, options = {}) {
    const editor = options.editor || vscode.window.activeTextEditor;
    const language = editor && languageForPath(editor.document.uri.fsPath);
    if (!editor || !language) {
      vscode.window.showInformationMessage(`Open a ${SUPPORTED_LABEL} file and place the cursor on a call first.`);
      return;
    }
    const callContext = await this._interactiveCallContext(editor);
    const inferred = callContext.functionName;
    const functionName = inferred || await vscode.window.showInputBox({
      title: `Model selected call as ${role}`,
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
    if (role === "sanitizer") {
      const picked = await vscode.window.showQuickPick(INTERACTIVE_SANITIZER_CAPABILITIES, {
        title: `What security guarantee does ${selectedCallName(functionName)} provide?`,
        placeHolder: "Choose the capability guaranteed by this function",
        matchOnDescription: true,
      });
      if (!picked) return;
      kind = picked.kind;
      argumentIndexes = await this._pickInteractiveArguments(callContext, "Sanitizer");
      if (!argumentIndexes) return;
    }
    if (role === "propagator") {
      argumentIndexes = await this._pickInteractiveArguments(callContext, "argument-to-return Propagator");
      if (!argumentIndexes) return;
    }
    const folder = vscode.workspace.getWorkspaceFolder(editor.document.uri);
    if (!folder) {
      vscode.window.showInformationMessage("Open the file inside a workspace before adding a project semantic model.");
      return;
    }
    const uri = vscode.Uri.joinPath(folder.uri, ".traceguard.json");
    if (vscode.workspace.textDocuments.some(document => document.uri.toString() === uri.toString() && document.isDirty)) {
      vscode.window.showWarningMessage("Save your unsaved .traceguard.json edits before adding a model.");
      return;
    }
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
    if (options.suppressNotice) return true;
    if (this.queryProvider.current && this.lastAuditRequest) {
      const request = this.lastAuditRequest;
      const result = await this.session.queryAudit(request.uri, request.line, request.kind, request.identifier);
      this.lastAuditQuery = result;
      this.queryProvider.setResult(result);
      this.clearSymbolTrace();
      for (const visible of vscode.window.visibleTextEditors) this._updateTraceDecorations(visible);
    }
    vscode.window.setStatusBarMessage(`$(check) ${selectedCallName(functionName)} saved as ${role} in .traceguard.json`, 4000);
    return true;
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

  async saveSemanticModelFromInspector(payload = {}) {
    const role = String(payload.role || "").toLowerCase();
    const functionName = selectedCallName(payload.functionName);
    if (!functionName) return { ok: false, message: "Enter a valid function or call name." };
    const absolutePath = String(payload.absolutePath || "");
    const language = String(payload.language || languageForPath(absolutePath) || "").toLowerCase();
    if (!language) return { ok: false, message: "Could not determine source language for this call." };
    const argumentIndexes = Array.isArray(payload.arguments) ? payload.arguments.map(Number) : [];
    const kind = payload.kind || (role === "source" ? "EXTERNAL_INPUT" : role === "sink" ? "SENSITIVE_OPERATION" : "INPUT_VALIDATION");

    let model;
    try {
      model = buildInteractiveModel({
        role,
        language,
        functionName,
        kind,
        arguments: argumentIndexes,
        certainty: "review",
      });
    } catch (error) {
      return { ok: false, message: firstLine(error?.message || error) };
    }

    const fileUri = absolutePath ? vscode.Uri.file(absolutePath) : vscode.window.activeTextEditor?.document.uri;
    const folder = (fileUri && vscode.workspace.getWorkspaceFolder(fileUri)) || vscode.workspace.workspaceFolders?.[0];
    if (!folder) return { ok: false, message: "Open a workspace folder before saving semantic models." };

    if (payload.temporary) {
      try {
        const result = await this.session.addTemporarySemanticModel(fileUri || folder.uri, role, model);
        if (!result.changed) return { ok: true, message: `${functionName} is already active as a temporary ${role}.` };
        await this._rerunCurrentQueryIfAny();
        return { ok: true, message: `Temporary ${role} applied for ${functionName}.` };
      } catch (error) {
        return { ok: false, message: firstLine(error?.message || error) };
      }
    }

    const uri = vscode.Uri.joinPath(folder.uri, ".traceguard.json");
    if (vscode.workspace.textDocuments.some(document => document.uri.toString() === uri.toString() && document.isDirty)) {
      return { ok: false, message: "Save your unsaved .traceguard.json edits before adding a model." };
    }
    let configuration = { version: 1, sources: [], sinks: [], sanitizers: [], propagators: [], rules: {}, excludePaths: [] };
    try {
      const bytes = await vscode.workspace.fs.readFile(uri);
      configuration = JSON.parse(Buffer.from(bytes).toString("utf8"));
    } catch (error) {
      if (!isFileNotFoundError(error)) return { ok: false, message: firstLine(error?.message || error) };
    }
    let update;
    try {
      update = mergeInteractiveModel(configuration, role, model);
    } catch (error) {
      return { ok: false, message: firstLine(error?.message || error) };
    }
    if (!update.changed) return { ok: true, message: `${functionName} is already configured as a ${role}.` };
    await vscode.workspace.fs.writeFile(uri, Buffer.from(`${JSON.stringify(update.configuration, null, 2)}\n`, "utf8"));
    await this.session.reloadProjectConfiguration({ rebuild: true });
    await this._rerunCurrentQueryIfAny();
    return { ok: true, message: `Saved ${functionName} (${role}) to .traceguard.json and recomputed.` };
  }

  async _rerunCurrentQueryIfAny() {
    if (this.queryProvider.current && this.lastAuditRequest) {
      const request = this.lastAuditRequest;
      const result = await this.session.queryAudit(request.uri, request.line, request.kind, request.identifier);
      this.lastAuditQuery = result;
      this.queryProvider.setResult(result);
      this.clearSymbolTrace();
      for (const visible of vscode.window.visibleTextEditors) this._updateTraceDecorations(visible);
    }
  }

  async addNoteFromInspector(payload = {}) {
    const absolutePath = String(payload.absolutePath || "");
    if (!absolutePath) return { ok: false, message: "No source file is associated with this step." };
    const line = Math.max(1, Number(payload.line) || 1);
    const type = String(payload.type || "Observation").trim() || "Observation";
    const note = String(payload.note || "").trim();
    const uri = vscode.Uri.file(absolutePath);
    let code = String(payload.code || "").trim();
    let anchor;
    try {
      const document = await vscode.workspace.openTextDocument(uri);
      const clamped = Math.min(document.lineCount, line);
      if (!code) code = document.lineAt(clamped - 1).text.trim();
      anchor = createEvidenceAnchor(document.getText(), clamped, clamped);
    } catch {
      if (!code) code = `${path.basename(absolutePath)}:${line}`;
    }
    await this.session.addEvidence({
      type,
      note,
      code,
      absolutePath,
      relativePath: payload.relativePath || workspaceRelativePath(uri),
      line,
      endLine: line,
      anchor,
    });
    return { ok: true, message: `Saved ${type} note.` };
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
    await this.session.addEvidence({ type, note, code, absolutePath: editor.document.uri.fsPath, relativePath: workspaceRelativePath(editor.document.uri), line: selection.start.line + 1, endLine: selection.end.line + 1,
      anchor: createEvidenceAnchor(editor.document.getText(), selection.start.line + 1, selection.end.line + 1) });
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

  async openEvidence(item) {
    if (!item) return;
    const current = this.session.snapshot.evidence.find(note => note.id === item.id);
    if (!current) return;
    let document;
    try { document = await vscode.workspace.openTextDocument(vscode.Uri.file(current.absolutePath)); }
    catch {
      await this.session.updateEvidenceLocation(current.id, { status: "stale" });
      vscode.window.showWarningMessage("This note's source file is unavailable. The saved evidence is still in Notes.");
      return;
    }
    const location = resolveEvidenceLocation(current, document.getText());
    await this.session.updateEvidenceLocation(current.id, location);
    if (location.status === "stale") {
      vscode.window.showWarningMessage("This evidence is stale or ambiguous: its saved code cannot be uniquely located. The original snippet is preserved in Notes.");
      return;
    }
    await openLocation(current.absolutePath, location.line, location.endLine, document);
  }
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
    if (this.session.workspaceIndexBuilt || this.session.indexing || this.session.analyses.length) {
      this.fileMonitor.enqueue("change", document.uri);
      return;
    }
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
    if (this.session.workspaceIndexBuilt || this.session.indexing || this.session.analyses.length) {
      for (const uri of files) this.fileMonitor.enqueue("create", uri);
      return;
    }
    if (files.some(isProjectConfigurationUri)) await this._reloadProjectConfiguration();
    if (files.some(isProjectIdentityUri)) await this._reloadProjectIdentity();
    for (const uri of files) await this.session.reindexFile(uri);
  }

  async _onFilesDeleted(files) {
    if (!vscode.workspace.isTrusted) return;
    if (this.session.workspaceIndexBuilt || this.session.indexing || this.session.analyses.length) {
      for (const uri of files) this.fileMonitor.enqueue("delete", uri);
      return;
    }
    await this.session.removeFiles(files);
    if (files.some(isProjectConfigurationUri)) await this._reloadProjectConfiguration();
    if (files.some(isProjectIdentityUri)) await this._reloadProjectIdentity();
  }

  async _onFilesRenamed(files) {
    if (!vscode.workspace.isTrusted) return;
    await this.session.migrateEvidencePaths(files);
    if (this.session.workspaceIndexBuilt || this.session.indexing || this.session.analyses.length) {
      for (const item of files) {
        this.fileMonitor.enqueue("delete", item.oldUri);
        this.fileMonitor.enqueue("create", item.newUri);
        if (!languageForPath(item.oldUri.fsPath) && !languageForPath(item.newUri.fsPath)) this.fileMonitor.requestRescan();
      }
      return;
    }
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
    this._updateTreeViewChrome();
    this._updateDecorations(vscode.window.activeTextEditor);
    this._updateTraceDecorations(vscode.window.activeTextEditor);
    this._updateDiagnostics();
    this._updateConfigurationDiagnostics();
    vscode.commands.executeCommand("setContext", "traceguard.hasAuditTargets", this.session.snapshot.items.length > 0);
    vscode.commands.executeCommand("setContext", "traceguard.hasAuditQuery", Boolean(this.lastAuditQuery));
  }

  _updateTreeViewChrome() {
    const data = this.session.snapshot;
    if (this.codeTreeView) {
      const openVerified = (data.findings || []).filter(f => f.status === "open" && findingPool(f) === "verified").length;
      const manual = data.manualReviewCoverage || { reviewed: data.statusCounts?.reviewed || 0, total: (data.items || []).length };
      this.codeTreeView.description = manual.total ? `${manual.reviewed}/${manual.total}` : undefined;
      this.codeTreeView.badge = openVerified > 0
        ? { value: openVerified, tooltip: `${openVerified} open verified flow${openVerified === 1 ? "" : "s"}` }
        : undefined;
      const filter = this.codeProvider.getFilterState();
      const parts = [];
      if (filter.filterId && filter.filterId !== "priority") parts.push(`Filter: ${filter.filterLabel}`);
      if (filter.searchQuery) parts.push(`Search: "${filter.searchQuery}"`);
      this.codeTreeView.message = parts.length ? parts.join(" · ") : undefined;
    }
    if (this.evidenceTreeView) {
      const count = (data.evidence || []).length;
      this.evidenceTreeView.description = count ? `${count}` : undefined;
    }
  }

  _updateStatus() {
    const data = this.session.snapshot;
    if (data.indexStale) {
      this.status.text = "$(sync) TraceGuard · Results pending refresh";
      this.status.tooltip = "Files changed on disk. The audit map is pending synchronization; use Refresh Code Review Index if synchronization failed.";
      return;
    }
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
    tooltip.supportThemeIcons = true;
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
          hover.supportThemeIcons = true;
          hover.appendMarkdown(`${hoverIcons[kind] || "$(eye)"} **TraceGuard ${kind}** — ${signal.label}\n\n`);
          hover.appendMarkdown("$(info) Audit clue, not a confirmed vulnerability.");
          return { range: editor.document.lineAt(Math.max(0, signal.line - 1)).range, hoverMessage: hover };
        }) : [];
      editor.setDecorations(decoration, ranges);
    }
  }

  _updateTraceDecorations(editor) {
    if (!editor || !languageForPath(editor.document.uri.fsPath)) return;
    if (!this.traceHighlightsEnabled) {
      this._clearTraceEditor(editor);
      return;
    }
    const flowPath = this.queryProvider.currentTrace;
    const groups = { source: [], flow: [], sink: [] };
    const lineGroups = { source: [], flow: [], sink: [] };
    const seenLines = new Set();
    const pushLineBadge = (kind, range) => {
      const lineKey = `${kind}:${range.start.line}`;
      if (seenLines.has(lineKey)) return;
      seenLines.add(lineKey);
      lineGroups[kind].push({ range: new vscode.Range(range.start.line, 0, range.start.line, 0) });
    };
    if (flowPath?.steps?.length) {
      const target = normalizePath(editor.document.uri.fsPath);
      const seen = new Set();
      flowPath.steps.forEach((step, index) => {
        if (this.queryProvider.isReviewed(step)) return;
        if (!step.absolutePath || normalizePath(step.absolutePath) !== target || !step.line) return;
        const range = traceStepRange(editor.document, step);
        const kind = step.kind === "source" ? "source" : step.kind === "sink" ? "sink" : "flow";
        const key = `${kind}:${range.start.line}:${range.start.character}:${range.end.character}`;
        if (seen.has(key)) return;
        seen.add(key);
        groups[kind].push({ range, hoverMessage: tracePathHover(flowPath, index) });
        pushLineBadge(kind, range);
      });
    } else if (this.queryProvider.current) {
      const target = normalizePath(editor.document.uri.fsPath);
      const visit = nodes => {
        for (const node of nodes || []) {
          if (this.queryProvider.isReviewed(node)) continue;
          const location = node.location;
          if (location?.absolutePath && normalizePath(location.absolutePath) === target && location.line) {
            const kind = node.kind === "source" ? "source" : node.kind === "sink" ? "sink" : "flow";
            const range = traceStepRange(editor.document, location);
            groups[kind].push({ range, hoverMessage: queryNodeHover(node) });
            pushLineBadge(kind, range);
          }
          visit(node.children);
        }
      };
      visit(this.queryProvider.current.roots);
    }
    for (const [kind, decoration] of Object.entries(this.tracePathDecorations)) {
      editor.setDecorations(decoration, groups[kind]);
    }
    for (const [kind, decoration] of Object.entries(this.traceLineDecorations)) {
      editor.setDecorations(decoration, lineGroups[kind]);
    }
    if (flowPath || this.queryProvider.current) this.tracedEditor = editor;
    void vscode.commands.executeCommand("setContext", "traceguard.hasTraceHighlights", Boolean(flowPath || this.queryProvider.current));
  }

  _updateDiagnostics() {
    updateDiagnostics(this.problemDiagnostics, this.session.snapshot);
  }

  _updateConfigurationDiagnostics() {
    updateConfigurationDiagnostics(this.configurationDiagnostics, [...(this.session.projectConfigurationIssues || []), ...(this.session.projectIdentityIssues || [])]);
  }

  dispose() {
    this.fileMonitor.dispose();
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

module.exports = { AuditController, buildReport, createDecorations, createTracePathDecorations, selectedAccessPath, traceStepRange };
