const path = require("path");
const vscode = require("vscode");
const { traceIdentifier } = require("./audit-analyzer");
const { AuditCodeLensProvider, AuditHoverProvider, AuditQueueProvider, AuditSummaryProvider, EvidenceProvider } = require("./audit-providers");
const { AuditSession } = require("./audit-session");
const { SUPPORTED_LABEL, SUPPORTED_SELECTORS, languageForPath } = require("./language-support");

class AuditController {
  constructor(context, output) {
    this.context = context;
    this.output = output;
    this.session = new AuditSession(context, output);
    this.queueProvider = new AuditQueueProvider(this.session);
    this.summaryProvider = new AuditSummaryProvider(this.session);
    this.evidenceProvider = new EvidenceProvider(this.session);
    this.codeLensProvider = new AuditCodeLensProvider(this.session);
    this.status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
    this.status.name = "TraceGuard Audit Coverage";
    this.status.command = "traceguard.openAuditView";
    this.status.show();
    this.documentTimers = new Map();
    this.decorations = createDecorations();
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
      this.queueProvider,
      this.summaryProvider,
      this.evidenceProvider,
      this.codeLensProvider,
      this.status,
      ...Object.values(this.decorations),
      this.traceDecoration,
      vscode.window.registerTreeDataProvider("traceguard.findings", this.queueProvider),
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
      vscode.commands.registerCommand("traceguard.traceSelectedSymbol", () => this.traceSelectedSymbol()),
      vscode.commands.registerCommand("traceguard.clearSymbolTrace", () => this.clearSymbolTrace()),
      vscode.commands.registerCommand("traceguard.nextAuditTarget", () => this.navigateTarget(1)),
      vscode.commands.registerCommand("traceguard.previousAuditTarget", () => this.navigateTarget(-1)),
      vscode.commands.registerCommand("traceguard.markCurrentReviewed", () => this.markCurrentReviewed()),
      vscode.commands.registerCommand("traceguard.focusAuditItem", item => this.focusItem(item)),
      vscode.commands.registerCommand("traceguard.markReviewed", item => item ? this.setStatus((item.auditItem || item).id, "reviewed") : this.setCurrentStatus("reviewed")),
      vscode.commands.registerCommand("traceguard.markInReview", item => item ? this.setStatus((item.auditItem || item).id, "in_review") : this.setCurrentStatus("in_review")),
      vscode.commands.registerCommand("traceguard.markNeedsContext", item => item ? this.setStatus((item.auditItem || item).id, "blocked") : this.setCurrentStatus("blocked")),
      vscode.commands.registerCommand("traceguard.resetReviewStatus", item => item ? this.setStatus((item.auditItem || item).id, "unreviewed") : this.setCurrentStatus("unreviewed")),
      vscode.commands.registerCommand("traceguard.addEvidence", () => this.addSelectionEvidence()),
      vscode.commands.registerCommand("traceguard.openEvidence", item => this.openEvidence(item)),
      vscode.commands.registerCommand("traceguard.removeEvidence", item => this.session.removeEvidence((item.evidenceItem || item).id)),
      vscode.commands.registerCommand("traceguard.generateAuditReport", () => this.generateReport()),
      vscode.commands.registerCommand("traceguard.exportReviewSession", () => this.exportReviewSession()),
      vscode.commands.registerCommand("traceguard.importReviewSession", () => this.importReviewSession()),
      vscode.workspace.onDidSaveTextDocument(document => this._onSaved(document)),
      vscode.workspace.onDidChangeTextDocument(event => this._onChanged(event.document)),
      vscode.window.onDidChangeActiveTextEditor(editor => { this.clearSymbolTrace(); this._updateDecorations(editor); }),
      vscode.workspace.onDidChangeConfiguration(event => {
        if (event.affectsConfiguration("traceguard.showAuditSignals")) this._updateDecorations(vscode.window.activeTextEditor);
        if (event.affectsConfiguration("traceguard.hideReviewedTargets")) this.queueProvider.refresh();
      }),
    );
  }

  async initialize() {
    if (!vscode.workspace.isTrusted || !vscode.workspace.workspaceFolders?.length) {
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
      if (showNotification) {
        const data = this.session.snapshot;
        vscode.window.showInformationMessage(`Audit map ready: ${data.entries.length} entry points, ${data.items.length} review targets, ${data.files} files indexed.`);
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

  async traceSelectedSymbol() {
    const editor = vscode.window.activeTextEditor;
    if (!editor || !languageForPath(editor.document.uri.fsPath)) {
      vscode.window.showInformationMessage(`Open a ${SUPPORTED_LABEL} file first.`);
      return;
    }
    let identifier = editor.document.getText(editor.selection).trim();
    if (!/^[A-Za-z_$][\w$]*$/.test(identifier)) {
      const range = editor.document.getWordRangeAtPosition(editor.selection.active, /[A-Za-z_$][\w$]*/);
      identifier = range ? editor.document.getText(range) : "";
    }
    if (!identifier) {
      vscode.window.showInformationMessage("Select a variable or place the cursor on one before tracing it.");
      return;
    }
    await this.session.reindexDocument(editor.document);
    const analysis = this.session.analysisForUri(editor.document.uri);
    const trace = traceIdentifier(editor.document.getText(), identifier, analysis?.signals || []);
    if (!trace.length) {
      vscode.window.showInformationMessage(`No references to “${identifier}” were found in this file.`);
      return;
    }
    this.clearSymbolTrace();
    this.tracedEditor = editor;
    editor.setDecorations(this.traceDecoration, trace.map(item => ({
      range: new vscode.Range(item.line - 1, item.column - 1, item.line - 1, item.endColumn - 1),
      hoverMessage: `TraceGuard: ${traceRoleLabel(item.role)}${item.signals.length ? ` · ${item.signals.map(signal => signal.label).join(", ")}` : ""}`,
    })));
    const selected = await vscode.window.showQuickPick(trace.map(item => ({
      label: `$(${traceRoleIcon(item.role)}) ${traceRoleLabel(item.role)} · Line ${item.line}`,
      description: item.signals.map(signal => signal.label).join(", "),
      detail: item.code,
      occurrence: item,
    })), {
      placeHolder: `${identifier}: ${trace.length} ordered reference${trace.length === 1 ? "" : "s"} in this file`,
      matchOnDescription: true,
      matchOnDetail: true,
    });
    if (selected) revealOccurrence(editor, selected.occurrence);
  }

  clearSymbolTrace() {
    this.tracedEditor?.setDecorations(this.traceDecoration, []);
    this.tracedEditor = undefined;
  }

  async navigateTarget(direction) {
    const items = this.session.snapshot.items;
    if (!items.length) {
      vscode.window.showInformationMessage("The review queue is empty. Run “TraceGuard: Start Code Review” first.");
      return;
    }
    const editor = vscode.window.activeTextEditor;
    const currentPath = editor ? path.normalize(editor.document.uri.fsPath).toLowerCase() : "";
    const currentLine = editor?.selection.active.line + 1 || 0;
    let index = items.findIndex(item => path.normalize(item.absolutePath).toLowerCase() === currentPath && currentLine >= item.line && currentLine <= item.endLine);
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

  async addSelectionEvidence() {
    const editor = vscode.window.activeTextEditor;
    if (!editor || !languageForPath(editor.document.uri.fsPath)) {
      vscode.window.showInformationMessage(`Select ${SUPPORTED_LABEL} code before adding an audit note.`);
      return;
    }
    const selection = editor.selection.isEmpty ? editor.document.lineAt(editor.selection.active.line).range : editor.selection;
    const code = editor.document.getText(selection).trim();
    const type = await vscode.window.showQuickPick(["Source", "Sink", "Authorization", "Validation", "Observation"], { placeHolder: "What does this code prove or require you to verify?" });
    if (!type) return;
    const note = await vscode.window.showInputBox({ prompt: "Audit note (optional)", placeHolder: "Why this evidence matters, assumptions, or follow-up question" });
    if (note === undefined) return;
    const folder = vscode.workspace.getWorkspaceFolder(editor.document.uri);
    const relativePath = folder ? path.relative(folder.uri.fsPath, editor.document.uri.fsPath).replaceAll("\\", "/") : path.basename(editor.document.uri.fsPath);
    await this.session.addEvidence({ type, note, code, absolutePath: editor.document.uri.fsPath, relativePath, line: selection.start.line + 1, endLine: selection.end.line + 1 });
    vscode.window.showInformationMessage(`Added ${type.toLowerCase()} evidence to the audit notebook.`);
  }

  async addEvidenceForItem(itemId) {
    const item = this.session.snapshot.items.find(candidate => candidate.id === itemId);
    if (!item) return;
    const type = await vscode.window.showQuickPick(["Source", "Sink", "Authorization", "Validation", "Observation"], { placeHolder: "Evidence type" });
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
    vscode.window.showInformationMessage(`Review session exported with ${Object.keys(payload.statuses).length} states and ${payload.evidence.length} notes.`);
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
      const payload = JSON.parse(Buffer.from(bytes).toString("utf8"));
      const imported = await this.session.importPortableState(payload);
      vscode.window.showInformationMessage(`Merged ${imported.statuses} review states and ${imported.evidence} audit notes.`);
    } catch (error) {
      vscode.window.showErrorMessage(`TraceGuard could not import the review session: ${error.message}`);
    }
  }

  _onSaved(document) {
    if (!languageForPath(document.uri.fsPath) || !vscode.workspace.isTrusted) return;
    const key = document.uri.toString();
    clearTimeout(this.documentTimers.get(key));
    this.documentTimers.delete(key);
    this.session.reindexDocument(document).then(() => this._updateDecorations(vscode.window.activeTextEditor));
  }

  _onChanged(document) {
    if (!languageForPath(document.uri.fsPath) || !vscode.workspace.isTrusted) return;
    if (!vscode.workspace.getConfiguration("traceguard", document.uri).get("liveIndex", true)) return;
    const key = document.uri.toString();
    clearTimeout(this.documentTimers.get(key));
    this.documentTimers.set(key, setTimeout(async () => {
      this.documentTimers.delete(key);
      await this.session.reindexDocument(document);
      if (vscode.window.activeTextEditor?.document === document) this._updateDecorations(vscode.window.activeTextEditor);
    }, 850));
  }

  _onSessionChanged() {
    this._updateStatus();
    this._updateDecorations(vscode.window.activeTextEditor);
    vscode.commands.executeCommand("setContext", "traceguard.hasAuditTargets", this.session.snapshot.items.length > 0);
  }

  _updateStatus() {
    const data = this.session.snapshot;
    if (!vscode.workspace.isTrusted) { this.status.text = "$(lock) TraceGuard: trust workspace"; this.status.tooltip = "Trust the workspace to build a local audit map"; return; }
    if (!data.indexed_at) { this.status.text = "$(references) Start code review"; this.status.tooltip = "Open the TraceGuard sidebar"; return; }
    this.status.text = `$(references) Review ${data.coverage}% · ${data.statusCounts.unreviewed} left`;
    this.status.tooltip = `${data.entries.length} entry points · ${data.items.length} review targets · ${data.evidence.length} evidence records`;
  }

  _updateDecorations(editor) {
    if (!editor || !languageForPath(editor.document.uri.fsPath)) return;
    const enabled = vscode.workspace.getConfiguration("traceguard", editor.document.uri).get("showAuditSignals", true);
    for (const [kind, decoration] of Object.entries(this.decorations)) {
      const ranges = enabled ? (this.session.analysisForUri(editor.document.uri)?.signals || [])
        .filter(signal => signal.kind === kind && signal.line > 0 && signal.line <= editor.document.lineCount)
        .map(signal => ({ range: editor.document.lineAt(Math.max(0, signal.line - 1)).range, hoverMessage: `TraceGuard ${signal.kind}: ${signal.label}` })) : [];
      editor.setDecorations(decoration, ranges);
    }
  }

  dispose() {
    this.subscription?.dispose();
    for (const timer of this.documentTimers.values()) clearTimeout(timer);
  }
}

function statusLabel(status) { return { unreviewed: "Not reviewed", in_review: "In review", reviewed: "Reviewed", blocked: "Needs context" }[status] || "Not reviewed"; }
function priorityIcon(priority) { return { P0: "flame", P1: "warning", P2: "eye" }[priority] || "circle-outline"; }
function signalIcon(kind) { return { source: "arrow-right", sink: "target", auth: "key", sanitizer: "verified" }[kind] || "circle-outline"; }
function traceRoleLabel(role) { return { input: "External input", parameter: "Parameter", assignment: "Assignment", condition: "Control check", validation: "Validation", "security-decision": "Security decision", "sensitive-use": "Sensitive use", reference: "Reference" }[role] || "Reference"; }
function traceRoleIcon(role) { return { input: "arrow-right", parameter: "symbol-parameter", assignment: "edit", condition: "git-compare", validation: "verified", "security-decision": "key", "sensitive-use": "target", reference: "references" }[role] || "references"; }

function revealOccurrence(editor, occurrence) {
  const start = new vscode.Position(occurrence.line - 1, occurrence.column - 1);
  const end = new vscode.Position(occurrence.line - 1, occurrence.endColumn - 1);
  editor.selection = new vscode.Selection(start, end);
  editor.revealRange(new vscode.Range(start, end), vscode.TextEditorRevealType.InCenterIfOutsideViewport);
}

function createDecorations() {
  return {
    source: vscode.window.createTextEditorDecorationType({ isWholeLine: true, overviewRulerColor: new vscode.ThemeColor("editorInfo.foreground"), overviewRulerLane: vscode.OverviewRulerLane.Right, after: { contentText: "  ◀ external input", color: new vscode.ThemeColor("editorInfo.foreground"), fontStyle: "italic" } }),
    sink: vscode.window.createTextEditorDecorationType({ isWholeLine: true, overviewRulerColor: new vscode.ThemeColor("editorError.foreground"), overviewRulerLane: vscode.OverviewRulerLane.Right, after: { contentText: "  ◀ sensitive operation", color: new vscode.ThemeColor("editorError.foreground"), fontStyle: "italic" } }),
    auth: vscode.window.createTextEditorDecorationType({ isWholeLine: true, overviewRulerColor: new vscode.ThemeColor("testing.iconPassed"), overviewRulerLane: vscode.OverviewRulerLane.Right, after: { contentText: "  ◀ security decision", color: new vscode.ThemeColor("testing.iconPassed"), fontStyle: "italic" } }),
    sanitizer: vscode.window.createTextEditorDecorationType({ isWholeLine: true, overviewRulerColor: new vscode.ThemeColor("charts.green"), overviewRulerLane: vscode.OverviewRulerLane.Right, after: { contentText: "  ◀ validation / encoding", color: new vscode.ThemeColor("charts.green"), fontStyle: "italic" } }),
  };
}

async function openLocation(absolutePath, line, endLine) {
  const document = await vscode.workspace.openTextDocument(vscode.Uri.file(absolutePath));
  const editor = await vscode.window.showTextDocument(document, { preview: true, preserveFocus: false });
  const start = new vscode.Position(Math.max(0, line - 1), 0);
  const end = new vscode.Position(Math.min(document.lineCount - 1, Math.max(line - 1, (endLine || line) - 1)), 0);
  editor.selection = new vscode.Selection(start, start);
  editor.revealRange(new vscode.Range(start, end), vscode.TextEditorRevealType.InCenterIfOutsideViewport);
}

function buildReport(audit) {
  const lines = [
    "# TraceGuard Code Audit Report", "",
    `Generated: ${new Date().toISOString()}`, "",
    "## Review coverage", "",
    `- Coverage: **${audit.coverage}%** (${audit.statusCounts.reviewed}/${audit.items.length} targets reviewed)`,
    `- Indexed: ${audit.files} files, ${audit.functions} functions, ${audit.lines} lines`,
    `- Attack surface: ${audit.entries.length} entry points`,
    `- Evidence records: ${audit.evidence.length}`, "",
    "## Attack surface", "",
    ...audit.entries.map(entry => `- \`${entry.title}\` — ${entry.relativePath}:${entry.line}`), "",
    "## Audit queue", "",
  ];
  for (const item of audit.items) {
    lines.push(`### ${item.priority} · ${item.title}`, "", `- Location: \`${item.relativePath}:${item.line}\``, `- Status: **${item.status}**`, `- Review reasons: ${item.reasons.join("; ")}`, "", "Checklist:", ...item.checklist.map(check => `- [${item.status === "reviewed" ? "x" : " "}] ${check.label} — ${check.evidence}`), "");
  }
  lines.push("## Evidence notebook", "");
  for (const evidence of audit.evidence) lines.push(`### ${evidence.type} · ${evidence.relativePath}:${evidence.line}`, "", evidence.note || "No note", "", "```", evidence.code, "```", "");
  lines.push("---", "TraceGuard audit signals are reviewer aids, not proof that code is secure or vulnerable.", "");
  return lines.join("\n");
}

module.exports = { AuditController, buildReport, createDecorations };
