"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vscode = require("vscode");
const { selectedAccessPath } = require("../src/audit-controller");

async function run() {
  console.log("TraceGuard smoke: starting assertions");
  // Exercise the real export commands without changing the user's clipboard or
  // depending on OS clipboard access (unavailable in some desktop sandboxes).
  const originalClipboard = Object.getOwnPropertyDescriptor(vscode.env, "clipboard");
  let clipboardText = "";
  const clipboard = { readText: async () => clipboardText, writeText: async value => { clipboardText = value; } };
  Object.defineProperty(vscode.env, "clipboard", { configurable: true, get: () => clipboard });
  try {
    await runSmokeAssertions();
  } finally {
    Object.defineProperty(vscode.env, "clipboard", originalClipboard);
  }
}

async function runSmokeAssertions() {
  const extension = vscode.extensions.getExtension("traceguard.traceguard-vscode");
  assert.ok(extension, "TraceGuard is visible to the Extension Host");

  const api = await extension.activate();
  console.log("TraceGuard smoke: extension activated");
  assert.equal(extension.isActive, true, "TraceGuard activates successfully");
  assert.ok(api?.audit?.session, "TraceGuard creates its audit session");
  assert.ok(api.audit.codeProvider, "TraceGuard exposes the prioritized Review Queue");
  const initialSummary = api.audit.summaryProvider.getChildren();
  assert.equal(initialSummary[0]?.label, "Review queue not built", "an idle workspace is not presented as permanently indexing");
  assert.equal(initialSummary[0]?.command?.command, "traceguard.startAudit", "the idle summary starts the review queue");
  const accessPathEditor = {
    document: {
      getText: () => `$_GET['cmd']`,
      getWordRangeAtPosition: () => undefined,
    },
    selection: { active: new vscode.Position(0, 5) },
  };
  assert.equal(selectedAccessPath(accessPathEditor), "$_GET.cmd", "quoted PHP access paths are accepted by interactive queries");

  const commands = new Set(await vscode.commands.getCommands(true));
  const requiredCommands = [
    "traceguard.startAudit",
    "traceguard.openTraceInspector",
    "traceguard.traceCrossFileFlow",
    "traceguard.traceFromEntry",
    "traceguard.traceFinding",
    "traceguard.modelInterruptedCall",
    "traceguard.searchEntries",
    "traceguard.previousTraceStep",
    "traceguard.nextTraceStep",
    "traceguard.selectTraceStep",
    "traceguard.selectQueryNode",
    "traceguard.clearTraceHighlights",
    "traceguard.toggleTraceReviewed",
    "traceguard.markSelectionAsSanitizer",
    "traceguard.copyAiPrompt",
    "traceguard.verifyChainWithAi",
    "traceguard.setAiApiKey",
    "traceguard.clearAiApiKey",
    "traceguard.traceBackward",
    "traceguard.traceForward",
    "traceguard.findCallers",
    "traceguard.findCallees",
    "traceguard.traceToEntry",
    "traceguard.showReachableSinks",
    "traceguard.explainAnalysisHere",
    "traceguard.copyAuditQueryMarkdown",
    "traceguard.exportAnalysisDebugJson",
    "traceguard.searchFindings",
    "traceguard.filterReviewQueue",
    "traceguard.openProjectConfiguration",
    "traceguard.markSelectionAsSource",
    "traceguard.markSelectionAsSink",
    "traceguard.markSelectionAsTemporarySanitizer",
    "traceguard.markSelectionAsTemporarySink",
    "traceguard.clearTemporaryModels",
    "traceguard.exportSarif",
    "traceguard.markFindingReviewed",
    "traceguard.markFindingFalsePositive",
    "traceguard.acceptFindingRisk",
    "traceguard.suppressFinding",
    "traceguard.resetFindingStatus",
    "traceguard.exportReviewSession",
  ];
  for (const command of requiredCommands) {
    assert.ok(commands.has(command), `${command} is registered`);
  }
  const manifest = extension.packageJSON.contributes;
  assert.equal(manifest.views.traceguard.find(view => view.id === "traceguard.summary")?.type, "webview");
  await vscode.commands.executeCommand("traceguard.openTraceInspector");
  assert.ok(api.audit.traceInspector.isOpen, "Inspector opens through its contributed command");
  for (const binding of manifest.keybindings || []) assert.ok(commands.has(binding.command), `${binding.command} keybinding is registered`);
  for (const entries of Object.values(manifest.menus || {})) {
    for (const entry of entries) if (entry.command?.startsWith("traceguard.")) assert.ok(commands.has(entry.command), `${entry.command} menu is registered`);
  }

  const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  assert.ok(workspaceRoot, "Extension Host smoke test has a workspace");
  const smokePath = path.join(workspaceRoot, ".traceguard-extension-host-smoke.ts");
  const smokeUri = vscode.Uri.file(smokePath);
  const customPath = path.join(workspaceRoot, ".traceguard-custom-semantics-smoke.ts");
  const customUri = vscode.Uri.file(customPath);
  const excludedPath = path.join(workspaceRoot, ".traceguard-generated-smoke", "excluded.ts");
  const excludedUri = vscode.Uri.file(excludedPath);
  const configurationPath = path.join(workspaceRoot, ".traceguard.json");
  const configurationUri = vscode.Uri.file(configurationPath);
  const previousConfiguration = fs.existsSync(configurationPath) ? fs.readFileSync(configurationPath) : undefined;
  try {
    fs.writeFileSync(smokePath, "export function proxy(req: any) { return fetch(req.query.url); }\napp.get('/proxy', proxy);", "utf8");
    await api.audit.session.reindexFile(smokeUri);
    console.log("TraceGuard smoke: initial Worker index completed");
    let snapshot = api.audit.session.snapshot;
    assert.equal(api.audit.session.analysisForUri(smokeUri).frontend.mode, "ast", "AST frontend runs inside Extension Host");
    assert.ok(snapshot.findings.some(finding => finding.ruleId === "potential-ssrf"), "Worker produces an SSRF finding inside Extension Host");
    const codeTree = flattenTreeProvider(api.audit.codeProvider, api.audit.codeProvider.getChildren());
    assert.ok(codeTree.some(item => item.label === "Manual review coverage"), "Review Queue separates human progress from analysis coverage");
    assert.ok(codeTree.some(item => item.kind === "section" && /^P0/.test(item.label)), "Review Queue prioritizes the entry-to-sensitive-operation target as P0");
    assert.ok(codeTree.some(item => item.kind === "finding" && /request/i.test(item.label)), "Review Queue exposes the live flow in its evidence pool");
    const attackSurface = flattenTreeProvider(api.audit.summaryProvider, api.audit.summaryProvider.getChildren());
    assert.ok(attackSurface.some(item => item.kind === "surface-method" && item.method === "GET"), "Attack Surface groups HTTP APIs by method");
    assert.ok(attackSurface.some(item => item.kind === "attack-entry" && /GET \/proxy/.test(item.label)), "Attack Surface exposes the route as a first-class review entry");
    let providerRefreshes = 0;
    const refreshSubscription = api.audit.codeProvider.onDidChangeTreeData(() => { providerRefreshes += 1; });
    for (let index = 0; index < 8; index += 1) api.audit.codeProvider.refresh();
    await new Promise(resolve => setTimeout(resolve, 220));
    refreshSubscription.dispose();
    assert.equal(providerRefreshes, 1, "Review Queue coalesces bursty session updates into one rebuild notification");

    const reviewedTarget = snapshot.items.find(item => item.absolutePath === smokePath && item.kind === "endpoint");
    assert.ok(reviewedTarget?.reviewFingerprint, "live review targets carry dependency fingerprints");
    await api.audit.session.setStatus(reviewedTarget.id, "reviewed");
    fs.writeFileSync(smokePath, "import { exec } from 'node:child_process';\nexport function proxy(req: any) { return exec(req.query.cmd); }\napp.get('/proxy', proxy);", "utf8");
    await api.audit.session.reindexFile(smokeUri);
    snapshot = api.audit.session.snapshot;
    assert.ok(snapshot.findings.some(finding => finding.ruleId === "potential-command-injection"), "incremental Worker update replaces the finding");
    assert.ok(!snapshot.findings.some(finding => finding.ruleId === "potential-ssrf"), "stale incremental findings are removed");
    assert.equal(snapshot.incrementallyInvalidatedFiles, 1);
    assert.equal(snapshot.items.find(item => item.id === reviewedTarget.id)?.status, "needs_review", "changed code returns to the review queue");
    api.audit.codeProvider.setFilter({ id: "needs_review", label: "Changed since review" });
    const changedTree = flattenTreeProvider(api.audit.codeProvider, api.audit.codeProvider.getChildren());
    assert.ok(changedTree.some(item => item.auditItem?.id === reviewedTarget.id && /Needs re-review/.test(item.description)), "the filter exposes changed targets with a clear label");
    api.audit.codeProvider.setFilter({ id: "priority", label: "P0 / P1 first" });

    const query = await api.audit.session.queryAudit(smokeUri, 0, "reachable-sinks", "req.query.cmd");
    assert.equal(query.schema, "traceguard-audit-query", "persistent Worker serves the audit query protocol");
    assert.ok(flattenQuery(query.roots).some(node => node.kind === "sink"), "audit query reaches the incrementally updated command sink");
    assert.ok(flattenQuery(query.roots).every(node => node.status && node.reason), "every query step explains its confidence and connection");
    api.audit.queryProvider.setResult(query);
    assert.equal(api.audit.queryProvider.current, query, "audit query tree receives the live query result");
    const queryRows = flattenTreeProvider(api.audit.queryProvider, api.audit.queryProvider.getChildren());
    const sinkRow = queryRows.find(item => item.node?.kind === "sink");
    assert.equal(sinkRow.command.command, "traceguard.selectQueryNode", "query nodes use trace-aware navigation");
    await vscode.commands.executeCommand(sinkRow.command.command, ...sinkRow.command.arguments);
    assert.equal(vscode.window.activeTextEditor.document.uri.fsPath, sinkRow.node.location.absolutePath);
    assert.equal(vscode.window.activeTextEditor.selection.start.line, sinkRow.node.location.line - 1);
    const decorations = new Map();
    const traceEditor = {
      document: vscode.window.activeTextEditor.document,
      setDecorations: (type, values) => decorations.set(type, values),
    };
    api.audit._updateTraceDecorations(traceEditor);
    assert.ok(decorations.get(api.audit.tracePathDecorations.sink).length, "variable query highlights its sink");
    assert.ok(decorations.get(api.audit.traceLineDecorations.sink).length, "variable query shows its sink line badge");
    await vscode.commands.executeCommand("traceguard.clearTraceHighlights");
    api.audit._updateTraceDecorations(traceEditor);
    assert.ok([...decorations.values()].every(values => values.length === 0), "Esc command keeps highlights cleared through redraws");
    assert.equal(api.audit.queryProvider.current, query, "clearing highlights preserves the trace tree");
    await api.audit.selectQueryNode(sinkRow.node);
    api.audit._updateTraceDecorations(traceEditor);
    assert.ok(decorations.get(api.audit.tracePathDecorations.sink).length, "selecting a node resumes highlighting");
    await vscode.commands.executeCommand("traceguard.toggleTraceReviewed", sinkRow);
    api.audit._updateTraceDecorations(traceEditor);
    assert.equal(decorations.get(api.audit.tracePathDecorations.sink).length, 0, "reviewed sink loses its trace decoration");
    assert.equal(decorations.get(api.audit.traceLineDecorations.sink).length, 0, "reviewed sink loses its line badge");
    const reviewedRows = flattenTreeProvider(api.audit.queryProvider, api.audit.queryProvider.getChildren());
    assert.ok(reviewedRows.some(row => row.contextValue === "traceguard.reviewedTraceNode"), "review decision appears in the tree");
    await vscode.commands.executeCommand("traceguard.toggleTraceReviewed", reviewedRows.find(row => row.contextValue === "traceguard.reviewedTraceNode"));
    await vscode.commands.executeCommand("traceguard.copyAuditQueryMarkdown");
    const queryMarkdown = await vscode.env.clipboard.readText();
    assert.match(queryMarkdown, /Enclosing functions/, "copy exports complete AST function context");
    // Awaited navigation and Inspector refreshes can replace tracedEditor with
    // the real editor. Make this decoration observer current before testing
    // synchronous cleanup, then also check that a redraw stays empty.
    api.audit._updateTraceDecorations(traceEditor);
    api.audit.clearAuditQuery();
    assert.ok([...decorations.values()].every(values => values.length === 0), "clearing the query removes trace decorations");
    api.audit._updateTraceDecorations(traceEditor);
    assert.ok([...decorations.values()].every(values => values.length === 0), "redraw after clearing does not restore trace decorations or line badges");
    const variableEditor = vscode.window.activeTextEditor;
    const variableColumn = variableEditor.document.lineAt(1).text.indexOf("req.query.cmd");
    for (const [command, kind] of [["traceguard.traceForward", "trace-forward"], ["traceguard.traceBackward", "trace-backward"]]) {
      variableEditor.selection = new vscode.Selection(1, variableColumn, 1, variableColumn + "req.query.cmd".length);
      await vscode.commands.executeCommand(command);
      assert.equal(api.audit.queryProvider.current.kind, kind, "editor command runs the requested query direction");
      assert.equal(api.audit.queryProvider.current.subject.variable, "req.query.cmd");
    }
    const finding = snapshot.findings.find(item => item.ruleId === "potential-command-injection");
    const tracePath = finding.paths?.[0] || finding.path;
    api.audit.queryProvider.setTrace(tracePath);
    assert.equal(api.audit.queryProvider.current, undefined, "interactive finding traces replace the generic query tree");
    assert.equal(api.audit.queryProvider.getChildren()[0]?.kind, "interactive-trace", "Traces exposes a Source to Sink stepper");
    const finalStep = api.audit.queryProvider.selectTraceStep(tracePath.steps.length - 1);
    assert.equal(finalStep.kind, "sink", "interactive traces can move directly to the Sink step");
    await vscode.commands.executeCommand("traceguard.copyAuditQueryMarkdown");
    assert.match(await vscode.env.clipboard.readText(), /\[sink\]/, "finding trace root supports Markdown export too");
    const callees = await api.audit.session.queryAudit(smokeUri, 1, "find-callees");
    api.audit.queryProvider.setResult(callees);
    const interruptedTree = flattenTreeProvider(api.audit.queryProvider, api.audit.queryProvider.getChildren());
    const interruption = interruptedTree.find(item => item.contextValue === "traceguard.modelableInterruption");
    assert.ok(interruption, "unresolved calls expose an actionable interruption");
    assert.equal(interruption.command.command, "traceguard.modelInterruptedCall");
    assert.doesNotThrow(() => JSON.stringify(interruption.command.arguments), "modeling command arguments are serializable");
    api.audit.queryProvider.setResult(query);

    const debug = await api.audit.session.debugAnalysisForUri(smokeUri, query);
    assert.equal(debug.schema, "traceguard-analysis-debug");
    assert.doesNotThrow(() => JSON.stringify(debug), "analysis debug payload is serializable");

    await api.audit.fileMonitor.flush();
    const diagnostics = api.audit.problemDiagnostics.get(smokeUri) || [];
    assert.ok(diagnostics.some(item => item.source === "TraceGuard" && /command/i.test(item.message)), "live findings are mapped to the Problems panel");

    const sarif = api.audit.createSarif();
    assert.ok(sarif.runs[0].results.some(result => result.ruleId === "potential-command-injection"), "SARIF is generated from the live Extension Host snapshot");
    assert.ok(sarif.runs[0].originalUriBaseIds.SRCROOT?.uri, "SARIF declares the workspace source root");
    assert.ok(sarif.runs[0].results.every(result => result.locations[0].physicalLocation.artifactLocation.uriBaseId === "SRCROOT"), "SARIF locations resolve against the declared source root");

    fs.writeFileSync(configurationPath, JSON.stringify({
      version: 1,
      sources: [{ language: "typescript", function: "readTenantValue" }],
      sinks: [{ language: "typescript", function: "runInternalCommand", arguments: [0], kind: "COMMAND_EXEC" }],
      severityOverrides: { "potential-command-injection": "medium" },
      excludePaths: [".traceguard-generated-smoke/**"],
    }, null, 2), "utf8");
    const configured = await api.audit.session.reloadProjectConfiguration({ rebuild: true });
    assert.equal(configured.valid, true, "valid .traceguard.json loads inside Extension Host");
    assert.equal(configured.config.semanticModels.length, 2);

    fs.writeFileSync(customPath, `
declare function readTenantValue(): string;
declare function runInternalCommand(value: string): void;
export function customFlow(): void {
  const value = readTenantValue();
  runInternalCommand(value);
}`, "utf8");
    await api.audit.session.reindexFile(customUri);
    const customFinding = api.audit.session.snapshot.findings.find(finding => finding.absolutePath === customPath && finding.ruleId === "potential-command-injection");
    assert.ok(customFinding, "custom Source and Sink produce a live finding");
    assert.equal(customFinding.severity, "medium", "project severity override reaches the normal rule engine");

    // Cross-file navigation uses real TextEditors, and both sides are repainted on activation.
    const crossFileTrace = { steps: [
      { kind: "source", label: "input", absolutePath: smokePath, line: 1 },
      { kind: "sink", label: "custom sink", absolutePath: customPath, line: 6 },
    ] };
    await api.audit.startInteractiveTrace(crossFileTrace);
    await api.audit.selectTraceStep(1);
    assert.equal(vscode.window.activeTextEditor.document.uri.fsPath, customPath);
    assert.equal(vscode.window.tabGroups.activeTabGroup.activeTab.isPreview, true, "trace navigation uses preview tabs");
    const crossDecorations = new Map();
    api.audit._updateTraceDecorations({ document: vscode.window.activeTextEditor.document, setDecorations: (type, values) => crossDecorations.set(type, values) });
    assert.equal(crossDecorations.get(api.audit.tracePathDecorations.sink).length, 1);
    await api.audit.selectTraceStep(0);
    assert.equal(vscode.window.activeTextEditor.document.uri.fsPath, smokePath);
    api.audit._updateTraceDecorations({ document: vscode.window.activeTextEditor.document, setDecorations: (type, values) => crossDecorations.set(type, values) });
    assert.equal(crossDecorations.get(api.audit.tracePathDecorations.source).length, 1);
    assert.equal(crossDecorations.get(api.audit.tracePathDecorations.sink).length, 0);

    const sanitizerText = "export function cleanFlow(value: string) { return cleanValue(value); }";
    const sanitizerEditor = await vscode.window.showTextDocument(customUri, { preview: true });
    const replacement = new vscode.WorkspaceEdit();
    replacement.replace(customUri, new vscode.Range(0, 0, sanitizerEditor.document.lineCount, 0), sanitizerText);
    await vscode.workspace.applyEdit(replacement);
    await sanitizerEditor.document.save();
    const callColumn = sanitizerText.indexOf("cleanValue");
    sanitizerEditor.selection = new vscode.Selection(0, callColumn, 0, callColumn + "cleanValue".length);
    const originalQuickPick = vscode.window.showQuickPick;
    const originalInput = vscode.window.showInputBox;
    try {
      vscode.window.showInputBox = async () => { throw new Error("A selected call must not require typing a function name"); };
      vscode.window.showQuickPick = async choices => choices.find(choice => choice.kind === "INPUT_VALIDATION") || choices[0];
      await vscode.commands.executeCommand("traceguard.markSelectionAsSanitizer");
      const saved = JSON.parse(fs.readFileSync(configurationPath, "utf8"));
      assert.equal(saved.sanitizers[0].function, "cleanValue");
      assert.deepEqual(saved.sanitizers[0].arguments, [0]);
      assert.deepEqual(saved.sanitizers[0].capability, ["INPUT_VALIDATION"]);
      assert.ok(api.audit.session.projectConfiguration.semanticModels.some(model => model.id === `custom.${saved.sanitizers[0].id}`), "saved sanitizer hot reloads into the model");
      await vscode.commands.executeCommand("traceguard.markSelectionAsSanitizer");
      assert.equal(JSON.parse(fs.readFileSync(configurationPath, "utf8")).sanitizers.length, 1, "repeated right-click modeling does not duplicate the rule");
      await vscode.commands.executeCommand("traceguard.markSelectionAsSink");
      assert.ok(JSON.parse(fs.readFileSync(configurationPath, "utf8")).sinks.some(model => model.function === "cleanValue" && model.kind === "SQL_QUERY"), "right-click Sink modeling persists the selected effect");
    } finally {
      vscode.window.showQuickPick = originalQuickPick;
      vscode.window.showInputBox = originalInput;
    }

    fs.mkdirSync(path.dirname(excludedPath), { recursive: true });
    fs.writeFileSync(excludedPath, "export function excluded() { return runInternalCommand(readTenantValue()); }", "utf8");
    await api.audit.session.reindexFile(excludedUri);
    assert.equal(api.audit.session.analysisForUri(excludedUri), undefined, "project exclude paths stay outside the Worker file table");

    await verifyAiCommands(api.audit, customPath);
    await verifyAccessorFields(api.audit, workspaceRoot);
    await verifyNamedArguments(api.audit, workspaceRoot);
    console.log("TraceGuard smoke: named call and default checks completed");
    const validFingerprint = api.audit.session.projectConfiguration.fingerprint;
    fs.writeFileSync(configurationPath, "{ invalid json", "utf8");
    const invalid = await api.audit.session.reloadProjectConfiguration({ rebuild: false });
    assert.equal(invalid.valid, false, "invalid project configuration is rejected");
    assert.equal(api.audit.session.projectConfiguration.fingerprint, validFingerprint, "invalid edits retain the last valid semantic model");
    assert.ok((api.audit.configurationDiagnostics.get(configurationUri) || []).some(item => item.source === "TraceGuard Configuration"), "configuration errors are visible in Problems");
  } finally {
    await api.audit.session.removeFiles([smokeUri, customUri, excludedUri]);
    if (fs.existsSync(smokePath)) fs.unlinkSync(smokePath);
    if (fs.existsSync(customPath)) fs.unlinkSync(customPath);
    if (fs.existsSync(excludedPath)) fs.unlinkSync(excludedPath);
    if (fs.existsSync(path.dirname(excludedPath))) fs.rmdirSync(path.dirname(excludedPath));
    if (previousConfiguration) fs.writeFileSync(configurationPath, previousConfiguration);
    else if (fs.existsSync(configurationPath)) fs.unlinkSync(configurationPath);
    await api.audit.session.reloadProjectConfiguration({ rebuild: false, silent: true });
  }

  if (process.env.TRACEGUARD_SMOKE_MARKER) {
    fs.writeFileSync(process.env.TRACEGUARD_SMOKE_MARKER, JSON.stringify({
      extensionId: extension.id,
      active: extension.isActive,
      commandsVerified: requiredCommands.length,
      astWorkerSarifVerified: true,
      customSemanticsVerified: true,
      traceNavigationReviewAndSliceVerified: true,
      aiPromptStreamingAndCancellationVerified: true,
      accessorFieldsAndNavigationVerified: true,
      namedArgumentsAndIncrementalUpdatesVerified: true,
      clipboardMode: "in-memory",
      vscodeVersion: vscode.version,
    }));
  }
}

function flattenQuery(nodes) {
  return (nodes || []).flatMap(node => [node, ...flattenQuery(node.children || [])]);
}

async function settleSmokeIndex(audit) {
  // File/configuration events can start a workspace rebuild while a fixture
  // queues its update. Await the actual replay instead of inspecting an old
  // snapshot immediately after the queued reindexFile call returns.
  await audit.fileMonitor.flush();
  if (audit.session.indexPromise) await audit.session.indexPromise;
  await audit.session.pendingRemovals;
}

async function reindexSmokeFiles(audit, uris) {
  await settleSmokeIndex(audit);
  for (const uri of uris) await audit.session.reindexFile(uri, { throwOnError: true });
  await settleSmokeIndex(audit);
}

async function verifyAccessorFields(audit, workspaceRoot) {
  const absolutePath = path.join(workspaceRoot, "TraceGuardAccessorSmoke.java");
  const uri = vscode.Uri.file(absolutePath);
  const text = `class SmokeCommandBox {
  private String command;
  void store(String value) { this.command = value; }
  String fetch() { return this.command; }
}
class TraceGuardAccessorSmoke {
  void run(HttpServletRequest request) {
    SmokeCommandBox box = new SmokeCommandBox();
    String value = request.getParameter("cmd");
    box.store(value);
    String selected = box.fetch();
    Runtime.getRuntime().exec(selected);
  }
}`;
  try {
    fs.writeFileSync(absolutePath, text, "utf8");
    await reindexSmokeFiles(audit, [uri]);
    const accessorSnapshot = audit.session.snapshot;
    assert.ok(accessorSnapshot.findings.some(finding => finding.relativePath === path.basename(absolutePath)),
      `Extension Host exposes accessor field findings: ${JSON.stringify({ indexed: audit.session.analysisForUri(uri)?.frontend,
        findings: accessorSnapshot.findings.map(finding => [finding.relativePath, finding.ruleId]),
        functions: audit.session.analysisForUri(uri)?.ir?.functions.map(fn => [fn.name, fn.accessorSummary]) })}`);
    const query = await audit.session.queryAudit(uri, 11, "trace-backward", "selected");
    assert.ok(flattenQuery(query.roots).some(node => node.kind === "source"), "Extension Host traces getter return values through setter writes");
    audit.queryProvider.setResult(query);
    const rows = flattenTreeProvider(audit.queryProvider, audit.queryProvider.getChildren());
    const getter = rows.find(row => row.node?.label.startsWith("fetch() reads"));
    assert.ok(getter, "Trace tree exposes the accessor body");
    await vscode.commands.executeCommand(getter.command.command, ...getter.command.arguments);
    assert.equal(vscode.window.activeTextEditor.document.uri.fsPath, absolutePath);
    assert.equal(vscode.window.activeTextEditor.selection.start.line, 3, "accessor navigation opens the actual getter definition");
    await vscode.commands.executeCommand("traceguard.copyAuditQueryMarkdown");
    const markdown = await vscode.env.clipboard.readText();
    assert.match(markdown, /void store\(String value\)/);
    assert.match(markdown, /String fetch\(\)/);
  } finally {
    audit.clearAuditQuery();
    if (fs.existsSync(absolutePath)) fs.unlinkSync(absolutePath);
    await audit.session.removeFiles([uri]);
  }
}

async function verifyNamedArguments(audit, workspaceRoot) {
  const samples = [
    {
      service: "named_service.py", entry: "named_entry.py", identifier: "command",
      serviceText: 'import os\nclass NamedRunnerService:\n    def dispatch(self, prefix="ok", command="fixed"):\n        os.system(command)\n',
      entryText: 'from named_service import NamedRunnerService\ndef named_handle(request):\n    service = NamedRunnerService()\n    value = request.args.get("cmd")\n    service.dispatch(command=value, prefix="fixed")\n    service.dispatch(prefix=value)\n',
      unsafeArgs: 'command=value, prefix="fixed"', safeArgs: 'command="fixed", prefix=value',
    },
    {
      service: "NamedService.php", entry: "NamedEntry.php", identifier: "$command",
      serviceText: '<?php\nnamespace HostNamed;\nclass NamedRunnerService {\n  function dispatch($prefix="ok", $command="fixed") { system($command); }\n}',
      entryText: '<?php\nnamespace HostNamed;\nfunction named_handle() {\n  $service = new NamedRunnerService();\n  $value = $_GET["cmd"];\n  $service->dispatch(command: $value, prefix: "fixed");\n  $service->dispatch(prefix: $value);\n}',
      unsafeArgs: 'command: $value, prefix: "fixed"', safeArgs: 'command: "fixed", prefix: $value',
    },
  ];
  for (const sample of samples) {
    const servicePath = path.join(workspaceRoot, sample.service);
    const entryPath = path.join(workspaceRoot, sample.entry);
    const serviceUri = vscode.Uri.file(servicePath);
    const entryUri = vscode.Uri.file(entryPath);
    try {
      fs.writeFileSync(servicePath, sample.serviceText, "utf8");
      fs.writeFileSync(entryPath, sample.entryText, "utf8");
      await reindexSmokeFiles(audit, [serviceUri, entryUri]);
      assert.ok(audit.session.snapshot.findings.some(finding => finding.relativePath === sample.service), "named call reaches its cross-file sensitive operation");
      const query = await audit.session.queryAudit(serviceUri, 3, "trace-backward", sample.identifier);
      assert.ok(flattenQuery(query.roots).some(node => node.kind === "source"));
      assert.ok(flattenQuery(query.roots).some(node => node.details?.argumentBinding?.status === "verified"));
      audit.queryProvider.setResult(query);
      const rows = flattenTreeProvider(audit.queryProvider, audit.queryProvider.getChildren());
      assert.ok(rows.some(row => row.node?.kind === "default-argument" && row.node.status === "verified"), "Trace renders declared scalar defaults");
      const call = rows.find(row => row.node?.details?.argumentBinding?.status === "verified");
      assert.ok(call?.command, "parameter binding retains source navigation");
      await vscode.commands.executeCommand(call.command.command, ...call.command.arguments);
      assert.equal(vscode.window.activeTextEditor.document.uri.fsPath, entryPath);
      await vscode.commands.executeCommand("traceguard.copyAuditQueryMarkdown");
      const markdown = await vscode.env.clipboard.readText();
      assert.match(markdown, /Argument binding/);
      assert.match(markdown, /named_handle/);
      assert.match(markdown, /dispatch/);
      const editor = vscode.window.activeTextEditor;
      const edit = new vscode.WorkspaceEdit();
      edit.replace(entryUri, new vscode.Range(0, 0, editor.document.lineCount, 0), sample.entryText.replace(sample.unsafeArgs, sample.safeArgs));
      assert.ok(await vscode.workspace.applyEdit(edit));
      await editor.document.save();
      await reindexSmokeFiles(audit, [entryUri]);
      assert.ok(!audit.session.snapshot.findings.some(finding => finding.relativePath === sample.service), "constant named command clears the previous flow while the sibling parameter remains tainted");
    } finally {
      audit.clearAuditQuery();
      for (const file of [servicePath, entryPath]) if (fs.existsSync(file)) fs.unlinkSync(file);
      await audit.session.removeFiles([serviceUri, entryUri]);
    }
  }
}

async function verifyAiCommands(audit, absolutePath) {
  const http = require("node:http");
  const config = vscode.workspace.getConfiguration("traceguard");
  const keys = ["ai.baseUrl", "ai.model", "ai.apiKey"];
  const previous = keys.map(key => config.inspect(key)?.globalValue);
  let received;
  let cancelMode = false;
  const cancellation = new vscode.EventEmitter();
  const server = http.createServer(async (req, res) => {
    let body = "";
    for await (const chunk of req) body += chunk;
    received = { body: JSON.parse(body), key: req.headers.authorization };
    res.writeHead(200, { "content-type": "text/event-stream" });
    res.write('data: {"choices":[{"index":0,"delta":{"content":"## Local mock verdict\\n"}}]}\n\n');
    if (cancelMode) setTimeout(() => cancellation.fire(), 150);
    else setTimeout(() => res.end('data: {"choices":[{"index":0,"delta":{"content":"Evidence insufficient."},"finish_reason":"stop"}]}\n\ndata: [DONE]\n\n'), 250);
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  const originalProgress = vscode.window.withProgress;
  let secretName;
  try {
    await config.update("ai.baseUrl", `http://127.0.0.1:${server.address().port}/v1`, vscode.ConfigurationTarget.Global);
    await config.update("ai.model", "mock-model", vscode.ConfigurationTarget.Global);
    await config.update("ai.apiKey", "fallback-test-key", vscode.ConfigurationTarget.Global);
    const chain = { steps: [{ kind: "sink", absolutePath, relativePath: "custom.ts", line: 1, code: "cleanValue(value)" }] };
    await vscode.commands.executeCommand("traceguard.copyAiPrompt", { flowPath: chain });
    const copied = await vscode.env.clipboard.readText();
    assert.match(copied, /cleanFlow/);
    assert.match(copied, /Remediation/);
    assert.equal(received, undefined, "copy mode does not call the LLM");
    secretName = audit.ai.settings().secretName;
    await audit.context.secrets.store(secretName, "secret-test-key");
    const uri = await vscode.commands.executeCommand("traceguard.verifyChainWithAi", { flowPath: chain });
    assert.equal(uri.scheme, "traceguard-ai");
    assert.equal(received.key, "Bearer secret-test-key", "SecretStorage takes precedence over plaintext settings");
    assert.equal(received.body.model, "mock-model");
    assert.match(received.body.messages[1].content, /cleanFlow/);
    assert.match(audit.ai.provider.provideTextDocumentContent(uri), /Local mock verdict/);
    assert.ok(audit.ai.provider.provideTextDocumentContent(uri).includes(require("../src/ai/locale").aiStrings(vscode.env.language).complete));
    const document = await vscode.workspace.openTextDocument(uri);
    assert.equal(document.languageId, "markdown");
    assert.equal(audit.ai.requests.size, 0);
    cancelMode = true;
    vscode.window.withProgress = (_options, task) => task({}, { isCancellationRequested: false, onCancellationRequested: cancellation.event });
    const cancelled = await vscode.commands.executeCommand("traceguard.verifyChainWithAi", { flowPath: chain });
    assert.ok(audit.ai.provider.provideTextDocumentContent(cancelled).includes(require("../src/ai/locale").aiStrings(vscode.env.language).cancelled));
    assert.equal(audit.ai.requests.size, 0);
    await vscode.commands.executeCommand("traceguard.clearAiApiKey");
    assert.equal(await audit.context.secrets.get(secretName), undefined);
  } finally {
    vscode.window.withProgress = originalProgress;
    cancellation.dispose();
    if (secretName) await audit.context.secrets.delete(secretName);
    for (let index = 0; index < keys.length; index++) await config.update(keys[index], previous[index], vscode.ConfigurationTarget.Global);
    await new Promise(resolve => { server.close(resolve); server.closeAllConnections(); });
  }
}

function flattenTreeProvider(provider, nodes) {
  return (nodes || []).flatMap(node => [node, ...flattenTreeProvider(provider, provider.getChildren(node))]);
}

module.exports = { run };
