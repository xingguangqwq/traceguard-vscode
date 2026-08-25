"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vscode = require("vscode");
const { selectedAccessPath } = require("../src/audit-controller");

async function run() {
  const extension = vscode.extensions.getExtension("traceguard.traceguard-vscode");
  assert.ok(extension, "TraceGuard is visible to the Extension Host");

  const api = await extension.activate();
  assert.equal(extension.isActive, true, "TraceGuard activates successfully");
  assert.ok(api?.audit?.session, "TraceGuard creates its audit session");
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
    "traceguard.traceCrossFileFlow",
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
    "traceguard.openProjectConfiguration",
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
    fs.writeFileSync(smokePath, "export function proxy(req: any) { return fetch(req.query.url); }", "utf8");
    await api.audit.session.reindexFile(smokeUri);
    let snapshot = api.audit.session.snapshot;
    assert.equal(api.audit.session.analysisForUri(smokeUri).frontend.mode, "ast", "AST frontend runs inside Extension Host");
    assert.ok(snapshot.findings.some(finding => finding.ruleId === "potential-ssrf"), "Worker produces an SSRF finding inside Extension Host");

    fs.writeFileSync(smokePath, "export function proxy(req: any) { return exec(req.query.cmd); }", "utf8");
    await api.audit.session.reindexFile(smokeUri);
    snapshot = api.audit.session.snapshot;
    assert.ok(snapshot.findings.some(finding => finding.ruleId === "potential-command-injection"), "incremental Worker update replaces the finding");
    assert.ok(!snapshot.findings.some(finding => finding.ruleId === "potential-ssrf"), "stale incremental findings are removed");
    assert.equal(snapshot.incrementallyInvalidatedFiles, 1);

    const query = await api.audit.session.queryAudit(smokeUri, 0, "reachable-sinks", "req.query.cmd");
    assert.equal(query.schema, "traceguard-audit-query", "persistent Worker serves the audit query protocol");
    assert.ok(flattenQuery(query.roots).some(node => node.kind === "sink"), "audit query reaches the incrementally updated command sink");
    assert.ok(flattenQuery(query.roots).every(node => node.status && node.reason), "every query step explains its confidence and connection");
    api.audit.queryProvider.setResult(query);
    assert.equal(api.audit.queryProvider.current, query, "audit query tree receives the live query result");

    const debug = api.audit.session.debugAnalysisForUri(smokeUri, query);
    assert.equal(debug.schema, "traceguard-analysis-debug");
    assert.doesNotThrow(() => JSON.stringify(debug), "analysis debug payload is serializable");

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

    fs.mkdirSync(path.dirname(excludedPath), { recursive: true });
    fs.writeFileSync(excludedPath, "export function excluded() { return runInternalCommand(readTenantValue()); }", "utf8");
    await api.audit.session.reindexFile(excludedUri);
    assert.equal(api.audit.session.analysisForUri(excludedUri), undefined, "project exclude paths stay outside the Worker file table");

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
      vscodeVersion: vscode.version,
    }));
  }
}

function flattenQuery(nodes) {
  return (nodes || []).flatMap(node => [node, ...flattenQuery(node.children || [])]);
}

module.exports = { run };
