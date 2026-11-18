"use strict";

const vscode = require("vscode");
const { findingPool } = require("../review/finding-pool");

function diagnosticSeverity(severity, confidence = "high") {
  if (["low", "review"].includes(confidence)) return vscode.DiagnosticSeverity.Information;
  if (confidence === "medium" && (severity === "critical" || severity === "high")) return vscode.DiagnosticSeverity.Warning;
  if (severity === "critical" || severity === "high") return vscode.DiagnosticSeverity.Error;
  if (severity === "medium") return vscode.DiagnosticSeverity.Warning;
  return vscode.DiagnosticSeverity.Information;
}

function updateDiagnostics(collection, snapshot) {
    if (snapshot.indexStale) {
      collection.clear();
      return;
    }
    const byUri = new Map();
    for (const finding of snapshot.findings) {
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
    collection.clear();
    collection.set([...byUri.values()].map(item => [item.uri, item.diagnostics]));
  }

function updateConfigurationDiagnostics(collection, issues) {
    const byUri = new Map();
    for (const issue of issues) {
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
    collection.clear();
    collection.set([...byUri.values()].map(item => [item.uri, item.diagnostics]));
  }

module.exports = { updateDiagnostics, updateConfigurationDiagnostics };
