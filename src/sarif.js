"use strict";

function buildSarif(snapshot) {
  const rules = new Map();
  const results = [];
  for (const finding of snapshot.findings || []) {
    if (!rules.has(finding.ruleId)) rules.set(finding.ruleId, sarifRule(finding));
    results.push(sarifResult(finding));
  }
  return {
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [{
      tool: {
        driver: {
          name: "TraceGuard",
          informationUri: "https://github.com/xingguangqwq/traceguard-vscode",
          semanticVersion: "0.7.0",
          rules: [...rules.values()],
        },
      },
      automationDetails: { id: "traceguard/local-incremental-sast" },
      invocations: [{
        executionSuccessful: true,
        properties: {
          indexIncomplete: Boolean(snapshot.indexIncomplete),
          skippedFiles: snapshot.indexSkippedFiles || 0,
          skippedFileDetails: snapshot.indexSkippedDetails || [],
          parserCapabilities: snapshot.languageCapabilities || {},
        },
      }],
      results,
    }],
  };
}

function sarifRule(finding) {
  return {
    id: finding.ruleId,
    name: finding.title.replace(/[^A-Za-z0-9]+/g, ""),
    shortDescription: { text: finding.title },
    fullDescription: { text: `TraceGuard found an explainable ${finding.sourceKind} to ${finding.sinkKind} data-flow candidate.` },
    help: { text: `Verify the Source → Sink path and the missing rule-specific guards: ${(finding.missingGuards || []).join(", ") || "none"}.` },
    properties: {
      tags: ["security", finding.cwe].filter(Boolean),
      precision: confidencePrecision(finding.confidence),
      securitySeverity: severityScore(finding.severity),
    },
  };
}

function sarifResult(finding) {
  const result = {
    ruleId: finding.ruleId,
    level: sarifLevel(finding.severity),
    message: { text: messageFor(finding) },
    locations: [sarifLocation(finding.relativePath, finding.line, `${finding.title} sink`) ],
    codeFlows: (finding.paths || [finding.path]).filter(Boolean).map(path => ({
      threadFlows: [{
        locations: path.steps.map((step, index) => ({
          location: sarifLocation(step.relativePath, step.line, `${index + 1}. ${step.label}`),
          kinds: [step.kind],
          importance: step.kind === "source" || step.kind === "sink" ? "essential" : "important",
        })),
      }],
    })),
    partialFingerprints: { "traceguardFindingId/v1": finding.id },
    properties: {
      confidence: finding.confidence,
      status: finding.status || "open",
      sourceKind: finding.sourceKind,
      sinkKind: finding.sinkKind,
      observedGuards: finding.observedGuards || [],
      missingGuards: finding.missingGuards || [],
      heuristicSteps: finding.explanation?.heuristics || [],
    },
  };
  if (["false_positive", "accepted_risk", "suppressed"].includes(finding.status)) {
    result.suppressions = [{
      kind: "external",
      status: "accepted",
      justification: `TraceGuard workspace decision: ${finding.status.replaceAll("_", " ")}`,
    }];
  }
  return result;
}

function sarifLocation(relativePath, line, message) {
  return {
    physicalLocation: {
      artifactLocation: { uri: String(relativePath || "unknown").replaceAll("\\", "/"), uriBaseId: "%SRCROOT%" },
      region: { startLine: Math.max(1, Number(line) || 1) },
    },
    message: { text: message },
  };
}

function messageFor(finding) {
  const missing = finding.missingGuards?.length ? ` Missing guards: ${finding.missingGuards.join(", ")}.` : "";
  const heuristic = finding.explanation?.heuristics?.length ? ` Heuristic steps: ${finding.explanation.heuristics.join("; ")}.` : "";
  return `${finding.title}: ${finding.sourceKind} reaches ${finding.sinkKind}.${missing}${heuristic}`;
}

function sarifLevel(severity) { return { critical: "error", high: "error", medium: "warning", low: "note" }[severity] || "warning"; }
function confidencePrecision(confidence) { return { high: "high", medium: "medium", review: "low" }[confidence] || "medium"; }
function severityScore(severity) { return { critical: "9.5", high: "8.0", medium: "5.5", low: "3.0" }[severity] || "5.0"; }

module.exports = { buildSarif, sarifLevel };
