"use strict";

const { stableHash } = require("../identity");
const { compareRisk, scoreRisk } = require("../risk/scorer");
const { RULES } = require("./definitions");
const { configurationForAbsolutePath } = require("../config/configuration-scope");

function evaluateFlowPaths(paths, rules = RULES, options = {}) {
  const findings = [];
  const ruleCache = new Map();
  for (const flow of paths) {
    const configuration = configurationForAbsolutePath(options, flow.sink.absolutePath);
    const configurationKey = configuration?.ruleFingerprint || configuration?.fingerprint || "default";
    let activeRules = ruleCache.get(configurationKey);
    if (!activeRules) {
      activeRules = configuredRules(rules || RULES, configuration);
      ruleCache.set(configurationKey, activeRules);
    }
    for (const rule of activeRules) {
      if (!rule.sourceKinds.includes(flow.sourceKind) || !rule.sinkKinds.includes(flow.sinkKind)) continue;
      const observedGuards = flow.guardCapabilities || [];
      if ((rule.sanitizerCapabilities || []).some(capability => observedGuards.includes(capability))) continue;
      const missingGuards = rule.recommendedGuards.filter(capability => !observedGuards.includes(capability));
      const risk = scoreRisk(rule, flow, missingGuards);
      findings.push({
        id: `finding_${stableHash(`${rule.id}:${flow.sink.workspaceRoot || ""}:${flow.sink.symbolKey}:${flow.sink.operationId || flow.sink.label}`)}`,
        workspaceRoot: flow.sink.workspaceRoot,
        kind: "finding",
        ruleId: rule.id,
        title: rule.title,
        cwe: rule.cwe,
        severity: risk.severity,
        confidence: risk.confidence,
        risk,
        sourceKind: flow.sourceKind,
        sinkKind: flow.sinkKind,
        observedGuards,
        guardHints: flow.guardHints || [],
        missingGuards,
        path: flow,
        absolutePath: flow.sink.absolutePath,
        relativePath: flow.sink.relativePath,
        line: flow.sink.line,
        functionName: flow.sink.functionName,
        paths: [flow],
        pathIds: [flow.id],
        pathCount: 1,
        explanation: explainFinding(rule, flow, observedGuards, missingGuards, risk),
      });
    }
  }
  const grouped = new Map();
  for (const finding of findings) {
    const existing = grouped.get(finding.id);
    if (!existing) {
      grouped.set(finding.id, finding);
      continue;
    }
    const primary = compareRisk(finding, existing) < 0 ? finding : existing;
    const paths = [...existing.paths, finding.path];
    grouped.set(finding.id, {
      ...primary,
      paths,
      pathIds: paths.map(item => item.id),
      pathCount: paths.length,
    });
  }
  return [...grouped.values()].sort(compareRisk);
}

function explainFinding(rule, flow, observedGuards, missingGuards, risk) {
  const propagation = flow.steps
    .filter(step => !["source", "sink", "validation", "authorization"].includes(step.kind))
    .map(step => ({
      kind: step.kind,
      label: step.label,
      symbolKey: step.symbolKey,
      relativePath: step.relativePath,
      line: step.line,
      status: step.analysisStatus || (step.kind === "call" ? callEvidenceStatus(step.candidateMatch) : "verified"),
      heuristic: step.kind === "call" ? step.candidateMatch !== "high" : ["heuristic", "unresolved"].includes(step.analysisStatus),
      reason: step.propagationReason || step.candidateReason,
      inputAccessPath: step.inputAccessPath,
      outputAccessPath: step.outputAccessPath,
    }));
  const heuristics = propagation.filter(step => step.heuristic).map(step => step.reason || "heuristic call resolution");
  if (["unverified", "symbol-unverified", "regex-unverified", "ast-validated-symbol-unverified"].includes(flow.sink.candidateStatus)) {
    heuristics.push("The sink name is a regex candidate that could not be verified to a modeled symbol.");
  }
  if (flow.sink.semanticVerification === "syntax") heuristics.push("The sink was matched by AST syntax without project-level symbol proof.");
  if (flow.sink.semanticVerification === "candidate") {
    heuristics.push("The method name matches a security sink, but the receiver type could not be resolved; review is required.");
  }
  return {
    source: { kind: flow.sourceKind, label: flow.source.label, relativePath: flow.source.relativePath, line: flow.source.line },
    propagation,
    sink: { kind: flow.sinkKind, label: flow.sink.label, relativePath: flow.sink.relativePath, line: flow.sink.line },
    observedGuards,
    guardHints: flow.guardHints || [],
    missingGuards,
    confidence: risk.confidence,
    confidenceReason: heuristics.length ? "One or more semantic facts used heuristic, syntax-only, or unresolved matching." : "The path is based on direct local def-use and resolved calls.",
    heuristics,
    ruleSemantics: {
      sources: rule.sourceKinds,
      propagators: rule.propagators || [],
      sinks: rule.sinkKinds,
      sanitizers: rule.sanitizerCapabilities || [],
    },
  };
}

function callEvidenceStatus(match) {
  if (match === "high") return "verified";
  if (match === "medium") return "syntax-only";
  if (match === "review") return "heuristic";
  return "unresolved";
}

function configuredRules(rules, configuration = {}) {
  const controls = configuration?.rules || {};
  return rules
    .filter(rule => controls[rule.id]?.enabled !== false)
    .map(rule => controls[rule.id]?.severity ? { ...rule, severity: controls[rule.id].severity } : rule);
}

module.exports = { configuredRules, evaluateFlowPaths };
