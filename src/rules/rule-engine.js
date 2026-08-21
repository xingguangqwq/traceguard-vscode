"use strict";

const crypto = require("crypto");
const { compareRisk, scoreRisk } = require("../risk/scorer");
const { RULES } = require("./definitions");

function evaluateFlowPaths(paths, rules = RULES) {
  const findings = [];
  for (const flow of paths) {
    for (const rule of rules) {
      if (!rule.sourceKinds.includes(flow.sourceKind) || !rule.sinkKinds.includes(flow.sinkKind)) continue;
      const observedGuards = flow.guardCapabilities || [];
      if ((rule.sanitizerCapabilities || []).some(capability => observedGuards.includes(capability))) continue;
      const missingGuards = rule.recommendedGuards.filter(capability => !observedGuards.includes(capability));
      const risk = scoreRisk(rule, flow, missingGuards);
      findings.push({
        id: hash(`${rule.id}:${flow.sink.absolutePath}:${flow.sink.line}:${flow.sink.functionName || ""}`),
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
        missingGuards,
        path: flow,
        absolutePath: flow.sink.absolutePath,
        relativePath: flow.sink.relativePath,
        line: flow.sink.line,
        functionName: flow.sink.functionName,
        paths: [flow],
        pathIds: [flow.id],
        pathCount: 1,
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

function hash(value) {
  return crypto.createHash("sha1").update(String(value)).digest("hex").slice(0, 16);
}

module.exports = { evaluateFlowPaths };
