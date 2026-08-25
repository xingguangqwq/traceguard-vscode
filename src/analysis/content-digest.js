"use strict";

const { stableHash } = require("../identity");

function analysisContentDigest(item) {
  return String(item?.id || "").startsWith("finding_") || item?.kind === "finding"
    ? findingDigest(item)
    : pathDigest(item);
}

function findingDigest(finding = {}) {
  return digest([
    finding.id, finding.ruleId, finding.severity, finding.confidence,
    finding.sourceKind, finding.sinkKind, finding.absolutePath, finding.line, finding.functionName,
    finding.observedGuards || [], finding.missingGuards || [], finding.guardHints || [],
    (finding.paths || (finding.path ? [finding.path] : [])).map(pathDigest),
  ]);
}

function pathDigest(flow = {}) {
  return digest([
    flow.id, flow.rootFunctionId, flow.sourceKind, flow.sinkKind, flow.category, flow.confidence,
    flow.reviewPriority, flow.guardCapabilities || [], flow.guardHints || [], flow.controls || {},
    (flow.steps || []).map(step => [
      step.kind, step.operationId, step.functionId, step.symbolKey, step.absolutePath, step.line,
      step.label, step.certainty, step.semanticModelId, step.semanticVerification, step.candidateStatus,
      step.candidateMatch, step.analysisStatus, step.guardCapabilities || [], step.guardDominance,
      step.inputAccessPath, step.outputAccessPath,
    ]),
  ]);
}

function digest(value) {
  return stableHash(JSON.stringify(value));
}

module.exports = { analysisContentDigest, findingDigest, pathDigest };
