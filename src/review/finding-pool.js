"use strict";

function findingPaths(finding) {
  const paths = [...(finding?.paths || []), finding?.path].filter(Boolean);
  const seen = new Set();
  return paths.filter(flow => {
    const key = flow.id || (flow.steps || []).map(step => `${step.functionId}:${step.operationId}:${step.kind}`).join("|");
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function pathVerificationStatus(flow) {
  if (flow?.sink?.semanticVerification === "candidate" || /unverified/.test(flow?.sink?.candidateStatus || "")) return "unresolved";
  if ((flow?.steps || []).some(step => step.analysisStatus === "unresolved" || /unresolved/.test(step.candidateStatus || ""))) return "unresolved";
  if (flow?.sink?.semanticVerification === "syntax" || ["low", "review"].includes(flow?.confidence) ||
    (flow?.steps || []).some(step => step.analysisStatus === "heuristic" ||
      (step.kind === "call" && step.candidateMatch && step.candidateMatch !== "high"))) return "heuristic";
  if ((flow?.steps || []).some(step => step.analysisStatus === "syntax-only" || step.semanticVerification === "syntax")) return "syntax-only";
  return "verified";
}

function findingPool(finding) {
  if (finding?.status && finding.status !== "open") return "resolved";
  const paths = findingPaths(finding);
  if (paths.some(flow => pathVerificationStatus(flow) === "verified")) return "verified";
  if (!paths.length && !["low", "review"].includes(finding?.confidence)) return "verified";
  return "review";
}

module.exports = { findingPaths, findingPool, pathVerificationStatus };
