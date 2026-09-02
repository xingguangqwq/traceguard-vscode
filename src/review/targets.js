"use strict";

const path = require("path");
const { legacyHash, normalizePath, stableHash } = require("../identity");

// Reading-order heuristics only. This layer ranks what deserves human attention
// first; it must not decide exploitability. Vulnerability candidates come from
// rules/rule-engine, structure and signals come from the language front-ends.
const SENSITIVE_PATH = /(?:auth|login|admin|upload|download|payment|billing|token|secret|config|account|user|permission|session|webhook|callback)/i;

const PRIORITY_RANK = { P0: 0, P1: 1, P2: 2, Backlog: 3 };

function buildReviewTargets(analysis, options = {}) {
  const items = [];
  const entryFunctionLines = new Set(analysis.entries.map(entry => entry.functionLine).filter(Boolean));

  for (const entry of analysis.entries) {
    const fn = analysis.functions.find(candidate => candidate.line === entry.functionLine);
    const scopedSignals = fn?.signals || analysis.signals.filter(signal => Math.abs(signal.line - entry.line) <= 35);
    items.push(prioritizeTarget({
      kind: "endpoint",
      title: entry.title,
      functionName: fn?.name || entry.functionName || "request handler",
      line: entry.line,
      endLine: fn?.endLine || entry.endLine || entry.line,
      signals: scopedSignals,
      absolutePath: analysis.absolutePath,
      relativePath: analysis.relativePath,
      language: analysis.language,
      sensitivePath: SENSITIVE_PATH.test(analysis.relativePath),
      functionId: fn?.id || entry.functionId,
      entryFunctionIds: [fn?.id || entry.functionId].filter(Boolean),
      reachableFromEntry: true,
      containsUnresolvedCalls: options.unresolvedFunctionIds?.has(fn?.id || entry.functionId) || false,
      symbolKey: ["endpoint", fn?.symbolKey || entry.symbolKey || "unresolved", entry.method, entry.route].join("::"),
      legacyStableKey: ["endpoint", entry.method, entry.route, fn?.name || entry.functionName || "request handler"].join(":"),
    }));
  }

  for (const fn of analysis.functions) {
    if (entryFunctionLines.has(fn.line)) continue;
    const hasSource = fn.signals.some(signal => signal.kind === "source");
    const sinks = fn.signals.filter(signal => signal.kind === "sink");
    const hasSensitiveFlow = (hasSource && sinks.length > 0) ||
      sinks.some(signal => ["command", "expression", "deserialization"].includes(signal.category)) ||
      (hasSource && SENSITIVE_PATH.test(`${analysis.relativePath} ${fn.name}`));
    const reachableFromEntry = options.reachableFunctionIds?.has(fn.id) || false;
    if (!hasSensitiveFlow && !reachableFromEntry) continue;
    items.push(prioritizeTarget({
      kind: "function",
      title: `${fn.name}()`,
      functionName: fn.name,
      line: fn.line,
      endLine: fn.endLine,
      signals: fn.signals,
      absolutePath: analysis.absolutePath,
      relativePath: analysis.relativePath,
      language: analysis.language,
      sensitivePath: SENSITIVE_PATH.test(`${analysis.relativePath} ${fn.name}`),
      backlog: !hasSensitiveFlow,
      functionId: fn.id,
      entryFunctionIds: [...(options.entryFunctionIdsByFunctionId?.get(fn.id) || [])],
      reachableFromEntry,
      containsUnresolvedCalls: options.unresolvedFunctionIds?.has(fn.id) || false,
      symbolKey: fn.symbolKey,
      legacyStableKey: ["function", fn.name, normalizeParameters(fn.parameters)].join(":"),
    }));
  }

  const coveredLines = new Set(analysis.functions.flatMap(fn => range(fn.line, fn.endLine)));
  const globalSensitive = analysis.signals.filter(signal => signal.kind === "sink" && !coveredLines.has(signal.line));
  if (globalSensitive.length && !items.some(item => item.kind === "endpoint")) {
    const globalFunction = analysis.ir?.functions.find(fn => fn.isGlobal);
    items.push(prioritizeTarget({
      kind: "file",
      title: `File-level execution: ${path.basename(analysis.relativePath)}`,
      functionName: "global scope",
      line: globalSensitive[0].line,
      endLine: analysis.lines,
      signals: analysis.signals.filter(signal => !coveredLines.has(signal.line)),
      absolutePath: analysis.absolutePath,
      relativePath: analysis.relativePath,
      language: analysis.language,
      sensitivePath: SENSITIVE_PATH.test(analysis.relativePath),
      symbolKey: globalFunction?.symbolKey || [analysis.language, normalizePath(analysis.relativePath), "global"].join("::"),
      legacyStableKey: "global-scope",
    }));
  }

  return items;
}

function prioritizeTarget(input) {
  const sources = input.signals.filter(signal => signal.kind === "source");
  const sinks = input.signals.filter(signal => signal.kind === "sink");
  const auth = input.signals.filter(signal => signal.kind === "auth");
  const sanitizers = input.signals.filter(signal => signal.kind === "sanitizer");
  const categories = [...new Set(sinks.map(signal => signal.category))];
  let score = input.kind === "endpoint" ? 18 : 5;
  score += Math.min(16, sources.length * 4) + Math.min(27, sinks.length * 9);
  if (sources.length && sinks.some(signal => ["command", "expression", "deserialization"].includes(signal.category))) score += 10;
  if (input.kind === "endpoint" && sinks.length && !auth.length) score += 10;
  if (sources.length && sinks.length && !sanitizers.length) score += 8;
  if (input.sensitivePath) score += 5;
  const priority = input.backlog ? "Backlog" : score >= 50 ? "P0" : score >= 32 ? "P1" : "P2";
  const reasons = [];
  if (input.kind === "endpoint") reasons.push("Externally reachable entry point");
  if (sources.length) reasons.push(`${sources.length} untrusted input signal${sources.length > 1 ? "s" : ""}`);
  if (sinks.length) reasons.push(`${sinks.length} sensitive operation${sinks.length > 1 ? "s" : ""}: ${categories.join(", ")}`);
  if (input.kind === "endpoint" && !auth.length) reasons.push("No obvious authorization decision in local scope");
  if (sources.length && sinks.length && !sanitizers.length) reasons.push("No obvious validation or encoding signal in local scope");
  if (input.sensitivePath) reasons.push("Security-sensitive file or function name");
  if (input.backlog) reasons.push("Ordinary function retained as reachable-code review backlog");
  return {
    id: `review_${stableHash(`${input.kind}:${input.symbolKey}`)}`,
    legacyIds: [...new Set([
      legacyHash(`${input.relativePath}:${input.line}:${input.kind}:${input.functionName}`),
      legacyHash(`${normalizePath(input.relativePath)}:${input.kind}:${input.legacyStableKey || input.functionName}`),
    ])],
    ...input,
    score,
    priority,
    reasons,
    categories,
    counts: { sources: sources.length, sinks: sinks.length, auth: auth.length, sanitizers: sanitizers.length },
    checklist: buildChecklist({ sources, sinks, auth, sanitizers }),
  };
}

function normalizeParameters(parameters) {
  return String(parameters || "").replace(/\s+/g, " ").trim();
}

function buildChecklist(groups) {
  return [
    { id: "boundary", label: "Identify caller, trust boundary and expected input", state: groups.sources.length ? "inspect" : "unknown", evidence: `${groups.sources.length} input signal(s)` },
    { id: "authentication", label: "Confirm authentication is required and enforced", state: groups.auth.length ? "observed" : "inspect", evidence: groups.auth[0]?.label || "No local authentication signal" },
    { id: "authorization", label: "Verify object- and action-level authorization", state: "inspect", evidence: "Requires reviewer confirmation" },
    { id: "validation", label: "Trace validation, canonicalization and output encoding", state: groups.sanitizers.length ? "observed" : "inspect", evidence: groups.sanitizers[0]?.label || "No local validation signal" },
    { id: "sinks", label: "Trace every sensitive operation back to its source", state: groups.sinks.length ? "inspect" : "unknown", evidence: `${groups.sinks.length} sensitive operation(s)` },
    { id: "failure", label: "Review failure paths, logging and sensitive data exposure", state: "inspect", evidence: "Manual review required" },
  ];
}

function compareTargets(left, right) {
  return (PRIORITY_RANK[left.priority] ?? 3) - (PRIORITY_RANK[right.priority] ?? 3) ||
    right.score - left.score ||
    left.relativePath.localeCompare(right.relativePath);
}

function calibrateReviewTargets(items, findings = []) {
  return (items || []).map(item => {
    const linkedFindings = (findings || []).filter(finding => findingTouchesTarget(finding, item));
    if (linkedFindings.length) {
      const paths = linkedFindings.flatMap(uniqueFindingPaths);
      const hasSupportedPath = paths.length
        ? paths.some(pathIsVerified)
        : linkedFindings.some(finding => ["high", "medium"].includes(String(finding.confidence || "").toLowerCase()));
      const containsUnresolvedCalls = paths.some(pathHasUnresolvedCall);
      const priority = item.kind === "endpoint"
        ? hasSupportedPath ? "P0" : "P1"
        : item.backlog && !containsUnresolvedCalls ? "Backlog" : "P2";
      return {
        ...item,
        priority,
        confidence: hasSupportedPath ? "verified" : "review",
        verifiedFindingIds: linkedFindings.map(finding => finding.id),
        reachableFromEntry: item.reachableFromEntry || item.kind === "endpoint" || linkedFindings.some(findingReachesEntry),
        containsUnresolvedCalls: item.containsUnresolvedCalls || containsUnresolvedCalls,
        reasons: [...item.reasons, item.kind === "endpoint" && hasSupportedPath
          ? "Entry reaches a data-flow-proven dangerous operation"
          : containsUnresolvedCalls
            ? "Entry-related path contains an unresolved or heuristic call"
            : `${linkedFindings.length} security-relevant flow${linkedFindings.length === 1 ? "" : "s"} crosses this target`],
      };
    }
    if (item.priority !== "P0") return {
      ...item,
      priority: item.kind === "endpoint" && item.containsUnresolvedCalls ? "P1" : item.priority,
      confidence: "review",
      verifiedFindingIds: [],
      reachableFromEntry: item.reachableFromEntry || item.kind === "endpoint",
      containsUnresolvedCalls: Boolean(item.containsUnresolvedCalls),
    };
    return {
      ...item,
      priority: "P1",
      confidence: "review",
      verifiedFindingIds: [],
      reachableFromEntry: true,
      containsUnresolvedCalls: true,
      reasons: [...item.reasons, "Source and sink clues are present, but no Source to Sink path is verified"],
    };
  }).sort(compareTargets);
}

function uniqueFindingPaths(finding) {
  const paths = [...(finding?.paths || []), finding?.path].filter(Boolean);
  return [...new Map(paths.map(flow => [
    flow.id || (flow.steps || []).map(step => `${step.functionId}:${step.operationId}:${step.kind}`).join("|"),
    flow,
  ])).values()];
}

function pathIsVerified(flow) {
  if (flow?.sink?.semanticVerification === "candidate" || /unverified/.test(flow?.sink?.candidateStatus || "")) return false;
  if (["low", "review"].includes(String(flow?.confidence || "").toLowerCase())) return false;
  return !(flow?.steps || []).some(step => step.analysisStatus === "heuristic" || step.analysisStatus === "unresolved" ||
    (step.kind === "call" && step.candidateMatch && step.candidateMatch !== "high"));
}

function pathHasUnresolvedCall(flow) {
  return !pathIsVerified(flow) || (flow?.steps || []).some(step =>
    step.analysisStatus === "unresolved" || step.analysisStatus === "heuristic" ||
    (step.kind === "call" && (step.candidateReason || (step.candidateMatch && step.candidateMatch !== "high"))));
}

function findingReachesEntry(finding) {
  return uniqueFindingPaths(finding).some(flow => (flow.steps || []).some(step =>
    step.kind === "entry" || step.entryPoint || step.source?.entryPoint));
}

function findingTouchesTarget(finding, target) {
  const targetPath = normalizePath(target.absolutePath);
  const findingPaths = [...(finding.paths || []), finding.path].filter(Boolean);
  const uniquePaths = [...new Map(findingPaths.map(flow => [
    flow.id || (flow.steps || []).map(step => `${step.functionId}:${step.operationId}:${step.kind}`).join("|"),
    flow,
  ])).values()];
  const paths = [
    { absolutePath: finding.absolutePath, relativePath: finding.relativePath, line: finding.line || finding.sinkLine || finding.sourceLine },
    ...uniquePaths.flatMap(flow => flow.steps || []).map(step => ({
      absolutePath: step.absolutePath,
      relativePath: step.relativePath,
      line: step.line,
    })),
    ...((finding.steps || []).map(step => ({
      absolutePath: step.absolutePath,
      relativePath: step.relativePath,
      line: step.line,
    }))),
  ];
  return paths.some(location => {
    const sameAbsolutePath = location.absolutePath && normalizePath(location.absolutePath) === targetPath;
    const sameRelativePath = !location.absolutePath && location.relativePath &&
      normalizePath(location.relativePath) === normalizePath(target.relativePath);
    if (!sameAbsolutePath && !sameRelativePath) return false;
    if (target.kind === "endpoint" || target.kind === "file" || !location.line) return true;
    return location.line >= target.line && location.line <= target.endLine;
  });
}

function severityRank(severity) {
  return ({ critical: 0, high: 1, medium: 2, low: 3 })[String(severity || "low").toLowerCase()] ?? 3;
}

function range(start, end) {
  return Array.from({ length: Math.max(0, end - start + 1) }, (_, index) => start + index);
}

module.exports = { SENSITIVE_PATH, buildChecklist, buildReviewTargets, calibrateReviewTargets, compareTargets, prioritizeTarget };
