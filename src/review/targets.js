"use strict";

const crypto = require("crypto");
const path = require("path");

// Reading-order heuristics only. This layer ranks what deserves human attention
// first; it must not decide exploitability. Vulnerability candidates come from
// rules/rule-engine, structure and signals come from the language front-ends.
const SENSITIVE_PATH = /(?:auth|login|admin|upload|download|payment|billing|token|secret|config|account|user|permission|session|webhook|callback)/i;

const PRIORITY_RANK = { P0: 0, P1: 1, P2: 2 };

function buildReviewTargets(analysis) {
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
      stableKey: ["endpoint", entry.method, entry.route, fn?.name || entry.functionName || "request handler"].join(":"),
    }));
  }

  for (const fn of analysis.functions) {
    if (entryFunctionLines.has(fn.line)) continue;
    const hasSensitiveFlow = fn.signals.some(signal => signal.kind === "sink") ||
      (fn.signals.some(signal => signal.kind === "source") && SENSITIVE_PATH.test(`${analysis.relativePath} ${fn.name}`));
    if (!hasSensitiveFlow) continue;
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
      stableKey: ["function", fn.name, normalizeParameters(fn.parameters)].join(":"),
    }));
  }

  const coveredLines = new Set(analysis.functions.flatMap(fn => range(fn.line, fn.endLine)));
  const globalSensitive = analysis.signals.filter(signal => signal.kind === "sink" && !coveredLines.has(signal.line));
  if (globalSensitive.length && !items.some(item => item.kind === "endpoint")) {
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
      stableKey: "global-scope",
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
  const priority = score >= 50 ? "P0" : score >= 32 ? "P1" : "P2";
  const reasons = [];
  if (input.kind === "endpoint") reasons.push("Externally reachable entry point");
  if (sources.length) reasons.push(`${sources.length} untrusted input signal${sources.length > 1 ? "s" : ""}`);
  if (sinks.length) reasons.push(`${sinks.length} sensitive operation${sinks.length > 1 ? "s" : ""}: ${categories.join(", ")}`);
  if (input.kind === "endpoint" && !auth.length) reasons.push("No obvious authorization decision in local scope");
  if (sources.length && sinks.length && !sanitizers.length) reasons.push("No obvious validation or encoding signal in local scope");
  if (input.sensitivePath) reasons.push("Security-sensitive file or function name");
  return {
    id: shortHash(`${normalizePath(input.relativePath)}:${input.kind}:${input.stableKey || input.functionName}`),
    legacyIds: [shortHash(`${input.relativePath}:${input.line}:${input.kind}:${input.functionName}`)],
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

function normalizePath(value) {
  return String(value || "").replaceAll("\\", "/").toLowerCase();
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

function range(start, end) {
  return Array.from({ length: Math.max(0, end - start + 1) }, (_, index) => start + index);
}

function shortHash(value) {
  return crypto.createHash("sha1").update(value).digest("hex").slice(0, 16);
}

module.exports = { SENSITIVE_PATH, buildChecklist, buildReviewTargets, compareTargets, prioritizeTarget };
