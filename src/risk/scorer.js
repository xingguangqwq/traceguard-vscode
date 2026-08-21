"use strict";

const SEVERITY_ORDER = Object.freeze({ critical: 0, high: 1, medium: 2, low: 3, info: 4 });
const CONFIDENCE_ORDER = Object.freeze({ high: 0, medium: 1, low: 2 });

function scoreRisk(rule, flow, missingGuards) {
  const confidence = flow.confidence === "high" ? "high" : flow.confidence === "medium" ? "medium" : "low";
  const external = flow.sourceKind !== "SELECTED_SYMBOL";
  return {
    severity: rule.severity,
    confidence,
    impact: rule.impact,
    reachability: external ? "external" : "reviewer-selected",
    userControl: external,
    missingGuardCount: missingGuards.length,
    sortScore: (5 - (SEVERITY_ORDER[rule.severity] ?? 4)) * 100 +
      (3 - (CONFIDENCE_ORDER[confidence] ?? 2)) * 10 +
      (external ? 5 : 0) + Math.min(4, missingGuards.length),
  };
}

function compareRisk(left, right) {
  return (SEVERITY_ORDER[left.severity] ?? 9) - (SEVERITY_ORDER[right.severity] ?? 9) ||
    (CONFIDENCE_ORDER[left.confidence] ?? 9) - (CONFIDENCE_ORDER[right.confidence] ?? 9) ||
    right.risk.sortScore - left.risk.sortScore;
}

module.exports = { CONFIDENCE_ORDER, SEVERITY_ORDER, compareRisk, scoreRisk };
