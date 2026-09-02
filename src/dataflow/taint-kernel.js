"use strict";

const { propagatedAssignmentTargets, removeAssignedTaint } = require("../ir/access-path");

function applyAssignment(taintedValues, event, options = {}) {
  const current = new Set(taintedValues || []);
  const outputs = event?.target ? propagatedAssignmentTargets(
    event.target,
    event.variables || [],
    current,
    event.assignmentMode || "expression",
  ) : [];
  const next = options.preserveTarget || !event?.target
    ? new Set(current)
    : removeAssignedTaint(current, event.target);
  for (const output of outputs) next.add(output);
  return { tainted: next, outputs };
}

function applySource(taintedValues, event) {
  const current = new Set(taintedValues || []);
  if (!event?.target) return current;
  const next = removeAssignedTaint(current, event.target);
  next.add(event.target);
  return next;
}

function applyCallOutput(taintedValues, event, propagates) {
  const current = new Set(taintedValues || []);
  if (!event?.target) return current;
  const next = removeAssignedTaint(current, event.target);
  if (propagates) next.add(event.target);
  return next;
}

module.exports = { applyAssignment, applyCallOutput, applySource };
