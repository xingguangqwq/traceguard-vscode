"use strict";

const {
  appendAccessPath,
  pathsOverlap,
  propagatedAssignmentTargets,
  relativeAccessPath,
} = require("../ir/access-path");

function assignmentOutputs(event, taintedValues) {
  if (!event?.target) return [];
  return propagatedAssignmentTargets(
    event.target,
    event.variables || [],
    taintedValues || [],
    event.assignmentMode || "expression",
  );
}

function assignmentInputs(event, output) {
  if (!event) return [];
  if ((event.assignmentMode || "expression") !== "alias") return event.variables || [];
  const suffix = relativeAccessPath(output, event.target);
  if (!suffix) return event.variables || [];
  return (event.variables || []).map(input => appendAccessPath(input, suffix)).filter(Boolean);
}

function assignmentFact(event, input, output) {
  const mode = event?.assignmentMode || "expression";
  return {
    input,
    output,
    mode,
    status: propagationStatus(event),
    reason: event?.propagationReason || (mode === "alias"
      ? `The alias assignment rebases the tainted Access Path ${input} onto ${output} without tainting sibling fields.`
      : `The expression reads ${input} and produces ${output}; the result is tainted as a whole value.`),
  };
}

function eventConsumes(event, value) {
  return (event?.variables || []).some(candidate => pathsOverlap(value, candidate)) ||
    (event?.argumentVariables || []).flat().some(candidate => pathsOverlap(value, candidate));
}

function propagationStatus(event) {
  if (event?.propagationStatus) return event.propagationStatus;
  if (event?.certainty === "high") return "verified";
  if (event?.certainty === "medium") return "syntax-only";
  return "heuristic";
}

function isReachableEvent(event) {
  return event?.reachable !== false;
}

module.exports = {
  assignmentFact,
  assignmentInputs,
  assignmentOutputs,
  eventConsumes,
  isReachableEvent,
  propagationStatus,
};
