"use strict";

const { appendAccessPath, normalizeAccessPath, splitAccessPath } = require("../ir/access-path");
const { stableHash } = require("../identity");
const { expressionInputs } = require("../frontends/expression-inputs");
const { buildFunctionIndex, resolveCandidates } = require("./call-resolver");
const { argumentValue, bindCallArguments, implicitReceiverOffset } = require("./call-bindings");

// Keep calls for navigation/dependency invalidation, but interpret proven field
// effects as ordinary assignments in the caller's existing CFG block. Both
// Findings and interactive queries therefore use the same overwrite semantics.
function applyAccessorEffects(functions) {
  const names = new Set(functions.filter(fn => fn.accessorSummary).map(fn => fn.name.toLowerCase()));
  if (!names.size) return functions;
  const index = buildFunctionIndex(functions);
  for (const caller of functions) {
    const modeled = new Map();
    for (const event of caller.events) {
      if (event.type !== "call" || !event.callee || event.semanticModelId || event.reachable === false || !names.has(event.callee.toLowerCase())) continue;
      const candidates = resolveCandidates(index, event, caller);
      if (candidates.length !== 1) continue;
      const resolution = candidates[0];
      const callee = resolution.fn;
      const summary = callee.accessorSummary;
      const localSelf = (!event.receiver || ["this", "$this", "self"].includes(event.receiver)) &&
        caller.absolutePath === callee.absolutePath && caller.enclosingScope === callee.enclosingScope;
      if (!summary || resolution.quality !== "high" || !resolution.precise && !localSelf) continue;
      const binding = bindCallArguments(callee, event);
      if (binding.status !== "verified") continue;
      const argument = binding.bindings.find(item => item.parameterIndex === (summary.parameterIndex || 0) + implicitReceiverOffset(callee, event));
      if (summary.kind === "write" && (!argument || argument.kind !== "explicit" || argument.parameterPath.length)) continue;
      const receiver = normalizeAccessPath(event.receiver || (caller.language === "java" ? "this" : ""));
      if (!receiver || splitAccessPath(receiver)?.segments.includes("*")) continue;
      const field = summary.path ? appendAccessPath(receiver, summary.path) : undefined;
      const output = summary.kind === "read" ? event.target ||
        `${caller.language === "php" ? "$" : ""}__traceguard_accessor_${event.id}` : undefined;
      modeled.set(event.id, { event, callee, summary, receiver, field, output, argument });
    }
    if (!modeled.size) continue;
    const reads = [...modeled.values()].filter(item => item.summary.kind === "read").sort((left, right) => left.event.startOffset - right.event.startOffset);
    const modeledRanges = new Set([...modeled.values()].map(item => `${item.event.startOffset}:${item.event.endOffset}`));
    for (const event of caller.events) rewriteReadInputs(event, reads, caller.language);
    caller.events = caller.events.flatMap(event => {
      const model = modeled.get(event.id);
      if (event.javaBeanGetter && modeledRanges.has(`${event.startOffset}:${event.endOffset}`)) return [];
      if (!model) return [event];
      event.accessorModeled = true;
      const { summary, field, receiver, output } = model;
      const effects = [];
      if (summary.kind === "read") {
        effects.push(effect(model, output, field ? [field] : [], field ? "alias" : "constant", "read"));
      } else {
        const value = argumentValue(event, model.argument);
        const inputs = value.variables;
        const mode = normalizeAccessPath(value.expression) ? "alias" : "aggregate";
        effects.push(effect(model, field, inputs, inputs.length ? mode : "constant", "write"));
        if (event.target && summary.returnsReceiver) effects.push(effect(model, event.target, [receiver], "alias", "return"));
      }
      return [event, ...effects];
    });
  }
  return functions;
}

function rewriteReadInputs(event, reads, language) {
  if (!Number.isFinite(event.startOffset) || !Number.isFinite(event.endOffset)) return;
  // Calls are ordered by source offset so a long sequence of independent reads
  // does not require comparing every operation with every getter in a function.
  let low = 0;
  let high = reads.length;
  while (low < high) {
    const middle = (low + high) >>> 1;
    if (reads[middle].event.startOffset < event.startOffset) low = middle + 1;
    else high = middle;
  }
  const nested = [];
  for (let index = low; index < reads.length && reads[index].event.startOffset <= event.endOffset; index++) {
    const read = reads[index];
    if (event !== read.event && contains(event, read.event) && read.event.callExpression) nested.push(read);
  }
  if (!nested.length) return;
  const rewrite = (expression, startOffset) => {
    if (!Number.isFinite(startOffset)) return expression;
    let value = expression;
    // Replace exact AST spans, from right to left. Identical getter text may
    // occur on both sides of a mutation and must retain distinct return values.
    for (const read of [...nested].reverse()) {
      const start = read.event.startOffset - startOffset;
      const end = read.event.endOffset - startOffset;
      if (start >= 0 && end <= expression.length && expression.slice(start, end) === read.event.callExpression) {
        value = value.slice(0, start) + read.output + value.slice(end);
      }
    }
    return value;
  };
  if (event.valueExpression) {
    const rewritten = rewrite(event.valueExpression, event.valueStartOffset);
    if (rewritten !== event.valueExpression) {
      event.variables = expressionInputs(rewritten, language);
      if (event.type === "assignment") event.assignmentMode = normalizeAccessPath(rewritten) ? "alias" : "aggregate";
    }
  }
  if (!event.arguments.length) return;
  const previous = event.argumentVariables.flat();
  let changed = false;
  const inputs = (event.argumentValues || event.arguments).map((argument, index) => {
    const rewritten = rewrite(argument, event.argumentRanges?.[index]?.startOffset);
    if (rewritten === argument) return event.argumentVariables[index] || [];
    changed = true;
    event.accessorArgumentPaths ||= [];
    event.accessorArgumentPaths[index] = normalizeAccessPath(rewritten);
    return expressionInputs(rewritten, language);
  });
  if (!changed) return;
  const extras = event.variables.filter(value => !previous.includes(value));
  event.argumentVariables = inputs;
  event.variables = [...new Set([...extras, ...inputs.flatMap((group, index) =>
    !event.taintArgumentIndexes || event.taintArgumentIndexes.includes(index) ? group : [])])];
}

function effect(model, target, variables, assignmentMode, kind) {
  const { event, callee, summary, field } = model;
  const operation = summary.kind === "read" ? "reads" : "writes";
  const label = kind === "return" ? `${callee.name}() returns its receiver` : `${callee.name}() ${operation} ${field || "a constant"}`;
  return {
    id: `${event.id}:accessor:${kind}:${stableHash(JSON.stringify([callee.id, summary]))}`,
    type: "assignment", target, variables, assignmentMode,
    line: event.line, startOffset: event.startOffset, endOffset: event.endOffset,
    code: event.code, blockId: event.blockId, reachable: event.reachable,
    certainty: "high", propagationStatus: "verified", propagationLabel: label,
    propagationReason: `${label}; the complete method body and unique call target prove this field effect.`,
    accessorEvidence: { ...callee.definitionLocation, functionId: callee.id, functionName: callee.name, symbolKey: callee.symbolKey },
  };
}

function contains(parent, child) {
  return [parent.startOffset, parent.endOffset, child.startOffset, child.endOffset].every(Number.isFinite) &&
    parent.startOffset <= child.startOffset && parent.endOffset >= child.endOffset;
}
module.exports = { applyAccessorEffects };
