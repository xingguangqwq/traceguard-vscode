"use strict";

const crypto = require("node:crypto");
const { OperationKind } = require("../ir/schema");
const { structuralDigest } = require("../analysis/structural-digest");

const DEFAULT_LIMITS = Object.freeze({ maxEntries: 10_000, maxOperations: 5000, maxPropagationSteps: 20_000, timeoutMs: 25 });
const ASYNC_CALLS = new Set(["then", "catch", "finally", "settimeout", "setinterval", "queuemicrotask", "runasync", "supplyasync", "launch", "async", "go"]);

class FunctionSummaryCache {
  constructor(options = {}) {
    this.maxEntries = Math.max(100, Number(options.maxEntries) || DEFAULT_LIMITS.maxEntries);
    this.values = new Map();
    this.hits = 0;
    this.misses = 0;
  }

  get(fn, build, options = {}) {
    const key = `${summaryCacheKey(fn)}:${summaryOptionsKey(options)}`;
    const cached = this.values.get(key);
    if (cached) {
      this.values.delete(key);
      this.values.set(key, cached);
      this.hits += 1;
      return cached;
    }
    this.misses += 1;
    const summary = build(fn, options);
    if (summary.analysis?.truncationReasons?.includes("summary-timeout")) return summary;
    this.values.set(key, summary);
    while (this.values.size > this.maxEntries) this.values.delete(this.values.keys().next().value);
    return summary;
  }

  clear() {
    this.values.clear();
    this.hits = 0;
    this.misses = 0;
  }

  snapshot() { return { entries: this.values.size, hits: this.hits, misses: this.misses }; }
}

function summarizeFileIR(ir, options = {}) {
  const cache = options.cache;
  return ir.functions.map(fn => cache
    ? cache.get(fn, buildFunctionSummary, options)
    : buildFunctionSummary(fn, options));
}

function buildFunctionSummary(fn, options = {}) {
  const limits = {
    maxOperations: bounded(options.maxOperations, DEFAULT_LIMITS.maxOperations, 100, 50_000),
    maxPropagationSteps: bounded(options.maxPropagationSteps, DEFAULT_LIMITS.maxPropagationSteps, 100, 200_000),
    timeoutMs: bounded(options.timeoutMs, DEFAULT_LIMITS.timeoutMs, 1, 1000),
  };
  const scopedFn = fn.operations.length > limits.maxOperations
    ? { ...fn, operations: fn.operations.slice(0, limits.maxOperations) }
    : fn;
  const context = propagationContext(scopedFn, limits, scopedFn !== fn);
  const calls = operations(scopedFn, OperationKind.CALL);
  return {
    id: fn.id,
    symbolKey: fn.symbolKey,
    name: fn.name,
    signature: fn.signature,
    relativePath: fn.location.relativePath,
    parameters: fn.parameters.map(parameter => parameter.name),
    sources: operations(scopedFn, OperationKind.SOURCE).map(operation => operation.semantic.sourceKind),
    sinks: operations(scopedFn, OperationKind.SINK).map(operation => operation.semantic.sinkKind),
    guards: operations(scopedFn, OperationKind.GUARD).flatMap(operation => operation.semantic.guardCapabilities || []),
    returns: operations(scopedFn, OperationKind.RETURN).map(operation => operation.inputs.map(input => input.name)),
    callees: calls.map(operation => ({
      function: operation.call?.function,
      receiver: operation.call?.receiver,
      argumentInputs: (operation.call?.argumentInputs || []).map(group => group.map(input => input.name)),
      higherOrder: Boolean(operation.call?.closure || operation.metadata?.closure),
      asyncBoundary: isAsyncBoundary(operation),
    })),
    parameterFlows: scopedFn.parameters.map((parameter, index) => summarizeParameterFlow(scopedFn, parameter.name, index, context)),
    sourceFlows: summarizeSources(scopedFn, context),
    analysis: {
      operations: fn.operations.length,
      analyzedOperations: scopedFn.operations.length,
      truncated: context.reasons.size > 0,
      truncationReasons: [...context.reasons],
      propagationSteps: context.steps,
    },
  };
}

function summarizeParameterFlow(fn, parameter, parameterIndex, context) {
  const tainted = context.propagate([parameter], fn.location.line);
  return {
    parameterIndex,
    parameter,
    toReturn: operations(fn, OperationKind.RETURN).some(operation => intersects(operation.inputs, tainted)),
    toSinks: operations(fn, OperationKind.SINK)
      .filter(operation => intersects(operation.inputs, tainted))
      .map(operation => operation.semantic.sinkKind),
    toProperties: operations(fn, OperationKind.ASSIGNMENT)
      .filter(operation => operation.output?.name?.includes(".") && intersects(operation.inputs, tainted))
      .map(operation => operation.output.name),
    throughCalls: operations(fn, OperationKind.CALL).flatMap(operation =>
      (operation.call?.argumentInputs || []).flatMap((inputs, argumentIndex) =>
        intersects(inputs, tainted) ? [{
          function: operation.call.function,
          argumentIndex,
          higherOrder: Boolean(operation.call?.closure || operation.metadata?.closure),
          asyncBoundary: isAsyncBoundary(operation),
        }] : [],
      ),
    ),
  };
}

function summarizeSources(fn, context) {
  return operations(fn, OperationKind.SOURCE).map(source => {
    const seeds = source.output ? [source.output.name] : source.inputs.map(input => input.name);
    const tainted = context.propagate(seeds, source.location.line);
    return {
      sourceKind: source.semantic.sourceKind,
      toReturn: operations(fn, OperationKind.RETURN).some(operation => intersects(operation.inputs, tainted)),
      toSinks: operations(fn, OperationKind.SINK)
        .filter(operation => intersects(operation.inputs, tainted))
        .map(operation => operation.semantic.sinkKind),
    };
  });
}

function propagationContext(fn, limits, operationBudgetExceeded = false) {
  const deadline = performance.now() + limits.timeoutMs;
  const reasons = new Set();
  const assignments = operations(fn, OperationKind.ASSIGNMENT);
  if (operationBudgetExceeded) reasons.add("summary-operation-budget");
  const memo = new Map();
  const context = {
    steps: 0,
    reasons,
    propagate(seeds, startLine) {
      const key = `${startLine}:${[...seeds].sort().join("|")}`;
      if (memo.has(key)) return memo.get(key);
      const tainted = new Set(seeds);
      for (const operation of assignments) {
        if (performance.now() >= deadline) { reasons.add("summary-timeout"); break; }
        if (context.steps >= limits.maxPropagationSteps) { reasons.add("summary-propagation-budget"); break; }
        if (operation.location.line < startLine || !operation.output) continue;
        context.steps += 1;
        if (intersects(operation.inputs, tainted)) tainted.add(operation.output.name);
      }
      memo.set(key, tainted);
      return tainted;
    },
  };
  return context;
}

function summaryCacheKey(fn) {
  const hash = crypto.createHash("sha256");
  hash.update(structuralDigest({
    symbolKey: fn.symbolKey,
    parameters: fn.parameters.map(parameter => [parameter.name, parameter.type, parameter.role]),
  }));
  for (const operation of fn.operations) {
    hash.update(structuralDigest({
      kind: operation.kind,
      inputs: operation.inputs.map(input => input.name),
      output: operation.output?.name,
      semantic: operation.semantic,
      call: operation.call ? {
        function: operation.call.function,
        receiver: operation.call.receiver,
        arguments: operation.call.arguments,
        argumentInputs: operation.call.argumentInputs,
        targetFunctionId: operation.call.targetFunctionId,
        closure: operation.call.closure,
      } : undefined,
    }));
  }
  return `${fn.id}:${hash.digest("hex")}`;
}

function summaryOptionsKey(options) {
  return [
    bounded(options.maxOperations, DEFAULT_LIMITS.maxOperations, 100, 50_000),
    bounded(options.maxPropagationSteps, DEFAULT_LIMITS.maxPropagationSteps, 100, 200_000),
    bounded(options.timeoutMs, DEFAULT_LIMITS.timeoutMs, 1, 1000),
  ].join(":");
}

function isAsyncBoundary(operation) {
  const name = String(operation.call?.function || "").replace(/[^A-Za-z0-9]/g, "").toLowerCase();
  return Boolean(operation.metadata?.asyncBoundary || ASYNC_CALLS.has(name) || [...ASYNC_CALLS].some(call => name.startsWith(`${call}callback`)));
}

function intersects(values, tainted) {
  return values.some(value => tainted.has(value.name));
}

function operations(fn, kind) {
  return fn.operations.filter(operation => operation.kind === kind);
}

function bounded(value, fallback, minimum, maximum) {
  const numeric = Number(value);
  return Math.max(minimum, Math.min(maximum, Number.isFinite(numeric) ? Math.floor(numeric) : fallback));
}

module.exports = { FunctionSummaryCache, buildFunctionSummary, isAsyncBoundary, summarizeFileIR, summaryCacheKey };
