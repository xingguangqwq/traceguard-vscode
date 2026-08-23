"use strict";

const { OperationKind } = require("../ir/schema");

function summarizeFileIR(ir) {
  return ir.functions.map(fn => ({
    id: fn.id,
    symbolKey: fn.symbolKey,
    name: fn.name,
    signature: fn.signature,
    relativePath: fn.location.relativePath,
    parameters: fn.parameters.map(parameter => parameter.name),
    sources: operations(fn, OperationKind.SOURCE).map(operation => operation.semantic.sourceKind),
    sinks: operations(fn, OperationKind.SINK).map(operation => operation.semantic.sinkKind),
    guards: operations(fn, OperationKind.GUARD).flatMap(operation => operation.semantic.guardCapabilities || []),
    returns: operations(fn, OperationKind.RETURN).map(operation => operation.inputs.map(input => input.name)),
    callees: operations(fn, OperationKind.CALL).map(operation => ({
      function: operation.call?.function,
      receiver: operation.call?.receiver,
      argumentInputs: (operation.call?.argumentInputs || []).map(group => group.map(input => input.name)),
    })),
    parameterFlows: fn.parameters.map((parameter, index) => summarizeParameterFlow(fn, parameter.name, index)),
    sourceFlows: summarizeSources(fn),
  }));
}

function summarizeParameterFlow(fn, parameter, parameterIndex) {
  const tainted = propagateLocally(fn, [parameter]);
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
        intersects(inputs, tainted) ? [{ function: operation.call.function, argumentIndex }] : [],
      ),
    ),
  };
}

function summarizeSources(fn) {
  return operations(fn, OperationKind.SOURCE).map(source => {
    const seeds = source.output ? [source.output.name] : source.inputs.map(input => input.name);
    const tainted = propagateLocally(fn, seeds, source.location.line);
    return {
      sourceKind: source.semantic.sourceKind,
      toReturn: operations(fn, OperationKind.RETURN).some(operation => intersects(operation.inputs, tainted)),
      toSinks: operations(fn, OperationKind.SINK)
        .filter(operation => intersects(operation.inputs, tainted))
        .map(operation => operation.semantic.sinkKind),
    };
  });
}

function propagateLocally(fn, seeds, startLine = fn.location.line) {
  const tainted = new Set(seeds);
  for (const operation of fn.operations) {
    if (operation.location.line < startLine || operation.kind !== OperationKind.ASSIGNMENT || !operation.output) continue;
    if (intersects(operation.inputs, tainted)) tainted.add(operation.output.name);
  }
  return tainted;
}

function intersects(values, tainted) {
  return values.some(value => tainted.has(value.name));
}

function operations(fn, kind) {
  return fn.operations.filter(operation => operation.kind === kind);
}

module.exports = { summarizeFileIR };
