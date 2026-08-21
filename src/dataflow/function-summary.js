"use strict";

const { OperationKind } = require("../ir/schema");

function summarizeFileIR(ir) {
  return ir.functions.map(fn => ({
    id: fn.id,
    name: fn.name,
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
  }));
}

function operations(fn, kind) {
  return fn.operations.filter(operation => operation.kind === kind);
}

module.exports = { summarizeFileIR };
