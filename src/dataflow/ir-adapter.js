"use strict";

const { OperationKind } = require("../ir/schema");
const { GuardCapability } = require("../security/semantics");

function functionsFromAnalyses(analyses) {
  return analyses.flatMap(analysis => (analysis.ir?.functions || []).map(flowFunctionFromIR));
}

function flowFunctionFromIR(fn) {
  return {
    id: fn.id,
    name: fn.name,
    parameters: fn.parameters.map(value => value.name),
    line: fn.location.line,
    endLine: fn.location.endLine,
    language: fn.language,
    absolutePath: fn.location.absolutePath,
    relativePath: fn.location.relativePath,
    isEntry: Boolean(fn.entryPoint),
    entryTitle: fn.entryPoint?.title,
    isGlobal: fn.isGlobal,
    references: fn.references || [],
    events: fn.operations.map(operationFromIR),
  };
}

function operationFromIR(operation) {
  const capabilities = operation.semantic.guardCapabilities || [];
  const isAuthorization = capabilities.includes(GuardCapability.AUTHENTICATION) || capabilities.includes(GuardCapability.AUTHORIZATION);
  return {
    type: operation.kind === OperationKind.GUARD ? "control" : operation.kind,
    line: operation.location.line,
    code: operation.location.code,
    variables: operation.inputs.map(value => value.name),
    target: operation.output?.name,
    label: operation.semantic.label,
    category: operation.semantic.category || operation.metadata.category,
    sourceKind: operation.semantic.sourceKind,
    sinkKind: operation.semantic.sinkKind,
    guardCapabilities: capabilities,
    controlKind: operation.kind === OperationKind.GUARD ? (isAuthorization ? "auth" : "sanitizer") : undefined,
    callee: operation.call?.function,
    receiver: operation.call?.receiver,
    arguments: operation.call?.arguments || [],
    argumentVariables: (operation.call?.argumentInputs || []).map(group => group.map(value => value.name)),
    certainty: operation.certainty,
  };
}

module.exports = { flowFunctionFromIR, functionsFromAnalyses, operationFromIR };
