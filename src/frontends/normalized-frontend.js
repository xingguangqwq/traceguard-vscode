"use strict";

const { stableHash } = require("../identity");
const { Certainty, OperationKind, fileIR, functionIR, location, operation, symbol } = require("../ir/schema");
const { guardAssociation, semanticForSignal } = require("../security/semantics");

const LEGACY_KIND = Object.freeze({
  source: OperationKind.SOURCE,
  assignment: OperationKind.ASSIGNMENT,
  call: OperationKind.CALL,
  return: OperationKind.RETURN,
  branch: OperationKind.BRANCH,
  control: OperationKind.GUARD,
  sink: OperationKind.SINK,
});

function buildNormalizedIR(input) {
  const functions = (input.scopes || input.flowFunctions || []).map(scope => normalizeFunction(scope, input));
  return fileIR({
    language: input.language,
    absolutePath: input.absolutePath,
    relativePath: input.relativePath,
    lines: input.lines,
    frontend: input.frontend || { id: `pattern-${input.language}`, mode: "pattern", capability: "fallback" },
    functions,
    entryPoints: (input.entries || []).map(entry => ({
      id: stableHash(`${input.relativePath}:entry:${entry.method}:${entry.route}:${functions.find(fn => fn.location.line === entry.functionLine)?.symbolKey || "global"}`),
      title: entry.title,
      method: entry.method,
      route: entry.route,
      functionId: functions.find(fn => fn.location.line === entry.functionLine)?.id,
      location: location({ ...input, line: entry.line, endLine: entry.endLine || entry.line }),
    })),
  });
}

function normalizeFunction(scope, file) {
  const functionLocation = location({
    ...file,
    line: scope.line,
    endLine: scope.endLine,
  });
  const operationOccurrences = new Map();
  const operations = scope.events.map(event => {
    const fingerprint = operationFingerprint(event);
    const occurrence = operationOccurrences.get(fingerprint) || 0;
    operationOccurrences.set(fingerprint, occurrence + 1);
    return normalizeOperation(event, scope, file, occurrence);
  });
  attachFallbackSemanticCalls(operations);
  attachFallbackGuardBindings(operations);
  return functionIR({
    id: scope.id,
    symbolKey: scope.symbolKey,
    name: scope.name,
    language: scope.language,
    enclosingScope: scope.enclosingScope,
    signature: `${scope.name}(${(scope.parameterDescriptors || []).map(parameter => parameter.type).join(",")})`,
    location: functionLocation,
    parameters: (scope.parameterDescriptors?.length ? scope.parameterDescriptors : scope.parameters.map(name => ({ name, type: "?" })))
      .map(parameter => symbol(parameter.name, parameter.type)),
    operations,
    references: scope.references,
    entryPoint: scope.isEntry ? { title: scope.entryTitle || scope.name } : undefined,
    isGlobal: scope.isGlobal,
  });
}

function normalizeOperation(event, scope, file, occurrence = 0) {
  const kind = LEGACY_KIND[event.type];
  const eventLocation = location({
    ...file,
    line: event.line,
    endLine: event.line,
    code: event.code,
  });
  const semanticSignal = event.type === "control"
    ? { kind: event.controlKind, label: event.label, category: event.category, code: event.code }
    : { kind: event.type, label: event.label, category: event.category, code: event.code };
  return operation({
    id: stableHash(`${scope.symbolKey || scope.id}:${operationFingerprint(event)}:${occurrence}`),
    kind,
    functionId: scope.id,
    location: eventLocation,
    inputs: (event.variables || []).map(symbol),
    output: event.target ? symbol(event.target) : undefined,
    semantic: ["source", "sink", "control"].includes(event.type) ? semanticForSignal(semanticSignal) : {},
    certainty: kind === OperationKind.SINK ? Certainty.LOW : Certainty.MEDIUM,
    call: event.type === "call" ? {
      function: event.callee,
      receiver: event.receiver,
      arguments: event.arguments,
      argumentInputs: event.argumentVariables.map(group => group.map(symbol)),
    } : undefined,
    metadata: {
      category: event.category,
      controlKind: event.controlKind,
      legacyType: event.type,
      candidateStatus: kind === OperationKind.SINK ? "regex-unverified" : undefined,
    },
  });
}

function attachFallbackGuardBindings(operations) {
  for (const guard of operations.filter(item => item.kind === OperationKind.GUARD)) {
    const call = operations.find(item => item.kind === OperationKind.CALL && item.location.line === guard.location.line);
    const association = guardAssociation(guard.semantic.guardCapabilities || []);
    guard.call ||= call?.call;
    guard.metadata.guardBinding = {
      capabilities: guard.semantic.guardCapabilities || [],
      inputs: guard.inputs.map(value => value.name),
      output: call?.output?.name,
      receiver: call?.call?.receiver,
      trustedOperands: (call?.call?.arguments || []).map((expression, index) => ({ expression, index }))
        .filter(item => /^\s*(?:["'`].*["'`]|\d+)\s*$/.test(item.expression)),
      semanticVerification: "unverified",
      ...association,
    };
  }
}

function attachFallbackSemanticCalls(operations) {
  for (const semanticOperation of operations.filter(item => [OperationKind.SOURCE, OperationKind.SINK, OperationKind.GUARD].includes(item.kind))) {
    semanticOperation.call ||= operations.find(item =>
      item.kind === OperationKind.CALL && item.location.line === semanticOperation.location.line)?.call;
  }
}

function operationFingerprint(event) {
  return [
    event.type,
    event.label || "",
    event.callee || "",
    event.target || "",
    stableHash(event.code || "", 12),
  ].join(":");
}

module.exports = { buildFileIRFromScopes: buildNormalizedIR, buildNormalizedIR, normalizeFunction, normalizeOperation };
