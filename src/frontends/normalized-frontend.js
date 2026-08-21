"use strict";

const crypto = require("crypto");
const { Certainty, OperationKind, fileIR, functionIR, location, operation, symbol } = require("../ir/schema");
const { semanticForSignal } = require("../security/semantics");

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
    functions,
    entryPoints: (input.entries || []).map(entry => ({
      id: hash(`${input.relativePath}:entry:${entry.line}:${entry.method}:${entry.route}`),
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
  return functionIR({
    id: scope.id,
    name: scope.name,
    language: scope.language,
    location: functionLocation,
    parameters: scope.parameters.map(symbol),
    operations: scope.events.map(event => normalizeOperation(event, scope, file)),
    references: scope.references,
    entryPoint: scope.isEntry ? { title: scope.entryTitle || scope.name } : undefined,
    isGlobal: scope.isGlobal,
  });
}

function normalizeOperation(event, scope, file) {
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
    id: hash(`${scope.id}:${event.type}:${event.line}:${event.label || event.callee || event.target || "operation"}`),
    kind,
    functionId: scope.id,
    location: eventLocation,
    inputs: (event.variables || []).map(symbol),
    output: event.target ? symbol(event.target) : undefined,
    semantic: ["source", "sink", "control"].includes(event.type) ? semanticForSignal(semanticSignal) : {},
    certainty: Certainty.MEDIUM,
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
    },
  });
}

function hash(value) {
  return crypto.createHash("sha1").update(String(value)).digest("hex").slice(0, 16);
}

module.exports = { buildFileIRFromScopes: buildNormalizedIR, buildNormalizedIR, normalizeFunction, normalizeOperation };
