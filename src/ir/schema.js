"use strict";

const IR_VERSION = 2;
const MAX_LOCATION_CODE_CHARACTERS = 1_000;

const OperationKind = Object.freeze({
  SOURCE: "source",
  ASSIGNMENT: "assignment",
  CALL: "call",
  RETURN: "return",
  THROW: "throw",
  BREAK: "break",
  CONTINUE: "continue",
  BRANCH: "branch",
  GUARD: "guard",
  SINK: "sink",
});

const ValueKind = Object.freeze({
  SYMBOL: "symbol",
  LITERAL: "literal",
  UNKNOWN: "unknown",
});

const Certainty = Object.freeze({
  HIGH: "high",
  MEDIUM: "medium",
  LOW: "low",
});

const ParameterRole = Object.freeze({
  REQUEST: "request",
  BODY: "body",
  QUERY: "query",
  PATH: "path",
  HEADER: "header",
  RESPONSE: "response",
  CONTEXT: "context",
  CONTINUATION: "continuation",
  SERVICE: "service",
  LOGGER: "logger",
  DATABASE: "database",
  CANCELLATION: "cancellation",
  ERROR: "error",
  CAPTURE: "capture",
  UNKNOWN: "unknown",
});

function symbol(name, type = "?", role, metadata = {}) {
  const value = { kind: ValueKind.SYMBOL, name: String(name || ""), type: String(type || "?") };
  if (role) value.role = String(role);
  if (Number.isInteger(metadata.parameterIndex) && metadata.parameterIndex >= 0) value.parameterIndex = metadata.parameterIndex;
  if (Array.isArray(metadata.bindings)) {
    value.bindings = metadata.bindings.map(binding => ({
      name: String(binding.name || ""),
      path: Array.isArray(binding.path) ? binding.path.map(segment => typeof segment === "number" ? segment : String(segment)) : [],
    })).filter(binding => binding.name);
  }
  if (metadata.captured) value.captured = true;
  if (Array.isArray(metadata.annotations)) value.annotations = metadata.annotations.map(String).filter(Boolean);
  if (metadata.cascadedValidation) value.cascadedValidation = true;
  return value;
}

function location(input) {
  const value = {
    absolutePath: input.absolutePath,
    relativePath: input.relativePath,
    line: Math.max(1, Number(input.line) || 1),
    endLine: Math.max(1, Number(input.endLine || input.line) || 1),
    code: boundedCodeExcerpt(input.code),
  };
  for (const key of ["startColumn", "endColumn", "startOffset", "endOffset"]) {
    if (Number.isFinite(input[key]) && input[key] >= 0) value[key] = Number(input[key]);
  }
  return value;
}

function boundedCodeExcerpt(code) {
  const value = String(code || "");
  if (value.length <= MAX_LOCATION_CODE_CHARACTERS) return value;
  const half = Math.floor((MAX_LOCATION_CODE_CHARACTERS - 5) / 2);
  return `${value.slice(0, half)} ... ${value.slice(-half)}`;
}

function operation(input) {
  return {
    id: input.id,
    kind: input.kind,
    functionId: input.functionId,
    location: input.location,
    inputs: input.inputs || [],
    output: input.output,
    semantic: input.semantic || {},
    certainty: input.certainty || Certainty.MEDIUM,
    call: input.call,
    metadata: input.metadata || {},
  };
}

function functionIR(input) {
  return {
    id: input.id,
    symbolKey: input.symbolKey || input.id,
    name: input.name,
    language: input.language,
    enclosingScope: input.enclosingScope || "<file>",
    packageName: input.packageName,
    namespaceName: input.namespaceName,
    qualifiedEnclosingScope: input.qualifiedEnclosingScope || input.enclosingScope || "<file>",
    implementedTypes: input.implementedTypes || [],
    declarationKind: input.declarationKind || "function",
    executable: input.executable !== false,
    signature: input.signature || `${input.name || "<anonymous>"}(${(input.parameters || []).map(parameter => parameter.type || "?").join(",")})`,
    location: input.location,
    parameters: input.parameters || [],
    operations: input.operations || [],
    cfg: input.cfg,
    references: input.references || [],
    entryPoint: input.entryPoint,
    entryPoints: input.entryPoints || (input.entryPoint ? [input.entryPoint] : []),
    isGlobal: Boolean(input.isGlobal),
  };
}

function fileIR(input) {
  const value = {
    schema: "traceguard-ir",
    version: IR_VERSION,
    language: input.language,
    absolutePath: input.absolutePath,
    relativePath: input.relativePath,
    lines: input.lines,
    frontend: input.frontend || { id: "unknown", mode: "unknown", capability: "fallback" },
    functions: input.functions || [],
    entryPoints: input.entryPoints || [],
    typeRelations: input.typeRelations || [],
  };
  const errors = validateFileIR(value);
  if (errors.length) throw new Error(`Invalid TraceGuard IR: ${errors.join("; ")}`);
  return value;
}

function validateFileIR(value) {
  const errors = [];
  if (value?.schema !== "traceguard-ir") errors.push("schema must be traceguard-ir");
  if (value?.version !== IR_VERSION) errors.push(`version must be ${IR_VERSION}`);
  if (!value?.language) errors.push("language is required");
  if (!value?.absolutePath) errors.push("absolutePath is required");
  if (!value?.relativePath) errors.push("relativePath is required");
  if (!Array.isArray(value?.functions)) errors.push("functions must be an array");
  for (const fn of value?.functions || []) {
    if (!fn.id || !fn.symbolKey || !fn.name) errors.push("every function requires id, symbolKey and name");
    if (!Array.isArray(fn.parameters) || !Array.isArray(fn.operations)) errors.push(`function ${fn.name || "<unknown>"} has invalid collections`);
    for (const parameter of fn.parameters || []) {
      if (parameter.role && !Object.values(ParameterRole).includes(parameter.role)) errors.push(`function ${fn.name || "<unknown>"} has invalid parameter role`);
      if (parameter.parameterIndex !== undefined && (!Number.isInteger(parameter.parameterIndex) || parameter.parameterIndex < 0)) {
        errors.push(`function ${fn.name || "<unknown>"} has invalid parameter index`);
      }
      for (const binding of parameter.bindings || []) {
        if (!binding?.name || !Array.isArray(binding.path)) errors.push(`function ${fn.name || "<unknown>"} has invalid parameter binding`);
      }
    }
    for (const op of fn.operations || []) {
      if (!Object.values(OperationKind).includes(op.kind)) errors.push(`operation ${op.id || "<unknown>"} has invalid kind`);
      if (!op.location?.relativePath || !op.location?.line) errors.push(`operation ${op.id || "<unknown>"} has invalid location`);
      if (!Array.isArray(op.inputs)) errors.push(`operation ${op.id || "<unknown>"} inputs must be an array`);
    }
  }
  return errors;
}

module.exports = {
  Certainty,
  IR_VERSION,
  MAX_LOCATION_CODE_CHARACTERS,
  OperationKind,
  ParameterRole,
  ValueKind,
  fileIR,
  functionIR,
  location,
  operation,
  symbol,
  validateFileIR,
};
