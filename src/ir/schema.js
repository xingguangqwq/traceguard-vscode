"use strict";

const IR_VERSION = 1;

const OperationKind = Object.freeze({
  SOURCE: "source",
  ASSIGNMENT: "assignment",
  CALL: "call",
  RETURN: "return",
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

function symbol(name) {
  return { kind: ValueKind.SYMBOL, name: String(name || "") };
}

function location(input) {
  return {
    absolutePath: input.absolutePath,
    relativePath: input.relativePath,
    line: Math.max(1, Number(input.line) || 1),
    endLine: Math.max(1, Number(input.endLine || input.line) || 1),
    code: String(input.code || ""),
  };
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
    name: input.name,
    language: input.language,
    location: input.location,
    parameters: input.parameters || [],
    operations: input.operations || [],
    references: input.references || [],
    entryPoint: input.entryPoint,
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
    functions: input.functions || [],
    entryPoints: input.entryPoints || [],
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
    if (!fn.id || !fn.name) errors.push("every function requires id and name");
    if (!Array.isArray(fn.parameters) || !Array.isArray(fn.operations)) errors.push(`function ${fn.name || "<unknown>"} has invalid collections`);
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
  OperationKind,
  ValueKind,
  fileIR,
  functionIR,
  location,
  operation,
  symbol,
  validateFileIR,
};
