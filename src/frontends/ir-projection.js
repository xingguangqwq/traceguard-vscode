"use strict";

const { OperationKind } = require("../ir/schema");

function projectAnalysis(ir) {
  const signals = dedupeSignals(ir.functions.flatMap(fn => fn.operations.map(signalFromOperation).filter(Boolean)));
  const functions = ir.functions.filter(fn => !fn.isGlobal).map(fn => ({
    name: fn.name,
    parameters: fn.parameters.map(parameter => parameter.name).join(", "),
    line: fn.location.line,
    endLine: fn.location.endLine,
    signals: fn.operations.map(signalFromOperation).filter(Boolean),
  }));
  const functionsById = new Map(ir.functions.map(fn => [fn.id, fn]));
  const entries = ir.entryPoints.map(entry => {
    const fn = functionsById.get(entry.functionId);
    return {
      title: entry.title,
      method: entry.method,
      route: entry.route,
      line: entry.location.line,
      endLine: entry.location.endLine,
      functionLine: fn?.location.line,
      functionName: fn?.name,
    };
  });
  return {
    absolutePath: ir.absolutePath,
    relativePath: ir.relativePath,
    language: ir.language,
    lines: ir.lines,
    signals,
    functions,
    entries,
    ir,
  };
}

function dedupeSignals(signals) {
  const seen = new Set();
  return signals.filter(signal => {
    const key = [signal.kind, signal.category, signal.line, signal.label, signal.code].join(":");
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function signalFromOperation(operation) {
  let kind;
  if (operation.kind === OperationKind.SOURCE) kind = "source";
  else if (operation.kind === OperationKind.SINK) kind = "sink";
  else if (operation.kind === OperationKind.GUARD) kind = operation.metadata.controlKind || "sanitizer";
  else return undefined;
  return {
    kind,
    label: operation.semantic.label || operation.metadata.label || kind,
    category: operation.semantic.category || operation.metadata.category || kind,
    line: operation.location.line,
    code: operation.location.code,
  };
}

module.exports = { dedupeSignals, projectAnalysis, signalFromOperation };
