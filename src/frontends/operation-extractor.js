"use strict";

const { buildSymbolKey, parameterDescriptors, symbolId } = require("../identity");
const { maskNonCodeLines } = require("../source-mask");
const {
  extractAssignment,
  extractCalls,
  extractFileReferences,
  extractIdentifiers,
  parseParameterNames,
  unique,
} = require("./syntax-tools");

const EVENT_ORDER = { source: 0, assignment: 1, control: 2, branch: 3, call: 4, sink: 5, return: 6 };

function buildIRScopes(lines, functions, signals, language, absolutePath, relativePath, entries = []) {
  const searchableLines = maskNonCodeLines(lines, language);
  const references = extractFileReferences(maskNonCodeLines(lines, language, false), language);
  const symbolOccurrences = new Map();
  const scopes = functions.map(fn => {
    const parameters = parseParameterNames(fn.parameters, language);
    const descriptors = fn.parameterDescriptors || parameterDescriptors(fn.parameters, language);
    const baseSymbolKey = buildSymbolKey({
      language,
      absolutePath,
      relativePath,
      kind: "function",
      enclosingScope: fn.enclosingScope,
      name: fn.name,
      parameterDescriptors: descriptors,
    });
    const occurrence = symbolOccurrences.get(baseSymbolKey) || 0;
    symbolOccurrences.set(baseSymbolKey, occurrence + 1);
    const symbolKey = occurrence ? `${baseSymbolKey}::duplicate:${occurrence}` : baseSymbolKey;
    return buildScope({
      id: symbolId(symbolKey),
      symbolKey,
      name: fn.name,
      parameters,
      parameterDescriptors: descriptors,
      enclosingScope: fn.enclosingScope,
      line: fn.line,
      endLine: fn.endLine,
      lineNumbers: range(fn.line, fn.endLine),
      signals: fn.signals || signals.filter(signal => signal.line >= fn.line && signal.line <= fn.endLine),
      isEntry: entries.some(item => item.functionLine === fn.line),
      entryTitle: entries.find(item => item.functionLine === fn.line)?.title,
      language,
      absolutePath,
      relativePath,
      references,
      lines,
      searchableLines,
    });
  });

  const covered = new Set(functions.flatMap(fn => range(fn.line, fn.endLine)));
  const globalLineNumbers = range(1, lines.length).filter(line => !covered.has(line));
  const globalSignals = signals.filter(signal => !covered.has(signal.line));
  const globalEntries = entries.filter(item => !item.functionLine);
  if (globalLineNumbers.length && (globalSignals.length || globalEntries.length)) {
    const symbolKey = buildSymbolKey({ language, absolutePath, relativePath, kind: "global", name: "global scope", enclosingScope: "<file>", parameterDescriptors: [] });
    scopes.push(buildScope({
      name: "global scope",
      id: symbolId(symbolKey),
      symbolKey,
      parameters: [],
      parameterDescriptors: [],
      enclosingScope: "<file>",
      line: globalLineNumbers[0],
      endLine: globalLineNumbers.at(-1),
      lineNumbers: globalLineNumbers,
      signals: globalSignals,
      isEntry: globalEntries.length > 0,
      entryTitle: globalEntries[0]?.title,
      language,
      absolutePath,
      relativePath,
      references,
      lines,
      searchableLines,
      isGlobal: true,
    }));
  }
  return scopes;
}

function buildScope(input) {
  const events = [];
  const lineSet = new Set(input.lineNumbers);
  for (const signal of input.signals) {
    if (!lineSet.has(signal.line) && signal.line > input.line) continue;
    const code = signal.code || input.lines[signal.line - 1]?.trim() || "";
    const assignment = extractAssignment(input.lines[signal.line - 1] || code);
    const referencedVariables = extractIdentifiers(code);
    let variables = assignment?.variables || referencedVariables;
    if (signal.kind === "source" && assignment?.target) variables = [assignment.target];
    if (signal.line <= input.line && input.parameters.length) variables = unique([...input.parameters, ...variables]);
    if (signal.kind === "source") {
      events.push({ type: "source", line: signal.line, code, variables, label: signal.label, category: signal.category });
    } else if (signal.kind === "sink") {
      events.push({ type: "sink", line: signal.line, code, variables, label: signal.label, category: signal.category });
    } else if (signal.kind === "auth" || signal.kind === "sanitizer") {
      events.push({ type: "control", controlKind: signal.kind, line: signal.line, code, variables, label: signal.label, category: signal.category });
    }
  }

  for (const line of input.lineNumbers) {
    const code = input.lines[line - 1] || "";
    const searchableCode = input.searchableLines?.[line - 1] || "";
    const trimmed = code.trim();
    if (!searchableCode.trim()) continue;
    const assignment = extractAssignment(searchableCode);
    const calls = extractCalls(searchableCode, input.name, line === input.line);
    if (assignment && !calls.length) events.push({ type: "assignment", line, code: trimmed, target: assignment.target, variables: assignment.variables });
    if (/\b(?:if|else\s+if|while|switch|case|match)\b/.test(searchableCode)) {
      events.push({ type: "branch", line, code: trimmed, variables: extractIdentifiers(searchableCode) });
    }
    for (const call of calls) events.push({ type: "call", line, code: trimmed, target: assignment?.target, ...call });
    const returnMatch = searchableCode.match(/\breturn\b([\s\S]*)/);
    if (returnMatch) events.push({ type: "return", line, code: trimmed, variables: extractIdentifiers(returnMatch[1]) });
  }

  events.sort((left, right) => left.line - right.line || (EVENT_ORDER[left.type] ?? 9) - (EVENT_ORDER[right.type] ?? 9));
  return {
    id: input.id,
    symbolKey: input.symbolKey,
    name: input.name,
    parameters: input.parameters,
    parameterDescriptors: input.parameterDescriptors || [],
    enclosingScope: input.enclosingScope || "<file>",
    line: input.line,
    endLine: input.endLine,
    language: input.language,
    absolutePath: input.absolutePath,
    relativePath: input.relativePath,
    isEntry: input.isEntry,
    entryTitle: input.entryTitle,
    isGlobal: Boolean(input.isGlobal),
    references: input.references || [],
    events,
  };
}

function range(start, end) { return Array.from({ length: Math.max(0, end - start + 1) }, (_, index) => start + index); }

module.exports = { buildFunctionFlows: buildIRScopes, buildIRScopes };
