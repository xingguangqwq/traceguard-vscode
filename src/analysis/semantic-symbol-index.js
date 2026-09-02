"use strict";

const path = require("path");
const { normalizePath } = require("../identity");

const INDEXED_LANGUAGES = new Set(["java", "csharp", "go"]);

function buildSemanticSymbolIndex(functions = []) {
  const byReceiver = new Map();
  for (const fn of functions) {
    if (!INDEXED_LANGUAGES.has(fn.language)) continue;
    const arity = callableArity(fn);
    for (const receiverType of functionReceiverTypes(fn)) {
      add(byReceiver, symbolKey(fn.language, fn.workspaceRoot, receiverType, fn.name, arity), fn);
    }
  }
  return { byReceiver, size: byReceiver.size };
}

function semanticCandidates(index, event, caller) {
  if (!index?.byReceiver || !INDEXED_LANGUAGES.has(caller?.language) || !event?.receiverType) return [];
  const arity = Array.isArray(event.arguments) ? event.arguments.length : undefined;
  if (arity === undefined) return [];
  const matches = [];
  for (const receiverType of typeKeys(event.receiverType)) {
    matches.push(...(index.byReceiver.get(symbolKey(caller.language, caller.workspaceRoot, receiverType, event.callee, arity)) || []));
  }
  return uniqueFunctions(matches);
}

function functionReceiverTypes(fn) {
  return unique([
    ...typeKeys(fn.qualifiedEnclosingScope),
    ...typeKeys(fn.enclosingScope),
    ...(fn.implementedTypes || []).flatMap(typeKeys),
  ]).filter(type => type && type !== "file");
}

function typeKeys(value) {
  const normalized = String(value || "")
    .replace(/<[^<>]*>/g, "")
    .replace(/\[[^\]]*\]/g, "")
    .replace(/[?*&]+/g, "")
    .replace(/::/g, ".")
    .replace(/\\/g, ".")
    .replace(/\s+/g, "")
    .replace(/^\.+|\.+$/g, "")
    .toLowerCase();
  if (!normalized) return [];
  const simple = normalized.split(".").filter(Boolean).at(-1);
  return unique([normalized, simple]);
}

function symbolKey(language, workspaceRoot, receiverType, name, arity) {
  return [
    String(language || "").toLowerCase(),
    workspaceKey(workspaceRoot),
    String(receiverType || "").toLowerCase(),
    canonicalName(name),
    Number(arity),
  ].join("|");
}

function callableArity(fn) {
  const parameters = fn.parameters || [];
  return fn.language === "python" && ["self", "cls"].includes(parameters[0]?.name || parameters[0])
    ? Math.max(0, parameters.length - 1)
    : parameters.length;
}

function workspaceKey(value) {
  if (!value) return "<workspace>";
  return normalizePath(path.resolve(String(value))).toLowerCase();
}

function add(index, key, fn) {
  if (!index.has(key)) index.set(key, []);
  index.get(key).push(fn);
}

function unique(values) { return [...new Set(values.filter(Boolean))]; }
function uniqueFunctions(values) { return [...new Map(values.map(fn => [fn.id, fn])).values()]; }
function canonicalName(value) { return String(value || "").replace(/[^A-Za-z0-9]/g, "").toLowerCase(); }

module.exports = { buildSemanticSymbolIndex, semanticCandidates, typeKeys };
