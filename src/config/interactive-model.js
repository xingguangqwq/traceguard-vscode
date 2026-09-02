"use strict";

const SUPPORTED_LANGUAGES = new Set(["javascript", "typescript", "java", "python", "php", "csharp", "go"]);
const SINK_KINDS = new Set([
  "SQL_QUERY", "COMMAND_EXEC", "DYNAMIC_EXEC", "FILE_ACCESS", "HTTP_REQUEST",
  "REDIRECT", "RESPONSE_OUTPUT", "DESERIALIZATION", "DIRECTORY_LOOKUP", "SENSITIVE_OPERATION",
]);
const SOURCE_KINDS = new Set(["HTTP_INPUT", "PROCESS_INPUT", "FILE_UPLOAD", "EXTERNAL_INPUT"]);
const GUARD_CAPABILITIES = new Set([
  "INPUT_VALIDATION", "VALIDATE_SCHEME", "VALIDATE_IP", "BLOCK_PRIVATE_IP", "URL_POLICY",
  "PATH_CANONICALIZATION", "PATH_CONFINEMENT", "OUTPUT_ENCODING", "SQL_PARAMETERIZATION",
  "SHELL_ESCAPE", "AUTHENTICATION", "AUTHORIZATION", "DESERIALIZATION_ALLOWLIST",
]);

function selectedCallName(text) {
  const value = String(text || "").trim();
  if (!value) return "";
  const exact = normalizeCallName(value.replace(/\s*\([^\n]*$/s, ""));
  if (exact) return exact;
  const matches = [...value.matchAll(/\$?[A-Za-z_][\w$]*(?:(?:\?\.|\.|::|->)[A-Za-z_$][\w$]*)*(?=\s*\()/g)];
  return normalizeCallName(matches.at(-1)?.[0] || "");
}

function callNameAtPosition(text, position) {
  return callDetailsAtPosition(text, position)?.functionName || "";
}

function callDetailsAtPosition(text, position) {
  const value = String(text || "");
  const cursor = Math.max(0, Math.min(value.length, Number(position) || 0));
  const matches = [...value.matchAll(/\$?[A-Za-z_][\w$]*(?:(?:\?\.|\.|::|->)[A-Za-z_$][\w$]*)*(?=\s*\()/g)]
    .map(match => {
      const rawName = String(match[0] || "").replaceAll("?.", ".");
      const functionName = lastCallSegment(rawName);
      const open = value.indexOf("(", match.index + match[0].length);
      const close = matchingParen(value, open);
      const argumentRanges = splitArgumentRanges(value, open + 1, close);
      const receiver = rawName.includes("->") || rawName.includes("::") || rawName.includes(".")
        ? rawName.split(/(?:\.|::|->)/).slice(0, -1).join(".")
        : undefined;
      return {
        rawName,
        functionName,
        receiver,
        arguments: argumentRanges.map(range => value.slice(range.start, range.end).trim()),
        selectedArgumentIndex: argumentRanges.findIndex(range => cursor >= range.start && cursor <= range.end),
        start: match.index,
        end: match.index + match[0].length,
        open,
        close,
      };
    }).filter(match => match.functionName && match.open >= 0);
  const direct = matches.find(match => cursor >= match.start && cursor <= match.end);
  if (direct) return direct;
  return matches.filter(match => cursor > match.open && cursor <= match.close)
    .sort((left, right) => right.open - left.open)[0];
}

function splitArgumentRanges(text, start, end) {
  const ranges = [];
  let segmentStart = start;
  let depth = 0;
  let quote = "";
  let escaped = false;
  for (let index = start; index < end; index += 1) {
    const character = text[index];
    if (quote) {
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === quote) quote = "";
      continue;
    }
    if (["\"", "'", "`"].includes(character)) { quote = character; continue; }
    if (["(", "[", "{"].includes(character)) depth += 1;
    else if ([")", "]", "}"].includes(character)) depth = Math.max(0, depth - 1);
    else if (character === "," && depth === 0) {
      if (text.slice(segmentStart, index).trim()) ranges.push({ start: segmentStart, end: index });
      segmentStart = index + 1;
    }
  }
  if (text.slice(segmentStart, end).trim()) ranges.push({ start: segmentStart, end });
  return ranges;
}

function matchingParen(text, open) {
  let depth = 0;
  let quote = "";
  let escaped = false;
  for (let index = open; index < text.length; index += 1) {
    const character = text[index];
    if (quote) {
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === quote) quote = "";
      continue;
    }
    if (["\"", "'", "`"].includes(character)) { quote = character; continue; }
    if (character === "(") depth += 1;
    else if (character === ")" && --depth === 0) return index;
  }
  return text.length;
}

function normalizeCallName(value) {
  const normalized = String(value || "").trim().replaceAll("?.", ".");
  if (!/^\$?[A-Za-z_][\w$]*(?:(?:\.|::|->)[A-Za-z_$][\w$]*)*$/.test(normalized)) return "";
  const segments = normalized.split(/(?:\.|::|->)/).filter(Boolean);
  if (/^\$/.test(segments[0]) || /^(?:this|self)$/i.test(segments[0])) return segments.at(-1).replace(/^\$/, "");
  return normalized.replace(/^\$/, "");
}

function lastCallSegment(value) {
  return String(value || "").split(/(?:\.|::|->)/).filter(Boolean).at(-1)?.replace(/^\$/, "") || "";
}

function buildInteractiveModel({ role, language, functionName, kind, receiverType, qualifiedName, symbol, arguments: argumentIndexes, certainty }) {
  const normalizedRole = String(role || "").toLowerCase();
  const normalizedLanguage = String(language || "").toLowerCase();
  const normalizedFunction = normalizeCallName(functionName);
  if (!SUPPORTED_LANGUAGES.has(normalizedLanguage)) throw new Error(`Unsupported language: ${language}`);
  if (!normalizedFunction || normalizedFunction.length > 300) throw new Error("Select a function or method call before adding a semantic model.");
  if (!["source", "sink", "sanitizer"].includes(normalizedRole)) throw new Error(`Unsupported interactive model role: ${role}`);
  const modelKind = String(kind || (normalizedRole === "source" ? "EXTERNAL_INPUT" : normalizedRole === "sink" ? "SENSITIVE_OPERATION" : "INPUT_VALIDATION")).toUpperCase();
  if (normalizedRole === "source" && !SOURCE_KINDS.has(modelKind)) throw new Error(`Unsupported Source kind: ${kind}`);
  if (normalizedRole === "sink" && !SINK_KINDS.has(modelKind)) throw new Error(`Unsupported Sink kind: ${kind}`);
  if (normalizedRole === "sanitizer" && !GUARD_CAPABILITIES.has(modelKind)) throw new Error(`Unsupported Sanitizer capability: ${kind}`);
  const taintArguments = normalizeArgumentIndexes(argumentIndexes);
  if (["sink", "sanitizer"].includes(normalizedRole) && !taintArguments.length) {
    throw new Error("Choose at least one affected argument; TraceGuard does not assume argument 0.");
  }
  const proof = {
    receiverType: boundedIdentity(receiverType),
    qualifiedName: boundedIdentity(qualifiedName),
    symbol: boundedIdentity(symbol),
  };
  const modelCertainty = String(certainty || (proof.receiverType || proof.qualifiedName || proof.symbol ? "verified" : "review")).toLowerCase();
  if (!["verified", "review"].includes(modelCertainty)) throw new Error(`Unsupported interactive model certainty: ${certainty}`);
  if (modelCertainty === "verified" && !proof.receiverType && !proof.qualifiedName && !proof.symbol) {
    throw new Error("A verified interactive model requires a resolved receiver, qualified symbol, or module-qualified function.");
  }
  const id = `ui-${normalizedRole}-${normalizedLanguage}-${normalizedFunction}`.replace(/[^A-Za-z0-9_.-]/g, "-").slice(0, 120);
  const identity = {
    ...(proof.receiverType ? { receiverType: proof.receiverType } : {}),
    ...(proof.qualifiedName ? { qualifiedName: proof.qualifiedName } : {}),
    ...(proof.symbol ? { symbol: proof.symbol } : {}),
    certainty: modelCertainty,
  };
  if (normalizedRole === "source") return { id, language: normalizedLanguage, function: normalizedFunction, kind: modelKind, returnsTaint: true, ...identity };
  if (normalizedRole === "sink") return { id, language: normalizedLanguage, function: normalizedFunction, kind: modelKind, arguments: taintArguments, ...identity };
  return { id, language: normalizedLanguage, function: normalizedFunction, capability: [modelKind], arguments: taintArguments, returnsTaint: true, ...identity };
}

function normalizeArgumentIndexes(values) {
  if (!Array.isArray(values)) return [];
  return [...new Set(values.filter(value => Number.isInteger(value) && value >= 0 && value <= 63))].sort((left, right) => left - right);
}

function boundedIdentity(value) {
  const normalized = String(value || "").trim();
  return normalized && normalized.length <= 500 ? normalized : undefined;
}

function mergeInteractiveModel(configuration, role, model) {
  if (!configuration || typeof configuration !== "object" || Array.isArray(configuration)) throw new Error(".traceguard.json must contain a JSON object.");
  const collection = role === "source" ? "sources" : role === "sink" ? "sinks" : role === "sanitizer" ? "sanitizers" : undefined;
  if (!collection) throw new Error(`Unsupported interactive model role: ${role}`);
  if (configuration[collection] !== undefined && !Array.isArray(configuration[collection])) {
    throw new Error(`.traceguard.json property “${collection}” must be an array before TraceGuard can update it.`);
  }
  const current = configuration[collection] || [];
  const duplicate = current.some(item => item && item.language === model.language
    && item.function === model.function && String(item.kind || "") === String(model.kind || "")
    && item.receiverType === model.receiverType && item.qualifiedName === model.qualifiedName
    && item.symbol === model.symbol && item.certainty === model.certainty
    && JSON.stringify(item.arguments || []) === JSON.stringify(model.arguments || [])
    && JSON.stringify(item.capability || []) === JSON.stringify(model.capability || []));
  if (duplicate) return { changed: false, configuration };
  if (current.length >= 200) throw new Error(`.traceguard.json already contains the maximum of 200 ${collection}.`);
  return {
    changed: true,
    configuration: { ...configuration, version: configuration.version ?? 1, [collection]: [...current, model] },
  };
}

module.exports = { buildInteractiveModel, callDetailsAtPosition, callNameAtPosition, mergeInteractiveModel, selectedCallName };
