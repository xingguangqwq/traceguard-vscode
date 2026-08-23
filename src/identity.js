"use strict";

const crypto = require("crypto");

const UNKNOWN_TYPE = "?";

function stableHash(value, length = 20) {
  return crypto.createHash("sha256").update(String(value || "")).digest("hex").slice(0, length);
}

function legacyHash(value) {
  return crypto.createHash("sha1").update(String(value || "")).digest("hex").slice(0, 16);
}

function normalizePath(value, options = {}) {
  const original = String(value || "");
  const normalized = original
    .replaceAll("\\", "/")
    .replace(/^\.\//, "")
    .replace(/\/{2,}/g, "/")
    .normalize("NFC");
  const caseSensitive = options.caseSensitive ?? isCaseSensitivePath(original, options.platform);
  return caseSensitive ? normalized : normalized.toLowerCase();
}

function isCaseSensitivePath(value, platform = process.platform) {
  const text = String(value || "");
  if (/^[A-Za-z]:[\\/]/.test(text) || /^\\\\/.test(text) || /^file:\/{2,3}[A-Za-z]:[\\/]/i.test(text)) return false;
  if (/^\//.test(text) || /^file:\/{2,3}\//i.test(text)) return true;
  return platform !== "win32";
}

function normalizeScope(value) {
  const normalized = String(value || "<file>")
    .replace(/\s+/g, " ")
    .replace(/\s*([.$:#/])\s*/g, "$1")
    .trim();
  return normalized || "<file>";
}

function normalizeType(value) {
  const normalized = String(value || UNKNOWN_TYPE)
    .replace(/\s+/g, " ")
    .replace(/\s*([<>{}\[\],?|:&*])\s*/g, "$1")
    .replace(/^(?:final|const|readonly)\s+/i, "")
    .trim();
  return normalized || UNKNOWN_TYPE;
}

function splitParameters(value) {
  const parts = [];
  let start = 0;
  let depth = 0;
  let quote = "";
  let escaped = false;
  const text = String(value || "");
  for (let index = 0; index < text.length; index += 1) {
    const character = text[index];
    if (quote) {
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === quote) quote = "";
      continue;
    }
    if (character === "'" || character === '"' || character === "`") { quote = character; continue; }
    if ("([{<".includes(character)) depth += 1;
    else if (")]}>".includes(character)) depth = Math.max(0, depth - 1);
    else if (character === "," && depth === 0) { parts.push(text.slice(start, index).trim()); start = index + 1; }
  }
  const tail = text.slice(start).trim();
  if (tail || parts.length) parts.push(tail);
  return parts.filter(Boolean);
}

function parameterDescriptors(parameters, language) {
  return splitParameters(parameters).map((raw, index) => describeParameter(raw, language, index));
}

function describeParameter(raw, language, index) {
  let text = String(raw || "")
    .replace(/@\w+(?:\([^)]*\))?\s*/g, "")
    .replace(/^\s*\[[^\]]+\]\s*/g, "")
    .replace(/\s*=.*$/s, "")
    .trim();
  const variadic = /(?:\.\.\.|\*\*?|\.\.\.)/.test(text);
  let name = "";
  let type = UNKNOWN_TYPE;

  if (language === "php") {
    name = text.match(/\$[A-Za-z_]\w*/g)?.at(-1) || "";
    type = text.slice(0, Math.max(0, text.lastIndexOf(name))).replace(/[?&]/g, match => match).trim() || UNKNOWN_TYPE;
  } else if (language === "typescript") {
    const match = text.match(/^(?:\.\.\.)?([A-Za-z_$][\w$]*)\??\s*(?::\s*([\s\S]+))?$/);
    name = match?.[1] || "";
    type = match?.[2] || UNKNOWN_TYPE;
  } else if (language === "python") {
    const match = text.match(/^\*{0,2}([A-Za-z_]\w*)\s*(?::\s*([\s\S]+))?$/);
    name = match?.[1] || "";
    type = match?.[2] || UNKNOWN_TYPE;
  } else if (language === "go") {
    const match = text.match(/^([A-Za-z_]\w*)\s+([\s\S]+)$/);
    name = match?.[1] || text.match(/[A-Za-z_]\w*/)?.[0] || "";
    type = match?.[2] || UNKNOWN_TYPE;
  } else if (["java", "csharp"].includes(language)) {
    text = text.replace(/^(?:(?:final|params|ref|out|in|this|scoped|readonly)\s+)+/i, "");
    const match = text.match(/([A-Za-z_$][\w$]*)\s*(?:\[\s*\])?$/);
    name = match?.[1] || "";
    type = name ? text.slice(0, match.index).trim() : UNKNOWN_TYPE;
  } else {
    name = text.replace(/^\.\.\./, "").match(/[A-Za-z_$][\w$]*/)?.[0] || "";
  }

  return {
    name: name || `parameter${index}`,
    type: normalizeType(type),
    optional: /\?\s*(?::|$)/.test(text),
    variadic,
  };
}

function typedSignature(name, parameters) {
  return `${String(name || "<anonymous>")}(${(parameters || []).map(parameter => normalizeType(parameter.type)).join(",")})`;
}

function buildSymbolKey(input) {
  const parameters = input.parameterDescriptors || parameterDescriptors(input.parameters, input.language);
  const parts = [
    String(input.language || "unknown").toLowerCase(),
    normalizePath(input.relativePath, { caseSensitive: isCaseSensitivePath(input.absolutePath || input.relativePath) }),
    String(input.kind || "function").toLowerCase(),
    normalizeScope(input.enclosingScope),
    typedSignature(input.name, parameters),
  ];
  if (input.discriminator) parts.push(`context:${normalizeScope(input.discriminator)}`);
  return parts.join("::");
}

function symbolId(symbolKey) {
  return `sym_${stableHash(symbolKey)}`;
}

module.exports = {
  UNKNOWN_TYPE,
  buildSymbolKey,
  legacyHash,
  isCaseSensitivePath,
  normalizePath,
  normalizeScope,
  normalizeType,
  parameterDescriptors,
  splitParameters,
  stableHash,
  symbolId,
  typedSignature,
};
