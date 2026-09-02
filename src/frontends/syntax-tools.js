"use strict";

const { normalizePath } = require("../identity");

const CALL_KEYWORDS = new Set([
  "if", "for", "while", "switch", "catch", "with", "return", "throw", "new",
  "function", "def", "func", "class", "interface", "typeof", "sizeof", "isset",
  "empty", "echo", "print", "include", "require", "match", "select", "go", "defer",
]);
const IDENTIFIER_KEYWORDS = new Set([
  ...CALL_KEYWORDS,
  "const", "let", "var", "final", "public", "private", "protected", "internal",
  "static", "async", "await", "export", "default", "true", "false", "null", "nil",
  "None", "self", "this", "void", "string", "int", "long", "bool", "boolean",
  "class", "struct", "package", "import", "from", "as", "in", "else", "elif",
]);

function extractFileReferences(lines, language) {
  const references = [];
  const pythonTypes = new Map();
  const add = (local, target, kind = "import") => {
    if (!local || !target) return;
    const key = [canonicalName(local), normalizePath(target), kind].join(":");
    if (!references.some(reference => reference.key === key)) references.push({ key, local, target, kind });
  };

  for (const rawLine of lines) {
    const code = String(rawLine).trim();
    if (!code || /^(?:\/\/|#|\*|\/\*)/.test(code)) continue;
    if (language === "javascript" || language === "typescript") {
      const imported = code.match(/^import\s+(.+?)\s+from\s+["']([^"']+)["']/);
      if (imported) for (const local of parseImportedBindings(imported[1])) add(local, imported[2]);
      const required = code.match(/\b(?:const|let|var)\s+(.+?)\s*=\s*require\s*\(\s*["']([^"']+)["']\s*\)/);
      if (required) for (const local of parseRequiredBindings(required[1])) add(local, required[2], "require");
    }
    if (language === "python") {
      const declaration = code.match(/^(?:async\s+)?class\s+([A-Za-z_]\w*)/);
      if (declaration) add(declaration[1], declaration[1], "declaration");
      const functionDeclaration = String(rawLine).match(/^(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(/);
      if (functionDeclaration) add(functionDeclaration[1], functionDeclaration[1], "declaration");
      const fromImport = code.match(/^from\s+([\w.]+)\s+import\s+(.+)$/);
      if (fromImport) {
        for (const part of splitArguments(fromImport[2])) {
          const match = part.trim().match(/^([A-Za-z_]\w*)(?:\s+as\s+([A-Za-z_]\w*))?/);
          if (match) add(match[2] || match[1], fromImport[1]);
        }
      }
      const imported = code.match(/^import\s+([\w.]+)(?:\s+as\s+([A-Za-z_]\w*))?/);
      if (imported) add(imported[2] || imported[1].split(".")[0], imported[1]);
      const constructed = code.match(/^([A-Za-z_]\w*)\s*(?::[^=]+)?=\s*([A-Za-z_][\w.]*)\s*\(/);
      if (constructed) {
        const resolvedType = resolvePythonFactoryType(constructed[2], references, pythonTypes);
        add(constructed[1], resolvedType, "type");
        pythonTypes.set(canonicalName(constructed[1]), resolvedType);
      }
      const contextConstructed = code.match(/^(?:async\s+)?with\s+([A-Za-z_][\w.]*)\s*\([^)]*\)\s+as\s+([A-Za-z_]\w*)/);
      if (contextConstructed) add(contextConstructed[2], contextConstructed[1], "type");
      for (const typed of code.matchAll(/\b([A-Za-z_]\w*)\s*:\s*([A-Za-z_][\w.]*)/g)) add(typed[1], typed[2], "type");
      const memberAssignment = code.match(/^self\.([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\s*$/);
      if (memberAssignment) {
        const sourceType = references.find(reference => reference.kind === "type" && canonicalName(reference.local) === canonicalName(memberAssignment[2]));
        if (sourceType) {
          add(`self.${memberAssignment[1]}`, sourceType.target, "type");
          pythonTypes.set(canonicalName(`self.${memberAssignment[1]}`), sourceType.target);
        }
      }
      const memberConstruction = code.match(/^self\.([A-Za-z_]\w*)\s*=\s*([A-Za-z_][\w.]*)\s*\(/);
      if (memberConstruction) add(`self.${memberConstruction[1]}`, memberConstruction[2], "type");
    }
    if (language === "java") {
      const declaration = code.match(/^(?:public\s+|protected\s+|private\s+|abstract\s+|final\s+|static\s+)*(?:class|interface|record|enum)\s+([A-Za-z_$][\w$]*)/);
      if (declaration) add(declaration[1], declaration[1], "declaration");
      const packageDeclaration = code.match(/^package\s+([\w.]+)\s*;/);
      if (packageDeclaration) add("<package>", packageDeclaration[1], "package");
      const imported = code.match(/^import\s+(?:static\s+)?([\w.*]+)\s*;/);
      if (imported) add(imported[1].split(".").at(-1), imported[1]);
      collectTypedReceivers(code, add);
    }
    if (language === "csharp") {
      const alias = code.match(/^using\s+([A-Za-z_]\w*)\s*=\s*([\w.]+)\s*;/);
      if (alias) add(alias[1], alias[2]);
      collectTypedReceivers(code, add);
    }
    if (language === "php") {
      const declaration = code.match(/^(?:(?:abstract|final|readonly)\s+)*(?:class|interface|trait|enum)\s+([A-Za-z_]\w*)/i);
      if (declaration) add(declaration[1], declaration[1], "declaration");
      const functionDeclaration = String(rawLine).match(/^(?:(?:public|protected|private|static|final|abstract)\s+)*function\s+&?\s*([A-Za-z_]\w*)\s*\(/i);
      if (functionDeclaration) add(functionDeclaration[1], functionDeclaration[1], "declaration");
      const imported = code.match(/^use\s+([^;]+);/i);
      if (imported) for (const binding of parsePhpUseBindings(imported[1])) add(binding.local, binding.target);
      const namespaceDeclaration = code.match(/^(?:<\?php\s*)?namespace\s+([^;]+);/i);
      if (namespaceDeclaration) add("<namespace>", namespaceDeclaration[1].trim(), "namespace");
      const constructed = code.match(/(\$[A-Za-z_]\w*)\s*=\s*new\s+([A-Za-z_\\][\w\\]*)/i);
      if (constructed) add(constructed[1], constructed[2], "type");
      collectTypedReceivers(code, add);
    }
    if (language === "go") {
      const imported = code.match(/^(?:([A-Za-z_]\w*)\s+)?["']([^"']+)["']\s*$/);
      if (imported) add(imported[1] || imported[2].split("/").at(-1), imported[2]);
    }
  }
  return references.map(({ key, ...reference }) => reference);
}

function resolvePythonFactoryType(target, references, knownTypes) {
  const value = String(target || "");
  const known = knownTypes.get(canonicalName(value));
  if (known) return known;
  const [root, member] = value.split(".");
  const rootType = knownTypes.get(canonicalName(root));
  if (member === "cursor" && /(?:^|\.)Connection$/i.test(rootType || "")) {
    return /sqlite|aiosqlite/i.test(rootType) ? `${String(rootType).replace(/\.Connection$/i, "")}.Cursor` : "Cursor";
  }
  const imported = references.find(reference => ["import", "require"].includes(reference.kind) && canonicalName(reference.local) === canonicalName(root));
  const moduleName = imported?.target || root;
  if (member === "connect" && /^(?:sqlite3|aiosqlite)$/i.test(moduleName)) return `${moduleName}.Connection`;
  if (!member && /^(?:sessionmaker|async_sessionmaker)$/i.test(value) && /sqlalchemy/i.test(imported?.target || "")) {
    return `${imported.target}.${/^async_/i.test(value) ? "AsyncSession" : "Session"}`;
  }
  return value;
}

function parsePhpUseBindings(value) {
  const input = String(value || "").trim().replace(/^(?:function|const)\s+/i, "");
  const group = input.match(/^([^{}]+)\{([^{}]+)\}$/);
  const values = group
    ? splitArguments(group[2]).map(item => `${group[1].replace(/\\+$/, "")}\\${item.trim()}`)
    : splitArguments(input);
  return values.map(raw => {
    const parts = raw.trim().split(/\s+as\s+/i);
    const target = parts[0].replace(/^\\+/, "");
    return { target, local: parts[1] || target.split("\\").at(-1) };
  }).filter(binding => binding.local && binding.target);
}

function parseImportedBindings(value) {
  const locals = [];
  const namespace = value.match(/\*\s+as\s+([A-Za-z_$][\w$]*)/);
  if (namespace) locals.push(namespace[1]);
  const named = value.match(/\{([^}]+)\}/);
  if (named) {
    for (const part of splitArguments(named[1])) {
      const match = part.trim().match(/^([A-Za-z_$][\w$]*)(?:\s+as\s+([A-Za-z_$][\w$]*))?/);
      if (match) locals.push(match[2] || match[1]);
    }
  }
  const defaultBinding = value.replace(/\{[^}]*\}|\*\s+as\s+[A-Za-z_$][\w$]*/g, "").split(",")[0].trim();
  if (/^[A-Za-z_$][\w$]*$/.test(defaultBinding)) locals.push(defaultBinding);
  return unique(locals);
}

function parseRequiredBindings(value) {
  const trimmed = value.trim();
  const named = trimmed.match(/^\{([^}]+)\}$/);
  if (!named) return /^[A-Za-z_$][\w$]*$/.test(trimmed) ? [trimmed] : [];
  return unique(splitArguments(named[1]).map(part => {
    const match = part.trim().match(/^([A-Za-z_$][\w$]*)(?:\s*:\s*([A-Za-z_$][\w$]*))?/);
    return match?.[2] || match?.[1];
  }).filter(Boolean));
}

function collectTypedReceivers(code, add) {
  const pattern = /\b((?:[A-Za-z_]\w*[.\\])*[A-Z][A-Za-z0-9_]*(?:<[^>]+>)?(?:\[\])?)\s+([a-z_$][\w$]*)\b/g;
  let match;
  while ((match = pattern.exec(code))) add(match[2], match[1].replace(/<.*>|\[\]/g, ""), "type");
}

function parseParameterNames(parameters, language) {
  const names = [];
  for (const rawPart of splitArguments(parameters || "")) {
    const part = rawPart.replace(/@\w+(?:\([^)]*\))?\s*/g, "").replace(/\[[^\]]+\]\s*/g, "").replace(/\s*=.*$/, "").trim();
    if (!part) continue;
    if (language === "php") {
      const match = part.match(/\$[A-Za-z_]\w*/g);
      if (match?.length) names.push(match.at(-1));
      continue;
    }
    const matches = part.match(/[A-Za-z_][\w$]*/g) || [];
    if (!matches.length) continue;
    if (["javascript", "typescript", "python", "go"].includes(language)) names.push(matches[0]);
    else names.push(matches.at(-1));
  }
  return unique(names.filter(name => !["self", "this", "cls"].includes(name)));
}

function extractAssignment(code) {
  const masked = maskStrings(code);
  const operator = /(?<![=!<>])(?::=|=)(?!=|>)/.exec(masked);
  if (!operator) return undefined;
  const left = masked.slice(0, operator.index);
  const right = code.slice(operator.index + operator[0].length);
  const target = left.match(/(\$?[A-Za-z_][\w$]*)\s*(?::[^=]+)?\s*$/)?.[1];
  if (!target) return undefined;
  return { target, variables: extractIdentifiers(right) };
}

function extractCalls(code, functionName, declarationLine) {
  const masked = maskStrings(code);
  const calls = [];
  const pattern = /([A-Za-z_$][\w$]*)\s*\(/g;
  let match;
  while ((match = pattern.exec(masked))) {
    const callee = match[1];
    const prefix = masked.slice(0, match.index);
    if (CALL_KEYWORDS.has(callee) || /\b(?:function|def|func|class|interface|new)\s*$/.test(prefix) || (declarationLine && callee === functionName)) continue;
    const openIndex = pattern.lastIndex - 1;
    const closeIndex = findClosingParen(masked, openIndex);
    if (closeIndex < 0) continue;
    const argumentsText = code.slice(openIndex + 1, closeIndex);
    const receiver = prefix.match(/(\$?[A-Za-z_][\w$]*)\s*(?:\.|->|::)\s*$/)?.[1];
    calls.push({
      callee,
      receiver,
      arguments: splitArguments(argumentsText),
      argumentVariables: splitArguments(argumentsText).map(extractIdentifiers),
    });
  }
  return calls;
}

function extractIdentifiers(code) {
  const masked = maskStrings(code);
  const names = [];
  const preciseRanges = [];
  const phpAccess = /(\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER))\s*\[\s*["']([^"']+)["']\s*\]/g;
  let access;
  while ((access = phpAccess.exec(String(code)))) {
    names.push(`${access[1]}[${access[2]}]`);
    preciseRanges.push([access.index, access.index + access[0].length]);
  }
  const pattern = /\$?[A-Za-z_][\w$]*/g;
  let match;
  while ((match = pattern.exec(masked))) {
    const name = match[0];
    if (preciseRanges.some(([start, end]) => match.index >= start && match.index < end)) continue;
    const before = masked.slice(0, match.index);
    if (/(?:\.|->|::)\s*$/.test(before)) continue;
    if (IDENTIFIER_KEYWORDS.has(name) || /^\d/.test(name)) continue;
    names.push(name);
  }
  return unique(names);
}

function splitArguments(value) {
  const parts = [];
  let start = 0;
  let depth = 0;
  let quote = "";
  let escaped = false;
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index];
    if (quote) {
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === quote) quote = "";
      continue;
    }
    if (character === "'" || character === '"' || character === "`") { quote = character; continue; }
    if ("([{".includes(character)) depth += 1;
    else if (")]}".includes(character)) depth = Math.max(0, depth - 1);
    else if (character === "," && depth === 0) { parts.push(value.slice(start, index).trim()); start = index + 1; }
  }
  const tail = value.slice(start).trim();
  if (tail || parts.length) parts.push(tail);
  return parts.filter(Boolean);
}

function findClosingParen(value, openIndex) {
  let depth = 0;
  for (let index = openIndex; index < value.length; index += 1) {
    if (value[index] === "(") depth += 1;
    else if (value[index] === ")") {
      depth -= 1;
      if (depth === 0) return index;
    }
  }
  return -1;
}

function maskStrings(code) {
  return String(code)
    .replace(/"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`/g, match => " ".repeat(match.length))
    .replace(/\/\/.*$/, match => " ".repeat(match.length));
}

function canonicalName(value) { return String(value || "").replace(/^\$/, "").replace(/[^A-Za-z0-9]/g, "").toLowerCase(); }
function unique(values) { return [...new Set(values.filter(Boolean))]; }

module.exports = {
  extractAssignment,
  extractCalls,
  extractFileReferences,
  extractIdentifiers,
  parseParameterNames,
  splitArguments,
  unique,
};
