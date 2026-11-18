"use strict";

// Language-specific text-level expression semantics shared by frontends:
// identifier extraction, Python f-string interpolation, and JavaBean property reads.
// No tree-sitter or TypeScript dependency; operates on source text only.

const { normalizeAccessPath } = require("../ir/access-path");
const { extractIdentifiers } = require("./syntax-tools");

function normalizedIdentifiers(value) {
  return extractIdentifiers(value).map(name => normalizeAccessPath(name) || name);
}

function expressionInputs(value, language, options = {}) {
  if (language === "php") {
    return phpExpressionInputs(String(value || ""));
  }
  if (language === "python") {
    const source = String(value || "");
    const interpolationInputs = pythonFormattedStringExpressions(source)
      .flatMap(expression => expressionInputs(expression, "python"));
    const paths = [...source.matchAll(/\b[A-Za-z_]\w*(?:(?:\.[A-Za-z_]\w*)|\[\s*(?:\d+|["'][^"']+["'])\s*\])+/g)]
      .filter(match => !/^\s*\(/.test(source.slice(match.index + match[0].length)))
      .map(match => normalizeAccessPath(match[0]))
      .filter(Boolean);
    const identifiers = normalizedIdentifiers(source).filter(identifier =>
      !paths.some(path => path === identifier || path.startsWith(`${identifier}.`) || path.startsWith(`${identifier}[`)));
    return [...new Set([...paths, ...identifiers, ...interpolationInputs])];
  }
  if (language !== "java") return normalizedIdentifiers(value);
  const accessPaths = [];
  let source = String(value || "");
  if (options.mapRead) source = source.replace(/\b([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\.get\s*\(\s*("[^"\\]*"|\d+|[A-Za-z_$][\w$]*)\s*\)/g, (match, receiver, key) => {
    const slot = options.mapRead(receiver, key);
    if (!slot) return match;
    accessPaths.push(slot);
    return " ".repeat(match.length);
  });
  for (const match of source.matchAll(/\b([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\.(?:get|is)([A-Z][A-Za-z0-9_$]*)\s*\(\s*\)/g)) {
    const property = javaBeanProperty(match[2]);
    const path = normalizeAccessPath(`${match[1]}.${property}`);
    if (path) accessPaths.push(path);
  }
  for (const match of source.matchAll(/(?:^|[^.\w$])(?:this\s*\.\s*)?(?:get|is)([A-Z][A-Za-z0-9_$]*)\s*\(\s*\)/g)) {
    const property = normalizeAccessPath(javaBeanProperty(match[1]));
    if (property) accessPaths.push(property);
  }
  const identifiers = normalizedIdentifiers(source).filter(identifier =>
    !accessPaths.some(path => path === identifier || path.startsWith(`${identifier}.`)) &&
    !/^get[A-Z]|^is[A-Z]/.test(identifier));
  return [...new Set([...accessPaths, ...identifiers])];
}

function phpExpressionInputs(source) {
  const paths = [];
  let quote = "";
  for (let index = 0; index < source.length;) {
    const character = source[index];
    if (quote && character === "\\") { index += 2; continue; }
    if (character === quote) { quote = ""; index++; continue; }
    if (!quote && (character === "'" || character === '"')) { quote = character; index++; continue; }
    if (quote === "'" || character !== "$") { index++; continue; }
    const root = /^\$[A-Za-z_]\w*/.exec(source.slice(index))?.[0];
    if (!root) { index++; continue; }
    let end = index + root.length;
    let raw = root;
    for (;;) {
      const member = /^\s*(?:->|\?->)\s*([A-Za-z_]\w*)/.exec(source.slice(end));
      if (member && !/^\s*\(/.test(source.slice(end + member[0].length))) {
        raw += `.${member[1]}`;
        end += member[0].length;
        continue;
      }
      const subscript = /^\s*\[\s*(?:'[^'\\]*'|"[^"\\]*"|[^\[\]'"\r\n]+)\s*\]/.exec(source.slice(end));
      if (!subscript) break;
      raw += subscript[0].trimStart();
      end += subscript[0].length;
    }
    paths.push(normalizeAccessPath(raw) || root);
    index = end;
  }
  return [...new Set(paths)];
}

function pythonFormattedStringExpressions(value) {
  const source = String(value || "").trim();
  if (!/^(?:fr|rf|f)(?:["']{1,3})/i.test(source)) return [];
  const expressions = [];
  for (const match of source.matchAll(/(?<!\{)\{([^{}]+)\}(?!\})/g)) {
    const expression = match[1].split(/[!:](?=(?:[^"']|["'][^"']*["'])*$)/, 1)[0].trim();
    if (expression) expressions.push(expression);
  }
  return expressions;
}

function javaBeanProperty(value) {
  return /^[A-Z]{2}/.test(value) ? value : value.charAt(0).toLowerCase() + value.slice(1);
}

function javaBeanGetterRead(call, output, language) {
  if (language !== "java" || !output?.name || (call?.arguments || []).length) return undefined;
  const match = /^(?:get|is)([A-Z][A-Za-z0-9_$]*)$/.exec(String(call.function || ""));
  if (!match) return undefined;
  const property = javaBeanProperty(match[1]);
  const receiver = String(call.receiver || "").trim();
  if (receiver && receiver !== "this") return undefined;
  return { input: property, output: output.name };
}

module.exports = { expressionInputs, javaBeanGetterRead, javaBeanProperty, pythonFormattedStringExpressions };
