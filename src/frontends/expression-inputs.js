"use strict";

// Language-specific text-level expression semantics shared by frontends:
// identifier extraction, Python f-string interpolation, and JavaBean property reads.
// No tree-sitter or TypeScript dependency; operates on source text only.

const { normalizeAccessPath } = require("../ir/access-path");
const { extractIdentifiers } = require("./syntax-tools");

function normalizedIdentifiers(value) {
  return extractIdentifiers(value).map(name => normalizeAccessPath(name) || name);
}

function expressionInputs(value, language) {
  if (language === "php") {
    return [...new Set([...normalizedIdentifiers(value), ...[...String(value || "").matchAll(/\$[A-Za-z_]\w*/g)].map(match => match[0])])];
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
  const source = String(value || "");
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
