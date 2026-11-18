"use strict";
// @ts-check

/** @typedef {import('../ir/contracts').SyntaxNode} SyntaxNode */
/** @typedef {import('../ir/contracts').CallableParameter} CallableParameter */
/** @typedef {import('../ir/contracts').ArgumentKind} ArgumentKind */
/** @typedef {import('../ir/contracts').ParameterKind} ParameterKind */

const { parameterDescriptors } = require("../identity");

/** @param {SyntaxNode} node @param {string} language @param {CallableParameter[]} fallback @returns {CallableParameter[]} */
function callableParameters(node, language, fallback) {
  if (!["python", "php"].includes(language)) return fallback;
  const parameters = node.childForFieldName("parameters");
  if (!parameters) return fallback;
  /** @type {(CallableParameter & {callBinding: import('../ir/contracts').CallBinding})[]} */
  const result = [];
  let keywordOnly = false;
  for (const child of parameters.namedChildren || []) {
    if (child.type === "comment") continue;
    if (child.type === "positional_separator") {
      for (const parameter of result) parameter.callBinding.kind = "positional-only";
      continue;
    }
    if (child.type === "keyword_separator") { keywordOnly = true; continue; }
    const raw = child.text;
    const descriptor = parameterDescriptors(raw, language)[0];
    if (!descriptor) continue;
    /** @type {ParameterKind} */
    let kind = keywordOnly ? "keyword-only" : "positional-or-keyword";
    if (language === "python" && /^\*\*/.test(raw)) kind = "variadic-keyword";
    else if (language === "python" && /^\*/.test(raw)) { kind = "variadic-positional"; keywordOnly = true; }
    else if (language === "php" && child.type === "variadic_parameter") kind = "variadic";
    const defaultNode = child.childForFieldName(language === "php" ? "default_value" : "value");
    result.push({ ...descriptor, raw, callBinding: {
      kind, hasDefault: Boolean(defaultNode),
      ...(defaultNode ? {
        defaultExpression: defaultNode.text.slice(0, 4096),
        defaultConstant: isScalarConstant(defaultNode),
        defaultTruncated: defaultNode.text.length > 4096,
        defaultLine: defaultNode.startPosition.row + 1,
      } : {}),
    } });
  }
  return result;
}

/** @param {SyntaxNode} node @param {SyntaxNode[]} argumentNodes @param {string[]} args */
function callArgumentFacts(node, argumentNodes, args) {
  const nodes = argumentNodes.filter(child => child.type !== "comment");
  if (nodes.length !== args.length || node.hasError) return {
    argumentKinds: args.map(() => /** @type {ArgumentKind} */ ("unknown")), valueNodes: [],
  };
  const names = [];
  /** @type {ArgumentKind[]} */
  const kinds = [];
  const values = [];
  const valueNodes = [];
  for (let index = 0; index < nodes.length; index++) {
    const argument = nodes[index];
    /** @type {SyntaxNode | null | undefined} */
    let value = argument;
    let name;
    /** @type {ArgumentKind} */
    let kind = "positional";
    if (argument.type === "keyword_argument") {
      name = argument.childForFieldName("name")?.text;
      value = argument.childForFieldName("value");
      kind = name && value ? "named" : "unknown";
    } else if (argument.type === "argument") {
      name = argument.childForFieldName("name")?.text;
      value = argument.namedChildren.at(-1);
      if (name) kind = "named";
      else if (value?.type === "variadic_unpacking") { kind = "unpack"; value = value.namedChildren[0]; }
    } else if (["list_splat", "dictionary_splat"].includes(argument.type)) {
      kind = argument.type === "list_splat" ? "unpack-positional" : "unpack-keyword";
      value = argument.namedChildren[0];
    }
    names.push(name || "");
    kinds.push(kind);
    values.push(kind === "positional" ? args[index] : value?.text || args[index]);
    valueNodes.push(value);
  }
  const special = kinds.some(kind => kind !== "positional");
  return {
    argumentNames: special ? names : undefined,
    argumentKinds: special ? kinds : undefined,
    argumentValues: special ? values : undefined,
    argumentRanges: valueNodes.map(value => ({ startOffset: value?.startIndex, endOffset: value?.endIndex })),
    argumentConstantFlags: valueNodes.map(isScalarConstant),
    valueNodes,
  };
}

/** @param {SyntaxNode | null | undefined} node @returns {boolean} */
function isScalarConstant(node) {
  if (!node) return false;
  if (/^(?:none|null|null_literal|true|false|boolean|boolean_literal|integer|integer_literal|decimal_integer_literal|float|float_literal)$/.test(node.type)) return true;
  if (!["string", "string_literal", "encapsed_string"].includes(node.type)) return false;
  return node.namedChildren.every(child => ["string_start", "string_end", "string_content", "string_fragment", "escape_sequence"].includes(child.type));
}

module.exports = { callArgumentFacts, callableParameters };
