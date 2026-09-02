"use strict";

// AST-level extraction of PHP fixed-numeric-collection join guard facts:
// an index-wise join guarded by is_numeric() checks over every element and a
// count() equality proof, e.g. validated octet reconstruction for shell commands.

const { normalizeAccessPath } = require("../ir/access-path");
const { GuardCapability } = require("../security/semantics");

function fixedNumericCollectionJoinFact(assignmentNode, language, text, helpers) {
  if (language !== "php") return undefined;
  const left = assignmentNode.childForFieldName("left") || assignmentNode.childForFieldName("name") || assignmentNode.namedChildren?.[0];
  const right = assignmentNode.childForFieldName("right") || assignmentNode.childForFieldName("value") || assignmentNode.namedChildren?.at(-1);
  const output = assignmentTarget(nodeText(left, text));
  if (!output || !right) return undefined;
  const controllingIf = enclosingConsequenceIf(assignmentNode, helpers.functionTypes);
  const condition = controllingIf?.childForFieldName("condition") || controllingIf?.namedChildren?.[0];
  const facts = collectionPredicateFacts(condition, text, helpers);
  if (!facts) return undefined;
  const joined = safeJoinElements(right, text);
  if (!joined || joined.collection !== facts.collection || joined.indexes.length !== facts.size) return undefined;
  if (!joined.indexes.every((value, index) => value === index)) return undefined;
  return {
    output,
    inputs: joined.indexes.map(index => `${facts.collection}[${index}]`),
    facts: {
      collection: facts.collection,
      size: facts.size,
      validatedIndexes: [...facts.indexes],
      elementConstraint: GuardCapability.NUMERIC_ONLY,
      joinSeparatorsLiteral: true,
    },
  };
}

function enclosingConsequenceIf(node, functionTypes) {
  for (let parent = node.parent; parent; parent = parent.parent) {
    if (parent.type === "if_statement") {
      const consequence = parent.childForFieldName("consequence") || parent.childForFieldName("body");
      if (consequence && containsTreeNode(consequence, node)) return parent;
    }
    if (Object.values(functionTypes).some(types => types.has(parent.type))) return undefined;
  }
  return undefined;
}

function collectionPredicateFacts(conditionNode, text, helpers) {
  if (!conditionNode) return undefined;
  const numericByCollection = new Map();
  const sizes = [];
  for (const predicate of flattenConjunction(conditionNode, text)) {
    const numeric = numericCollectionPredicate(predicate, text, helpers);
    if (numeric) {
      if (!numericByCollection.has(numeric.collection)) numericByCollection.set(numeric.collection, new Set());
      numericByCollection.get(numeric.collection).add(numeric.index);
    }
    const fixed = fixedCollectionPredicate(predicate, text, helpers);
    if (fixed) sizes.push(fixed);
  }
  for (const fixed of sizes) {
    if (fixed.size < 1 || fixed.size > 64) continue;
    const indexes = numericByCollection.get(fixed.collection);
    if (!indexes || indexes.size !== fixed.size) continue;
    if (![...Array(fixed.size).keys()].every(index => indexes.has(index))) continue;
    return { collection: fixed.collection, size: fixed.size, indexes: [...indexes].sort((a, b) => a - b) };
  }
  return undefined;
}

function flattenConjunction(node, text) {
  const value = unwrapExpression(node);
  if (value?.type === "binary_expression" && ["&&", "and"].includes(nodeText(value.childForFieldName("operator"), text))) {
    return [
      ...flattenConjunction(value.childForFieldName("left"), text),
      ...flattenConjunction(value.childForFieldName("right"), text),
    ];
  }
  return value ? [value] : [];
}

function numericCollectionPredicate(node, text, helpers) {
  const value = unwrapExpression(node);
  if (!value || !helpers.callTypes.has(value.type)) return undefined;
  const call = helpers.parseCall(value, text);
  if (String(call.function || "").toLowerCase() !== "is_numeric" || call.arguments.length !== 1) return undefined;
  return indexedCollectionAccess(call.arguments[0]);
}

function fixedCollectionPredicate(node, text, helpers) {
  const value = unwrapExpression(node);
  if (value?.type !== "binary_expression" || !["==", "==="].includes(nodeText(value.childForFieldName("operator"), text))) return undefined;
  const pairs = [
    [unwrapExpression(value.childForFieldName("left")), unwrapExpression(value.childForFieldName("right"))],
    [unwrapExpression(value.childForFieldName("right")), unwrapExpression(value.childForFieldName("left"))],
  ];
  for (const [callNode, sizeNode] of pairs) {
    if (!callNode || !helpers.callTypes.has(callNode.type) || sizeNode?.type !== "integer") continue;
    const call = helpers.parseCall(callNode, text);
    if (!new Set(["count", "sizeof"]).has(String(call.function || "").toLowerCase()) || call.arguments.length !== 1) continue;
    const collection = normalizeAccessPath(call.arguments[0]);
    const size = Number(nodeText(sizeNode, text));
    if (collection && Number.isInteger(size)) return { collection, size };
  }
  return undefined;
}

function safeJoinElements(node, text) {
  const leaves = flattenBinaryOperator(node, ".", text);
  const indexes = [];
  let collection;
  for (const leaf of leaves) {
    const value = unwrapExpression(leaf);
    if (!value) return undefined;
    if (value.type === "string") continue;
    const access = indexedCollectionAccess(nodeText(value, text));
    if (!access || collection && access.collection !== collection) return undefined;
    collection = access.collection;
    indexes.push(access.index);
  }
  return collection && indexes.length ? { collection, indexes } : undefined;
}

function flattenBinaryOperator(node, operator, text) {
  const value = unwrapExpression(node);
  if (value?.type === "binary_expression" && nodeText(value.childForFieldName("operator"), text) === operator) {
    return [
      ...flattenBinaryOperator(value.childForFieldName("left"), operator, text),
      ...flattenBinaryOperator(value.childForFieldName("right"), operator, text),
    ];
  }
  return value ? [value] : [];
}

function indexedCollectionAccess(value) {
  const accessPath = normalizeAccessPath(value);
  const match = String(accessPath || "").match(/^(.*)\[(\d+)\]$/);
  return match ? { collection: match[1], index: Number(match[2]) } : undefined;
}

function unwrapExpression(node) {
  let value = node;
  while (value && /^(?:parenthesized_expression|argument)$/.test(value.type) && value.namedChildren?.length === 1) {
    value = value.namedChildren[0];
  }
  return value;
}

function assignmentTarget(value) {
  const text = String(value || "").trim();
  const candidate = text.match(/\$?[A-Za-z_][\w$]*(?:(?:\.|->)[A-Za-z_]\w*|\[[^\]]+\])*$/)?.[0];
  return normalizeAccessPath(candidate);
}

function nodeText(node, text) { return node ? String(node.text ?? String(text).slice(node.startIndex, node.endIndex)) : ""; }

function containsTreeNode(container, node) {
  return Boolean(container && node && container.startIndex <= node.startIndex && container.endIndex >= node.endIndex);
}

module.exports = { fixedNumericCollectionJoinFact };
