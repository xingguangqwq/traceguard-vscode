"use strict";
// @ts-check

/** @typedef {import('../ir/contracts').SyntaxNode} SyntaxNode */
/** @typedef {import('../ir/contracts').SyntaxFunctionRecord} SyntaxFunctionRecord */

const { normalizeAccessPath, splitAccessPath } = require("../ir/access-path");

// Deliberately recognize only whole, straight-line method bodies. A method name
// such as getCommand/setCommand is never evidence of which field it accesses.
/** @param {SyntaxFunctionRecord} record @param {string} language @returns {import('../ir/contracts').AccessorSummary | undefined} */
function inferAccessorSummary(record, language) {
  if (!["java", "php", "python"].includes(language) || record.enclosingScope === "<file>") return undefined;
  const node = record.node;
  if (language === "java" && node.type !== "method_declaration" || language === "php" && node.type !== "method_declaration") return undefined;
  if (language === "python" && (node.parent?.parent?.type !== "class_definition" || node.children.some(child => child.type === "async"))) return undefined;
  const body = node.childForFieldName("body");
  if (!body || node.hasError || node.parent?.type === "decorated_definition") return undefined;
  if ((node.namedChildren || []).some(child => /modifier/.test(child.type) && /\b(?:static|abstract|async)\b/.test(child.text))) return undefined;
  const parameters = record.parameterDescriptors || [];
  if (language === "python" && parameters[0]?.name !== "self") return undefined;
  const explicit = language === "python" ? parameters.slice(1) : parameters;
  // Defaults, variadics and by-reference arguments have additional semantics.
  if (explicit.some(parameter => /[=&]|\.\.\.|\*/.test(parameter.raw || ""))) return undefined;
  const statements = (body.namedChildren || []).filter(child => child.type !== "comment");
  if (!statements.length || statements.length > 2) return undefined;
  if (statements.length === 1 && statements[0].type === "return_statement" && !explicit.length) {
    const value = statements[0].namedChildren?.[0];
    const path = instanceField(value, record, language);
    if (path) return { kind: "read", path };
    if (isConstant(value)) return { kind: "read", constant: true };
    return undefined;
  }
  if (explicit.length !== 1) return undefined;
  const statement = statements[0];
  const assignment = statement.type === "expression_statement" ? statement.namedChildren?.[0] : statement;
  if (!assignment || !["assignment", "assignment_expression"].includes(assignment.type)) return undefined;
  const left = assignment.childForFieldName("left");
  const right = assignment.childForFieldName("right");
  // Reject augmented assignments even in grammars sharing assignment nodes.
  if (!left || !right || assignment.text.slice(left.endIndex - assignment.startIndex, right.startIndex - assignment.startIndex).trim() !== "=") return undefined;
  const path = instanceField(left, record, language);
  if (!path || right.text.trim() !== explicit[0].name) return undefined;
  let returnsReceiver = false;
  if (statements.length === 2) {
    if (statements[1].type !== "return_statement") return undefined;
    const value = statements[1].namedChildren?.[0]?.text.trim();
    const receiver = { java: "this", php: "$this", python: "self" }[language];
    if (value !== receiver) return undefined;
    returnsReceiver = true;
  }
  return { kind: "write", path, parameterIndex: 0, returnsReceiver };
}

/** @param {SyntaxNode | null | undefined} node @param {SyntaxFunctionRecord} record @param {string} language @returns {import('../ir/contracts').AccessPathSegment[] | undefined} */
function instanceField(node, record, language) {
  if (!node || !["field_access", "member_access_expression", "attribute", "identifier"].includes(node.type)) return undefined;
  const raw = node.text.trim().replace(/\s*(?:->|\.)\s*/g, ".");
  const path = splitAccessPath(normalizeAccessPath(raw));
  const receiver = { java: "this", php: "$this", python: "self" }[language];
  if (path?.root === receiver && path.segments.length === 1 && path.segments[0] !== "*") {
    if (language === "java" && javaField(record, String(path.segments[0])) === "static") return undefined;
    return path.segments;
  }
  if (language !== "java" || node.type !== "identifier" || record.parameterDescriptors.some(parameter => parameter.name === raw)) return undefined;
  // Java permits an unqualified instance field. Verify its declaration rather
  // than mistaking a local variable, static field or method name for a field.
  return javaField(record, raw) === "instance" ? [raw] : undefined;
}

/** @param {SyntaxFunctionRecord} record @param {string} name */
function javaField(record, name) {
  for (let parent = record.node.parent; parent; parent = parent.parent) {
    if (!["class_body", "enum_body"].includes(parent.type)) continue;
    const declaration = parent.namedChildren.find(field => field.type === "field_declaration" &&
      field.namedChildren.some(child => child.type === "variable_declarator" && child.childForFieldName("name")?.text === name));
    if (!declaration) return undefined;
    return declaration.namedChildren.some(child => child.type === "modifiers" && /\bstatic\b/.test(child.text)) ? "static" : "instance";
  }
  return undefined;
}

/** @param {SyntaxNode | null | undefined} node */
function isConstant(node) {
  if (!node) return false;
  if (/^(?:null_literal|true|false|boolean_literal|integer|integer_literal|decimal_integer_literal|float|float_literal)$/.test(node.type)) return true;
  if (!["string", "string_literal", "encapsed_string"].includes(node.type)) return false;
  return (node.namedChildren || []).every(child => ["string_start", "string_end", "string_content", "string_fragment", "escape_sequence"].includes(child.type));
}

module.exports = { inferAccessorSummary };
