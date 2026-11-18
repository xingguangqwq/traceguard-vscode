"use strict";

const { appendAccessPath, normalizeAccessPath, pathsOverlap } = require("../ir/access-path");
const { expressionInputs } = require("./expression-inputs");

const PATTERNS = new Set(["pattern_list", "tuple_pattern", "list_pattern"]);
const SEQUENCES = new Set(["tuple", "list", "expression_list"]);

// Exact positional bindings for known tuple/list literals and access-path unpacking.
// Calls and starred patterns need separate return/length models, so stay on the existing fallback.
function pythonBindingAssignments(left, right) {
  if (!left || !right) return undefined;
  const containsSplat = node => node.type.includes("splat") || node.namedChildren.some(containsSplat);
  if (containsSplat(right)) return undefined;
  const result = [];
  const assign = (target, value, node) => {
    if (SEQUENCES.has(value?.type)) {
      result.push({ target, inputs: [], mode: "constant", node });
      value.namedChildren.forEach((child, index) => assign(appendAccessPath(target, [index]), child, child));
      return true;
    }
    const input = typeof value === "string" ? value : value.text;
    result.push({ target, inputs: expressionInputs(input, "python"), mode: normalizeAccessPath(input) ? "alias" : "aggregate", node });
    return true;
  };
  const bind = (pattern, value, node) => {
    if (PATTERNS.has(pattern.type)) {
      if (pattern.namedChildren.some(child => child.type.includes("splat"))) return false;
      const literal = SEQUENCES.has(value?.type);
      const input = literal ? undefined : normalizeAccessPath(typeof value === "string" ? value : value.text);
      if (!literal && !input) return false;
      if (literal && value.namedChildren.length !== pattern.namedChildren.length) return false;
      return pattern.namedChildren.every((child, index) => bind(child,
        literal ? value.namedChildren[index] : appendAccessPath(input, [index]), child));
    }
    const target = normalizeAccessPath(pattern.text);
    return Boolean(target) && assign(target, value, node);
  };
  if (!PATTERNS.has(left.type) && !SEQUENCES.has(right.type)) return undefined;
  if (!bind(left, right, left)) return undefined;
  const snapshots = [];
  // Python evaluates all RHS values before updating any of the LHS bindings.
  for (let index = 0; index < result.length; index++) {
    const binding = result[index];
    if (!binding.inputs.some(input => result.some(other => pathsOverlap(input, other.target)))) continue;
    const temporary = `$traceguard_unpack_${left.startIndex}_${index}`;
    snapshots.push({ ...binding, target: temporary });
    result[index] = { ...binding, inputs: [temporary], mode: "alias" };
  }
  return [...snapshots, ...result];
}

module.exports = { pythonBindingAssignments };
