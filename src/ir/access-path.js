"use strict";
// @ts-check

/** @typedef {import("./contracts").AccessPathSegment} AccessPathSegment */

const IDENTIFIER = /^\$?[A-Za-z_][\w$]*$/;
const PROPERTY = /^[A-Za-z_$][\w$]*$/;

/** @param {unknown} value @param {{dynamic?: boolean}} [options] @returns {string} */
function normalizeAccessPath(value, options = {}) {
  const input = String(value || "").trim().replace(/\?\./g, ".").replace(/->/g, ".");
  const root = input.match(/^\$?[A-Za-z_][\w$]*/)?.[0];
  if (!root) return "";
  /** @type {AccessPathSegment[]} */
  const segments = [];
  let offset = root.length;
  while (offset < input.length) {
    if (input[offset] === ".") {
      const match = input.slice(offset + 1).match(/^[A-Za-z_$][\w$]*/)?.[0];
      if (!match) return "";
      segments.push(match);
      offset += match.length + 1;
      continue;
    }
    if (input[offset] !== "[") return "";
    const end = input.indexOf("]", offset + 1);
    if (end < 0) return "";
    const raw = input.slice(offset + 1, end).trim();
    if (/^\d+$/.test(raw)) segments.push(Number(raw));
    else if (raw === "*") segments.push("*");
    else {
      const quoted = raw.match(/^(["'])([\s\S]*)\1$/);
      if (quoted) segments.push(quoted[2]);
      else if (root.startsWith("$") && !raw.startsWith("$") && PROPERTY.test(raw)) segments.push(raw);
      else if (options.dynamic !== false && raw) segments.push("*");
      else return "";
    }
    offset = end + 1;
  }
  return formatAccessPath(root, segments);
}

/** @param {unknown} value @returns {{root: string, segments: AccessPathSegment[]} | undefined} */
function splitAccessPath(value) {
  const normalized = normalizeAccessPath(value);
  const root = normalized.match(/^\$?[A-Za-z_][\w$]*/)?.[0];
  if (!root) return undefined;
  /** @type {AccessPathSegment[]} */
  const segments = [];
  let offset = root.length;
  while (offset < normalized.length) {
    if (normalized[offset] === ".") {
      const match = normalized.slice(offset + 1).match(/^[A-Za-z_$][\w$]*/)?.[0];
      if (!match) return undefined;
      segments.push(match);
      offset += match.length + 1;
      continue;
    }
    const end = normalized.indexOf("]", offset + 1);
    if (end < 0) return undefined;
    const raw = normalized.slice(offset + 1, end);
    if (/^\d+$/.test(raw)) segments.push(Number(raw));
    else if (raw === "*") segments.push("*");
    else {
      try { segments.push(JSON.parse(raw)); } catch { return undefined; }
    }
    offset = end + 1;
  }
  return { root, segments };
}

/** @param {string} root @param {readonly AccessPathSegment[]} [segments] @returns {string} */
function formatAccessPath(root, segments = []) {
  if (!IDENTIFIER.test(String(root || ""))) return "";
  return segments.reduce((result, segment) => {
    if (segment === "*") return `${result}[*]`;
    if (typeof segment === "number" || /^\d+$/.test(String(segment))) return `${result}[${Number(segment)}]`;
    return PROPERTY.test(String(segment)) ? `${result}.${segment}` : `${result}[${JSON.stringify(String(segment))}]`;
  }, String(root));
}

/** @param {string} root @param {readonly AccessPathSegment[]} [segments] @returns {string} */
function appendAccessPath(root, segments = []) {
  const parsed = splitAccessPath(root);
  return parsed ? formatAccessPath(parsed.root, [...parsed.segments, ...segments]) : "";
}

/** @param {string} produced @param {string} consumed @returns {boolean} */
function pathFeeds(produced, consumed) {
  const left = splitAccessPath(produced);
  const right = splitAccessPath(consumed);
  if (!left || !right || left.root !== right.root || left.segments.length > right.segments.length) return false;
  return left.segments.every((segment, index) => compatibleSegment(segment, right.segments[index]));
}

/** @param {string} left @param {string} right @returns {boolean} */
function pathsOverlap(left, right) {
  return pathFeeds(left, right) || pathFeeds(right, left);
}

/** @param {string} value @param {string} root @returns {AccessPathSegment[] | undefined} */
function relativeAccessPath(value, root) {
  const child = splitAccessPath(value);
  const parent = splitAccessPath(root);
  if (!child || !parent || child.root !== parent.root || parent.segments.length > child.segments.length) return undefined;
  if (!parent.segments.every((segment, index) => compatibleSegment(segment, child.segments[index]))) return undefined;
  return child.segments.slice(parent.segments.length);
}

/** @param {string} taintedPath @param {string} inputPath @param {string} outputPath @param {string} [mode] @returns {string} */
function rebaseTaint(taintedPath, inputPath, outputPath, mode = "alias") {
  const tainted = normalizeAccessPath(taintedPath);
  const input = normalizeAccessPath(inputPath);
  const output = normalizeAccessPath(outputPath);
  if (!tainted || !input || !output) return "";
  if (mode === "aggregate") return pathsOverlap(tainted, input) ? output : "";
  if (mode !== "alias") return pathFeeds(tainted, input) ? output : "";
  if (!pathsOverlap(tainted, input)) return "";
  if (pathFeeds(tainted, input)) return output;
  const suffix = relativeAccessPath(tainted, input);
  return suffix ? appendAccessPath(output, suffix) : output;
}

/** @param {string} target @param {Iterable<string>} inputs @param {Iterable<string>} taintedPaths @param {string} [mode] @returns {string[]} */
function propagatedAssignmentTargets(target, inputs, taintedPaths, mode = "expression") {
  const output = normalizeAccessPath(target);
  if (!output) return [];
  /** @type {Set<string>} */
  const results = new Set();
  for (const input of inputs || []) {
    for (const tainted of taintedPaths || []) {
      const rebased = rebaseTaint(tainted, input, output, mode);
      if (rebased) results.add(rebased);
    }
  }
  return [...results];
}

/** @param {Iterable<string>} taintedPaths @param {string} target @returns {Set<string>} */
function removeAssignedTaint(taintedPaths, target) {
  const output = splitAccessPath(target);
  // An unknown key writes one slot, not every slot. Likewise a known-key write
  // cannot erase wildcard evidence that may still reside in another element.
  if (!output || output.segments.includes("*")) return new Set(taintedPaths || []);
  return new Set([...(taintedPaths || [])].filter(value => {
    const current = splitAccessPath(value);
    return !current || current.root !== output.root || current.segments.length < output.segments.length ||
      !output.segments.every((segment, index) => segment === current.segments[index]);
  }));
}

/** @param {AccessPathSegment} left @param {AccessPathSegment} right @returns {boolean} */
function compatibleSegment(left, right) {
  return left === "*" || right === "*" || left === right;
}

module.exports = {
  appendAccessPath,
  formatAccessPath,
  normalizeAccessPath,
  pathFeeds,
  pathsOverlap,
  propagatedAssignmentTargets,
  rebaseTaint,
  relativeAccessPath,
  removeAssignedTaint,
  splitAccessPath,
};
