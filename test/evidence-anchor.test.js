"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { createEvidenceAnchor, resolveEvidenceLocation } = require("../src/review/evidence-anchor");

test("evidence relocates after inserted lines and normalizes CRLF", () => {
  const original = "function run() {\n  review(value);\n}\n";
  const note = { line: 2, endLine: 2, code: "review(value);", anchor: createEvidenceAnchor(original, 2, 2) };
  assert.deepEqual(resolveEvidenceLocation(note, original), { status: "current", line: 2, endLine: 2 });
  assert.deepEqual(resolveEvidenceLocation(note, "// header\r\n" + original.replaceAll("\n", "\r\n")), { status: "relocated", line: 3, endLine: 3 });
});

test("evidence rejects removed or ambiguous snippets rather than trusting an old line", () => {
  const note = { line: 1, code: "review(value);" };
  assert.equal(resolveEvidenceLocation(note, "review(other);").status, "stale");
  assert.equal(resolveEvidenceLocation(note, "review(value);\nreview(value);").status, "stale");
  assert.equal(resolveEvidenceLocation({ line: 1, code: "" }, "anything").status, "stale");
});

test("surrounding lines disambiguate identical code in different functions", () => {
  const source = "function one() {\n review(value);\n}\n\nfunction two() {\n review(value);\n}\n";
  const note = { line: 6, code: "review(value);", anchor: createEvidenceAnchor(source, 6, 6) };
  assert.deepEqual(resolveEvidenceLocation(note, "// header\n" + source), { status: "relocated", line: 7, endLine: 7 });
});

test("multiline legacy evidence finds its unique new span without an anchor", () => {
  const note = { line: 50, code: "first();\n  second();" };
  assert.deepEqual(resolveEvidenceLocation(note, "// header\n  first();\n  second();\n"), { status: "relocated", line: 2, endLine: 3 });
});
