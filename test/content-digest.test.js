"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { findingDigest, pathDigest } = require("../src/analysis/content-digest");

test("path digests include step order, confidence, receiver proof, and guards", () => {
  const base = {
    id: "path_one",
    confidence: "high",
    guardCapabilities: [],
    steps: [
      { kind: "source", operationId: "source", functionId: "a", line: 1 },
      { kind: "sink", operationId: "sink", functionId: "b", line: 2, semanticVerification: "verified" },
    ],
  };
  assert.notEqual(pathDigest(base), pathDigest({ ...base, steps: [...base.steps].reverse() }));
  assert.notEqual(pathDigest(base), pathDigest({ ...base, confidence: "review" }));
  assert.notEqual(pathDigest(base), pathDigest({ ...base, guardCapabilities: ["SQL_PARAMETERIZATION"] }));
  assert.notEqual(pathDigest(base), pathDigest({ ...base, steps: [base.steps[0], { ...base.steps[1], semanticVerification: "candidate" }] }));
});

test("finding digests change when any candidate path changes", () => {
  const path = { id: "path_one", confidence: "high", steps: [{ kind: "sink", operationId: "sink", line: 2 }] };
  const finding = { id: "finding_one", ruleId: "rule", severity: "high", confidence: "high", paths: [path] };
  assert.notEqual(findingDigest(finding), findingDigest({ ...finding, paths: [{ ...path, confidence: "review" }] }));
});
