"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { evaluateCase, compareBaseline, scoreFindings, validateManifest } = require("../scripts/evaluate-corpus");

test("negative corpus cases count findings instead of silently discarding them", async () => {
  const specification = require("../eval-corpus/manifest.json").cases.find(item => item.id === "java-prepared-statement");
  const normal = await evaluateCase(specification);
  assert.equal(normal.detected, 1);
  const negative = await evaluateCase({ ...specification, expected: [] });
  assert.ok(negative.falsePositives >= 1);
});

test("evaluation checks all rules by default and supports explicit checkedRules", () => {
  const findings = [{ id: "unexpected", ruleId: "other", relativePath: "a.js", line: 1 }];
  assert.equal(scoreFindings({ expected: [] }, findings).falsePositives, 1);
  assert.equal(scoreFindings({ expected: [], checkedRules: ["sql"] }, findings).falsePositives, 0);
});

test("baseline comparison rejects missing cases and every loss of verified paths", () => {
  const before = { id: "a", expected: 1, detected: 1, falsePositives: 0, verifiedPaths: 1, heuristicPaths: 0, unresolvedPaths: 0 };
  const baseline = { cases: [before] };
  assert.match(compareBaseline(baseline, { cases: [] }).regressions.join(), /missing/i);
  const downgraded = { ...before, verifiedPaths: 0, unresolvedPaths: 1 };
  assert.match(compareBaseline(baseline, { cases: [downgraded] }).regressions.join(), /verified/i);
  assert.equal(compareBaseline(baseline, baseline).regressions.length, 0);
});

test("a matched unresolved or missing path cannot satisfy a verified expectation", () => {
  const expected = [{ ruleId: "sql", relativePath: "a.js", allowHeuristic: false }];
  const finding = { id: "f", ruleId: "sql", relativePath: "a.js", confidence: "medium", path: { sink: { semanticVerification: "candidate" }, steps: [] } };
  assert.equal(scoreFindings({ expected }, [finding]).unexpectedHeuristicPaths, 1);
  assert.equal(scoreFindings({ expected }, [{ ...finding, path: undefined }]).unexpectedHeuristicPaths, 1);
});

test("declared syntax limitations still reject unresolved paths and require a reason", () => {
  const specification = { id: "limited", projectDir: "a", proofLimitation: "Known missing receiver identity",
    expected: [{ ruleId: "sql", relativePath: "a.js", allowedProofStatuses: ["verified", "heuristic"] }] };
  const finding = { id: "f", ruleId: "sql", relativePath: "a.js", path: { steps: [{ analysisStatus: "unresolved" }] } };
  assert.equal(scoreFindings(specification, [finding]).unexpectedHeuristicPaths, 1);
  finding.path.steps[0].analysisStatus = "heuristic";
  assert.equal(scoreFindings(specification, [finding]).unexpectedHeuristicPaths, 0);
  assert.throws(() => validateManifest({ schema: "traceguard-eval-corpus", version: 1,
    cases: [{ ...specification, proofLimitation: undefined }] }), /proofLimitation/);
});

test("empty proof cannot enter the Verified Flow pool", () => {
  const { findingPool, pathVerificationStatus } = require("../src/review/finding-pool");
  assert.equal(pathVerificationStatus({ steps: [] }), "unresolved");
  assert.equal(findingPool({ confidence: "high", status: "open" }), "review");
});

test("manifest rejects empty suites, duplicate IDs and expectations outside checkedRules", () => {
  const manifest = { schema: "traceguard-eval-corpus", version: 1, cases: [] };
  assert.throws(() => validateManifest(manifest), /empty/i);
  const specification = require("../eval-corpus/manifest.json").cases.find(item => item.id === "java-prepared-statement");
  assert.throws(() => validateManifest({ ...manifest, cases: [specification, specification] }), /duplicate/i);
  assert.throws(() => validateManifest({ ...manifest, cases: [{ ...specification, checkedRules: ["other"] }] }), /checkedRules/);
});
