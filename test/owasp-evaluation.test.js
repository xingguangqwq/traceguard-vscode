"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { compareBaseline, metrics, parseExpectedResults, summarize } = require("../scripts/evaluate-owasp");

test("OWASP CSV validates truth, case IDs and duplicates rather than silently changing labels", () => {
  const csv = "# test name, category, real vulnerability, cwe\nBenchmarkTest00001,sqli,true,89\nBenchmarkTest00002,sqli,false,89\n";
  assert.deepEqual(parseExpectedResults(csv).map(item => item.vulnerable), [true, false]);
  for (const row of ["../escape,sqli,true,89", "BenchmarkTest00001,sqli,unknown,89", "BenchmarkTest00001,sqli,true,89,extra"]) assert.throws(() => parseExpectedResults(row), /Invalid/);
  assert.throws(() => parseExpectedResults(csv + "BenchmarkTest00001,sqli,true,89\n"), /Duplicate/);
});

test("OWASP scores errors separately and distinguishes candidates from verified findings", () => {
  const cases = [
    { vulnerable: true, detected: true, verified: false, category: "sqli" },
    { vulnerable: false, detected: true, verified: false, category: "sqli" },
    { vulnerable: false, detected: false, verified: false, category: "sqli", error: "parser unavailable" },
  ];
  assert.deepEqual(metrics(cases), { tp: 1, fn: 0, fp: 1, tn: 0, errors: 1, precision: 0.5, recall: 1, fpr: 1, youden: 0 });
  assert.equal(summarize(cases).verifiedOnly.tp, 0);
  assert.equal(metrics([]).recall, null);
  assert.equal(metrics([]).precision, null);
});

test("OWASP baseline rejects changed coverage and detects per-case regressions", () => {
  const item = { name: "BenchmarkTest00001", category: "sqli", cwe: "CWE-89", sourceSha256: "source", vulnerable: true, detected: true, verified: true, truncated: false };
  const baseline = { schema: "traceguard-owasp-report", version: 1, complete: true, dataset: { commit: "commit", expectedResultsSha256: "csv", sourceSha256: "tree" }, options: { maxDepth: 6 }, cases: [item] };
  const changed = structuredClone(baseline);
  changed.cases[0].detected = false;
  changed.cases[0].verified = false;
  changed.cases[0].truncated = true;
  assert.equal(compareBaseline(baseline, changed).regressions.length, 3);
  changed.cases = [];
  assert.throws(() => compareBaseline(baseline, changed), /coverage/);
  assert.throws(() => compareBaseline(baseline, { ...baseline, complete: false }), /complete/);
  assert.throws(() => compareBaseline(baseline, { ...baseline, dataset: { ...baseline.dataset, commit: "different" } }), /identity/);
  assert.throws(() => compareBaseline(baseline, { ...baseline, options: { maxDepth: 30 } }), /budgets/);
});
