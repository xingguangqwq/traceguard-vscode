"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { analyzeText } = require("../src/audit-analyzer");
const { runDataflowAnalysis } = require("../src/dataflow/pipeline");
const { buildSarif } = require("../src/sarif");

test("SARIF export preserves rules, fingerprints, statuses and Source-to-Sink code flows", () => {
  const analysis = analyzeText(`
function proxy(req) {
  const url = req.query.url;
  fetch(url);
}`, "javascript", "C:\\repo\\proxy.js", "proxy.js");
  const findings = runDataflowAnalysis([analysis]).findings.map(finding => ({ ...finding, status: "accepted_risk" }));
  const sarif = buildSarif({
    findings,
    indexIncomplete: true,
    indexSkippedFiles: 1,
    languageCapabilities: { javascript: { files: 1, astFiles: 1 } },
  });

  assert.equal(sarif.version, "2.1.0");
  assert.equal(sarif.runs[0].tool.driver.rules[0].id, "potential-ssrf");
  assert.equal(sarif.runs[0].results[0].partialFingerprints["traceguardFindingId/v1"], findings[0].id);
  assert.equal(sarif.runs[0].results[0].properties.status, "accepted_risk");
  assert.equal(sarif.runs[0].results[0].suppressions[0].kind, "external");
  assert.equal(sarif.runs[0].results[0].suppressions[0].status, "accepted");
  assert.ok(sarif.runs[0].results[0].codeFlows[0].threadFlows[0].locations.length >= 2);
  assert.equal(sarif.runs[0].invocations[0].properties.indexIncomplete, true);
});
