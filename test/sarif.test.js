"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { analyzeText } = require("../src/audit-analyzer");
const { runDataflowAnalysis } = require("../src/dataflow/pipeline");
const { buildSarif } = require("../src/sarif");
const { version } = require("../package.json");

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
  }, { sourceRoots: [{ id: "SRCROOT", uri: "file:///C:/repo", pathPrefix: "" }] });

  assert.equal(sarif.version, "2.1.0");
  assert.equal(sarif.runs[0].tool.driver.semanticVersion, version);
  assert.equal(sarif.runs[0].originalUriBaseIds.SRCROOT.uri, "file:///C:/repo/");
  assert.equal(sarif.runs[0].tool.driver.rules[0].id, "potential-ssrf");
  assert.equal(sarif.runs[0].results[0].partialFingerprints["traceguardFindingId/v1"], findings[0].id);
  assert.equal(sarif.runs[0].results[0].properties.status, "accepted_risk");
  assert.equal(sarif.runs[0].results[0].suppressions[0].kind, "external");
  assert.equal(sarif.runs[0].results[0].suppressions[0].status, "accepted");
  assert.ok(sarif.runs[0].results[0].codeFlows[0].threadFlows[0].locations.length >= 2);
  assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uriBaseId, "SRCROOT");
  const flowLocations = sarif.runs[0].results[0].codeFlows[0].threadFlows[0].locations;
  assert.deepEqual(flowLocations[0].kinds, ["acquire", "taint"]);
  assert.deepEqual(flowLocations.at(-1).kinds, ["release", "taint"]);
  assert.equal(flowLocations[0].properties.traceguardKind, "source");
  assert.equal(sarif.runs[0].invocations[0].properties.indexIncomplete, true);
});

test("SARIF assigns files to their declared workspace root", () => {
  const finding = {
    id: "finding_multi_root",
    ruleId: "test-rule",
    title: "Test finding",
    severity: "medium",
    confidence: "medium",
    sourceKind: "HTTP_INPUT",
    sinkKind: "FILE_ACCESS",
    relativePath: "api/src/controller.py",
    line: 7,
    path: { steps: [{ kind: "sink", label: "open", relativePath: "api/src/controller.py", line: 7 }] },
  };
  const sarif = buildSarif({ findings: [finding] }, { sourceRoots: [
    { id: "SRCROOT_1", uri: "file:///C:/repo/web", pathPrefix: "web/" },
    { id: "SRCROOT_2", uri: "file:///C:/repo/api", pathPrefix: "api/" },
  ] });
  const artifact = sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation;

  assert.deepEqual(artifact, { uri: "src/controller.py", uriBaseId: "SRCROOT_2" });
});
