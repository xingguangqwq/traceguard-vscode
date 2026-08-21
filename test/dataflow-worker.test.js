"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { analyzeText } = require("../src/audit-analyzer");
const { DataflowWorkerClient } = require("../src/dataflow/worker-client");

test("dataflow worker returns explainable paths and rule findings", async () => {
  const client = new DataflowWorkerClient();
  try {
    const analysis = analyzeText(`
export function proxy(req) {
  const url = req.query.url;
  fetch(url);
}`, "javascript", "C:\\repo\\proxy.js", "proxy.js");
    const result = await client.analyze([analysis], { maxDepth: 6, maxPaths: 40 });
    assert.ok(result.paths.some(path => path.category === "network"));
    assert.ok(result.findings.some(finding => finding.ruleId === "potential-ssrf"));
    assert.equal(result.metadata.truncated, false);
  } finally {
    await client.dispose();
  }
});
