"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { IncrementalAnalysisCache } = require("../src/analysis/incremental-cache");
const { analyzeText } = require("../src/audit-analyzer");
const { summarizeFileIR } = require("../src/dataflow/function-summary");

test("incremental cache tracks versions and transitively invalidates dependent functions", () => {
  const cache = new IncrementalAnalysisCache();
  cache.updateFile({
    absolutePath: "C:\\repo\\service.js",
    version: 1,
    functionSummaries: [{ id: "service", sinks: [] }],
  });
  cache.updateFile({
    absolutePath: "C:\\repo\\controller.js",
    version: 1,
    functionSummaries: [{ id: "controller", sinks: [] }],
    dependencyFunctionIds: ["service"],
  });
  cache.updateFile({
    absolutePath: "C:\\repo\\routes.js",
    version: 1,
    functionSummaries: [{ id: "routes", sinks: [] }],
    dependencyFunctionIds: ["controller"],
  });

  assert.equal(cache.updateFile({ absolutePath: "C:\\repo\\service.js", version: 1 }).cacheHit, true);
  const changed = cache.updateFile({
    absolutePath: "C:\\repo\\service.js",
    version: 2,
    functionSummaries: [{ id: "service", sinks: ["COMMAND_EXEC"] }],
  });
  assert.deepEqual(new Set(changed.invalidatedFiles), new Set([
    "c:\\repo\\service.js",
    "c:\\repo\\controller.js",
    "c:\\repo\\routes.js",
  ]));
});

test("function summaries are derived from frontend IR security semantics", () => {
  const analysis = analyzeText(
    "function load(req) { const url = req.query.url; return fetch(url); }",
    "javascript",
    "C:\\repo\\route.js",
    "route.js",
  );
  const summary = summarizeFileIR(analysis.ir).find(item => item.name === "load");

  assert.ok(summary.sources.includes("HTTP_INPUT"));
  assert.ok(summary.sinks.includes("HTTP_REQUEST"));
  assert.deepEqual(summary.parameters, ["req"]);
});
