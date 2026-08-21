"use strict";

const { performance } = require("node:perf_hooks");
const { analyzeText, buildAuditModel } = require("../src/audit-analyzer");
const { runDataflowAnalysis } = require("../src/dataflow/pipeline");

const requested = Number(process.argv.find(argument => argument.startsWith("--files="))?.split("=")[1] || 200);
const fileCount = Math.min(5000, Math.max(1, Number.isFinite(requested) ? Math.floor(requested) : 200));
const heapBefore = process.memoryUsage().heapUsed;
const startedAt = performance.now();
const analyses = Array.from({ length: fileCount }, (_, index) => analyzeText(
  `function route${index}(req, res) {\n  const target = req.query.url;\n  fetch(target);\n  res.send("ok");\n}\n`,
  "javascript",
  `C:\\benchmark\\route-${index}.js`,
  `route-${index}.js`,
));
const parsedAt = performance.now();
const model = buildAuditModel(analyses);
const dataflow = runDataflowAnalysis(analyses, { maxDepth: 6, maxPaths: Math.max(400, fileCount * 2) });
const finishedAt = performance.now();
const memory = process.memoryUsage();

process.stdout.write(`${JSON.stringify({
  fixture: "independent-js-routes",
  files: fileCount,
  functions: model.functions,
  paths: dataflow.paths.length,
  findings: dataflow.findings.length,
  parseMs: round(parsedAt - startedAt),
  modelAndDataflowMs: round(finishedAt - parsedAt),
  totalMs: round(finishedAt - startedAt),
  filesPerSecond: round(fileCount / ((finishedAt - startedAt) / 1000)),
  heapDeltaMiB: round(Math.max(0, memory.heapUsed - heapBefore) / 1024 / 1024),
  rssMiB: round(memory.rss / 1024 / 1024),
}, null, 2)}\n`);

function round(value) {
  return Math.round(value * 100) / 100;
}
