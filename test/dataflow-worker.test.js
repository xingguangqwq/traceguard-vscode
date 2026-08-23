"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { analyzeText } = require("../src/audit-analyzer");
const { DataflowWorkerClient, isRetriableWorkerFailure } = require("../src/dataflow/worker-client");
const { parseProjectConfigurationText } = require("../src/config/project-config");
const { QueryKind } = require("../src/query/audit-query-engine");

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

test("worker timeouts and analysis errors fail once instead of repeating a stuck request", () => {
  assert.equal(isRetriableWorkerFailure({ code: "WORKER_TIMEOUT" }), false);
  assert.equal(isRetriableWorkerFailure({ code: "WORKER_CANCELLED" }), false);
  assert.equal(isRetriableWorkerFailure({ code: "WORKER_REQUEST_ERROR" }), false);
  assert.equal(isRetriableWorkerFailure({ code: "WORKER_EXIT" }), true);
  assert.equal(isRetriableWorkerFailure({ code: "WORKER_ERROR" }), true);
});

test("persistent worker updates one file and returns only analysis/finding deltas", async () => {
  const client = new DataflowWorkerClient();
  const controller = {
    absolutePath: "C:\\repo\\controller.js",
    relativePath: "controller.js",
    language: "javascript",
    version: "controller-1",
    text: "export function handler(req) { return run(req.body.command); }",
  };
  const service = {
    absolutePath: "C:\\repo\\service.js",
    relativePath: "service.js",
    language: "javascript",
    version: "service-1",
    text: "export function run(value) { exec(value); }",
  };
  try {
    const initialized = await client.initializeWorkspace([controller, service], { maxDepth: 6, maxPaths: 80 });
    assert.equal(initialized.analyses.length, 2);
    assert.ok(initialized.findingDelta.upsert.some(finding => finding.ruleId === "potential-command-injection"));

    const updated = await client.updateFile({
      ...service,
      version: "service-2",
      text: "export function run(value) { return value; }",
    });
    assert.equal(updated.analysis.relativePath, "service.js");
    assert.equal(updated.analyses, undefined);
    assert.equal(updated.findings, undefined);
    assert.ok(updated.affectedFiles.includes("c:/repo/service.js"));
    assert.ok(updated.affectedFiles.includes("c:/repo/controller.js"));
    assert.ok(updated.findingDelta.removedIds.length > 0);
  } finally {
    await client.dispose();
  }
});

test("persistent worker replays workspace state after a crash", async () => {
  const client = new DataflowWorkerClient();
  const file = {
    absolutePath: "C:\\repo\\proxy.js",
    relativePath: "proxy.js",
    language: "javascript",
    version: "one",
    text: "export function proxy(req) { fetch(req.query.url); }",
  };
  try {
    await client.initializeWorkspace([file]);
    const crashedWorker = client.worker;
    await crashedWorker.terminate();
    const result = await client.updateFile({ ...file, version: "two", text: "export function proxy(req) { return req.query.url; }" });
    assert.equal(result.analysis.relativePath, "proxy.js");
    assert.notEqual(client.worker, crashedWorker);
  } finally {
    await client.dispose();
  }
});

test("persistent worker serializes superseded updates and keeps the newest file state", async () => {
  const worker = new DataflowWorkerClient();
  const file = {
    language: "javascript",
    absolutePath: "C:\\workspace\\route.js",
    relativePath: "route.js",
  };
  await worker.initializeWorkspace([{ ...file, version: "1", text: "function run(req) { exec(req.body.cmd); }" }]);

  const older = worker.updateFile({ ...file, version: "2", text: "function run(req) { exec(req.body.old); }" });
  const newest = worker.updateFile({ ...file, version: "3", text: "function run(req) { fetch(req.body.url); }" });
  const [olderResult, newestResult] = await Promise.allSettled([older, newest]);
  assert.equal(olderResult.status, "rejected");
  assert.equal(olderResult.reason.code, "SUPERSEDED");
  assert.equal(newestResult.status, "fulfilled");

  const queried = await worker.queryPaths();
  assert.ok(queried.findings.some(finding => finding.ruleId === "potential-ssrf"));
  assert.ok(!queried.findings.some(finding => finding.ruleId === "potential-command-injection"));
  await worker.dispose();
});

test("persistent worker answers audit queries from its latest incremental IR", async () => {
  const worker = new DataflowWorkerClient();
  const file = {
    language: "javascript",
    absolutePath: "C:\\workspace\\query.js",
    relativePath: "query.js",
    version: "1",
    text: "export function run(req) { const command = req.body.command; exec(command); }",
  };
  try {
    const initialized = await worker.initializeWorkspace([file]);
    const fn = initialized.analyses[0].ir.functions.find(item => item.name === "run");
    const before = await worker.queryAudit({ kind: QueryKind.REACHABLE_SINKS, functionId: fn.id });
    assert.ok(flattenQuery(before.roots).some(node => node.kind === "sink"));

    await worker.updateFile({ ...file, version: "2", text: "export function run(req) { return req.body.command; }" });
    const after = await worker.queryAudit({ kind: QueryKind.REACHABLE_SINKS, functionId: fn.id });
    assert.equal(flattenQuery(after.roots).some(node => node.kind === "sink"), false);
  } finally {
    await worker.dispose();
  }
});

test("persistent worker applies and reconfigures project-local audit semantics", async () => {
  const worker = new DataflowWorkerClient();
  const enabled = parseProjectConfigurationText(JSON.stringify({
    sources: [{ language: "typescript", function: "readTenantValue" }],
    sinks: [{ language: "typescript", function: "runInternalCommand", arguments: [0], kind: "COMMAND_EXEC" }],
    severityOverrides: { "potential-command-injection": "medium" },
  })).config;
  const file = {
    language: "typescript",
    absolutePath: "C:\\workspace\\custom.ts",
    relativePath: "custom.ts",
    version: "1",
    text: `
declare function readTenantValue(): string;
declare function runInternalCommand(value: string): void;
export function run(): void {
  const value = readTenantValue();
  runInternalCommand(value);
}`,
  };
  try {
    const initialized = await worker.initializeWorkspace([file], { projectConfiguration: enabled });
    const finding = initialized.findingDelta.upsert.find(item => item.ruleId === "potential-command-injection");
    assert.ok(finding);
    assert.equal(finding.severity, "medium");

    const disabled = parseProjectConfigurationText(JSON.stringify({
      sources: [{ language: "typescript", function: "readTenantValue" }],
      sinks: [{ language: "typescript", function: "runInternalCommand", arguments: [0], kind: "COMMAND_EXEC" }],
      rules: { "potential-command-injection": false },
    })).config;
    const changed = await worker.configure({ projectConfiguration: disabled });
    assert.equal(changed.analyses, undefined, "rule-only changes do not rebuild frontend IR");
    assert.ok(changed.findingDelta.removedIds.includes(finding.id));
    const queried = await worker.queryPaths();
    assert.equal(queried.findings.some(item => item.ruleId === "potential-command-injection"), false);
  } finally {
    await worker.dispose();
  }
});

function flattenQuery(nodes) { return (nodes || []).flatMap(node => [node, ...flattenQuery(node.children)]); }
