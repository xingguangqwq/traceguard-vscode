"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { analyzeTextAsync } = require("../src/audit-analyzer");
const { QueryKind, QueryStatus, formatQueryMarkdown, runAuditQuery } = require("../src/query/audit-query-engine");

async function queryFixture() {
  const routes = await analyzeTextAsync(`
import { run } from "./service";
app.get("/run", (req, res) => {
  run(req.query.cmd);
  res.send("ok");
});
`, "typescript", "C:\\repo\\routes.ts", "routes.ts");
  const service = await analyzeTextAsync(`
import { exec } from "node:child_process";
export function run(value) {
  const command = value;
  exec(command);
}
`, "typescript", "C:\\repo\\service.ts", "service.ts");
  return { analyses: [routes, service], routes, service };
}

test("audit queries share one explainable tree contract", async () => {
  const fixture = await queryFixture();
  const entry = fixture.routes.ir.functions.find(fn => fn.entryPoints?.length || fn.entryPoint);
  const service = fixture.service.ir.functions.find(fn => fn.name === "run");
  assert.ok(entry);
  assert.ok(service);

  const requests = [
    { kind: QueryKind.TRACE_FORWARD, functionId: entry.id, identifier: "req.query.cmd", line: entry.location.line },
    { kind: QueryKind.TRACE_BACKWARD, functionId: service.id, identifier: "command", line: 5 },
    { kind: QueryKind.FIND_CALLERS, functionId: service.id },
    { kind: QueryKind.FIND_CALLEES, functionId: entry.id },
    { kind: QueryKind.TRACE_TO_ENTRY, functionId: service.id },
    { kind: QueryKind.REACHABLE_SINKS, functionId: entry.id },
    { kind: QueryKind.EXPLAIN, functionId: service.id, line: 5 },
  ];
  for (const request of requests) {
    const result = runAuditQuery(fixture.analyses, request);
    assert.equal(result.schema, "traceguard-audit-query");
    assert.ok(result.roots.length, request.kind);
    const nodes = flatten(result.roots);
    assert.ok(nodes.every(node => Object.values(QueryStatus).includes(node.status)), request.kind);
    assert.ok(nodes.every(node => node.reason), request.kind);
  }

  const forward = runAuditQuery(fixture.analyses, requests[0]);
  assert.ok(flatten(forward.roots).some(node => node.kind === "sink" && /command/i.test(node.label)));
  const backward = runAuditQuery(fixture.analyses, requests[1]);
  assert.ok(flatten(backward.roots).some(node => node.kind === "entry"));
  const callers = runAuditQuery(fixture.analyses, requests[2]);
  assert.ok(flatten(callers.roots).some(node => node.kind === "call" && /run/.test(node.label)));
  const entries = runAuditQuery(fixture.analyses, requests[4]);
  assert.ok(flatten(entries.roots).some(node => node.kind === "entry" && /GET/.test(node.label)));
  const sinks = runAuditQuery(fixture.analyses, requests[5]);
  assert.ok(flatten(sinks.roots).some(node => node.kind === "sink"));
  const explain = runAuditQuery(fixture.analyses, requests[6]);
  assert.ok(flatten(explain.roots).some(node => node.details.semanticModelId === "node.child_process.command"));
});

test("unresolved calls are explicit and Markdown preserves status and reason", async () => {
  const analysis = await analyzeTextAsync(`
export function route(req) {
  const value = req.query.value;
  dynamicDispatch(value);
}
`, "typescript", "C:\\repo\\unresolved.ts", "unresolved.ts");
  const fn = analysis.ir.functions.find(item => item.name === "route");
  const result = runAuditQuery([analysis], { kind: QueryKind.FIND_CALLEES, functionId: fn.id });
  const unresolved = flatten(result.roots).find(node => node.status === QueryStatus.UNRESOLVED);

  assert.ok(unresolved);
  assert.match(unresolved.reason, /No indexed function/);
  const markdown = formatQueryMarkdown(result);
  assert.match(markdown, /\[unresolved\]/);
  assert.match(markdown, /dynamicDispatch/);
});

test("forward Access Path queries keep unrelated object fields separate", async () => {
  const analysis = await analyzeTextAsync(`
import { exec } from "node:child_process";
function consume(options) { exec(options.safe); }
export function route(req) {
  const command = req.body.command;
  const payload = { command, safe: "fixed" };
  consume(payload);
}
`, "typescript", "C:\\repo\\fields.ts", "fields.ts");
  const fn = analysis.ir.functions.find(item => item.name === "route");
  const result = runAuditQuery([analysis], {
    kind: QueryKind.TRACE_FORWARD,
    functionId: fn.id,
    identifier: "payload.command",
    line: 6,
  });

  assert.equal(flatten(result.roots).some(node => node.kind === "sink"), false);
});

test("forward and backward queries explain container alias rebasing", async () => {
  const analysis = await analyzeTextAsync(`
import { exec } from "node:child_process";
export function route(req) {
  const command = req.body.command;
  const payload = { command, safe: "fixed" };
  const alias = payload;
  exec(alias.command);
}
`, "typescript", "C:\\repo\\query-alias.ts", "query-alias.ts");
  const fn = analysis.ir.functions.find(item => item.name === "route");
  const forward = runAuditQuery([analysis], {
    kind: QueryKind.TRACE_FORWARD,
    functionId: fn.id,
    identifier: "payload.command",
    line: 5,
  });
  const backward = runAuditQuery([analysis], {
    kind: QueryKind.TRACE_BACKWARD,
    functionId: fn.id,
    identifier: "alias.command",
    line: 7,
  });

  const forwardAlias = flatten(forward.roots).find(node => node.kind === "assignment" && /alias\.command/.test(node.label));
  const backwardAlias = flatten(backward.roots).find(node => node.kind === "assignment" && /alias/.test(node.label));
  assert.ok(forwardAlias);
  assert.match(forwardAlias.reason, /rebases/);
  assert.ok(backwardAlias);
  assert.ok(flatten(backward.roots).some(node => /payload\.command/.test(node.label)));
});

function flatten(nodes) { return nodes.flatMap(node => [node, ...flatten(node.children || [])]); }
