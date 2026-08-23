"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { analyzeTextAsync } = require("../src/audit-analyzer");
const { runDataflowAnalysis } = require("../src/dataflow/pipeline");
const { SinkKind } = require("../src/security/semantics");
const { SEMANTIC_MODELS, resolveSemanticCall } = require("../src/security/semantic-models");

test("semantic models expose stable call and taint contracts", () => {
  for (const model of SEMANTIC_MODELS) {
    assert.ok(model.id);
    assert.ok(model.languages.length);
    assert.ok(Array.isArray(model.moduleNames));
    assert.ok(Array.isArray(model.qualifiedNames));
    assert.ok(Array.isArray(model.receiverTypes));
    assert.ok(Array.isArray(model.taintArguments));
    assert.ok(model.taintRestFrom === undefined || Number.isInteger(model.taintRestFrom));
    assert.equal(typeof model.returnsTaint, "boolean");
    assert.ok(model.role);
    assert.ok(Array.isArray(model.callForms));
    if (model.role === "source") assert.ok(model.sourceKind);
    if (model.role === "sink") assert.ok(model.sinkKind);
    if (model.role === "guard") assert.ok(model.guardCapabilities.length);
  }
});

test("module identity verifies aliases while local shadowing rejects the candidate", () => {
  const imported = resolveSemanticCall("typescript", {
    function: "run",
    symbol: {
      kind: "import",
      moduleName: "node:child_process",
      exportName: "exec",
      verified: true,
    },
  });
  const shadowed = resolveSemanticCall("typescript", {
    function: "exec",
    symbol: { kind: "local", shadowed: true, verified: true },
  });

  assert.equal(imported.status, "verified");
  assert.equal(imported.model.sinkKind, SinkKind.COMMAND_EXEC);
  assert.deepEqual(imported.model.taintArguments, [0]);
  assert.equal(shadowed.status, "rejected");
});

test("TypeScript Checker verifies import forms and rejects shadowed lookalikes", async () => {
  const cases = [
    `import { exec as run } from "node:child_process";\nexport function f(req) {\n const cmd = req.query.cmd;\n run(cmd);\n}`,
    `import * as processApi from "child_process";\nexport function f(req) {\n const cmd = req.query.cmd;\n processApi.exec(cmd);\n}`,
    `import processApi from "child_process";\nexport function f(req) {\n const cmd = req.query.cmd;\n processApi.exec(cmd);\n}`,
    `const { exec: run } = require("child_process");\nexport function f(req) {\n const cmd = req.query.cmd;\n run(cmd);\n}`,
    `import { exec } from "child_process";\nconst run = exec;\nexport function f(req) {\n const cmd = req.query.cmd;\n run(cmd);\n}`,
  ];
  for (const [index, source] of cases.entries()) {
    const analysis = await analyzeTextAsync(source, "typescript", `C:\\repo\\semantic-${index}.ts`, `semantic-${index}.ts`);
    const finding = runDataflowAnalysis([analysis]).findings.find(item => item.ruleId === "potential-command-injection");
    const sink = analysis.ir.functions.flatMap(fn => fn.operations).find(operation => operation.semantic.modelId === "node.child_process.command");
    assert.ok(sink, `import form ${index} did not create a modeled sink`);
    assert.equal(sink.certainty, "high");
    assert.equal(finding?.confidence, "high");
  }

  const shadowed = await analyzeTextAsync(`
import { exec as systemExec } from "child_process";
export function f(req) {
  const exec = value => logger.write(value);
  exec(req.query.cmd);
  logger.exec(req.query.cmd);
}`, "typescript", "C:\\repo\\shadowed.ts", "shadowed.ts");
  assert.equal(runDataflowAnalysis([shadowed]).findings.some(item => item.ruleId === "potential-command-injection"), false);
});

test("unresolved regex sink candidates stay review-only", async () => {
  const analysis = await analyzeTextAsync(`export function f(req) { exec(req.query.cmd); }`, "typescript", "C:\\repo\\candidate.ts", "candidate.ts");
  const finding = runDataflowAnalysis([analysis]).findings.find(item => item.ruleId === "potential-command-injection");

  assert.equal(finding?.confidence, "low");
  assert.equal(finding?.path.sink.candidateStatus, "symbol-unverified");
  assert.ok(finding?.explanation.heuristics.some(item => item.includes("regex candidate")));
});

test("generic AST frontends attach syntax-verified semantic models", async () => {
  const cases = [
    {
      language: "java",
      file: "Run.java",
      modelId: "java.lang.Runtime.exec",
      source: `class Run { void run(HttpServletRequest request) { String cmd = request.getParameter("cmd"); Runtime.getRuntime().exec(cmd); } }`,
    },
    {
      language: "go",
      file: "main.go",
      modelId: "go.os_exec.Command",
      source: `package main\nfunc run(r *http.Request) { cmd := r.FormValue("cmd"); exec.Command(cmd) }`,
    },
    {
      language: "csharp",
      file: "Run.cs",
      modelId: "dotnet.System.Diagnostics.Process.Start",
      source: `class Run { void Handle(HttpRequest request) { var cmd = request.Query["cmd"]; Process.Start(cmd); } }`,
    },
  ];

  for (const sample of cases) {
    const analysis = await analyzeTextAsync(sample.source, sample.language, `C:\\repo\\${sample.file}`, sample.file);
    const sink = analysis.ir.functions.flatMap(fn => fn.operations).find(operation => operation.semantic.modelId === sample.modelId);
    assert.ok(sink, `${sample.language} did not bind ${sample.modelId}`);
    assert.equal(sink.certainty, "medium");
    assert.equal(sink.metadata.semanticVerification, "syntax");
  }
});

test("source and propagator models participate in local dataflow", async () => {
  const analysis = await analyzeTextAsync(`
import path from "node:path";
import { exec } from "node:child_process";
export function run() {
  const name = Deno.env.get("TRACEGUARD_NAME");
  const command = path.join("tools", String(name));
  exec(command);
}`, "typescript", "C:\\repo\\modeled-flow.ts", "modeled-flow.ts");
  const operations = analysis.ir.functions.flatMap(fn => fn.operations);
  const finding = runDataflowAnalysis([analysis]).findings.find(item => item.ruleId === "potential-command-injection");

  assert.ok(operations.some(item => item.semantic.modelId === "javascript.deno.environment" && item.kind === "source"));
  assert.ok(operations.some(item => item.semantic.modelId === "node.path.value-propagation" && item.kind === "call"));
  assert.ok(operations.some(item => item.semantic.modelId === "javascript.global.string-conversion" && item.kind === "call"));
  assert.equal(finding?.confidence, "medium");
  assert.equal(finding?.path.source.kind, "source");
  assert.ok(finding?.explanation.propagation.some(step => step.kind === "call" && /unresolved external/.test(step.reason)));
});

test("a variable alias of a modeled global keeps its symbol identity", async () => {
  const analysis = await analyzeTextAsync(`
const request = fetch;
export function proxy(req) {
  const url = req.query.url;
  return request(url);
}`, "typescript", "C:\\repo\\fetch-alias.ts", "fetch-alias.ts");
  const sink = analysis.ir.functions.flatMap(fn => fn.operations).find(operation => operation.semantic.modelId === "web.fetch.request");
  const finding = runDataflowAnalysis([analysis]).findings.find(item => item.ruleId === "potential-ssrf");

  assert.ok(sink);
  assert.equal(sink.certainty, "high");
  assert.equal(finding?.confidence, "high");
});

test("generic receiver types reject same-named safe methods", async () => {
  const analysis = await analyzeTextAsync(`
class SafeStore { void executeQuery(String value) {} }
class Search {
  void run(HttpServletRequest request, SafeStore store) {
    String value = request.getParameter("value");
    store.executeQuery(value);
  }
}`, "java", "C:\\repo\\SafeStore.java", "SafeStore.java");

  assert.equal(runDataflowAnalysis([analysis]).findings.some(item => item.ruleId === "potential-sql-injection"), false);
});

test("Python pickle calls receive a syntax-verified deserialization model", async () => {
  const analysis = await analyzeTextAsync(`
def load(request):
    value = request.data
    return pickle.loads(value)
`, "python", "C:\\repo\\pickle_model.py", "pickle_model.py");
  const sink = analysis.ir.functions.flatMap(fn => fn.operations).find(operation => operation.semantic.modelId === "python.pickle.deserialize");

  assert.ok(sink);
  assert.equal(sink.metadata.semanticVerification, "syntax");
  assert.ok(runDataflowAnalysis([analysis]).findings.some(item => item.ruleId === "potential-unsafe-deserialization"));
});

test("generic frontend import aliases can create semantic facts without a regex name hit", async () => {
  const analysis = await analyzeTextAsync(`
import pickle as serializer
def load(request):
    value = request.data
    return serializer.loads(value)
`, "python", "C:\\repo\\pickle_alias.py", "pickle_alias.py");
  const sink = analysis.ir.functions.flatMap(fn => fn.operations).find(operation => operation.semantic.modelId === "python.pickle.deserialize");

  assert.ok(sink);
  assert.equal(sink.metadata.semanticVerification, "verified");
  assert.ok(runDataflowAnalysis([analysis]).findings.some(item => item.ruleId === "potential-unsafe-deserialization"));
});

test("semantic sink models use signature-specific taint argument positions", async () => {
  const write = await analyzeTextAsync(`
import fs from "node:fs";
export function save(req) { const content = req.body.content; fs.writeFile("/srv/fixed.txt", content); }
`, "typescript", "C:\\repo\\write.ts", "write.ts");
  const rename = await analyzeTextAsync(`
import fs from "node:fs";
export function move(req) { const target = req.body.target; fs.rename("/srv/source.txt", target); }
`, "typescript", "C:\\repo\\rename.ts", "rename.ts");
  const go = await analyzeTextAsync(`package main
func run(r *http.Request, ctx context.Context) {
  argument := r.FormValue("argument")
  exec.CommandContext(ctx, "fixed-command", argument)
}`, "go", "C:\\repo\\command_context.go", "command_context.go");

  assert.equal(runDataflowAnalysis([write]).findings.some(item => item.ruleId === "potential-path-traversal"), false);
  assert.ok(runDataflowAnalysis([rename]).findings.some(item => item.ruleId === "potential-path-traversal"));
  assert.ok(runDataflowAnalysis([go]).findings.some(item => item.ruleId === "potential-command-injection"));
  const goSink = go.ir.functions.flatMap(fn => fn.operations).find(operation => operation.semantic.modelId === "go.os_exec.CommandContext");
  assert.deepEqual(goSink.metadata.taintArguments, [1, 2]);
});
