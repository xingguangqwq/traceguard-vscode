"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { analyzeText } = require("../src/audit-analyzer");
const { findSourceSinkPaths } = require("../src/dataflow/path-engine");
const { registerFrontend } = require("../src/frontends/registry");
const { Certainty, OperationKind, fileIR, functionIR, location, operation, symbol, validateFileIR } = require("../src/ir/schema");
const { SinkKind, SourceKind } = require("../src/security/semantics");

test("language analysis produces validated normalized IR", () => {
  const analysis = analyzeText(`
export function run(req) {
  const url = req.query.url;
  if (url) fetch(url);
}`, "javascript", "C:\\repo\\controller.js", "controller.js");

  assert.equal(analysis.ir.schema, "traceguard-ir");
  assert.equal(analysis.ir.version, 2);
  assert.deepEqual(validateFileIR(analysis.ir), []);
  const operations = analysis.ir.functions[0].operations;
  assert.ok(operations.some(item => item.kind === OperationKind.SOURCE && item.semantic.sourceKind === SourceKind.HTTP_INPUT));
  assert.ok(operations.some(item => item.kind === OperationKind.BRANCH));
  assert.ok(operations.some(item => item.kind === OperationKind.SINK && item.semantic.sinkKind === SinkKind.HTTP_REQUEST));
});

test("IR validation rejects malformed operations", () => {
  const errors = validateFileIR({
    schema: "traceguard-ir",
    version: 2,
    language: "javascript",
    absolutePath: "C:\\repo\\bad.js",
    relativePath: "bad.js",
    functions: [{ id: "fn", name: "bad", parameters: [], operations: [{ id: "op", kind: "made-up", inputs: [] }] }],
  });
  assert.ok(errors.some(error => error.includes("invalid kind")));
});

test("analysis enters through the registered language frontend and projects its IR", () => {
  registerFrontend("synthetic", {
    parse(input) {
      const sourceLocation = location({ ...input, line: 3, code: "frontend-produced input" });
      return fileIR({
        ...input,
        language: "synthetic",
        lines: 3,
        functions: [functionIR({
          id: "synthetic-handler",
          name: "frontendHandler",
          language: "synthetic",
          location: sourceLocation,
          parameters: [symbol("payload")],
          operations: [operation({
            id: "synthetic-source",
            kind: OperationKind.SOURCE,
            functionId: "synthetic-handler",
            location: sourceLocation,
            inputs: [symbol("payload")],
            semantic: { label: "Synthetic input", category: "source", sourceKind: SourceKind.HTTP_INPUT },
            certainty: Certainty.HIGH,
          })],
        })],
      });
    },
  });

  const analysis = analyzeText("this text has no parser syntax", "synthetic", "C:\\repo\\sample.synthetic", "sample.synthetic");
  assert.equal(analysis.ir.functions[0].name, "frontendHandler");
  assert.equal(analysis.functions[0].name, "frontendHandler");
  assert.equal(analysis.signals[0].label, "Synthetic input");
});

test("dataflow consumes IR even when compatibility projections are absent", () => {
  const analysis = analyzeText(`
function run(req) {
  const url = req.query.url;
  fetch(url);
}`, "javascript", "C:\\repo\\controller.js", "controller.js");

  analysis.signals = [];
  analysis.functions = [];
  analysis.entries = [];
  const paths = findSourceSinkPaths([analysis], { absolutePath: analysis.absolutePath, line: 3 });
  assert.ok(paths.some(item => item.category === "network"));
});

test("function IR IDs survive unrelated lines inserted above the symbol", () => {
  const before = analyzeText(`function run(value) {\n  return value;\n}`, "javascript", "C:\\repo\\run.js", "run.js");
  const after = analyzeText(`const banner = true;\n\nfunction run(value) {\n  return value;\n}`, "javascript", "C:\\repo\\run.js", "run.js");
  assert.equal(before.ir.functions[0].id, after.ir.functions[0].id);
});

test("typed overloads and enclosing types receive distinct stable symbol keys", () => {
  const before = analyzeText(`
class FirstController {
  public void load(String value) { Runtime.getRuntime().exec(value); }
  public void load(int value) { Runtime.getRuntime().exec(String.valueOf(value)); }
}
class SecondController {
  public void load(String value) { Runtime.getRuntime().exec(value); }
}`, "java", "C:\\repo\\Controllers.java", "Controllers.java");
  const after = analyzeText(`
// unrelated header

class FirstController {
  public void load(String value) { Runtime.getRuntime().exec(value); }
  public void load(int value) { Runtime.getRuntime().exec(String.valueOf(value)); }
}
class SecondController {
  public void load(String value) { Runtime.getRuntime().exec(value); }
}`, "java", "C:\\repo\\Controllers.java", "Controllers.java");

  const keys = before.ir.functions.map(fn => fn.symbolKey);
  assert.equal(new Set(keys).size, 3);
  assert.ok(keys.some(key => key.includes("FirstController") && key.endsWith("load(String)")));
  assert.ok(keys.some(key => key.includes("FirstController") && key.endsWith("load(int)")));
  assert.ok(keys.some(key => key.includes("SecondController") && key.endsWith("load(String)")));
  assert.deepEqual(before.ir.functions.map(fn => fn.id), after.ir.functions.map(fn => fn.id));
});
