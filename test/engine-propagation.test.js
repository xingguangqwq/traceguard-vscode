"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { analyzeTextAsync } = require("../src/audit-analyzer");
const { runDataflowAnalysis } = require("../src/dataflow/pipeline");
const { runAuditQuery, QueryKind } = require("../src/query/audit-query-engine");
const { removeAssignedTaint } = require("../src/ir/access-path");
const { expressionInputs } = require("../src/frontends/expression-inputs");
const { isJavaMap } = require("../src/security/collection-semantics");

async function analyze(language, text) {
  const extension = { java: "java", php: "php", python: "py" }[language];
  return analyzeTextAsync(text, language, `C:/repo/Propagation.${extension}`, `Propagation.${extension}`);
}
function hasCommand(analysis) { return runDataflowAnalysis([analysis]).findings.some(finding => finding.ruleId === "potential-command-injection"); }
function flatten(nodes) { return nodes.flatMap(node => [node, ...flatten(node.children || [])]); }
function query(analysis, kind, identifier, line) {
  return flatten(runAuditQuery([analysis], { absolutePath: analysis.absolutePath, kind, identifier, line }).roots);
}
function javaMap(body, sink) {
  return `import java.util.Map;
import java.util.HashMap;
class Propagation {
  void run(HttpServletRequest request, String key) {
    String value = request.getParameter("cmd");
    Map<String, String> data = new HashMap<>();
    ${body}
    Runtime.getRuntime().exec(${sink});
  }
}`;
}

test("Java Map constant keys preserve positive flow and isolate sibling keys in scans and forward queries", async () => {
  for (const [key, expected] of [["cmd", true], ["safe", false]]) {
    const analysis = await analyze("java", javaMap('data.put("cmd", value);\n    data.put("safe", "fixed");', `data.get("${key}")`));
    assert.equal(hasCommand(analysis), expected, key);
    assert.equal(query(analysis, QueryKind.TRACE_FORWARD, "value", 5).some(node => node.kind === "sink"), expected, `${key} forward`);
  }
});

test("Map overwrites kill only the exact key; dynamic writes preserve possible earlier values", async () => {
  for (const [body, expected] of [
    ['data.put("cmd", value);\n    data.put("cmd", "fixed");', false],
    ['data.put("cmd", value);\n    data.put(key, "fixed");', true],
    ['data.put(key, value);\n    data.put("safe", "fixed");', true],
  ]) {
    const analysis = await analyze("java", javaMap(body, 'data.get("cmd")'));
    assert.equal(hasCommand(analysis), expected, body);
    assert.equal(query(analysis, QueryKind.TRACE_FORWARD, "value", 5).some(node => node.kind === "sink"), expected, `forward ${body}`);
    assert.equal(query(analysis, QueryKind.TRACE_BACKWARD, "data.cmd", 9).some(node => node.kind === "source"), expected, `backward ${body}`);
  }
});

test("Map reads assigned to locals use the selected key instead of the whole receiver", async () => {
  for (const [key, expected] of [["cmd", true], ["safe", false]]) {
    const analysis = await analyze("java", javaMap(`data.put("cmd", value);\n    String selected = data.get("${key}");`, "selected"));
    assert.equal(hasCommand(analysis), expected, key);
  }
  assert.equal(isJavaMap({ symbol: { receiverType: "app.Map", shadowed: true } }), false);
});

test("PHP dictionary/property paths retain constant keys through aliases and concatenation", async () => {
  for (const [access, expected] of [['$alias["cmd"]', true], ['$alias [ "safe" ]', false], ['$object->cmd', true], ['$object->safe', false]]) {
    const analysis = await analyze("php", `<?php
function run() {
  $value = $_GET['cmd'];
  $data['cmd'] = $value;
  $data['safe'] = 'fixed';
  $object->cmd = $value;
  $object->safe = 'fixed';
  $alias = $data;
  system('tool ' . ${access});
}`);
    assert.equal(hasCommand(analysis), expected, access);
    assert.equal(query(analysis, QueryKind.TRACE_FORWARD, "$value", 3).some(node => node.kind === "sink"), expected, `${access} forward`);
  }
});

test("PHP interpolation reads fields but single-quoted variable text is constant", () => {
  assert.deepEqual(expressionInputs('"prefix {$data[\'cmd\']}"', "php"), ["$data.cmd"]);
  assert.deepEqual(expressionInputs("'$data'", "php"), []);
  assert.deepEqual(expressionInputs('"\\$data"', "php"), []);
  assert.deepEqual(expressionInputs('$data[$key]', "php"), ["$data[*]"]);
});

test("Python nested tuple/list unpacking keeps positional fields in scans and forward/backward queries", async () => {
  for (const [read, expected] of [["command", true], ["safe", false]]) {
    const analysis = await analyze("python", `def run(request):
    value = request.args.get("cmd")
    pair = (value, ["fixed", "other"])
    command, (safe, other) = pair
    os.system(f"tool {${read}}")
`);
    assert.equal(hasCommand(analysis), expected, read);
    assert.equal(query(analysis, QueryKind.TRACE_FORWARD, "value", 2).some(node => node.kind === "sink"), expected, `${read} forward`);
    assert.equal(query(analysis, QueryKind.TRACE_BACKWARD, read, 5).some(node => node.kind === "source"), expected, `${read} backward`);
  }
});

test("Python tuple swaps evaluate RHS values before overwriting the LHS", async () => {
  for (const [read, expected] of [["a", false], ["b", true]]) {
    const analysis = await analyze("python", `def run(request):
    a = request.args.get("cmd")
    b = "fixed"
    a, b = b, a
    os.system(${read})
`);
    assert.equal(hasCommand(analysis), expected, read);
    assert.equal(query(analysis, QueryKind.TRACE_BACKWARD, read, 5).some(node => node.kind === "source"), expected, `${read} backward`);
  }
});

test("unknown-key writes cannot clear known slots or wildcard evidence", () => {
  assert.deepEqual([...removeAssignedTaint(["data.cmd", "data.other"], "data[*]")], ["data.cmd", "data.other"]);
  assert.deepEqual([...removeAssignedTaint(["data[*]", "data.cmd", "data.other"], "data.cmd")], ["data[*]", "data.other"]);
  assert.deepEqual([...removeAssignedTaint(["data[*]", "data.cmd"], "data")], []);
});
