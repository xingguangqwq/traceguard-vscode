"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { analyzeTextAsync } = require("../src/audit-analyzer");
const { runDataflowAnalysis } = require("../src/dataflow/pipeline");
const { functionsFromAnalyses } = require("../src/dataflow/ir-adapter");
const { QueryKind, runAuditQuery } = require("../src/query/audit-query-engine");
const { WorkspaceAnalysisEngine } = require("../src/analysis/workspace-engine");
const { buildSliceContext } = require("../src/query/slice-context");
const { FunctionSummaryCache, buildFunctionSummary } = require("../src/dataflow/function-summary");
const { parseProjectConfigurationText } = require("../src/config/project-config");

function fixture(language, options = {}) {
  const read = options.read || "command";
  const inline = options.inline;
  if (language === "java") return [
    { language, relativePath: "Box.java", text: `package demo;
class Box {
  private String command;
  private String safe;
  void store(String value) { this.command = value; }
  String fetch() { return this.${read}; }
  String getCommand() { return "fixed"; }
  Box withCommand(String value) { this.command = value; return this; }
}` },
    { language, relativePath: "Controller.java", text: `package demo;
class Controller {
  void run(HttpServletRequest request, boolean reset) {
    Box box = new Box();
    Box other = new Box();
    String value = request.getParameter("cmd");
    box.store(value);
    ${options.after || ""}
    ${inline ? "" : "String selected = box.fetch();"}
    Runtime.getRuntime().exec(${inline ? "box.fetch()" : "selected"});
  }
}` },
  ];
  if (language === "php") return [
    { language, relativePath: "Box.php", text: `<?php
namespace Demo;
class Box {
  function store($value) { $this->command = $value; }
  function fetch() { return $this->${read}; }
  function getCommand() { return 'fixed'; }
  function withCommand($value) { $this->command = $value; return $this; }
}` },
    { language, relativePath: "Controller.php", text: `<?php
namespace Demo;
function run($reset) {
  $box = new Box();
  $other = new Box();
  $value = $_GET['cmd'];
  $box->store($value);
  ${options.after || ""}
  ${inline ? "" : "$selected = $box->fetch();"}
  system(${inline ? "$box->fetch()" : "$selected"});
}` },
  ];
  return [
    { language, relativePath: "box.py", text: `class Box:
    def store(self, value):
        self.command = value
    def fetch(self):
        return self.${read}
    def getCommand(self):
        return "fixed"
    def withCommand(self, value):
        self.command = value
        return self
` },
    { language, relativePath: "controller.py", text: `from box import Box
import os
def run(request, reset):
    box = Box()
    other = Box()
    value = request.args.get("cmd")
    box.store(value)
    ${options.after || ""}
    ${inline ? "" : "selected = box.fetch()"}
    os.system(${inline ? "box.fetch()" : "selected"})
` },
  ];
}

async function analyze(files, options = {}) {
  return Promise.all(files.map(async file => ({ ...await analyzeTextAsync(file.text, file.language, `C:/repo/${file.relativePath}`, file.relativePath, options), testSource: file.text })));
}
function flatten(nodes) { return nodes.flatMap(node => [node, ...flatten(node.children || [])]); }
function commandFindings(analyses) { return runDataflowAnalysis(analyses).findings.filter(finding => finding.ruleId === "potential-command-injection"); }
function trace(analyses, kind, identifier, marker) {
  const caller = analyses.at(-1);
  const line = caller.testSource?.split(/\r?\n/).findIndex(text => text.includes(marker)) + 1 ||
    caller.ir.functions.flatMap(fn => fn.operations).find(operation => operation.location.code?.includes(marker))?.location.line;
  return flatten(runAuditQuery(analyses, { absolutePath: caller.absolutePath, kind, identifier, line }).roots);
}

for (const language of ["java", "php", "python"]) {
  test(`${language}: cross-file setter/getter effects reach sinks in scanning and both query directions`, async () => {
    const analyses = await analyze(fixture(language));
    const findings = commandFindings(analyses);
    assert.ok(findings.length, "setter field write was not visible to its caller");
    const steps = findings.flatMap(finding => finding.paths.flatMap(path => path.steps));
    assert.ok(steps.some(step => step.functionName === "store" && /Box|box/.test(step.relativePath)), "setter body missing from evidence");
    assert.ok(steps.some(step => step.functionName === "fetch"), "getter body missing from evidence");
    assert.ok(trace(analyses, QueryKind.TRACE_FORWARD, language === "php" ? "$value" : "value", language === "java" ? "String value" : "value =").some(node => node.kind === "sink"));
    assert.ok(trace(analyses, QueryKind.TRACE_BACKWARD, language === "php" ? "$selected" : "selected", language === "java" ? ".exec(" : language === "php" ? "system(" : "os.system(").some(node => node.kind === "source"));
  });

  test(`${language}: inline getters preserve field effects and sibling fields stay isolated`, async () => {
    for (const [read, expected] of [["command", true], ["safe", false]]) {
      const analyses = await analyze(fixture(language, { read, inline: true }));
      assert.equal(commandFindings(analyses).length > 0, expected, read);
      assert.equal(trace(analyses, QueryKind.TRACE_FORWARD, language === "php" ? "$value" : "value", language === "java" ? "String value" : "value =").some(node => node.kind === "sink"), expected, `${read} forward`);
    }
  });

  test(`${language}: constant setter overwrites clear the field on their CFG path`, async () => {
    const reset = { java: 'box.store("fixed");', php: "$box->store('fixed');", python: 'box.store("fixed")' }[language];
    const safe = await analyze(fixture(language, { after: reset }));
    assert.equal(commandFindings(safe).length, 0);
    assert.ok(!trace(safe, QueryKind.TRACE_BACKWARD, language === "php" ? "$selected" : "selected", language === "java" ? ".exec(" : language === "php" ? "system(" : "os.system(").some(node => node.kind === "source"));
    const branch = { java: `if (reset) { ${reset} }`, php: `if ($reset) { ${reset} }`, python: `if reset:\n        ${reset}` }[language];
    assert.ok(commandFindings(await analyze(fixture(language, { after: branch }))).length, "conditional overwrite erased the unmodified branch");
  });

  test(`${language}: another instance and a constant-returning getCommand do not inherit taint`, async () => {
    const files = fixture(language);
    files[1].text = files[1].text.replace(language === "php" ? "$box->fetch()" : "box.fetch()", language === "php" ? "$other->fetch()" : "other.fetch()");
    assert.equal(commandFindings(await analyze(files)).length, 0);
    const constant = fixture(language, { inline: true });
    constant[1].text = constant[1].text.replace(language === "php" ? "$box->fetch()" : "box.fetch()", language === "php" ? "$box->getCommand()" : "box.getCommand()");
    assert.equal(commandFindings(await analyze(constant)).length, 0, "getter name overrode its constant method body");
  });

  test(`${language}: fluent setter return aliases preserve the updated field`, async () => {
    const files = fixture(language);
    if (language === "java") files[1].text = files[1].text.replace("box.store(value);", "Box alias = box.withCommand(value);").replace("box.fetch()", "alias.fetch()");
    else if (language === "php") files[1].text = files[1].text.replace("$box->store($value);", "$alias = $box->withCommand($value);").replace("$box->fetch()", "$alias->command");
    else files[1].text = files[1].text.replace("box.store(value)", "alias = box.withCommand(value)").replace("box.fetch()", "alias.command");
    assert.ok(commandFindings(await analyze(files)).length);
  });
}

test("accessor inference rejects conditional, static, decorated and side-effecting bodies", async () => {
  const java = await analyze([{ language: "java", relativePath: "Box.java", text: `class Box {
    String command;
    void conditional(String value) { if (value != null) this.command = value; }
    void effect(String value) { log(value); this.command = value; }
    static String read(Box box) { return box.command; }
    static String shared;
    String staticField() { return this.shared; }
    String implicit() { return command; }
    void implicitWrite(String value) { command = value; }
  }` }]);
  const summaries = new Map(java[0].ir.functions.map(fn => [fn.name, fn.accessorSummary]));
  for (const name of ["conditional", "effect", "read", "staticField"]) assert.equal(summaries.get(name), undefined, name);
  assert.deepEqual(summaries.get("implicit")?.path, ["command"]);
  assert.equal(summaries.get("implicitWrite")?.kind, "write");
  const python = await analyze([{ language: "python", relativePath: "box.py", text: `class Box:
    @property
    def command(self):
        return self.value
    @staticmethod
    def read(self):
        return self.value
    async def asyncRead(self):
        return self.value
` }]);
  assert.ok(python[0].ir.functions.every(fn => !fn.accessorSummary));
});

test("accessor field effects retain call navigation and remain isolated by workspace root", async () => {
  const files = fixture("java");
  const analyses = await analyze(files);
  const caller = analyses[1];
  const callees = runAuditQuery(analyses, { kind: QueryKind.FIND_CALLEES, absolutePath: caller.absolutePath, line: 3 });
  assert.ok(flatten(callees.roots).some(node => node.label === "run() → store()"));
  const split = await Promise.all(files.map((file, index) => analyzeTextAsync(file.text, file.language, `C:/root${index}/${file.relativePath}`, file.relativePath)));
  const options = { projectConfigurationsByRoot: [{ root: "C:/root0" }, { root: "C:/root1" }] };
  assert.ok(functionsFromAnalyses(split, options).every(fn => fn.events.every(event => !event.accessorModeled)));
});

test("ambiguous interface dispatch never manufactures a verified accessor effect", async () => {
  const analyses = await analyze([{ language: "java", relativePath: "Dispatch.java", text: `interface Slot { void store(String value); }
class First implements Slot { String command; public void store(String value) { this.command = value; } }
class Second implements Slot { String safe; public void store(String value) { this.safe = value; } }
class Dispatch { void run(Slot slot, String value) { slot.store(value); } }` }]);
  const caller = functionsFromAnalyses(analyses).find(fn => fn.name === "run");
  assert.ok(caller.events.every(event => !event.accessorModeled && !event.accessorEvidence));
});

test("cached function summaries distinguish accessor field changes", async () => {
  const files = fixture("java");
  const before = (await analyze(files))[0].ir.functions.find(fn => fn.name === "fetch");
  files[0].text = files[0].text.replace("return this.command;", "return this.safe;");
  const after = (await analyze(files))[0].ir.functions.find(fn => fn.name === "fetch");
  const cache = new FunctionSummaryCache();
  assert.deepEqual(cache.get(before, buildFunctionSummary).accessorSummary.path, ["command"]);
  assert.deepEqual(cache.get(after, buildFunctionSummary).accessorSummary.path, ["safe"]);
});

test("identical inline reads on either side of a mutation keep distinct values and sink argument positions", async () => {
  for (const [argument, expected] of [[0, false], [2, true]]) {
    const files = fixture("java", { inline: true });
    files[1].text = files[1].text.replace("boolean reset)", "boolean reset, AuditSink sink)")
      .replace("box.store(value);", 'box.store("fixed");')
      .replace("Runtime.getRuntime().exec(box.fetch());", "sink.send(box.fetch(), box.withCommand(value), box.fetch());");
    const configuration = parseProjectConfigurationText(JSON.stringify({
      sinks: [{ language: "java", receiverType: "AuditSink", function: "send", arguments: [argument], kind: "COMMAND_EXEC" }],
    }));
    assert.equal(configuration.valid, true);
    const analyses = await analyze(files, { semanticModels: configuration.config.semanticModels });
    assert.equal(commandFindings(analyses).length > 0, expected, `argument ${argument}`);
  }
});

test("accessor evidence exports the actual method bodies in code slices", async () => {
  const files = fixture("java", { inline: true });
  const analyses = await analyze(files);
  const path = commandFindings(analyses)[0]?.paths[0];
  assert.ok(path);
  const slice = await buildSliceContext(path, { readSource: async absolutePath => files.find(file => absolutePath === `C:/repo/${file.relativePath}`) });
  assert.ok(slice.functions.some(fn => fn.code.includes("void store(")));
  assert.ok(slice.functions.some(fn => fn.code.includes("String fetch(")));
});

test("incremental accessor-body edits invalidate callers and recompute scan and query results", async () => {
  const engine = new WorkspaceAnalysisEngine();
  const files = fixture("java").map(file => ({ ...file, absolutePath: `C:/repo/${file.relativePath}` }));
  try {
    await engine.initializeWorkspace(files);
    assert.ok(engine.dataflow.findings.length);
    const changed = { ...files[0], text: files[0].text.replace("return this.command;", "return this.safe;") };
    await engine.updateFile(changed);
    assert.equal(engine.dataflow.findings.length, 0);
    assert.ok(functionsFromAnalyses(engine.analyses()).some(fn => fn.events.some(event => event.accessorModeled)));
    assert.ok(!trace(engine.analyses().sort((a, b) => a.relativePath.localeCompare(b.relativePath)), QueryKind.TRACE_BACKWARD, "selected", ".exec(").some(node => node.kind === "source"));
  } finally {
    for (const file of files) await engine.removeFile(file.absolutePath);
  }
});
