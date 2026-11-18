"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { analyzeTextAsync } = require("../src/audit-analyzer");
const { runDataflowAnalysis } = require("../src/dataflow/pipeline");
const { runAuditQuery, QueryKind } = require("../src/query/audit-query-engine");
const { WorkspaceAnalysisEngine } = require("../src/analysis/workspace-engine");
const { pathVerificationStatus } = require("../src/review/finding-pool");

function project(language, options = {}) {
  const signature = options.signature || (language === "python" ? "prefix, command" : "$prefix, $command");
  const read = options.read || (language === "python" ? "command" : "$command");
  if (language === "python") return [
    { language, relativePath: "service.py", text: `import os
class RunnerService:
    def dispatch(self, ${signature}):
        os.system(${read})
` },
    { language, relativePath: "controller.py", text: `from service import RunnerService
def handle(request):
    service = RunnerService()
    value = request.args.get("cmd")
    ${options.before || ""}
    service.dispatch(${options.args || 'command=value, prefix="fixed"'})
` },
  ];
  return [
    { language, relativePath: "Service.php", text: `<?php
namespace Demo;
class RunnerService {
  function dispatch(${signature}) { system(${read}); }
}` },
    { language, relativePath: "Controller.php", text: `<?php
namespace Demo;
function handle() {
  $service = new RunnerService();
  $value = $_GET['cmd'];
  ${options.before || ""}
  $service->dispatch(${options.args || 'command: $value, prefix: "fixed"'});
}` },
  ];
}

async function analyze(files) {
  return Promise.all(files.map(async file => ({
    ...await analyzeTextAsync(file.text, file.language, `C:/repo/${file.relativePath}`, file.relativePath), testText: file.text,
  })));
}
function flatten(nodes) { return nodes.flatMap(node => [node, ...flatten(node.children || [])]); }
function findings(analyses) { return runDataflowAnalysis(analyses).findings.filter(finding => finding.ruleId === "potential-command-injection"); }
function query(analyses, fileIndex, kind, identifier, marker) {
  const analysis = analyses[fileIndex];
  const line = analysis.testText.split(/\r?\n/).findIndex(text => text.includes(marker)) + 1;
  return flatten(runAuditQuery(analyses, { kind, identifier, absolutePath: analysis.absolutePath, line }).roots);
}

for (const language of ["python", "php"]) {
  const value = language === "php" ? "$value" : "value";
  const command = language === "php" ? "$command" : "command";
  const forward = analyses => query(analyses, 1, QueryKind.TRACE_FORWARD, value, language === "php" ? "$value =" : "value =");
  const backward = (analyses, variable = command) => query(analyses, 0, QueryKind.TRACE_BACKWARD, variable, language === "php" ? "system(" : "os.system(");

  test(`${language}: reordered named arguments reach the correct cross-file parameter in scans and both query directions`, async () => {
    const analyses = await analyze(project(language));
    assert.ok(findings(analyses).length);
    assert.ok(forward(analyses).some(node => node.kind === "sink"));
    assert.ok(backward(analyses).some(node => node.kind === "source"));
    const call = forward(analyses).find(node => node.kind === "call");
    assert.match(call.details.argumentBinding.reason, /command/);
    assert.equal(call.details.argumentBinding.status, "verified");
  });

  test(`${language}: named labels and tainted sibling parameters do not contaminate a constant sink parameter`, async () => {
    const args = language === "python" ? 'prefix=value, command="fixed"' : 'prefix: $value, command: "fixed"';
    const files = project(language, { args });
    const analyses = await analyze(files);
    assert.equal(findings(analyses).length, 0);
    assert.ok(!forward(analyses).some(node => node.kind === "sink"));
    assert.ok(!backward(analyses).some(node => node.kind === "source"));
    const labels = files.map(file => ({ ...file, text: file.text.replaceAll(language === "php" ? "$value" : "value", command) }));
    assert.equal(findings(await analyze(labels)).length, 0, "the keyword name was treated as a caller variable read");
  });

  test(`${language}: omitted defaults are not filled by a same-named caller variable`, async () => {
    const signature = language === "python" ? 'command="fixed", prefix="ok"' : '$command="fixed", $prefix="ok"';
    const args = language === "python" ? "prefix=value" : "prefix: $value";
    const analyses = await analyze(project(language, { signature, args }));
    assert.equal(findings(analyses).length, 0);
    assert.ok(!forward(analyses).some(node => node.kind === "sink"));
    const nodes = backward(analyses);
    assert.ok(nodes.some(node => node.kind === "default-argument" && node.status === "verified"));
    assert.ok(!nodes.some(node => node.kind === "source"));
    const skipped = await analyze(project(language, {
      signature: language === "python" ? 'prefix="ok", command="fixed"' : '$prefix="ok", $command="fixed"',
      args: language === "python" ? "command=value" : "command: $value",
    }));
    assert.ok(findings(skipped).length, "skipping an optional parameter lost the supplied command");
  });

  test(`${language}: positional and named arguments can be mixed without shifting the parameter mapping`, async () => {
    const args = language === "python" ? '"fixed", command=value' : '"fixed", command: $value';
    const analyses = await analyze(project(language, { args }));
    assert.ok(findings(analyses).length);
    assert.ok(forward(analyses).some(node => node.kind === "sink"));
  });

  test(`${language}: named bindings also propagate project return values to the caller`, async () => {
    for (const expected of [true, false]) {
      const text = language === "python" ? `import os
def select_value(prefix, command):
    return command
def handle(request):
    value = request.args.get("cmd")
    selected = select_value(command=${expected ? "value" : '"fixed"'}, prefix=value)
    os.system(selected)
` : `<?php
function select_value($prefix, $command) { return $command; }
function handle() {
  $value = $_GET["cmd"];
  $selected = select_value(command: ${expected ? "$value" : '"fixed"'}, prefix: $value);
  system($selected);
}`;
      const analyses = await analyze([{ language, relativePath: language === "python" ? "return.py" : "Return.php", text }]);
      assert.equal(findings(analyses).length > 0, expected);
      assert.equal(query(analyses, 0, QueryKind.TRACE_BACKWARD, language === "python" ? "selected" : "$selected", language === "python" ? "os.system(" : "system(").some(node => node.kind === "source"), expected);
      assert.equal(query(analyses, 0, QueryKind.TRACE_FORWARD, value, "value =").some(node => node.kind === "sink"), expected);
    }
  });

  test(`${language}: explicit null is a supplied scalar argument and does not select the default`, async () => {
    const signature = language === "python" ? 'prefix="ok", command="fixed"' : '$prefix="ok", $command="fixed"';
    const args = language === "python" ? "prefix=value, command=None" : "prefix: $value, command: null";
    const analyses = await analyze(project(language, { signature, args }));
    assert.equal(findings(analyses).length, 0);
    const nodes = backward(analyses);
    assert.ok(nodes.some(node => node.kind === "argument" && node.status === "verified"));
    assert.ok(nodes.every(node => node.kind !== "default-argument"));
  });

  test(`${language}: comparisons in named argument expressions do not corrupt the argument list`, async () => {
    for (const expected of [true, false]) {
      const selected = expected ? value : '"fixed"';
      const before = language === "python" ? "retry = 1\n    limit = 2" : "$retry = 1;\n  $limit = 2;";
      const args = language === "python" ? `command=(${selected} if retry < limit else ${selected}), prefix=${value}` :
        `command: ($retry < $limit ? ${selected} : ${selected}), prefix: ${value}`;
      const analyses = await analyze(project(language, { before, args }));
      assert.equal(findings(analyses).length > 0, expected);
      assert.equal(query(analyses, 0, QueryKind.TRACE_BACKWARD, command, language === "python" ? "os.system(" : "system(").some(node => node.kind === "source"), expected);
    }
  });

  test(`${language}: constant keys survive argument-to-parameter binding`, async () => {
    for (const [field, expected] of [["cmd", true], ["safe", false]]) {
      const before = language === "python" ? 'payload.cmd = value\n    payload.safe = "fixed"' : '$payload["cmd"] = $value;\n  $payload["safe"] = "fixed";';
      const args = language === "python" ? `command=payload.${field}, prefix="fixed"` : `command: $payload["${field}"], prefix: "fixed"`;
      const analyses = await analyze(project(language, { before, args }));
      assert.equal(findings(analyses).length > 0, expected, field);
      assert.equal(forward(analyses).some(node => node.kind === "sink"), expected, `${field} forward`);
    }
  });

  test(`${language}: variadic positional arguments retain separate element paths`, async () => {
    for (const [slot, expected] of [[0, true], [1, false]]) {
      const signature = language === "python" ? "prefix, *commands" : "$prefix, ...$commands";
      const args = language === "python" ? '"fixed", value, "safe"' : '"fixed", $value, "safe"';
      const read = language === "python" ? `commands[${slot}]` : `$commands[${slot}]`;
      const analyses = await analyze(project(language, { signature, args, read }));
      assert.equal(findings(analyses).length > 0, expected, `slot ${slot}`);
      assert.equal(forward(analyses).some(node => node.kind === "sink"), expected, `slot ${slot} forward`);
      assert.equal(backward(analyses, read).some(node => node.kind === "source"), expected, `slot ${slot} backward`);
    }
  });

  test(`${language}: variadic named arguments retain their key identity`, async () => {
    for (const [key, expected] of [["command", true], ["safe", false]]) {
      const signature = language === "python" ? "**commands" : "...$commands";
      const args = language === "python" ? 'command=value, safe="fixed"' : 'command: $value, safe: "fixed"';
      const read = language === "python" ? `commands["${key}"]` : `$commands["${key}"]`;
      const analyses = await analyze(project(language, { signature, args, read }));
      assert.equal(findings(analyses).length > 0, expected, key);
      assert.equal(forward(analyses).some(node => node.kind === "sink"), expected, `${key} forward`);
      assert.equal(backward(analyses, read).some(node => node.kind === "source"), expected, `${key} backward`);
    }
  });

  test(`${language}: an unresolved variadic slot does not borrow a constant from its sibling`, async () => {
    const signature = language === "python" ? "*commands" : "...$commands";
    const read = language === "python" ? "commands[0]" : "$commands[0]";
    const analyses = await analyze(project(language, { signature, read, args: 'opaque(), "fixed"' }));
    const nodes = backward(analyses, read);
    assert.ok(nodes.some(node => node.status === "unresolved"));
    assert.ok(nodes.every(node => node.kind !== "argument" || node.status !== "verified"));
  });

  test(`${language}: unknown or duplicate names are explicit invalid bindings and cannot create a flow`, async () => {
    const cases = language === "python" ? [
      'unknown=value, prefix="fixed"', 'value, prefix="fixed", command="fixed"', 'command=value, command="fixed", prefix="fixed"',
    ] : [
      'unknown: $value, prefix: "fixed"', '$value, prefix: "fixed", command: "fixed"', 'command: $value, command: "fixed", prefix: "fixed"',
    ];
    for (const args of cases) {
      const analyses = await analyze(project(language, { args }));
      assert.equal(findings(analyses).length, 0, args);
      const nodes = query(analyses, 1, QueryKind.FIND_CALLEES, undefined, "service");
      assert.ok(nodes.some(node => node.kind === "call" && node.status === "unresolved" && node.details.argumentBinding?.status === "invalid"), args);
    }
  });

  test(`${language}: dynamic unpacking stays a review hypothesis and explains the binding gap`, async () => {
    const args = language === "python" ? "**value" : "...$value";
    const analyses = await analyze(project(language, { args }));
    const paths = runDataflowAnalysis(analyses).paths;
    assert.ok(paths.length, "possible taint through unpacking disappeared");
    assert.ok(paths.every(path => pathVerificationStatus(path) !== "verified"));
    assert.ok(forward(analyses).some(node => node.kind === "call" && node.status === "unresolved" && /Unpacked/.test(node.details.argumentBinding?.reason)));
  });

  test(`${language}: named setter writes and constant overwrites use the same field semantics`, async () => {
    const files = language === "python" ? [
      { language, relativePath: "box.py", text: "class Box:\n    def store(self, *, value):\n        self.command = value\n    def fetch(self):\n        return self.command\n" },
      { language, relativePath: "controller.py", text: 'from box import Box\nimport os\ndef handle(request):\n    box = Box()\n    value = request.args.get("cmd")\n    box.store(value=value)\n    os.system(box.fetch())\n' },
    ] : [
      { language, relativePath: "Box.php", text: "<?php namespace Demo; class Box { function store($value) { $this->command = $value; } function fetch() { return $this->command; } }" },
      { language, relativePath: "Controller.php", text: '<?php\nnamespace Demo;\nfunction handle() {\n $box = new Box();\n $value = $_GET["cmd"];\n $box->store(value: $value);\n system($box->fetch());\n}' },
    ];
    assert.ok(findings(await analyze(files)).length);
    files[1].text = files[1].text.replace(language === "python" ? "box.store(value=value)" : "$box->store(value: $value);",
      language === "python" ? 'box.store(value=value)\n    box.store(value="fixed")' : '$box->store(value: $value);\n $box->store(value: "fixed");');
    assert.equal(findings(await analyze(files)).length, 0);
  });
}

test("Python positional-only and keyword-only separators do not become fake IR parameters", async () => {
  const good = await analyze(project("python", { signature: "prefix, /, *, command", args: '"fixed", command=value' }));
  assert.deepEqual(good[0].ir.functions[0].parameters.map(parameter => parameter.name), ["self", "prefix", "command"]);
  assert.ok(findings(good).length);
  for (const args of ['prefix="fixed", command=value', '"fixed", value']) {
    const bad = await analyze(project("python", { signature: "prefix, /, *, command", args }));
    assert.equal(findings(bad).length, 0, args);
  }
});

test("nonliteral defaults stay unresolved and never borrow caller-scope values", async () => {
  const analyses = await analyze(project("python", { signature: "command=value, prefix=None", args: "prefix=value" }));
  const nodes = query(analyses, 0, QueryKind.TRACE_BACKWARD, "command", "os.system(");
  assert.ok(nodes.some(node => node.kind === "default-argument" && node.status === "unresolved"));
  assert.ok(!nodes.some(node => node.kind === "source"));
});

test("excessive argument unpacking stops at an explicit binding budget", async () => {
  const analyses = await analyze(project("python", { args: Array(129).fill("**value").join(", ") }));
  const nodes = query(analyses, 1, QueryKind.FIND_CALLEES, undefined, "service");
  assert.ok(nodes.some(node => node.status === "unresolved" && /binding budget exceeded/.test(node.details.argumentBinding?.reason)));
});

test("inline getter results retain live field evidence when supplied by name", async () => {
  for (const language of ["python", "php"]) for (const [field, expected] of [["command", true], ["safe", false]]) {
    const files = project(language, {
      before: language === "python" ? "box = Box()\n    box.store(value=value)" : "$box = new Box();\n  $box->store(value: $value);",
      args: language === "python" ? 'prefix="fixed", command=box.fetch()' : 'prefix: "fixed", command: $box->fetch()',
    });
    if (language === "python") {
      files[1].text = `from box import Box\n${files[1].text}`;
      files.push({ language, relativePath: "box.py", text: `class Box:\n    def store(self, *, value):\n        self.command = value\n    def fetch(self):\n        return self.${field}\n` });
    } else files.push({ language, relativePath: "Box.php", text: `<?php namespace Demo; class Box { function store($value) { $this->command = $value; } function fetch() { return $this->${field}; } }` });
    const analyses = await analyze(files);
    assert.equal(findings(analyses).length > 0, expected, `${language}/${field}`);
    assert.equal(query(analyses, 1, QueryKind.TRACE_FORWARD, language === "python" ? "value" : "$value", "value =").some(node => node.kind === "sink"), expected);
  }
});

test("invalid named arguments cannot redirect a known receiver to an unrelated same-named method", async () => {
  const cases = [
    ["python", "dispatch.py", `import os
class Intended:
    def dispatch(self, task):
        pass
class Other:
    def dispatch(self, command):
        os.system(command)
def handle(request):
    service = Intended()
    value = request.args.get("cmd")
    service.dispatch(command=value)
`],
    ["php", "Dispatch.php", `<?php
class Intended { function dispatch($task) {} }
class Other { function dispatch($command) { system($command); } }
function handle() {
  $service = new Intended();
  $value = $_GET["cmd"];
  $service->dispatch(command: $value);
}`],
  ];
  for (const [language, relativePath, text] of cases) {
    const analyses = await analyze([{ language, relativePath, text }]);
    assert.equal(findings(analyses).length, 0, language);
    const calls = query(analyses, 0, QueryKind.FIND_CALLEES, undefined, "service").filter(node => /dispatch\(\)/.test(node.label));
    assert.ok(calls.length && calls.every(node => node.details.argumentBinding.status === "invalid"), language);
  }
});

test("incremental signature edits invalidate named call mappings and remove stale findings", async () => {
  const engine = new WorkspaceAnalysisEngine();
  const files = project("python").map(file => ({ ...file, absolutePath: `C:/repo/${file.relativePath}` }));
  await engine.initializeWorkspace(files);
  try {
    assert.ok(engine.dataflow.findings.length);
    const changed = { ...files[0], text: files[0].text.replaceAll("command", "task") };
    const updated = await engine.updateFile(changed);
    assert.ok(updated.findingDelta.removedIds.length);
    assert.equal(engine.dataflow.findings.length, 0);
    const analyses = engine.analyses().map(analysis => ({ ...analysis, testText: analysis.relativePath === "service.py" ? changed.text : files[1].text }))
      .sort((a, b) => b.relativePath.localeCompare(a.relativePath));
    assert.ok(query(analyses, 1, QueryKind.FIND_CALLEES, undefined, "service").some(node => node.details.argumentBinding?.status === "invalid"));
  } finally {
    for (const file of files) await engine.removeFile(file.absolutePath);
  }
});

test("default-only signature edits invalidate cached summaries and refresh displayed default evidence", async () => {
  const engine = new WorkspaceAnalysisEngine();
  const files = project("python", { signature: 'prefix="ok", command="old"', args: "prefix=value" })
    .map(file => ({ ...file, absolutePath: `C:/repo/${file.relativePath}` }));
  const initialized = await engine.initializeWorkspace(files);
  try {
    const method = initialized.analyses[0].ir.functions.find(fn => fn.name === "dispatch");
    const changed = { ...files[0], text: files[0].text.replace('command="old"', 'command="new"') };
    const result = await engine.updateFile(changed);
    assert.ok(result.changedFunctionIds.includes(method.id), "default metadata was lost behind an unchanged function body");
    const queryResult = engine.queryAudit({ kind: QueryKind.TRACE_BACKWARD, absolutePath: changed.absolutePath, identifier: "command", line: 4 });
    assert.ok(flatten(queryResult.roots).some(node => node.kind === "default-argument" && node.details.expression === '"new"'));
  } finally {
    for (const file of files) await engine.removeFile(file.absolutePath);
  }
});
