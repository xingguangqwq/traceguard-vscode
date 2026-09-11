"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { buildInteractiveModel, mergeInteractiveModel } = require("../src/config/interactive-model");
const { parseProjectConfigurationText } = require("../src/config/project-config");
const { WorkspaceAnalysisEngine } = require("../src/analysis/workspace-engine");

test("an argument-to-return model preserves selected arguments without upgrading unknown symbols", () => {
  assert.throws(() => buildInteractiveModel({ role: "propagator", language: "python", functionName: "unwrap" }), /argument/);
  const model = buildInteractiveModel({ role: "propagator", language: "python", functionName: "unwrap", arguments: [2, 1, 2] });
  assert.deepEqual(model.arguments, [1, 2]);
  assert.equal(model.certainty, "review");
  assert.equal(model.returnsTaint, true);
  const merged = mergeInteractiveModel({ version: 1 }, "propagator", model);
  const parsed = parseProjectConfigurationText(JSON.stringify(merged.configuration), "/workspace/.traceguard.json");
  assert.equal(parsed.valid, true);
  assert.equal(parsed.config.semanticModels[0].role, "propagator");
  assert.deepEqual(parsed.config.semanticModels[0].taintArguments, [1, 2]);
  assert.equal(mergeInteractiveModel(merged.configuration, "propagator", model).changed, false);
});

test("adding a propagator reconnects a Worker query without upgrading an unqualified model", async () => {
  const engine = new WorkspaceAnalysisEngine();
  const absolutePath = require("node:path").resolve("model-workspace/handler.py");
  await engine.initializeWorkspace([{ absolutePath, relativePath: "handler.py", language: "python", version: "1", text:
    'from flask import request\nimport os\ndef handle():\n    raw = request.args.get("cmd")\n    command = unwrap(raw)\n    os.system(command)\n' }]);
  const request = { absolutePath, line: 4, kind: "trace-forward", identifier: "raw" };
  const flatten = nodes => nodes.flatMap(node => [node, ...flatten(node.children || [])]);
  const before = flatten(engine.queryAudit(request).roots);
  assert.ok(before.some(node => node.status === "unresolved"));
  assert.equal(before.some(node => node.kind === "sink"), false);
  const model = buildInteractiveModel({ role: "propagator", language: "python", functionName: "unwrap", arguments: [0] });
  const projectConfiguration = parseProjectConfigurationText(JSON.stringify({ version: 1, propagators: [model] })).config;
  await engine.configure({ projectConfiguration });
  const after = flatten(engine.queryAudit(request).roots);
  const modeled = after.find(node => /^Modeled unwrap/.test(node.label));
  assert.ok(modeled);
  assert.notEqual(modeled.status, "verified");
  assert.ok(after.some(node => node.kind === "sink"));
});

test("model changes only reparse their workspace root and retain another root's analysis", async () => {
  const path = require("node:path");
  const engine = new WorkspaceAnalysisEngine();
  const roots = [path.resolve("model-a"), path.resolve("model-b")];
  const empty = parseProjectConfigurationText('{"version":1}').config;
  const files = roots.map(root => ({ absolutePath: path.join(root, "handler.py"), relativePath: "handler.py", language: "python", version: "1",
    text: 'from flask import request\nimport os\ndef handle():\n    os.system(request.args.get("cmd"))\n' }));
  await engine.initializeWorkspace(files, { projectConfigurationsByRoot: roots.map(root => ({ root, configuration: empty })) });
  const other = engine.analyses().find(item => item.absolutePath === files[1].absolutePath);
  const configuration = parseProjectConfigurationText(JSON.stringify({ version: 1, propagators: [
    buildInteractiveModel({ role: "propagator", language: "python", functionName: "unwrap", arguments: [0] })] })).config;
  const result = await engine.configure({ projectConfigurationsByRoot: [
    { root: roots[0], configuration }, { root: roots[1], configuration: empty }] });
  assert.equal(result.metadata.configurationReparsedFiles, 1);
  assert.equal(result.affectedFiles.length, 1);
  assert.equal(engine.analyses().find(item => item.absolutePath === files[1].absolutePath), other);
});
