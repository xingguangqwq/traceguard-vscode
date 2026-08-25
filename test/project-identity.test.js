"use strict";

const assert = require("node:assert/strict");
const path = require("node:path");
const test = require("node:test");
const { WorkspaceAnalysisEngine } = require("../src/analysis/workspace-engine");
const { normalizePath } = require("../src/identity");
const {
  composerPathsForType,
  parseComposerConfigurationText,
} = require("../src/config/project-identity");

test("Composer PSR-4 and PSR-4 dev mappings compile into deterministic source identities", () => {
  const parsed = parseComposerConfigurationText(JSON.stringify({
    autoload: { "psr-4": { "App\\": "src/", "Shared\\": ["packages/shared/src", "legacy/shared"] } },
    "autoload-dev": { "psr-4": { "Tests\\": "tests/" } },
  }), path.resolve("C:\\workspace"), path.resolve("C:\\workspace\\composer.json"));

  assert.equal(parsed.valid, true);
  assert.deepEqual(composerPathsForType(parsed.identity, "App\\Service\\Runner"), [normalizePath(path.resolve("C:\\workspace\\src\\Service\\Runner.php"))]);
  assert.deepEqual(composerPathsForType(parsed.identity, "Tests\\Feature\\AuditTest"), [normalizePath(path.resolve("C:\\workspace\\tests\\Feature\\AuditTest.php"))]);
  assert.equal(parsed.identity.mappings.find(item => item.prefix === "Tests\\").dev, true);
});

test("Composer identity selects the mapped PHP class when namespace metadata is incomplete", async () => {
  const root = path.resolve("C:\\workspace");
  const identity = parseComposerConfigurationText(JSON.stringify({ autoload: { "psr-4": { "App\\": "src/" } } }), root).identity;
  const engine = new WorkspaceAnalysisEngine();
  const result = await engine.initializeWorkspace([
    file(path.join(root, "src", "Service", "Runner.php"), "src/Service/Runner.php", `<?php class Runner { public function run($value) { system($value); } }`),
    file(path.join(root, "legacy", "Runner.php"), "legacy/Runner.php", `<?php class Runner { public function run($value) { return $value; } }`),
    file(path.join(root, "src", "Controller.php"), "src/Controller.php", `<?php
use App\\Service\\Runner;
class Controller {
  public function handle(Runner $runner) { $runner->run($_GET["cmd"]); }
}`),
  ], {
    projectIdentitiesByRoot: [{ root, identity }],
    maxDepth: 6,
    maxPaths: 80,
  });

  const finding = result.findingDelta.upsert.find(item => item.ruleId === "potential-command-injection");
  assert.ok(finding);
  assert.ok(finding.path.steps.some(step => step.relativePath === "src/Service/Runner.php"));
  assert.ok(!finding.path.steps.some(step => step.relativePath === "legacy/Runner.php"));
});

function file(absolutePath, relativePath, text) {
  return { language: "php", absolutePath, relativePath, text, version: text.length.toString() };
}
