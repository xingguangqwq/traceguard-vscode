"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { SemanticRole } = require("../src/security/semantic-models");
const { WorkspaceAnalysisEngine } = require("../src/analysis/workspace-engine");
const {
  combinedExcludeGlob,
  emptyProjectConfiguration,
  matchesExcludedPath,
  mergeProjectConfigurations,
  parseProjectConfigurationText,
} = require("../src/config/project-config");

test("project configuration compiles custom audit semantics into registry models", () => {
  const result = parseProjectConfigurationText(JSON.stringify({
    version: 1,
    sources: [{ language: "javascript", function: "getUserInput", returnsTaint: true }],
    sinks: [{ language: "javascript", module: "./internal", function: "internalExec", arguments: [0], kind: "COMMAND_EXEC" }],
    sanitizers: [{ language: "javascript", function: "validateInternalUrl", arguments: [0], capability: "URL_POLICY" }],
    propagators: [{ language: "javascript", function: "wrapValue", arguments: [0], returnsTaint: true }],
    wrappers: [{ language: "python", function: "run_query", role: "sink", arguments: [1], kind: "SQL_QUERY" }],
    rules: { "potential-open-redirect": false, "potential-command-injection": { severity: "high" } },
    severityOverrides: { "potential-ssrf": "medium" },
    excludePaths: ["generated/**", "**/*.fixture.ts"],
  }), "C:/repo/.traceguard.json");

  assert.equal(result.valid, true, JSON.stringify(result.issues));
  assert.deepEqual(result.config.semanticModels.map(model => model.role), [
    SemanticRole.SOURCE, SemanticRole.SINK, SemanticRole.GUARD, SemanticRole.PROPAGATOR, SemanticRole.SINK,
  ]);
  assert.equal(result.config.semanticModels[1].sinkKind, "COMMAND_EXEC");
  assert.deepEqual(result.config.semanticModels[1].taintArguments, [0]);
  assert.deepEqual(result.config.semanticModels[2].applicableSinkKinds, ["HTTP_REQUEST", "REDIRECT"]);
  assert.equal(result.config.rules["potential-open-redirect"].enabled, false);
  assert.equal(result.config.rules["potential-command-injection"].severity, "high");
  assert.equal(result.config.rules["potential-ssrf"].severity, "medium");
  assert.ok(result.config.fingerprint);
});

test("invalid configuration is rejected atomically with precise issues", () => {
  const malformed = parseProjectConfigurationText("{\n  \"version\": 1,\n}", "broken/.traceguard.json");
  assert.equal(malformed.valid, false);
  assert.equal(malformed.issues[0].line, 3);

  const invalidModel = parseProjectConfigurationText(JSON.stringify({
    version: 2,
    sources: [{ language: "javascript", function: "selected", kind: "SELECTED_SYMBOL" }],
    sinks: [{ language: "ruby", function: "run", arguments: [-1], kind: "NOT_A_SINK" }],
    excludePaths: ["../outside/**"],
  }), "invalid/.traceguard.json");
  assert.equal(invalidModel.valid, false);
  assert.ok(invalidModel.issues.some(item => /version/.test(item.message)));
  assert.ok(invalidModel.issues.some(item => /SELECTED_SYMBOL/.test(item.message)));
  assert.ok(invalidModel.issues.some(item => /Unsupported language/.test(item.message)));
  assert.ok(invalidModel.issues.some(item => /parent traversal/.test(item.message)));
});

test("workspace-relative exclusion globs and multi-root configurations merge deterministically", () => {
  const first = parseProjectConfigurationText(JSON.stringify({
    sources: [{ language: "typescript", function: "fromA" }],
    rules: { "potential-ssrf": false },
    excludePaths: ["generated/**"],
  }), "a/.traceguard.json").config;
  const second = parseProjectConfigurationText(JSON.stringify({
    sinks: [{ language: "typescript", function: "toB", kind: "HTTP_REQUEST" }],
    rules: { "potential-ssrf": { enabled: true, severity: "medium" } },
    excludePaths: ["**/*.fixture.ts"],
  }), "b/.traceguard.json").config;
  const merged = mergeProjectConfigurations([first, second]);

  assert.equal(merged.semanticModels.length, 2);
  assert.deepEqual(merged.rules["potential-ssrf"], { enabled: true, severity: "medium" });
  assert.equal(matchesExcludedPath("generated/client.ts", merged.excludePaths), true);
  assert.equal(matchesExcludedPath("src/example.fixture.ts", merged.excludePaths), true);
  assert.equal(matchesExcludedPath("src/index.ts", merged.excludePaths), false);
  assert.match(combinedExcludeGlob("**/node_modules/**", merged.excludePaths), /generated/);
  assert.notEqual(merged.fingerprint, emptyProjectConfiguration().fingerprint);
});

test("custom Source, Propagator and imported Sink execute in the persistent workspace engine", async () => {
  const configuration = parseProjectConfigurationText(JSON.stringify({
    sources: [{ language: "typescript", function: "getUserInput", returnsTaint: true }],
    sinks: [{ language: "typescript", module: "./internal", function: "internalExec", arguments: [0], kind: "COMMAND_EXEC" }],
    propagators: [{ language: "typescript", function: "wrapValue", arguments: [0], returnsTaint: true }],
  }), "C:/repo/.traceguard.json").config;
  const engine = new WorkspaceAnalysisEngine();
  const result = await engine.initializeWorkspace([
    file("C:\\repo\\internal.ts", "internal.ts", "export function internalExec(value: string): void {}"),
    file("C:\\repo\\route.ts", "route.ts", `
import { internalExec } from "./internal";
function getUserInput(): string { return "runtime"; }
function wrapValue(value: string): string { return value; }
export function route(): void {
  const input = getUserInput();
  const wrapped = wrapValue(input);
  internalExec(wrapped);
}`),
  ], { projectConfiguration: configuration, maxDepth: 6, maxPaths: 80 });

  const finding = result.findingDelta.upsert.find(item => item.ruleId === "potential-command-injection");
  assert.ok(finding, JSON.stringify(result.analyses.map(item => item.ir.functions), null, 2));
  const operations = result.analyses.flatMap(item => item.ir.functions.flatMap(fn => fn.operations));
  assert.ok(operations.some(operation => operation.semantic.modelRole === "source" && operation.semantic.modelId.startsWith("custom.")));
  assert.ok(operations.some(operation => operation.semantic.modelRole === "propagator"));
  assert.ok(operations.some(operation => operation.semantic.modelRole === "sink" && operation.metadata.semanticVerification === "verified"));
});

test("custom sanitizer scope, rule toggles and severity overrides use the normal rule engine", async () => {
  const base = {
    sources: [{ language: "typescript", module: "./security", function: "customInput" }],
    sinks: [{ language: "typescript", module: "./security", function: "customExec", arguments: [0], kind: "COMMAND_EXEC" }],
    sanitizers: [{ language: "typescript", module: "./security", function: "escapeCommand", arguments: [0], capability: "SHELL_ESCAPE" }],
    severityOverrides: { "potential-command-injection": "high" },
  };
  const configuration = parseProjectConfigurationText(JSON.stringify(base), "C:/repo/.traceguard.json").config;
  const engine = new WorkspaceAnalysisEngine();
  const result = await engine.initializeWorkspace([
    file("C:\\repo\\security.ts", "security.ts", `
export declare function customInput(): string;
export declare function customExec(value: string): void;
export declare function escapeCommand(value: string): string;
`),
    file("C:\\repo\\app.ts", "app.ts", `
import { customInput, customExec, escapeCommand } from "./security";
export function unsafe(): void {
  const raw = customInput();
  customExec(raw);
}
export function safe(): void {
  const raw = customInput();
  const escaped = escapeCommand(raw);
  customExec(escaped);
}
`),
  ], { projectConfiguration: configuration, maxDepth: 6, maxPaths: 80 });
  const findings = result.findingDelta.upsert.filter(item => item.ruleId === "potential-command-injection");
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "high");
  assert.equal(findings[0].functionName, "unsafe");

  const disabled = parseProjectConfigurationText(JSON.stringify({ ...base, rules: { "potential-command-injection": false } }), "C:/repo/.traceguard.json").config;
  const configured = await engine.configure({ projectConfiguration: disabled });
  assert.ok(configured.findingDelta.removedIds.includes(findings[0].id));
  assert.equal(engine.dataflow.findings.some(item => item.ruleId === "potential-command-injection"), false);
});

test("module-qualified custom models follow import aliases and reject same-named local shadowing", async () => {
  const configuration = parseProjectConfigurationText(JSON.stringify({
    sources: [{ language: "typescript", module: "./security", function: "tenantInput" }],
    sinks: [{ language: "typescript", module: "./security", function: "internalExec", arguments: [0], kind: "COMMAND_EXEC" }],
  }), "C:/repo/.traceguard.json").config;
  const engine = new WorkspaceAnalysisEngine();
  await engine.initializeWorkspace([
    file("C:\\repo\\security.ts", "security.ts", `
export declare function tenantInput(): string;
export declare function internalExec(value: string): void;
`),
    file("C:\\repo\\alias.ts", "alias.ts", `
import { tenantInput as readTenant, internalExec as executeInternal } from "./security";
export function aliased(): void {
  const value = readTenant();
  executeInternal(value);
}`),
    file("C:\\repo\\shadow.ts", "shadow.ts", `
import { tenantInput as readTenant } from "./security";
function internalExec(value: string): void {}
export function shadowed(): void {
  const value = readTenant();
  internalExec(value);
}`),
  ], { projectConfiguration: configuration, maxDepth: 6, maxPaths: 80 });

  const findings = engine.dataflow.findings.filter(item => item.ruleId === "potential-command-injection");
  assert.equal(findings.length, 1);
  assert.equal(findings[0].functionName, "aliased");
  assert.equal(findings[0].path.sink.semanticVerification, "verified");
});

test("receiver-qualified custom models work in generic Tree-sitter frontends without matching safe receivers", async () => {
  const configuration = parseProjectConfigurationText(JSON.stringify({
    sinks: [{ language: "java", receiverType: "CommandService", function: "execute", arguments: [0], kind: "COMMAND_EXEC" }],
  }), "C:/repo/.traceguard.json").config;
  const engine = new WorkspaceAnalysisEngine();
  await engine.initializeWorkspace([{
    absolutePath: "C:\\repo\\Controller.java",
    relativePath: "Controller.java",
    language: "java",
    version: "1",
    text: `
class Controller {
  @GetMapping("/run")
  void run(@RequestParam String command, CommandService service, Logger logger) {
    service.execute(command);
    logger.execute(command);
  }
}`,
  }], { projectConfiguration: configuration, maxDepth: 6, maxPaths: 80 });

  const findings = engine.dataflow.findings.filter(item => item.ruleId === "potential-command-injection");
  assert.equal(findings.length, 1);
  assert.match(findings[0].path.sink.code, /service\.execute/);
  assert.equal(findings[0].path.sink.semanticVerification, "verified");
});

function file(absolutePath, relativePath, text) {
  return { absolutePath, relativePath, language: "typescript", text, version: String(text.length) };
}
