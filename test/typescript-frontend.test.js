"use strict";

const assert = require("node:assert/strict");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");
const { analyzeTextAsync } = require("../src/audit-analyzer");
const { OperationKind } = require("../src/ir/schema");
const { runDataflowAnalysis } = require("../src/dataflow/pipeline");
const { TreeSitterRuntime } = require("../src/frontends/tree-sitter-runtime");
const { WorkspaceAnalysisEngine } = require("../src/analysis/workspace-engine");

test("JS/TS production analysis uses Tree-sitter and Compiler API ASTs", async () => {
  const analysis = await analyzeTextAsync(`
import { request as send } from "./client";
const brace = /\\{/;

export async function proxy(
  req: Request,
  suffix?: string,
): Promise<Response> {
  const url = req.query?.url;
  const target = \`${"${url}"}/\${suffix ?? ""}\`;
  if (target?.length) return fetch(target);
  return send("/fallback");
}

class Handler {
  run(value: string) {
    return [value].map(item => item?.trim());
  }
}
`, "typescript", "C:\\repo\\proxy.ts", "proxy.ts", { differential: true });

  assert.equal(analysis.frontend.mode, "ast");
  assert.equal(analysis.frontend.capability, "tier-b");
  assert.equal(analysis.frontend.treeHasErrors, false);
  assert.equal(analysis.frontend.compilerDiagnostics, 0);
  assert.ok(analysis.frontend.differential);
  assert.deepEqual(analysis.ir.functions.filter(fn => !fn.isGlobal).map(fn => fn.name), ["proxy", "run", "map$callback0"]);
  const proxy = analysis.ir.functions.find(fn => fn.name === "proxy");
  assert.ok(proxy.symbolKey.endsWith("proxy(Request,string)"));
  assert.ok(proxy.operations.some(item => item.kind === OperationKind.ASSIGNMENT));
  assert.ok(proxy.operations.some(item => item.kind === OperationKind.BRANCH));
  assert.ok(proxy.operations.some(item => item.kind === OperationKind.SINK));
  assert.ok(proxy.references.some(reference => reference.local === "send" && reference.target === "./client"));
});

test("workspace analysis reuses a project-level TypeScript Program with import resolution", async () => {
  const engine = new WorkspaceAnalysisEngine();
  const modelPath = path.resolve(".traceguard-test-project", "model.ts");
  const proxyPath = path.resolve(".traceguard-test-project", "proxy.ts");
  const initialized = await engine.initializeWorkspace([
    {
      absolutePath: modelPath,
      relativePath: "model.ts",
      language: "typescript",
      version: "1",
      text: "export interface RequestData { url: string } export const fallback: RequestData = { url: '/safe' };",
    },
    {
      absolutePath: proxyPath,
      relativePath: "proxy.ts",
      language: "typescript",
      version: "1",
      text: "import { RequestData } from './model'; export function proxy(input: RequestData) { return fetch(input.url); }",
    },
  ]);

  const proxy = initialized.analyses.find(analysis => analysis.relativePath === "proxy.ts");
  assert.equal(proxy.frontend.compilerProjectMode, true);
  assert.equal(proxy.frontend.compilerProjectFiles, 2);
  assert.equal(proxy.frontend.compilerStandardLibrary, true);
  assert.equal(proxy.frontend.compilerDiagnostics, 0);
  assert.ok(proxy.ir.functions.find(fn => fn.name === "proxy").references.some(reference => reference.target === "./model"));

  const compiler = engine.typescriptProject.modelFor(proxyPath);
  let typeReference;
  const visit = node => {
    if (ts.isTypeReferenceNode(node) && node.typeName.getText(compiler.sourceFile) === "RequestData") typeReference = node.typeName;
    ts.forEachChild(node, visit);
  };
  visit(compiler.sourceFile);
  const alias = compiler.checker.getSymbolAtLocation(typeReference);
  const resolved = alias && (alias.flags & ts.SymbolFlags.Alias) ? compiler.checker.getAliasedSymbol(alias) : alias;
  assert.ok(resolved?.declarations?.some(declaration => path.normalize(declaration.getSourceFile().fileName) === path.normalize(modelPath)));
});

test("Tree-sitter reuses the previous syntax tree for single-file updates", async () => {
  const absolutePath = "C:\\repo\\incremental.ts";
  const before = await analyzeTextAsync("export function run(value: string) { return value; }", "typescript", absolutePath, "incremental.ts");
  const after = await analyzeTextAsync("// moved\nexport function run(value: string) { return value?.trim(); }", "typescript", absolutePath, "incremental.ts");

  assert.equal(before.frontend.incremental, false);
  assert.equal(after.frontend.incremental, true);
  assert.equal(before.ir.functions[0].symbolKey, after.ir.functions[0].symbolKey);
});

test("Tree-sitter runtime bounds retained incremental syntax trees", async () => {
  const bounded = new TreeSitterRuntime({ maxTrees: 2 });
  for (let index = 0; index < 3; index += 1) {
    await bounded.parse({ language: "javascript", absolutePath: `/workspace/${index}.js`, text: `function f${index}() { return ${index}; }` });
  }
  assert.equal(bounded.trees.size, 2);
  assert.ok(!bounded.trees.has("/workspace/0.js"));
});

test("TSX files use the packaged TSX grammar without recovery errors", async () => {
  const analysis = await analyzeTextAsync(
    "export const View = ({ value }: { value: string }) => <section>{value?.trim()}</section>;",
    "typescript",
    "C:\\workspace\\View.tsx",
    "View.tsx",
  );
  assert.equal(analysis.frontend.mode, "ast");
  assert.equal(analysis.frontend.treeHasErrors, false);
  assert.ok(analysis.functions.some(fn => fn.name === "View"));
});

test("AST CFG applies guards only on dominated source-to-sink paths", async () => {
  const guarded = await analyzeTextAsync(`
function run(req) {
  const cmd = req.body.command;
  if (validate(cmd)) {
    exec(cmd);
  }
}`, "javascript", "C:\\repo\\guarded.js", "guarded.js");
  const unrelated = await analyzeTextAsync(`
function run(req) {
  const cmd = req.body.command;
  if (validate(cmd)) {
    console.log(cmd);
  }
  exec(cmd);
}`, "javascript", "C:\\repo\\unrelated.js", "unrelated.js");
  const earlyReject = await analyzeTextAsync(`
function run(req) {
  const cmd = req.body.command;
  if (!validate(cmd)) {
    return;
  }
  exec(cmd);
}`, "javascript", "C:\\repo\\early.js", "early.js");

  const guardedPath = runDataflowAnalysis([guarded]).paths.find(path => path.category === "command");
  const unrelatedPath = runDataflowAnalysis([unrelated]).paths.find(path => path.category === "command");
  const earlyPath = runDataflowAnalysis([earlyReject]).paths.find(path => path.category === "command");
  assert.ok(guardedPath.guardCapabilities.includes("INPUT_VALIDATION"));
  assert.ok(!unrelatedPath.guardCapabilities.includes("INPUT_VALIDATION"));
  assert.ok(earlyPath.guardCapabilities.includes("INPUT_VALIDATION"));
  assert.equal(guarded.ir.functions[0].cfg.entry, "entry");
  assert.ok(guarded.ir.functions[0].cfg.edges.some(edge => edge.kind === "true"));
  assert.ok(guarded.ir.functions[0].cfg.edges.some(edge => edge.kind === "false"));
});

test("AST def-use follows destructuring, object properties and templates without mixing sibling fields", async () => {
  const propagated = await analyzeTextAsync(`
function proxy(req) {
  const { url } = req.query;
  const options = { endpoint: \`${"${url}"}/status\` };
  return fetch(options.endpoint);
}`, "javascript", "C:\\repo\\properties.js", "properties.js");
  const isolated = await analyzeTextAsync(`
function proxy(req) {
  const request = {};
  request.safe = req.query.safe;
  return fetch(request.url);
}`, "javascript", "C:\\repo\\isolated.js", "isolated.js");

  assert.ok(runDataflowAnalysis([propagated]).paths.some(path => path.category === "network"));
  assert.ok(!runDataflowAnalysis([isolated]).paths.some(path => path.category === "network"));
  const assignments = propagated.ir.functions[0].operations.filter(item => item.kind === OperationKind.ASSIGNMENT);
  assert.ok(assignments.some(item => item.output?.name === "url"));
  assert.ok(assignments.some(item => item.output?.name === "options.endpoint"));
});

test("destructured parameters retain field-level access paths", async () => {
  const vulnerable = await analyzeTextAsync(`
app.post("/run", ({ body: { cmd }, query: { safe } }, res) => {
  exec(cmd);
});`, "javascript", "C:\\repo\\destructured.js", "destructured.js");
  const isolated = await analyzeTextAsync(`
app.post("/run", ({ body: { safe }, query: { cmd } }, res) => {
  exec(safe);
});`, "javascript", "C:\\repo\\destructured-safe.js", "destructured-safe.js");
  const handler = vulnerable.ir.functions.find(fn => fn.parameters.some(parameter => parameter.bindings?.length));

  assert.deepEqual(handler.parameters[0].bindings, [
    { name: "cmd", path: ["body", "cmd"] },
    { name: "safe", path: ["query", "safe"] },
  ]);
  assert.equal(handler.parameters[0].parameterIndex, 0);
  assert.ok(runDataflowAnalysis([vulnerable]).findings.some(item => item.ruleId === "potential-command-injection"));
  assert.ok(runDataflowAnalysis([isolated]).findings.some(item => item.ruleId === "potential-command-injection"));
});

test("destructuring assignments map only the selected property and array element", async () => {
  const analysis = await analyzeTextAsync(`
function run(req) {
  const { safe, nested: { cmd } } = req.body;
  const [first] = req.query.items;
  exec(cmd);
}`, "javascript", "C:\\repo\\access-paths.js", "access-paths.js");
  const assignments = analysis.ir.functions[0].operations.filter(item => item.kind === OperationKind.ASSIGNMENT);

  assert.ok(assignments.some(item => item.output?.name === "safe" && item.inputs.some(value => value.name === "req.body.safe")));
  assert.ok(assignments.some(item => item.output?.name === "cmd" && item.inputs.some(value => value.name === "req.body.nested.cmd")));
  assert.ok(assignments.some(item => item.output?.name === "first" && item.inputs.some(value => value.name === "req.query.items[0]")));
});

test("cross-function destructuring maps only tainted object fields", async () => {
  const safe = await analyzeTextAsync(`
import { exec } from "node:child_process";
function execute({ cmd, safe }) { exec(safe); }
export function route(req) {
  const cmd = req.body.cmd;
  const payload = { cmd, safe: "fixed-command" };
  execute(payload);
}`, "javascript", "C:\\repo\\field-safe.js", "field-safe.js");
  const vulnerable = await analyzeTextAsync(`
import { exec } from "node:child_process";
function execute({ cmd, safe }) { exec(cmd); }
export function route(req) {
  const cmd = req.body.cmd;
  const payload = { cmd, safe: "fixed-command" };
  execute(payload);
}`, "javascript", "C:\\repo\\field-vulnerable.js", "field-vulnerable.js");

  assert.equal(runDataflowAnalysis([safe]).findings.some(item => item.ruleId === "potential-command-injection"), false);
  assert.ok(runDataflowAnalysis([vulnerable]).findings.some(item => item.ruleId === "potential-command-injection"));
});

test("cross-function access paths preserve nested object fields and array indexes", async () => {
  const safeObject = await analyzeTextAsync(`
import { exec } from "node:child_process";
function execute(options) { exec(options.target.safe); }
export function route(req) {
  const command = req.body.command;
  const payload = { target: { command, safe: "fixed" } };
  execute(payload);
}
`, "typescript", "C:\\repo\\object-safe.ts", "object-safe.ts");
  const vulnerableObject = await analyzeTextAsync(`
import { exec } from "node:child_process";
function execute(options) { exec(options.target.command); }
export function route(req) {
  const command = req.body.command;
  const payload = { target: { command, safe: "fixed" } };
  execute(payload);
}
`, "typescript", "C:\\repo\\object-vulnerable.ts", "object-vulnerable.ts");
  const safeArray = await analyzeTextAsync(`
import { exec } from "node:child_process";
function execute(options) { exec(options[1]); }
export function route(req) {
  const command = req.body.command;
  const payload = [command, "fixed"];
  execute(payload);
}
`, "typescript", "C:\\repo\\array-safe.ts", "array-safe.ts");
  const vulnerableArray = await analyzeTextAsync(`
import { exec } from "node:child_process";
function execute(options) { exec(options[0]); }
export function route(req) {
  const command = req.body.command;
  const payload = [command, "fixed"];
  execute(payload);
}
`, "typescript", "C:\\repo\\array-vulnerable.ts", "array-vulnerable.ts");

  assert.equal(runDataflowAnalysis([safeObject]).findings.some(item => item.ruleId === "potential-command-injection"), false);
  assert.ok(runDataflowAnalysis([vulnerableObject]).findings.some(item => item.ruleId === "potential-command-injection"));
  assert.equal(runDataflowAnalysis([safeArray]).findings.some(item => item.ruleId === "potential-command-injection"), false);
  assert.ok(runDataflowAnalysis([vulnerableArray]).findings.some(item => item.ruleId === "potential-command-injection"));
});

test("container aliases rebase tainted descendants and strong scalar updates kill stale taint", async () => {
  const vulnerable = await analyzeTextAsync(`
import { exec } from "node:child_process";
function execute(options) { exec(options.command); }
export function route(req) {
  const command = req.body.command;
  const payload = { command, safe: "fixed" };
  const alias = payload;
  execute(alias);
}
`, "typescript", "C:\\repo\\alias-container.ts", "alias-container.ts");
  const safeSibling = await analyzeTextAsync(`
import { exec } from "node:child_process";
function execute(options) { exec(options.safe); }
export function route(req) {
  const command = req.body.command;
  const payload = { command, safe: "fixed" };
  const alias = payload;
  execute(alias);
}
`, "typescript", "C:\\repo\\alias-container-safe.ts", "alias-container-safe.ts");
  const overwritten = await analyzeTextAsync(`
import { exec } from "node:child_process";
export function route(req) {
  let command = req.body.command;
  command = "fixed";
  exec(command);
}
`, "typescript", "C:\\repo\\strong-update.ts", "strong-update.ts");

  assert.ok(runDataflowAnalysis([vulnerable]).findings.some(item => item.ruleId === "potential-command-injection"));
  assert.equal(runDataflowAnalysis([safeSibling]).findings.some(item => item.ruleId === "potential-command-injection"), false);
  assert.equal(runDataflowAnalysis([overwritten]).findings.some(item => item.ruleId === "potential-command-injection"), false);
});

test("typed Map and array mutations preserve element Access Paths with explicit propagation proof", async () => {
  const vulnerableMap = await analyzeTextAsync(`
import { exec } from "node:child_process";
export function route(req) {
  const command = req.body.command;
  const values = new Map();
  values.set("command", command);
  const selected = values.get("command");
  exec(selected);
}
`, "typescript", "C:\\repo\\map-vulnerable.ts", "map-vulnerable.ts");
  const safeMap = await analyzeTextAsync(`
import { exec } from "node:child_process";
export function route(req) {
  const command = req.body.command;
  const values = new Map();
  values.set("command", command);
  const selected = values.get("safe");
  exec(selected);
}
`, "typescript", "C:\\repo\\map-safe.ts", "map-safe.ts");
  const vulnerableArray = await analyzeTextAsync(`
import { exec } from "node:child_process";
export function route(req) {
  const command = req.body.command;
  const values = [];
  values.push(command);
  exec(values[0]);
}
`, "typescript", "C:\\repo\\array-push.ts", "array-push.ts");

  const mapFinding = runDataflowAnalysis([vulnerableMap]).findings.find(item => item.ruleId === "potential-command-injection");
  assert.ok(mapFinding);
  assert.equal(runDataflowAnalysis([safeMap]).findings.some(item => item.ruleId === "potential-command-injection"), false);
  assert.ok(runDataflowAnalysis([vulnerableArray]).findings.some(item => item.ruleId === "potential-command-injection"));
  const assignments = vulnerableMap.ir.functions.find(fn => fn.name === "route").operations
    .filter(item => item.kind === OperationKind.ASSIGNMENT);
  assert.ok(assignments.some(item => item.output?.name === "values.command" && item.metadata.propagationStatus === "verified"));
  assert.ok(assignments.some(item => item.output?.name === "selected" && item.inputs.some(value => value.name === "values.command")));
  assert.ok(mapFinding.explanation.propagation.some(step =>
    step.status === "verified" && step.outputAccessPath === "values.command" && /Map Access Path/.test(step.reason)));
});

test("captured outer values flow through an explicit closure call edge", async () => {
  const vulnerable = await analyzeTextAsync(`
import { exec } from "node:child_process";
export function route(req) {
  const command = req.body.command;
  setTimeout(() => exec(command), 1);
}
`, "typescript", "C:\\repo\\closure-vulnerable.ts", "closure-vulnerable.ts");
  const safe = await analyzeTextAsync(`
import { exec } from "node:child_process";
export function route(req) {
  const command = req.body.command;
  const fixed = "safe";
  setTimeout(() => exec(fixed), 1);
}
`, "typescript", "C:\\repo\\closure-safe.ts", "closure-safe.ts");
  const finding = runDataflowAnalysis([vulnerable]).findings.find(item => item.ruleId === "potential-command-injection");
  const closure = vulnerable.ir.functions.find(fn => fn.parameters.some(parameter => parameter.captured));
  const parent = vulnerable.ir.functions.find(fn => fn.name === "route");
  const closureCall = parent.operations.find(operation => operation.call?.closure);

  assert.ok(finding);
  assert.equal(runDataflowAnalysis([safe]).findings.some(item => item.ruleId === "potential-command-injection"), false);
  assert.ok(closure);
  assert.ok(closure.parameters.some(parameter => parameter.name === "command" && parameter.role === "capture"));
  assert.equal(closureCall.call.targetFunctionId, closure.id);
  assert.ok(finding.path.steps.some(step => step.kind === "call" && step.candidateReason === "explicit closure target"));
});

test("receiver types disambiguate same-named class methods in one TypeScript file", async () => {
  const analysis = await analyzeTextAsync(`
import { exec } from "node:child_process";
class ShellService {
  execute(value: string) { exec(value); }
}
class SafeService {
  execute(value: string) { console.log(value); }
}
export function route(req, service: ShellService) {
  service.execute(req.body.command);
}
`, "typescript", "C:\\repo\\typed-receiver.ts", "typed-receiver.ts");
  const result = runDataflowAnalysis([analysis]);
  const finding = result.findings.find(item => item.ruleId === "potential-command-injection");

  assert.ok(finding);
  const projectCall = finding.path.steps.find(step => step.kind === "call" && /execute/.test(step.label));
  assert.match(projectCall.candidateReason, /receiver type ShellService/);
  assert.equal(projectCall.candidateCount, 1);
});

test("interface dispatch keeps a bounded implementation set and marks ambiguity", async () => {
  const analysis = await analyzeTextAsync(`
import { exec } from "node:child_process";
interface Runner { execute(value: string): void; }
class ShellRunner implements Runner {
  execute(value: string) { exec(value); }
}
class SafeRunner implements Runner {
  execute(value: string) { console.log(value); }
}
export function route(req, runner: Runner) {
  runner.execute(req.body.command);
}
`, "typescript", "C:\\repo\\interface-dispatch.ts", "interface-dispatch.ts");
  const finding = runDataflowAnalysis([analysis]).findings.find(item => item.ruleId === "potential-command-injection");
  const projectCall = finding?.path.steps.find(step => step.kind === "call" && /execute/.test(step.label));

  assert.ok(finding);
  assert.equal(projectCall.candidateCount, 2);
  assert.equal(projectCall.candidateMatch, "review");
  assert.match(projectCall.candidateReason, /receiver contract Runner/);
  assert.equal(finding.confidence, "low");
});

test("path normalization is explained but never treated as path confinement", async () => {
  const analysis = await analyzeTextAsync(`
function read(req) {
  const name = req.query.name;
  const normalized = path.normalize(name);
  return fs.readFile(normalized);
}`, "javascript", "C:\\repo\\files.js", "files.js");
  const finding = runDataflowAnalysis([analysis]).findings.find(item => item.ruleId === "potential-path-traversal");

  assert.ok(finding);
  assert.ok(finding.observedGuards.includes("PATH_CANONICALIZATION"));
  assert.ok(finding.missingGuards.includes("PATH_CONFINEMENT"));
  assert.ok(finding.explanation.propagation.length > 0);
  assert.equal(finding.explanation.sink.kind, "FILE_ACCESS");
});

test("AST finding identity survives unrelated line movement", async () => {
  const before = await analyzeTextAsync(`
function proxy(req) {
  const url = req.query.url;
  return fetch(url);
}`, "javascript", "C:\\repo\\stable.js", "stable.js");
  const after = await analyzeTextAsync(`
function proxy(req) {
  const auditLabel = "proxy";
  const url = req.query.url;
  return fetch(url);
}`, "javascript", "C:\\repo\\stable.js", "stable.js");
  const first = runDataflowAnalysis([before]).findings.find(item => item.ruleId === "potential-ssrf");
  const second = runDataflowAnalysis([after]).findings.find(item => item.ruleId === "potential-ssrf");

  assert.equal(first.id, second.id);
  assert.notEqual(first.line, second.line);
});
