"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { analyzeText } = require("../src/audit-analyzer");
const { extractIdentifiers, findSourceSinkPaths, parseParameterNames } = require("../src/flow-analyzer");

test("JavaScript input follows direct calls across three files to a command sink", () => {
  const analyses = [
    analyzeText(`
export function run(req) {
  const command = req.body.command;
  return dispatch(command);
}`, "javascript", "C:\\repo\\controller.js", "controller.js"),
    analyzeText(`
export function dispatch(command) {
  executeCommand(command);
}`, "javascript", "C:\\repo\\service.js", "service.js"),
    analyzeText(`
export function executeCommand(value) {
  exec(value);
}`, "javascript", "C:\\repo\\shell.js", "shell.js"),
  ];

  const paths = findSourceSinkPaths(analyses, {
    absolutePath: "C:\\repo\\controller.js",
    line: 3,
  });
  assert.ok(paths.length >= 1);
  const flow = paths.find(item => item.category === "command");
  assert.ok(flow);
  assert.deepEqual(flow.files, ["controller.js", "service.js", "shell.js"]);
  assert.deepEqual(flow.steps.filter(step => step.kind === "call").map(step => step.label), [
    "run() → dispatch()",
    "dispatch() → executeCommand()",
  ]);
  assert.equal(flow.steps.at(-1).functionName, "executeCommand");
});

test("selected variable can start a cross-file trace without a recognized framework entry", () => {
  const analyses = [
    analyzeText(`
function forward(target) {
  fetchRemote(target);
}`, "javascript", "C:\\repo\\forward.js", "forward.js"),
    analyzeText(`
function fetchRemote(url) {
  fetch(url);
}`, "javascript", "C:\\repo\\network.js", "network.js"),
  ];
  const paths = findSourceSinkPaths(analyses, {
    absolutePath: "C:\\repo\\forward.js",
    line: 3,
    identifier: "target",
    code: "fetchRemote(target);",
  });
  assert.equal(paths[0].category, "network");
  assert.equal(paths[0].source.label, "Selected variable target");
  assert.equal(paths[0].files.length, 2);
});

test("PHP request input reaches a network sink in another file", () => {
  const analyses = [
    analyzeText(`<?php
function route() {
  $url = $_GET['url'];
  fetch_remote($url);
}`, "php", "C:\\repo\\route.php", "route.php"),
    analyzeText(`<?php
function fetch_remote($url) {
  curl_init($url);
}`, "php", "C:\\repo\\http.php", "http.php"),
  ];
  const paths = findSourceSinkPaths(analyses, {
    absolutePath: "C:\\repo\\route.php",
    line: 3,
  });
  assert.ok(paths.some(item => item.category === "network" && item.files.length === 2));
});

test("Java request parameter follows a project method call to a process sink", () => {
  const analyses = [
    analyzeText(`
class ToolController {
  @PostMapping("/run")
  public void run(@RequestParam String command) {
    execute(command);
  }
}`, "java", "C:\\repo\\ToolController.java", "ToolController.java"),
    analyzeText(`
class ToolService {
  public void execute(String command) {
    Runtime.getRuntime().exec(command);
  }
}`, "java", "C:\\repo\\ToolService.java", "ToolService.java"),
  ];
  const paths = findSourceSinkPaths(analyses, {
    absolutePath: "C:\\repo\\ToolController.java",
    line: 5,
  });
  assert.ok(paths.some(item => item.category === "command" && item.files.includes("ToolService.java")));
});

test("parameter names are normalized for supported language styles", () => {
  assert.deepEqual(parseParameterNames("@RequestParam String id, long count", "java"), ["id", "count"]);
  assert.deepEqual(parseParameterNames("$url, string $method = 'GET'", "php"), ["$url", "$method"]);
  assert.deepEqual(parseParameterNames("req: Request, value = null", "typescript"), ["req", "value"]);
  assert.deepEqual(parseParameterNames("w http.ResponseWriter, r *http.Request", "go"), ["w", "r"]);
});

test("PHP superglobal fields remain distinct symbols", () => {
  assert.deepEqual(extractIdentifiers('$_SERVER["REQUEST_METHOD"] . $_SERVER["QUERY_STRING"]'), [
    "$_SERVER[REQUEST_METHOD]",
    "$_SERVER[QUERY_STRING]",
  ]);
});

test("JavaScript import path disambiguates same-named functions", () => {
  const analyses = [
    analyzeText(`
import { execute } from "./services/shell";
export function run(req) {
  const command = req.body.command;
  execute(command);
}`, "javascript", "C:\\repo\\controller.js", "controller.js"),
    analyzeText(`
export function execute(command) {
  exec(command);
}`, "javascript", "C:\\repo\\services\\shell.js", "services/shell.js"),
    analyzeText(`
export function execute(url) {
  fetch(url);
}`, "javascript", "C:\\repo\\legacy\\shell.js", "legacy/shell.js"),
  ];

  const paths = findSourceSinkPaths(analyses, { absolutePath: "C:\\repo\\controller.js", line: 4 });
  assert.ok(paths.some(item => item.category === "command" && item.files.includes("services/shell.js")));
  assert.ok(!paths.some(item => item.files.includes("legacy/shell.js")));
  assert.equal(paths[0].confidence, "high");
  assert.match(paths[0].steps.find(step => step.kind === "call").candidateReason, /import/);
});

test("Java receiver type selects the matching service implementation", () => {
  const analyses = [
    analyzeText(`
class ToolController {
  private final AuditService auditService;
  @PostMapping("/run")
  public void run(@RequestParam String command) {
    auditService.process(command);
  }
}`, "java", "C:\\repo\\ToolController.java", "ToolController.java"),
    analyzeText(`
class AuditService {
  public void process(String command) {
    Runtime.getRuntime().exec(command);
  }
}`, "java", "C:\\repo\\services\\AuditService.java", "services/AuditService.java"),
    analyzeText(`
class OtherService {
  public void process(String url) {
    new URL(url);
  }
}`, "java", "C:\\repo\\legacy\\OtherService.java", "legacy/OtherService.java"),
  ];

  const paths = findSourceSinkPaths(analyses, { absolutePath: "C:\\repo\\ToolController.java", line: 6 });
  assert.ok(paths.some(item => item.category === "command" && item.files.includes("services/AuditService.java")));
  assert.ok(!paths.some(item => item.files.includes("legacy/OtherService.java")));
});

test("flow metadata reports validation and authorization controls", () => {
  const analyses = [analyzeText(`
export function run(req) {
  const command = req.body.command;
  validate(command);
  authorize(command);
  exec(command);
}`, "javascript", "C:\\repo\\controller.js", "controller.js")];

  const [flow] = findSourceSinkPaths(analyses, { absolutePath: "C:\\repo\\controller.js", line: 3 });
  assert.deepEqual(flow.controls, { validation: 1, authorization: 1 });
  assert.equal(flow.reviewPriority, "controls-present");
});

test("authorization annotations above an entry function stay on the flow", () => {
  const analyses = [analyzeText(`
class AdminController {
  @PreAuthorize("hasRole('ADMIN')")
  @PostMapping("/run")
  public void run(@RequestParam String command) {
    Runtime.getRuntime().exec(command);
  }
}`, "java", "C:\\repo\\AdminController.java", "AdminController.java")];

  const [flow] = findSourceSinkPaths(analyses, { absolutePath: "C:\\repo\\AdminController.java", line: 5 });
  assert.equal(flow.controls.authorization, 1);
  assert.ok(flow.steps.some(step => step.kind === "authorization" && step.line === 3));
});

test("taint returns from a project function back to its caller", () => {
  const analyses = [
    analyzeText(`
import { identity } from "./identity";
export function run(req) {
  const input = req.body.command;
  const output = identity(input);
  exec(output);
}`, "javascript", "C:\\repo\\controller.js", "controller.js"),
    analyzeText(`
export function identity(value) {
  return value;
}`, "javascript", "C:\\repo\\identity.js", "identity.js"),
  ];

  const paths = findSourceSinkPaths(analyses, { absolutePath: "C:\\repo\\controller.js", line: 4 });
  const commandFlow = paths.find(item => item.category === "command");
  assert.ok(commandFlow);
  assert.ok(commandFlow.steps.some(step => step.kind === "return" && step.functionName === "identity"));
  assert.deepEqual(commandFlow.files, ["controller.js", "identity.js"]);
});

test("inline route callbacks are indexed as functions and bound to their entry", () => {
  const analysis = analyzeText(`
app.get("/health", (req, res) => {
  res.send("ok");
});`, "javascript", "C:\\repo\\app.js", "app.js");
  assert.equal(analysis.functions.length, 1);
  assert.equal(analysis.functions[0].name, "callback");
  const entry = analysis.entries.find(item => item.route === "/health");
  assert.equal(entry.functionLine, analysis.functions[0].line);
  assert.deepEqual(analysis.ir.functions[0].parameters.map(parameter => parameter.name), ["req", "res"]);
});

test("path limits keep later high-impact sinks and disclose truncation", () => {
  const outputFunctions = Array.from(
    { length: 80 },
    (_, index) => `function output${index}(req, res) { const value = req.query.value; res.send(value); }`,
  ).join("\n");
  const commandFunction = `function commandLast(req) { const value = req.body.command; exec(value); }`;
  const analysis = analyzeText(`${outputFunctions}\n${commandFunction}`, "javascript", "C:\\repo\\many.js", "many.js");
  const paths = findSourceSinkPaths([analysis], { maxPaths: 80 });

  assert.equal(paths.length, 80);
  assert.equal(paths.truncated, true);
  assert.ok(paths.totalCandidates >= 81);
  assert.ok(paths.some(item => item.category === "command"));
});
