"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { analyzeTextAsync } = require("../src/audit-analyzer");
const { runDataflowAnalysis } = require("../src/dataflow/pipeline");

const CASES = [
  {
    name: "javascript command injection",
    ruleId: "potential-command-injection",
    language: "javascript",
    vulnerable: "function run(req) { const cmd = req.body.cmd; exec(cmd); }",
    safe: "function run(req) { const cmd = req.body.cmd; exec(\"fixed-command\"); }",
  },
  {
    name: "javascript SQL injection",
    ruleId: "potential-sql-injection",
    language: "javascript",
    vulnerable: "function load(req) { const id = req.query.id; db.query(\"SELECT * FROM users WHERE id = \" + id); }",
    safe: "function load(req) { const id = req.query.id; db.query(\"SELECT * FROM users WHERE id = ?\", [id]); }",
  },
  {
    name: "javascript path traversal",
    ruleId: "potential-path-traversal",
    language: "javascript",
    vulnerable: "function read(req) { const name = req.query.name; fs.readFile(name); }",
    safe: `function read(req) {
  const ROOT = "/srv/files";
  const name = req.query.name;
  const resolved = path.resolve(ROOT, name);
  if (!resolved.startsWith(ROOT)) return;
  fs.readFile(resolved);
}`,
  },
  {
    name: "javascript SSRF",
    ruleId: "potential-ssrf",
    language: "javascript",
    vulnerable: "function proxy(req) { const url = req.query.url; fetch(url); }",
    safe: "function proxy(req) { const url = req.query.url; fetch(\"https://api.example.test/status\"); }",
  },
  {
    name: "python unsafe deserialization",
    ruleId: "potential-unsafe-deserialization",
    language: "python",
    vulnerable: "def load(request):\n    data = request.data\n    return pickle.loads(data)\n",
    safe: "def load(request):\n    data = request.data\n    return json.loads(data)\n",
  },
  {
    name: "typescript SSRF",
    ruleId: "potential-ssrf",
    language: "typescript",
    vulnerable: "function proxy(req: any) { const url: string = req.query.url; return fetch(url); }",
    safe: "function proxy(req: any) { const url: string = req.query.url; return fetch(\"https://api.example.test/status\"); }",
  },
  {
    name: "Java SQL injection",
    ruleId: "potential-sql-injection",
    language: "java",
    vulnerable: "class Query { void run(HttpServletRequest req, Statement stmt) { String id = req.getParameter(\"id\"); stmt.executeQuery(\"SELECT * FROM users WHERE id=\" + id); } }",
    safe: "class Query { void run(HttpServletRequest req, PreparedStatement ps) { String id = req.getParameter(\"id\"); ps.setString(1, id); ps.executeQuery(); } }",
  },
  {
    name: "PHP command injection",
    ruleId: "potential-command-injection",
    language: "php",
    vulnerable: "<?php function run() { $cmd = $_GET['cmd']; system($cmd); }",
    safe: "<?php function run() { $cmd = $_GET['cmd']; system('fixed-command'); }",
  },
  {
    name: "C# Minimal API command injection",
    ruleId: "potential-command-injection",
    language: "csharp",
    vulnerable: "app.MapGet(\"/run\", (HttpRequest req) => Process.Start(req.Query[\"cmd\"].ToString()));",
    safe: "app.MapGet(\"/run\", (HttpRequest req) => Process.Start(\"fixed-command\"));",
  },
  {
    name: "Go inline handler command injection",
    ruleId: "potential-command-injection",
    language: "go",
    vulnerable: "package main\nfunc configure() { http.HandleFunc(\"/run\", func(w http.ResponseWriter, r *http.Request) { exec.Command(r.URL.Query().Get(\"cmd\")) }) }",
    safe: "package main\nfunc configure() { http.HandleFunc(\"/run\", func(w http.ResponseWriter, r *http.Request) { exec.Command(\"fixed-command\") }) }",
  },
  {
    name: "typescript command import alias and shadowing",
    ruleId: "potential-command-injection",
    language: "typescript",
    vulnerable: `import { exec as run } from "node:child_process";
export function handler(req: any) { const cmd = req.body.cmd; run(cmd); }`,
    safe: `import { exec as systemExec } from "node:child_process";
export function handler(req: any) { const cmd = req.body.cmd; const exec = (value: string) => logger.write(value); exec(cmd); }`,
    dimensions: ["alias", "shadowing"],
  },
  {
    name: "javascript command destructuring and unrelated guard",
    ruleId: "potential-command-injection",
    language: "javascript",
    vulnerable: `import { exec } from "node:child_process";
export function handler(req) { const { cmd } = req.body; escapeHtml(cmd); exec(cmd); }`,
    safe: `import { exec } from "node:child_process";
export function handler(req) { const { cmd } = req.body; escapeHtml(cmd); exec("fixed-command"); }`,
    dimensions: ["destructuring", "unrelated-guard"],
  },
  {
    name: "Java SQL unrelated receiver guard and same-name safe receiver",
    ruleId: "potential-sql-injection",
    language: "java",
    vulnerable: `class Search { void run(HttpServletRequest request, PreparedStatement safe, Statement unsafe) {
      String user = request.getParameter("user"); safe.setString(1, user); unsafe.executeQuery("SELECT " + user); } }`,
    safe: `class SafeStore { void executeQuery(String value) {} }
class Search { void run(HttpServletRequest request, SafeStore store) { String value = request.getParameter("value"); store.executeQuery(value); } }`,
    dimensions: ["unrelated-guard", "same-name"],
  },
  {
    name: "javascript path untrusted and trusted confinement roots",
    ruleId: "potential-path-traversal",
    language: "javascript",
    vulnerable: `export function read(req) { const root = req.query.root; const candidate = path.resolve(root, req.query.name);
      if (candidate.startsWith(root)) return fs.readFile(candidate); }`,
    safe: `export function read(req) { const root = "/srv/files"; const candidate = path.resolve(root, req.query.name);
      if (candidate.startsWith(root)) return fs.readFile(candidate); }`,
    dimensions: ["unrelated-guard", "safe-guard"],
  },
  {
    name: "typescript SSRF variable alias and local shadowing",
    ruleId: "potential-ssrf",
    language: "typescript",
    vulnerable: `const request = fetch; export function proxy(req: any) { const url = req.query.url; return request(url); }`,
    safe: `function fetch(value: string) { return value; } export function proxy(req: any) { const url = req.query.url; return fetch(url); }`,
    dimensions: ["alias", "shadowing"],
  },
  {
    name: "python deserialization wrapper and safe parser",
    ruleId: "potential-unsafe-deserialization",
    language: "python",
    vulnerable: "def decode(value):\n    return pickle.loads(value)\ndef load(request):\n    data = request.data\n    return decode(data)\n",
    safe: "def decode(value):\n    return json.loads(value)\ndef load(request):\n    data = request.data\n    return decode(data)\n",
    dimensions: ["wrapper", "same-name-safe-parser"],
  },
];

const EXTENSIONS = { javascript: "js", typescript: "ts", python: "py", java: "java", php: "php", csharp: "cs", go: "go" };
const EXTRA_DIMENSIONS = ["cross-file"];

for (const fixture of CASES) {
  test(`${fixture.name} has vulnerable/safe paired coverage`, async () => {
    const extension = EXTENSIONS[fixture.language];
    const slug = fixture.name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
    const vulnerable = await analyzeTextAsync(fixture.vulnerable, fixture.language, `C:\\fixtures\\vulnerable-${slug}.${extension}`, `vulnerable-${slug}.${extension}`);
    const safe = await analyzeTextAsync(fixture.safe, fixture.language, `C:\\fixtures\\safe-${slug}.${extension}`, `safe-${slug}.${extension}`);
    const vulnerableFinding = runDataflowAnalysis([vulnerable]).findings.find(finding => finding.ruleId === fixture.ruleId);
    const safeFinding = runDataflowAnalysis([safe]).findings.find(finding => finding.ruleId === fixture.ruleId);
    assert.ok(vulnerableFinding, `expected vulnerable fixture to trigger ${fixture.ruleId}`);
    assert.equal(safeFinding, undefined, `expected safe fixture not to trigger ${fixture.ruleId}`);
  });
}

test("core-rule corpus includes a cross-file wrapper path", async () => {
  const controller = await analyzeTextAsync(`
import { run } from "./shell";
export function handler(req) { const command = req.body.command; run(command); }
`, "javascript", "C:\\corpus\\controller.js", "controller.js");
  const shell = await analyzeTextAsync(`
import { exec } from "node:child_process";
export function run(command) { exec(command); }
`, "javascript", "C:\\corpus\\shell.js", "shell.js");

  const finding = runDataflowAnalysis([controller, shell]).findings.find(item => item.ruleId === "potential-command-injection");
  assert.ok(finding);
  assert.ok(finding.path.files.includes("controller.js"));
  assert.ok(finding.path.files.includes("shell.js"));
});

test("core-rule regression corpus records precision and recall", async () => {
  const metrics = new Map();
  for (const fixture of CASES) {
    const extension = EXTENSIONS[fixture.language];
    const key = `${fixture.ruleId}:${fixture.language}`;
    const metric = metrics.get(key) || {
      ruleId: fixture.ruleId, language: fixture.language, truePositive: 0, trueNegative: 0, falsePositive: 0, falseNegative: 0,
    };
    const slug = fixture.name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
    const vulnerableName = `v-${slug}.${extension}`;
    const safeName = `s-${slug}.${extension}`;
    const vulnerable = await analyzeTextAsync(fixture.vulnerable, fixture.language, `C:\\corpus\\${vulnerableName}`, vulnerableName);
    const safe = await analyzeTextAsync(fixture.safe, fixture.language, `C:\\corpus\\${safeName}`, safeName);
    if (runDataflowAnalysis([vulnerable]).findings.some(finding => finding.ruleId === fixture.ruleId)) metric.truePositive += 1;
    else metric.falseNegative += 1;
    if (runDataflowAnalysis([safe]).findings.some(finding => finding.ruleId === fixture.ruleId)) metric.falsePositive += 1;
    else metric.trueNegative += 1;
    metrics.set(key, metric);
  }

  const report = [...metrics.values()].map(metric => ({
    ruleId: metric.ruleId,
    language: metric.language,
    samples: metric.truePositive + metric.trueNegative + metric.falsePositive + metric.falseNegative,
    precision: metric.truePositive / Math.max(1, metric.truePositive + metric.falsePositive),
    recall: metric.truePositive / Math.max(1, metric.truePositive + metric.falseNegative),
  }));
  assert.equal(new Set(CASES.map(fixture => fixture.language)).size, 7);
  assert.equal(report.reduce((sum, metric) => sum + metric.samples, 0), CASES.length * 2);
  for (const metric of report) {
    assert.equal(metric.precision, 1, `${metric.ruleId}/${metric.language} precision regressed`);
    assert.equal(metric.recall, 1, `${metric.ruleId}/${metric.language} recall regressed`);
  }
  const dimensions = new Set([...CASES.flatMap(fixture => fixture.dimensions || ["vulnerable", "safe"]), ...EXTRA_DIMENSIONS]);
  for (const dimension of ["alias", "shadowing", "wrapper", "destructuring", "cross-file", "unrelated-guard", "same-name"]) {
    assert.ok(dimensions.has(dimension), `corpus is missing ${dimension} coverage`);
  }
});
