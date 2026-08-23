"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { analyzeText, analyzeTextAsync } = require("../src/audit-analyzer");
const { findSourceSinkPaths } = require("../src/flow-analyzer");
const { evaluateFlowPaths } = require("../src/rules/rule-engine");
const { GuardCapability } = require("../src/security/semantics");

test("declarative rules turn flow facts into a separate finding", () => {
  const analyses = [analyzeText(`
export function proxy(req) {
  const url = req.query.url;
  fetch(url);
}`, "javascript", "C:\\repo\\proxy.js", "proxy.js")];

  const paths = findSourceSinkPaths(analyses, { absolutePath: "C:\\repo\\proxy.js", line: 3 });
  const findings = evaluateFlowPaths(paths);
  const ssrf = findings.find(item => item.ruleId === "potential-ssrf");
  assert.ok(ssrf);
  assert.equal(ssrf.severity, "high");
  assert.equal(ssrf.confidence, "low");
  assert.ok(ssrf.missingGuards.includes(GuardCapability.BLOCK_PRIVATE_IP));
  assert.equal(ssrf.kind, "finding");
});

test("guards are capabilities and do not erase the underlying flow", async () => {
  const analyses = [await analyzeTextAsync(`
import escapeHtml from "escape-html";
export function render(req, res) {
  const value = req.query.value;
  const encoded = escapeHtml(value);
  res.send(encoded);
}`, "javascript", "C:\\repo\\render.js", "render.js")];

  const paths = findSourceSinkPaths(analyses, { absolutePath: "C:\\repo\\render.js", line: 3 });
  const finding = evaluateFlowPaths(paths).find(item => item.ruleId === "potential-unsafe-output");
  assert.ok(finding);
  assert.ok(finding.observedGuards.includes(GuardCapability.OUTPUT_ENCODING));
  assert.ok(!finding.missingGuards.includes(GuardCapability.OUTPUT_ENCODING));
});

test("a same-named local sanitizer cannot suppress a finding", async () => {
  const analysis = await analyzeTextAsync(`
function escapeHtml(value) { return value; }
export function render(req, res) {
  const value = req.query.value;
  const encoded = escapeHtml(value);
  res.send(encoded);
}`, "javascript", "C:\\repo\\fake-encoding.js", "fake-encoding.js");
  const finding = evaluateFlowPaths(findSourceSinkPaths([analysis], {})).find(item => item.ruleId === "potential-unsafe-output");

  assert.ok(finding);
  assert.ok(!finding.observedGuards.includes(GuardCapability.OUTPUT_ENCODING));
});

test("transform guards protect only the value returned by the guard", async () => {
  const analysis = await analyzeTextAsync(`
import escapeHtml from "escape-html";
export function render(req, res) {
  const value = req.query.value;
  escapeHtml(value);
  res.send(value);
}`, "javascript", "C:\\repo\\ignored-encoding.js", "ignored-encoding.js");
  const finding = evaluateFlowPaths(findSourceSinkPaths([analysis], {})).find(item => item.ruleId === "potential-unsafe-output");

  assert.ok(finding);
  assert.ok(!finding.observedGuards.includes(GuardCapability.OUTPUT_ENCODING));
  assert.ok(finding.missingGuards.includes(GuardCapability.OUTPUT_ENCODING));
  assert.ok(finding.guardHints.some(hint => hint.capabilities.includes(GuardCapability.OUTPUT_ENCODING)));
  assert.ok(finding.guardHints.some(hint => /return value|produced by the guard/.test(hint.reason)));
});

test("receiver-scoped SQL guards cannot suppress a different statement", async () => {
  const analysis = await analyzeTextAsync(`
class Search {
  void run(HttpServletRequest request, PreparedStatement safe, Statement unsafe) {
    String user = request.getParameter("user");
    safe.setString(1, user);
    unsafe.executeQuery("SELECT * FROM users WHERE name='" + user + "'");
  }
}`, "java", "C:\\repo\\Search.java", "Search.java");
  const finding = evaluateFlowPaths(findSourceSinkPaths([analysis], {})).find(item => item.ruleId === "potential-sql-injection");

  assert.ok(finding);
  assert.ok(!finding.observedGuards.includes(GuardCapability.SQL_PARAMETERIZATION));
  assert.ok(finding.guardHints.some(hint => /receivers/.test(hint.reason)));
});

test("parameter binding cannot sanitize SQL that still contains the raw value", async () => {
  const analysis = await analyzeTextAsync(`
class Search {
  void run(HttpServletRequest request, PreparedStatement statement) {
    String user = request.getParameter("user");
    statement.setString(1, user);
    statement.executeQuery("SELECT * FROM users WHERE name='" + user + "'");
  }
}`, "java", "C:\\repo\\RawPreparedQuery.java", "RawPreparedQuery.java");
  const finding = evaluateFlowPaths(findSourceSinkPaths([analysis], {})).find(item => item.ruleId === "potential-sql-injection");

  assert.ok(finding);
  assert.ok(!finding.observedGuards.includes(GuardCapability.SQL_PARAMETERIZATION));
  assert.ok(finding.guardHints.some(hint => /raw value/.test(hint.reason)));
});

test("path confinement requires a trusted root operand", async () => {
  const untrusted = await analyzeTextAsync(`
export function read(req) {
  const root = req.query.root;
  const candidate = path.resolve(root, req.query.name);
  if (candidate.startsWith(root)) return fs.readFile(candidate);
}`, "javascript", "C:\\repo\\untrusted-root.js", "untrusted-root.js");
  const trusted = await analyzeTextAsync(`
export function read(req) {
  const root = "/srv/files";
  const candidate = path.resolve(root, req.query.name);
  if (candidate.startsWith(root)) return fs.readFile(candidate);
}`, "javascript", "C:\\repo\\trusted-root.js", "trusted-root.js");
  const unsafeFinding = evaluateFlowPaths(findSourceSinkPaths([untrusted], {})).find(item => item.ruleId === "potential-path-traversal");
  const safeFinding = evaluateFlowPaths(findSourceSinkPaths([trusted], {})).find(item => item.ruleId === "potential-path-traversal");

  assert.ok(unsafeFinding);
  assert.ok(!unsafeFinding.observedGuards.includes(GuardCapability.PATH_CONFINEMENT));
  assert.ok(unsafeFinding.guardHints.some(hint => /trusted/.test(hint.reason)));
  assert.equal(safeFinding, undefined);
});

test("constant framework responses are not findings while untrusted redirects stay flagged", () => {
  const constant = analyzeText(`
public class LoginServlet extends HttpServlet {
  @Override
  public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
    response.sendRedirect("/login");
  }
}`, "java", "C:\\repo\\LoginServlet.java", "LoginServlet.java");
  assert.equal(evaluateFlowPaths(findSourceSinkPaths([constant], {})).length, 0);

  const untrusted = analyzeText(`
public class NextServlet extends HttpServlet {
  @Override
  public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
    response.sendRedirect(request.getParameter("next"));
  }
}`, "java", "C:\\repo\\NextServlet.java", "NextServlet.java");
  const findings = evaluateFlowPaths(findSourceSinkPaths([untrusted], {}));
  assert.ok(findings.some(item => item.cwe === "CWE-601"));
});

test("inline handlers flag reflected input but not constant response bodies", () => {
  const reflected = analyzeText(`
app.get("/echo", (req, res) => {
  res.send(req.query.msg);
});`, "javascript", "C:\\repo\\echo.js", "echo.js");
  assert.ok(evaluateFlowPaths(findSourceSinkPaths([reflected], {})).some(item => item.cwe === "CWE-79"));

  const constant = analyzeText(`
app.get("/health", (req, res) => {
  res.send("ok");
});`, "javascript", "C:\\repo\\health.js", "health.js");
  assert.equal(evaluateFlowPaths(findSourceSinkPaths([constant], {})).length, 0);
});

test("AST-verified Python parameterized SQL keeps the flow but suppresses the injection rule", async () => {
  const analysis = await analyzeTextAsync(`
@app.post("/save")
def save():
    name = request.args.get("name")
    cursor.execute("INSERT INTO users (name) VALUES (?)", (name,))
`, "python", "C:\\repo\\app.py", "app.py");

  const paths = findSourceSinkPaths([analysis], {});
  const sqlPath = paths.find(item => item.category === "database");
  assert.ok(sqlPath);
  assert.ok(sqlPath.guardCapabilities.includes(GuardCapability.SQL_PARAMETERIZATION));
  assert.ok(!evaluateFlowPaths(paths).some(item => item.ruleId === "potential-sql-injection"));
});

test("regex-only parameterization evidence cannot suppress a finding", () => {
  const analysis = analyzeText(`
@app.post("/save")
def save():
    name = request.args.get("name")
    cursor.execute("INSERT INTO users (name) VALUES (?)", (name,))
`, "python", "C:\\repo\\fallback.py", "fallback.py");
  const path = findSourceSinkPaths([analysis], {}).find(item => item.category === "database");
  const finding = evaluateFlowPaths([path]).find(item => item.ruleId === "potential-sql-injection");

  assert.ok(finding);
  assert.ok(!path.guardCapabilities.includes(GuardCapability.SQL_PARAMETERIZATION));
  assert.ok(path.guardHints.some(hint => /trusted semantic model/.test(hint.reason)));
});

test("same-rule paths ending at one sink are consolidated", () => {
  const analysis = analyzeText(`
export function search(req) {
  const first = req.query.first;
  const second = req.query.second;
  database.query(first + second);
}
`, "javascript", "C:\\repo\\search.js", "search.js");

  const sql = evaluateFlowPaths(findSourceSinkPaths([analysis], {})).filter(item => item.ruleId === "potential-sql-injection");
  assert.equal(sql.length, 1);
  assert.equal(sql[0].pathCount, 2);
  assert.equal(sql[0].pathIds.length, 2);
});

test("Selenium navigation is modeled as an SSRF sink", () => {
  const analysis = analyzeText(`
@app.get("/preview")
def preview():
    url = request.args.get("url")
    driver.get(url)
`, "python", "C:\\repo\\preview.py", "preview.py");

  const findings = evaluateFlowPaths(findSourceSinkPaths([analysis], {}));
  const ssrf = findings.find(item => item.ruleId === "potential-ssrf" && item.line === 5);
  assert.ok(ssrf);
  assert.equal(ssrf.confidence, "low");
});

test("unrelated PHP superglobal fields do not create duplicate paths", () => {
  const analysis = analyzeText(`<?php
if ($_SERVER["REQUEST_METHOD"] === "GET") {
  $url = $_SERVER["QUERY_STRING"];
  curl_setopt($ch, CURLOPT_URL, $url);
}
`, "php", "C:\\repo\\proxy.php", "proxy.php");

  const ssrf = evaluateFlowPaths(findSourceSinkPaths([analysis], {})).find(item => item.ruleId === "potential-ssrf");
  assert.ok(ssrf);
  assert.equal(ssrf.pathCount, 1);
  assert.equal(ssrf.path.source.line, 3);
});
