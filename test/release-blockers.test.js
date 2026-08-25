"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const path = require("node:path");
const { WorkspaceAnalysisEngine } = require("../src/analysis/workspace-engine");
const { analyzeTextAsync } = require("../src/audit-analyzer");
const { runDataflowAnalysis } = require("../src/dataflow/pipeline");
const { normalizePath } = require("../src/identity");

test("an unrelated saved comment does not rebuild the call graph or dataflow", async () => {
  const engine = new WorkspaceAnalysisEngine();
  const file = {
    language: "java",
    absolutePath: "/workspace/Search.java",
    relativePath: "Search.java",
    version: "1",
    text: "class Search { void run(HttpServletRequest request) { Runtime.getRuntime().exec(request.getParameter(\"cmd\")); } }",
  };
  const initial = await engine.initializeWorkspace([file]);
  const generation = initial.metadata.generation;
  const findingIds = engine.dataflow.findings.map(finding => finding.id);

  const updated = await engine.updateFile({ ...file, version: "2", text: `${file.text}\n// saved comment` });

  assert.equal(updated.semanticNoop, true);
  assert.deepEqual(updated.affectedFiles, []);
  assert.deepEqual(updated.changedFunctionIds, []);
  assert.equal(updated.metadata.generation, generation);
  assert.equal(updated.metadata.dataflowMs, 0);
  assert.deepEqual(engine.dataflow.findings.map(finding => finding.id), findingIds);
});

test("POSIX case-sensitive paths remain distinct in the workspace engine", async () => {
  const engine = new WorkspaceAnalysisEngine();
  const result = await engine.initializeWorkspace([
    { language: "javascript", absolutePath: "/workspace/Foo.js", relativePath: "Foo.js", version: "1", text: "export function upper() { return 1; }" },
    { language: "javascript", absolutePath: "/workspace/foo.js", relativePath: "foo.js", version: "1", text: "export function lower() { return 2; }" },
  ]);

  assert.equal(result.analyses.length, 2);
  assert.equal(new Set(result.analyses.flatMap(analysis => analysis.ir.functions.map(fn => fn.symbolKey))).size, 2);
  assert.equal(normalizePath("C:\\Workspace\\Foo.js"), normalizePath("c:\\workspace\\foo.js"));
});

test("inline JavaScript and PHP routes receive distinct semantic callback identities", async () => {
  const javascript = await analyzeTextAsync(`
app.get("/a", (req, res) => res.send(req.query.value));
app.get("/b", (req, res) => res.send(req.query.value));
`, "javascript", "/workspace/routes.js", "routes.js");
  const php = await analyzeTextAsync(`<?php
Route::get('/a', function ($request) { system($request->query('cmd')); });
Route::get('/b', function ($request) { system($request->query('cmd')); });
`, "php", "/workspace/routes.php", "routes.php");

  for (const analysis of [javascript, php]) {
    const handlers = analysis.ir.functions.filter(fn => !fn.isGlobal);
    assert.equal(handlers.length, 2);
    assert.equal(new Set(handlers.map(fn => fn.id)).size, 2);
    assert.equal(analysis.entries.length, 2);
    assert.equal(new Set(analysis.entries.map(entry => entry.functionId)).size, 2);
  }

  const moved = await analyzeTextAsync(`
// unrelated header
app.get("/a", (req, res) => res.send(req.query.value));
app.get("/b", (req, res) => res.send(req.query.value));
`, "javascript", "/workspace/routes.js", "routes.js");
  const idsByRoute = Object.fromEntries(javascript.entries.map(entry => [entry.route, entry.functionId]));
  assert.deepEqual(Object.fromEntries(moved.entries.map(entry => [entry.route, entry.functionId])), idsByRoute);
});

test("all generic language frontends attach AST branch ranges", async () => {
  const cases = [
    ["java", "Branch.java", "class Branch { void run(boolean ok) { if (ok) { System.out.println(ok); } } }"],
    ["python", "branch.py", "def run(ok):\n    if ok:\n        print(ok)\n"],
    ["php", "branch.php", "<?php function run($ok) { if ($ok) { echo $ok; } }"],
    ["csharp", "Branch.cs", "class Branch { void Run(bool ok) { if (ok) { Console.WriteLine(ok); } } }"],
    ["go", "branch.go", "package main\nfunc run(ok bool) { if ok { println(ok) } }\n"],
  ];
  for (const [language, fileName, source] of cases) {
    const analysis = await analyzeTextAsync(source, language, `/workspace/${fileName}`, fileName);
    const branch = analysis.ir.functions.flatMap(fn => fn.operations).find(operation => operation.kind === "branch");
    assert.ok(branch?.metadata.branch.thenRange, `${language} has no thenRange`);
    assert.ok(branch.metadata.branch.conditionRange, `${language} has no conditionRange`);
  }
});

test("plain TypeScript generics use TS ScriptKind rather than TSX", async () => {
  const analysis = await analyzeTextAsync(
    "const identity = <T>(value: T): T => value;",
    "typescript",
    "/workspace/identity.ts",
    "identity.ts",
  );

  assert.equal(analysis.frontend.compilerDiagnostics, 0);
  assert.equal(analysis.frontend.degraded, false);
  assert.ok(analysis.ir.functions.some(fn => fn.name === "identity"));
});

test("TypeScript compiler parse diagnostics explicitly degrade frontend capability", async () => {
  const analysis = await analyzeTextAsync(
    "export function broken(value: string { return value; }",
    "typescript",
    "/workspace/broken.ts",
    "broken.ts",
  );
  assert.ok(analysis.frontend.compilerDiagnostics > 0);
  assert.equal(analysis.frontend.degraded, true);
  assert.match(analysis.frontend.degradedReason, /Compiler API reported/);
});

test("Java branch-local SQL parameterization does not sanitize a sink after the branch", async () => {
  const analysis = await analyzeTextAsync(`
class QueryController {
  void run(HttpServletRequest req, PreparedStatement ps, Statement stmt, boolean trusted) {
    String user = req.getParameter("user");
    if (trusted) {
      ps.setString(1, user);
    }
    stmt.executeQuery("SELECT * FROM users WHERE name='" + user + "'");
  }
}
`, "java", "/workspace/QueryController.java", "QueryController.java");
  const result = runDataflowAnalysis([analysis]);

  assert.ok(result.findings.some(finding => finding.ruleId === "potential-sql-injection"));
  const fn = analysis.ir.functions.find(item => item.name === "run");
  const branch = fn.operations.find(operation => operation.kind === "branch");
  assert.ok(branch.metadata.branch.thenRange);
  assert.ok(fn.cfg.edges.some(edge => edge.kind === "true"));
  assert.ok(fn.cfg.edges.some(edge => edge.kind === "false"));
});

test("C# Minimal API and Go inline HandleFunc handlers become entry functions", async () => {
  const csharp = await analyzeTextAsync(`
app.MapGet("/x", (HttpRequest req) =>
    Process.Start(req.Query["cmd"].ToString()));
`, "csharp", "/workspace/Program.cs", "Program.cs");
  const go = await analyzeTextAsync(`
package main
func configure() {
  http.HandleFunc("/x", func(w http.ResponseWriter, r *http.Request) {
    exec.Command(r.URL.Query().Get("cmd"))
  })
}
`, "go", "/workspace/main.go", "main.go");

  for (const analysis of [csharp, go]) {
    assert.equal(analysis.entries.length, 1, `${analysis.language} entries: ${JSON.stringify(analysis.entries)}`);
    const entry = analysis.entries[0];
    assert.ok(entry.functionId);
    assert.ok(analysis.ir.functions.some(fn => fn.id === entry.functionId && !fn.isGlobal));
    assert.ok(runDataflowAnalysis([analysis]).findings.some(finding => finding.ruleId === "potential-command-injection"));
  }
});

test("AST route extraction is invariant when framework calls span multiple lines", async () => {
  const cases = [
    ["javascript", "routes.js", `app.get(
  "/x",
  (req, res) => exec(req.query.cmd),
);`, `app.get("/x", (req, res) => exec(req.query.cmd));`],
    ["php", "routes.php", `<?php Route::get(
  '/x',
  function ($request) { system($request->query('cmd')); }
);`, `<?php Route::get('/x', function ($request) { system($request->query('cmd')); });`],
    ["csharp", "Program.cs", `app.MapGet(
  "/x",
  (HttpRequest req) => Process.Start(req.Query["cmd"].ToString())
);`, `app.MapGet("/x", (HttpRequest req) => Process.Start(req.Query["cmd"].ToString()));`],
    ["go", "main.go", `package main
func configure() {
  http.HandleFunc(
    "/x",
    func(w http.ResponseWriter, r *http.Request) { exec.Command(r.URL.Query().Get("cmd")) },
  )
}`, `package main
func configure() { http.HandleFunc("/x", func(w http.ResponseWriter, r *http.Request) { exec.Command(r.URL.Query().Get("cmd")) }) }`],
  ];

  for (const [language, fileName, source, compactSource] of cases) {
    const analysis = await analyzeTextAsync(source, language, `/workspace/${fileName}`, fileName);
    const compact = await analyzeTextAsync(compactSource, language, `/workspace/${fileName}`, fileName);
    const route = analysis.entries.find(entry => entry.route === "/x");
    const compactRoute = compact.entries.find(entry => entry.route === "/x");
    assert.ok(route, `${language} lost the multiline /x route: ${JSON.stringify(analysis.entries)}`);
    assert.ok(route.functionId, `${language} did not bind /x to its handler`);
    assert.deepEqual(
      { method: route.method, route: route.route, functionId: route.functionId },
      { method: compactRoute?.method, route: compactRoute?.route, functionId: compactRoute?.functionId },
      `${language} route identity changed with formatting`,
    );
    const rules = value => runDataflowAnalysis([value]).findings.map(finding => finding.ruleId).sort();
    assert.deepEqual(rules(analysis), rules(compact), `${language} findings changed with formatting`);
    assert.ok(rules(analysis).includes("potential-command-injection"), `${language} lost the command flow`);
  }
});

test("single-line Java branch spans keep a following SQL sink outside the branch", async () => {
  const source = `class QueryController { void run(HttpServletRequest req, PreparedStatement ps, Statement stmt, boolean trusted) { String user = req.getParameter("user"); if (trusted) { ps.setString(1, user); } return stmt.executeQuery("SELECT " + user); } }`;
  const analysis = await analyzeTextAsync(source, "java", "/workspace/InlineQuery.java", "InlineQuery.java");
  const formatted = await analyzeTextAsync(`
class QueryController {
  void run(HttpServletRequest req, PreparedStatement ps, Statement stmt, boolean trusted) {
    String user = req.getParameter("user");
    if (trusted) { ps.setString(1, user); }
    return stmt.executeQuery("SELECT " + user);
  }
}`, "java", "/workspace/InlineQuery.java", "InlineQuery.java");
  const finding = runDataflowAnalysis([analysis]).findings.find(item => item.ruleId === "potential-sql-injection");
  const formattedFinding = runDataflowAnalysis([formatted]).findings.find(item => item.ruleId === "potential-sql-injection");

  assert.ok(finding, "source layout must not move the SQL sink into the if branch");
  assert.equal(finding.sinkKind, formattedFinding?.sinkKind);
  const operations = analysis.ir.functions.find(fn => fn.name === "run").operations;
  const branch = operations.find(item => item.kind === "branch");
  const sink = operations.find(item => item.kind === "sink");
  assert.ok(branch.metadata.branch.thenRange.endOffset < sink.location.startOffset);
});

test("TypeScript dependency changes regenerate imported consumers", async () => {
  const engine = new WorkspaceAnalysisEngine();
  const root = path.resolve(".traceguard-type-invalidation");
  const providerPath = path.join(root, "provider.ts");
  const consumerPath = path.join(root, "consumer.ts");
  const provider = type => ({
    language: "typescript",
    absolutePath: providerPath,
    relativePath: "provider.ts",
    version: type,
    text: `export function consume(callback: (value: ${type}) => void) { callback(${type === "string" ? "'safe'" : "1"}); }`,
  });
  const consumer = {
    language: "typescript",
    absolutePath: consumerPath,
    relativePath: "consumer.ts",
    version: "1",
    text: `import { consume } from "./provider"; consume(value => fetch(String(value)));`,
  };

  await engine.initializeWorkspace([provider("string"), consumer]);
  const before = engine.analyses().find(item => item.relativePath === "consumer.ts").ir.functions.find(fn => fn.name.includes("callback"));
  const updated = await engine.updateFile(provider("number"));
  const after = engine.analyses().find(item => item.relativePath === "consumer.ts").ir.functions.find(fn => fn.name.includes("callback"));

  assert.equal(before.parameters[0].type, "string");
  assert.equal(after.parameters[0].type, "number");
  assert.notEqual(after.symbolKey, before.symbolKey);
  assert.ok(updated.affectedFiles.includes(normalizePath(consumerPath)));
});

test("Express routes bind every middleware and the final handler", async () => {
  const analysis = await analyzeTextAsync(`
function auth(req, res, next) { next(); }
app.get("/x", auth, (req, res) => exec(req.query.cmd));
`, "javascript", "/workspace/routes.js", "routes.js");
  const routeEntries = analysis.ir.entryPoints.filter(entry => entry.route === "/x");

  assert.equal(routeEntries.length, 2);
  assert.equal(new Set(routeEntries.map(entry => entry.functionId)).size, 2);
  assert.ok(routeEntries.every(entry => entry.functionId));
  assert.ok(runDataflowAnalysis([analysis]).findings.some(finding => finding.ruleId === "potential-command-injection"));

  const chained = await analyzeTextAsync(`
const route = "/x";
function auth(req, res, next) { next(); }
function handler(req, res) { exec(req.query.cmd); }
router.route(route).get([auth, handler]);
`, "javascript", "/workspace/chained-routes.js", "chained-routes.js");
  const chainedEntries = chained.ir.entryPoints.filter(entry => entry.route === "/x");
  assert.equal(chainedEntries.length, 2);
  assert.equal(new Set(chainedEntries.map(entry => entry.functionId)).size, 2);
  assert.ok(runDataflowAnalysis([chained]).findings.some(finding => finding.ruleId === "potential-command-injection"));
});

test("TypeScript routes bind imported handlers through the project checker", async () => {
  const engine = new WorkspaceAnalysisEngine();
  const root = path.resolve(".traceguard-cross-file-route");
  const routesPath = path.join(root, "routes.ts");
  const handlersPath = path.join(root, "handlers.ts");
  const result = await engine.initializeWorkspace([
    {
      language: "typescript", absolutePath: routesPath, relativePath: "routes.ts", version: "1",
      text: `import { handler } from "./handlers"; app.get("/x", handler);`,
    },
    {
      language: "typescript", absolutePath: handlersPath, relativePath: "handlers.ts", version: "1",
      text: `export function handler(req: Request, res: Response) { exec(req.url); }`,
    },
  ]);
  const routes = result.analyses.find(item => item.relativePath === "routes.ts");
  const handlers = result.analyses.find(item => item.relativePath === "handlers.ts");
  const handler = handlers.ir.functions.find(fn => fn.name === "handler");
  const entry = routes.ir.entryPoints.find(item => item.route === "/x");

  assert.equal(entry.functionId, handler.id);
  assert.equal(entry.symbolKey, handler.symbolKey);
  assert.ok(engine.queryPaths().findings.some(finding => finding.ruleId === "potential-command-injection"));
});

test("TypeScript checker follows handler aliases, namespaces and default imports", async () => {
  const engine = new WorkspaceAnalysisEngine();
  const root = path.resolve(".traceguard-handler-import-shapes");
  const routesPath = path.join(root, "routes.ts");
  const handlersPath = path.join(root, "handlers.ts");
  const result = await engine.initializeWorkspace([
    {
      language: "typescript", absolutePath: routesPath, relativePath: "routes.ts", version: "1",
      text: `
import fallback, { handler as aliased } from "./handlers";
import * as handlers from "./handlers";
app.get("/alias", aliased);
app.get("/namespace", handlers.handler);
app.get("/default", fallback);`,
    },
    {
      language: "typescript", absolutePath: handlersPath, relativePath: "handlers.ts", version: "1",
      text: `
export function handler(req: Request) { exec(req.url); }
export default function fallback(req: Request) { exec(req.url); }`,
    },
  ]);
  const routes = result.analyses.find(item => item.relativePath === "routes.ts");
  const handlers = result.analyses.find(item => item.relativePath === "handlers.ts");
  const named = handlers.ir.functions.find(fn => fn.name === "handler");
  const fallback = handlers.ir.functions.find(fn => fn.name === "fallback");
  const entries = Object.fromEntries(routes.ir.entryPoints.map(entry => [entry.route, entry]));

  assert.equal(entries["/alias"].functionId, named.id);
  assert.equal(entries["/namespace"].functionId, named.id);
  assert.equal(entries["/default"].functionId, fallback.id);
  assert.ok(engine.queryPaths().findings.some(finding => finding.ruleId === "potential-command-injection"));
});

test("re-exported TypeScript handlers are transitively invalidated", async () => {
  const engine = new WorkspaceAnalysisEngine();
  const root = path.resolve(".traceguard-handler-barrel");
  const handlersPath = path.join(root, "handlers.ts");
  const barrelPath = path.join(root, "index.ts");
  const routesPath = path.join(root, "routes.ts");
  const handler = (version, vulnerable) => ({
    language: "typescript", absolutePath: handlersPath, relativePath: "handlers.ts", version,
    text: `export function handler(req: Request) { ${vulnerable ? "exec(req.url);" : "return req.url;"} }`,
  });
  await engine.initializeWorkspace([
    handler("1", true),
    {
      language: "typescript", absolutePath: barrelPath, relativePath: "index.ts", version: "1",
      text: `export { handler } from "./handlers";`,
    },
    {
      language: "typescript", absolutePath: routesPath, relativePath: "routes.ts", version: "1",
      text: `import { handler } from "./index"; app.get("/x", handler);`,
    },
  ]);
  assert.ok(engine.queryPaths().findings.some(finding => finding.ruleId === "potential-command-injection"));

  const updated = await engine.updateFile(handler("2", false));

  assert.ok(updated.reparsedTypeDependents.includes(normalizePath(barrelPath)));
  assert.ok(updated.reparsedTypeDependents.includes(normalizePath(routesPath)));
  assert.equal(engine.queryPaths().findings.some(finding => finding.ruleId === "potential-command-injection"), false);
});

test("dynamic route expressions retain their handlers and HTTP method", async () => {
  const analysis = await analyzeTextAsync(`
const route = "/x";
app.get(route, (req, res) => exec(req.query.cmd));
`, "javascript", "/workspace/dynamic-route.js", "dynamic-route.js");
  const entry = analysis.ir.entryPoints.find(item => item.method === "GET");

  assert.ok(entry);
  assert.ok(entry.route === "/x" || entry.route === "<dynamic>");
  assert.ok(entry.functionId);
  assert.ok(runDataflowAnalysis([analysis]).findings.some(finding => finding.ruleId === "potential-command-injection"));
});

test("dynamic PHP, C# and Go routes remain bound AST entry points", async () => {
  const cases = [
    ["php", "routes.php", `<?php
$route = getenv("ROUTE");
Route::get($route, function ($request) { system($request->query("cmd")); });`, "GET"],
    ["csharp", "Program.cs", `
var route = config.Route;
app.MapGet(route, (HttpRequest req) => Process.Start(req.Query["cmd"].ToString()));`, "GET"],
    ["go", "main.go", `package main
func configure() {
  route := os.Getenv("ROUTE")
  http.HandleFunc(route, func(w http.ResponseWriter, r *http.Request) {
    exec.Command(r.URL.Query().Get("cmd"))
  })
}`, "REQUEST"],
  ];

  for (const [language, fileName, source, method] of cases) {
    const analysis = await analyzeTextAsync(source, language, `/workspace/${fileName}`, fileName);
    const entry = analysis.ir.entryPoints.find(item => item.route === "<dynamic>" && item.method === method);

    assert.equal(analysis.ir.frontend.mode, "ast");
    assert.ok(entry, `${language} discarded its dynamic route: ${JSON.stringify(analysis.ir.entryPoints)}`);
    assert.ok(entry.functionId, `${language} did not bind the dynamic route handler`);
    assert.ok(runDataflowAnalysis([analysis]).findings.some(finding => finding.ruleId === "potential-command-injection"));
  }
});

test("pathless Express middleware chains bind every handler", async () => {
  const analysis = await analyzeTextAsync(`
function auth(req, res, next) { next(); }
function handler(req, res) { exec(req.query.cmd); }
app.use(auth, handler);
`, "javascript", "/workspace/middleware.js", "middleware.js");
  const entries = analysis.ir.entryPoints.filter(item => item.route === "<all>");

  assert.equal(entries.length, 2);
  assert.equal(new Set(entries.map(entry => entry.functionId)).size, 2);
  assert.deepEqual(entries.map(entry => entry.handlerIndex), [0, 1]);
  assert.ok(runDataflowAnalysis([analysis]).findings.some(finding => finding.ruleId === "potential-command-injection"));
});

test("entry taint uses framework parameter roles instead of variable names", async () => {
  const analysis = await analyzeTextAsync(
    `app.get("/x", (response, res) => exec(response.query.cmd));`,
    "javascript",
    "/workspace/renamed-request.js",
    "renamed-request.js",
  );
  const handler = analysis.ir.functions.find(fn => !fn.isGlobal);

  assert.deepEqual(handler.parameters.map(parameter => parameter.role), ["request", "response"]);
  assert.ok(runDataflowAnalysis([analysis]).findings.some(finding => finding.ruleId === "potential-command-injection"));
});

test("C# Minimal API dependency-injected services are not HTTP taint seeds", async () => {
  const analysis = await analyzeTextAsync(`
app.MapGet("/run",
    ([FromServices] CommandService service) =>
        Process.Start(service.GetFixedCommand()));
`, "csharp", "/workspace/Program.cs", "Program.cs");
  const handler = analysis.ir.functions.find(fn => !fn.isGlobal);

  assert.equal(handler.parameters[0].role, "service");
  assert.equal(runDataflowAnalysis([analysis]).findings.some(finding => finding.ruleId === "potential-command-injection"), false);
});

test("C# binding attributes produce explicit parameter provenance", async () => {
  const analysis = await analyzeTextAsync(`
app.MapGet("/run",
    ([FromQuery] string command,
     [FromRoute] string id,
     [FromHeader] string token,
     [FromBody] Payload payload,
     [FromServices] CommandService service) =>
        Process.Start(command));
`, "csharp", "/workspace/Bindings.cs", "Bindings.cs");
  const handler = analysis.ir.functions.find(fn => !fn.isGlobal);
  const finding = runDataflowAnalysis([analysis]).findings.find(item => item.ruleId === "potential-command-injection");

  assert.deepEqual(handler.parameters.map(parameter => parameter.role), ["query", "path", "header", "body", "service"]);
  assert.equal(finding?.confidence, "medium");
});

test("removing a TypeScript provider reparses its consumers", async () => {
  const engine = new WorkspaceAnalysisEngine();
  const root = path.resolve(".traceguard-type-removal");
  const providerPath = path.join(root, "provider.ts");
  const consumerPath = path.join(root, "consumer.ts");
  await engine.initializeWorkspace([
    {
      language: "typescript", absolutePath: providerPath, relativePath: "provider.ts", version: "1",
      text: `export function consume(callback: (value: string) => void) { callback("safe"); }`,
    },
    {
      language: "typescript", absolutePath: consumerPath, relativePath: "consumer.ts", version: "1",
      text: `import { consume } from "./provider"; consume(value => fetch(String(value)));`,
    },
  ]);
  const before = engine.analyses().find(item => item.relativePath === "consumer.ts").ir.functions.find(fn => fn.name.includes("callback"));
  const removed = await engine.removeFile(providerPath);
  const after = engine.analyses().find(item => item.relativePath === "consumer.ts").ir.functions.find(fn => fn.name.includes("callback"));

  assert.equal(before.parameters[0].type, "string");
  assert.equal(after.parameters[0].type, "?");
  assert.notEqual(after.symbolKey, before.symbolKey);
  assert.ok(removed.affectedFiles.includes(normalizePath(consumerPath)));
  assert.ok(removed.reparsedTypeDependents.includes(normalizePath(consumerPath)));
});

test("dynamic import and CommonJS require participate in TypeScript invalidation", async () => {
  const engine = new WorkspaceAnalysisEngine();
  const root = path.resolve(".traceguard-dynamic-dependencies");
  const providerPath = path.join(root, "provider.ts");
  const dynamicPath = path.join(root, "dynamic.ts");
  const commonJsPath = path.join(root, "commonjs.js");
  const provider = type => ({
    language: "typescript", absolutePath: providerPath, relativePath: "provider.ts", version: type,
    text: `export function consume(callback: (value: ${type}) => void) { callback(${type === "string" ? "'safe'" : "1"}); }`,
  });
  await engine.initializeWorkspace([
    provider("string"),
    {
      language: "typescript", absolutePath: dynamicPath, relativePath: "dynamic.ts", version: "1",
      text: `async function run() { const { consume } = await import("./provider"); consume(value => fetch(String(value))); }`,
    },
    {
      language: "javascript", absolutePath: commonJsPath, relativePath: "commonjs.js", version: "1",
      text: `const { consume } = require("./provider"); consume(value => fetch(String(value)));`,
    },
  ]);
  const before = engine.analyses().find(item => item.relativePath === "dynamic.ts").ir.functions.find(fn => fn.name.includes("callback"));
  const updated = await engine.updateFile(provider("number"));
  const after = engine.analyses().find(item => item.relativePath === "dynamic.ts").ir.functions.find(fn => fn.name.includes("callback"));

  assert.equal(before.parameters[0].type, "string");
  assert.equal(after.parameters[0].type, "number");
  assert.ok(updated.reparsedTypeDependents.includes(normalizePath(dynamicPath)));
  assert.ok(updated.reparsedTypeDependents.includes(normalizePath(commonJsPath)));
});

test("Go Gorilla Methods refines HandleFunc HTTP methods", async () => {
  const analysis = await analyzeTextAsync(`
package main
func handler(w http.ResponseWriter, r *http.Request) { exec.Command(r.URL.Query().Get("cmd")) }
func configure() { router.HandleFunc("/x", handler).Methods("POST") }
`, "go", "/workspace/main.go", "main.go");
  const entries = analysis.ir.entryPoints.filter(entry => entry.route === "/x");

  assert.equal(entries.length, 1);
  assert.equal(entries[0].method, "POST");
  assert.ok(entries[0].functionId);
  assert.ok(runDataflowAnalysis([analysis]).findings.some(finding => finding.ruleId === "potential-command-injection"));
});

test("adding and removing a cross-file route invalidates the bound handler", async () => {
  const engine = new WorkspaceAnalysisEngine();
  const root = path.resolve(".traceguard-entry-binding-invalidation");
  const routesPath = path.join(root, "routes.ts");
  const handlersPath = path.join(root, "handlers.ts");
  const routes = (version, enabled) => ({
    language: "typescript", absolutePath: routesPath, relativePath: "routes.ts", version,
    text: `import { handler } from "./handlers"; ${enabled ? "app.get('/x', handler);" : "export const routes = [];"}`,
  });
  await engine.initializeWorkspace([
    routes("1", false),
    {
      language: "typescript", absolutePath: handlersPath, relativePath: "handlers.ts", version: "1",
      text: `export function handler(req: Request) { exec(req.url); }`,
    },
  ]);
  const handlerId = engine.analyses().find(item => item.relativePath === "handlers.ts").ir.functions.find(fn => fn.name === "handler").id;
  assert.equal(engine.queryPaths().findings.some(finding => finding.ruleId === "potential-command-injection"), false);

  const added = await engine.updateFile(routes("2", true));
  assert.ok(added.changedFunctionIds.includes(handlerId));
  assert.ok(engine.queryPaths().findings.some(finding => finding.ruleId === "potential-command-injection"));

  const removed = await engine.updateFile(routes("3", false));
  assert.ok(removed.changedFunctionIds.includes(handlerId));
  assert.equal(engine.queryPaths().findings.some(finding => finding.ruleId === "potential-command-injection"), false);
});

test("unknown Minimal API parameter roles remain reviewable at reduced confidence", async () => {
  const analysis = await analyzeTextAsync(
    `app.MapGet("/run", (string value) => Process.Start(value));`,
    "csharp",
    "/workspace/UnknownBinding.cs",
    "UnknownBinding.cs",
  );
  const handler = analysis.ir.functions.find(fn => !fn.isGlobal);
  const finding = runDataflowAnalysis([analysis]).findings.find(item => item.ruleId === "potential-command-injection");

  assert.equal(handler.parameters[0].role, "unknown");
  assert.equal(finding?.confidence, "medium");
});
