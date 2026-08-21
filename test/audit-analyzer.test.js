const assert = require("node:assert/strict");
const test = require("node:test");
const { analyzeText, buildAuditModel, traceIdentifier } = require("../src/audit-analyzer");
const { buildReviewTargets } = require("../src/review/targets");
const { languageForPath } = require("../src/language-support");

test("Java Spring endpoint becomes an audit target with local controls and sinks", () => {
  const source = `
class UserController {
  @GetMapping("/users/{id}")
  @PreAuthorize("hasRole('ADMIN')")
  public User find(@PathVariable String id) {
    PreparedStatement stmt = connection.prepareStatement("SELECT * FROM users WHERE id = ?");
    stmt.setString(1, id);
    return stmt.executeQuery();
  }
}`;
  const analysis = analyzeText(source, "java", "C:\\src\\UserController.java", "src/UserController.java");
  assert.equal(analysis.entries.length, 1);
  assert.equal(analysis.entries[0].title, "GET /users/{id}");
  const items = buildReviewTargets(analysis);
  assert.equal(items[0].kind, "endpoint");
  assert.ok(items[0].counts.sources >= 1);
  assert.ok(items[0].counts.auth >= 1);
  assert.ok(items[0].counts.sanitizers >= 1);
  assert.ok(items[0].counts.sinks >= 1);
});

test("PHP route with request data and a command is prioritized for review", () => {
  const source = `<?php
Route::post('/tools/ping', function () {
  $host = $_POST['host'];
  system('ping ' . $host);
});`;
  const analysis = analyzeText(source, "php", "C:\\public\\routes.php", "public/routes.php");
  assert.equal(analysis.entries.length, 1);
  const items = buildReviewTargets(analysis);
  assert.equal(items[0].priority, "P0");
  assert.match(items[0].reasons.join(" "), /sensitive operation/i);
  assert.equal(items[0].categories[0], "command");
});

test("workspace audit model orders priority and records indexed coverage surface", () => {
  const php = analyzeText("<?php $id=$_GET['id']; echo $id;", "php", "C:\\a.php", "a.php");
  const java = analyzeText("class Safe { public void helper() { int x = 1; } }", "java", "C:\\Safe.java", "Safe.java");
  const model = buildAuditModel([java, php]);
  assert.equal(model.files, 2);
  assert.equal(model.entries.length, 1);
  assert.ok(model.items.length >= 1);
  assert.equal(model.languages.java, 1);
  assert.equal(model.languages.php, 1);
});

test("TypeScript Nest endpoint exposes request and database review clues", () => {
  const source = `
class SearchController {
  @Post("/search")
  async search(@Body() input: SearchDto) {
    return this.database.query("SELECT * FROM docs WHERE title = " + input.title);
  }
}`;
  const analysis = analyzeText(source, "typescript", "C:\\src\\search.controller.ts", "src/search.controller.ts");
  assert.equal(analysis.entries[0].title, "POST /search");
  const items = buildReviewTargets(analysis);
  assert.ok(items[0].counts.sources >= 1);
  assert.ok(items[0].counts.sinks >= 1);
});

test("Python Flask route records request input and outbound request", () => {
  const source = `
@app.post("/fetch")
def fetch_url():
    target = request.json["url"]
    return requests.get(target).text
`;
  const analysis = analyzeText(source, "python", "C:\\app\\views.py", "app/views.py");
  assert.equal(analysis.entries[0].title, "POST /fetch");
  const items = buildReviewTargets(analysis);
  assert.equal(items[0].categories[0], "network");
  assert.ok(items[0].counts.sources >= 1);
});

test("C# ASP.NET action includes authorization and process execution", () => {
  const source = `
class ToolController {
  [HttpPost("run")]
  [Authorize]
  public IActionResult Run([FromBody] ToolInput input) {
    Process.Start(input.Command);
    return Ok();
  }
}`;
  const analysis = analyzeText(source, "csharp", "C:\\Controllers\\ToolController.cs", "Controllers/ToolController.cs");
  assert.equal(analysis.entries[0].title, "POST run");
  const items = buildReviewTargets(analysis);
  assert.ok(items[0].counts.auth >= 1);
  assert.equal(items[0].categories[0], "command");
});

test("Go HTTP handler becomes a navigable review target", () => {
  const source = `
func proxy(w http.ResponseWriter, r *http.Request) {
    target := r.URL.Query().Get("url")
    response, _ := http.Get(target)
    fmt.Fprint(w, response.Status)
}

func routes() {
    http.HandleFunc("/proxy", proxy)
}`;
  const analysis = analyzeText(source, "go", "C:\\cmd\\server.go", "cmd/server.go");
  assert.ok(analysis.entries.some(item => item.route === "/proxy"));
  const target = buildReviewTargets(analysis).find(item => item.functionName === "proxy");
  assert.ok(target.counts.sources >= 1);
  assert.ok(target.counts.sinks >= 1);
});

test("supported file extensions map to the intended analyzers", () => {
  assert.equal(languageForPath("controller.java"), "java");
  assert.equal(languageForPath("route.php"), "php");
  assert.equal(languageForPath("handler.jsx"), "javascript");
  assert.equal(languageForPath("handler.tsx"), "typescript");
  assert.equal(languageForPath("views.py"), "python");
  assert.equal(languageForPath("Controller.cs"), "csharp");
  assert.equal(languageForPath("server.go"), "go");
  assert.equal(languageForPath("README.md"), undefined);
});

test("selected symbol trace orders input, assignment and sensitive use", () => {
  const source = `
function run(req) {
  const command = req.body.command;
  if (!command) return;
  exec(command);
}`;
  const analysis = analyzeText(source, "javascript", "C:\\src\\run.js", "src/run.js");
  const trace = traceIdentifier(source, "command", analysis.signals);
  assert.deepEqual(trace.map(item => item.role), ["input", "condition", "sensitive-use"]);
  assert.deepEqual(trace.map(item => item.line), [3, 4, 5]);
});

test("parser output stays free of review priority; the review-target layer adds it", () => {
  const analysis = analyzeText(`<?php $id = $_GET['id']; system('ping ' . $id);`, "php", "C:\\tools.php", "tools.php");
  assert.equal(analysis.items, undefined);
  assert.ok(analysis.signals.some(signal => signal.kind === "source"));
  assert.ok(analysis.signals.some(signal => signal.kind === "sink"));
  const items = buildReviewTargets(analysis);
  assert.equal(items.length, 1);
  assert.equal(items[0].priority, "P0");
  assert.ok(items[0].id);
});

test("plain helpers without sensitive flows stay out of the review queue", () => {
  const analysis = analyzeText(`
function add(left, right) {
  return left + right;
}`, "javascript", "C:\\src\\util.js", "src/util.js");
  assert.deepEqual(buildReviewTargets(analysis), []);
});

test("commented braces do not truncate function ranges", () => {
  const source = `
function run(req) {
  // } fake close
  /* } another fake */
  /*
    multi } line } comment
  */
  exec(req.body.cmd);
  return "ok }";
}`;
  const analysis = analyzeText(source, "javascript", "C:\\src\\run.js", "src/run.js");
  assert.equal(analysis.functions.length, 1);
  assert.equal(analysis.functions[0].endLine, 10);
});

test("strings and comments do not create audit signals or findings", () => {
  const samples = [
    `function stringOnly() { console.log("req.body.cmd; exec(req.body.cmd)"); }`,
    `function lineComment() { const safe = 1; // exec(req.body.cmd)\nreturn safe; }`,
    `function blockComment() { /* exec(req.body.cmd) */ return 1; }`,
    `function multilineComment() {\n/* req.body.cmd\nexec(req.body.cmd) */\nreturn 1;\n}`,
  ];
  for (const [index, source] of samples.entries()) {
    const analysis = analyzeText(source, "javascript", `C:\\src\\safe-${index}.js`, `src/safe-${index}.js`);
    assert.deepEqual(analysis.signals, []);
    assert.deepEqual(buildAuditModel([analysis]).items, []);
  }
});

test("Python signals do not leak from the previous function and nested projections are deduplicated", () => {
  const analysis = analyzeText(`
def save_history(value):
    cursor.execute("INSERT INTO history (value) VALUES (?)", (value,))

def handler():
    value = request.args.get("value")
    def nested():
        return value
    return nested()
`, "python", "C:\\repo\\app.py", "app.py");

  const handler = analysis.ir.functions.find(fn => fn.name === "handler");
  assert.ok(handler);
  assert.ok(!handler.operations.some(operation => operation.kind === "sink"));
  assert.equal(analysis.signals.filter(signal => signal.kind === "source").length, 1);
});

test("empty PHP curl handles are not network sinks", () => {
  const analysis = analyzeText(`<?php
function proxy($url) {
  $ch = curl_init();
  curl_setopt($ch, CURLOPT_URL, $url);
}
`, "php", "C:\\repo\\proxy.php", "proxy.php");

  assert.deepEqual(analysis.signals.filter(signal => signal.kind === "sink").map(signal => signal.line), [4]);
});

test("review target IDs survive unrelated lines inserted above a function", () => {
  const before = analyzeText(`
export function run(req) {
  exec(req.body.command);
}`, "javascript", "C:\\repo\\run.js", "run.js");
  const after = analyzeText(`
const banner = "unchanged behavior";

export function run(req) {
  exec(req.body.command);
}`, "javascript", "C:\\repo\\run.js", "run.js");

  assert.equal(buildReviewTargets(before)[0].id, buildReviewTargets(after)[0].id);
  assert.notEqual(buildReviewTargets(before)[0].line, buildReviewTargets(after)[0].line);
});
