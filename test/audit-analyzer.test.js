const assert = require("node:assert/strict");
const test = require("node:test");
const { analyzeText, buildAuditModel, traceIdentifier } = require("../src/audit-analyzer");
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
  assert.equal(analysis.items[0].kind, "endpoint");
  assert.ok(analysis.items[0].counts.sources >= 1);
  assert.ok(analysis.items[0].counts.auth >= 1);
  assert.ok(analysis.items[0].counts.sanitizers >= 1);
  assert.ok(analysis.items[0].counts.sinks >= 1);
});

test("PHP route with request data and a command is prioritized for review", () => {
  const source = `<?php
Route::post('/tools/ping', function () {
  $host = $_POST['host'];
  system('ping ' . $host);
});`;
  const analysis = analyzeText(source, "php", "C:\\public\\routes.php", "public/routes.php");
  assert.equal(analysis.entries.length, 1);
  assert.equal(analysis.items[0].priority, "P0");
  assert.match(analysis.items[0].reasons.join(" "), /sensitive operation/i);
  assert.equal(analysis.items[0].categories[0], "command");
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
  assert.ok(analysis.items[0].counts.sources >= 1);
  assert.ok(analysis.items[0].counts.sinks >= 1);
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
  assert.equal(analysis.items[0].categories[0], "network");
  assert.ok(analysis.items[0].counts.sources >= 1);
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
  assert.ok(analysis.items[0].counts.auth >= 1);
  assert.equal(analysis.items[0].categories[0], "command");
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
  const target = analysis.items.find(item => item.functionName === "proxy");
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
