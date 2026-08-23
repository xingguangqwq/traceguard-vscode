"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { analyzeTextAsync } = require("../src/audit-analyzer");
const { OperationKind } = require("../src/ir/schema");

const CASES = [
  ["java", "Controller.java", `
class Controller {
  public void run(HttpServletRequest req) {
    String cmd = req.getParameter("cmd");
    Runtime.getRuntime().exec(cmd);
  }
}`],
  ["python", "app.py", `
def run(request):
    cmd = request.args.get("cmd")
    subprocess.run(cmd)
`],
  ["php", "index.php", `<?php
class Controller {
  public function run(string $prefix) {
    $cmd = $_GET["cmd"];
    system($cmd);
  }
}
`],
  ["csharp", "Controller.cs", `
class Controller {
  public void Run() {
    var cmd = Request.Query["cmd"];
    Process.Start(cmd);
  }
}`],
  ["go", "handler.go", `
package handler
func Run(c *gin.Context) {
  cmd := c.Query("cmd")
  exec.Command(cmd)
}
`],
];

for (const [language, fileName, source] of CASES) {
  test(`${language} uses its Tree-sitter WASM frontend and emits normalized IR`, async () => {
    const analysis = await analyzeTextAsync(source, language, `C:\\repo\\${fileName}`, fileName, { differential: true });
    assert.equal(analysis.frontend.mode, "ast");
    assert.equal(analysis.frontend.parser, "tree-sitter-wasm");
    assert.equal(analysis.frontend.treeHasErrors, false);
    assert.ok(analysis.frontend.differential);
    const fn = analysis.ir.functions.find(candidate => !candidate.isGlobal);
    assert.ok(fn?.symbolKey);
    assert.ok(fn.operations.some(operation => operation.kind === OperationKind.SOURCE));
    assert.ok(fn.operations.some(operation => operation.kind === OperationKind.SINK));
    assert.ok(fn.operations.some(operation => operation.kind === OperationKind.CALL));
  });
}
